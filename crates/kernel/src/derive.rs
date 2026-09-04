use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, SecretKey};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KernelError, Result};
use crate::secret::SecretBytes;

type HmacSha512 = Hmac<Sha512>;

/// Marks an index as hardened. BIP-32 writes this as an apostrophe in the path.
pub const HARDENED: u32 = 0x8000_0000;

/// Which curve a chain family signs with.
///
/// This is not cosmetic. secp256k1 supports non-hardened derivation because a child public key
/// can be computed from a parent public key; ed25519 cannot, so SLIP-0010 defines hardened
/// derivation only and a non-hardened index must be rejected rather than quietly hardened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Secp256k1,
    Ed25519,
}

impl Curve {
    /// The HMAC key that seeds the master node, from BIP-32 and SLIP-0010.
    fn master_key(self) -> &'static [u8] {
        match self {
            Self::Secp256k1 => b"Bitcoin seed",
            Self::Ed25519 => b"ed25519 seed",
        }
    }
}

/// A parsed BIP-44 style derivation path.
///
/// Paths come from the chain registry, never from a hardcoded table, so a chain with an
/// unusual coin type such as Terra (330) or Secret (529) works without a code change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    indices: Vec<u32>,
}

impl DerivationPath {
    /// Parses `m/44'/118'/0'/0/0`. Accepts `'` or `h` or `H` for hardened.
    pub fn parse(path: &str) -> Result<Self> {
        let trimmed = path.trim();
        let mut parts = trimmed.split('/');

        match parts.next() {
            Some("m") | Some("M") => {}
            _ => return Err(KernelError::PathSyntax),
        }

        let mut indices = Vec::new();
        for part in parts {
            if part.is_empty() {
                return Err(KernelError::PathSyntax);
            }
            let (digits, hardened) = match part.strip_suffix(['\'', 'h', 'H']) {
                Some(rest) => (rest, true),
                None => (part, false),
            };
            let raw: u32 = digits.parse().map_err(|_| KernelError::PathSyntax)?;
            if raw >= HARDENED {
                // A literal index at or above 2^31 is ambiguous with the hardened flag.
                return Err(KernelError::PathSyntax);
            }
            indices.push(if hardened { raw | HARDENED } else { raw });
        }

        // A bare "m" is the master key, a depth-zero path. Valid BIP-32, and the official test
        // vectors start every chain with it, so it is accepted rather than rejected as empty.
        // Callers that need an account path should ask for one; this type does not police that.
        Ok(Self { indices })
    }

    /// Builds the standard BIP-44 account path `m/44'/coin'/account'/0/index`.
    pub fn bip44(coin_type: u32, account: u32, index: u32) -> Self {
        Self {
            indices: vec![
                44 | HARDENED,
                coin_type | HARDENED,
                account | HARDENED,
                0,
                index,
            ],
        }
    }

    /// Builds the SLIP-0010 ed25519 path `m/44'/coin'/index'/0'`, used by Solana.
    pub fn slip10_ed25519(coin_type: u32, index: u32) -> Self {
        Self {
            indices: vec![
                44 | HARDENED,
                coin_type | HARDENED,
                index | HARDENED,
                HARDENED,
            ],
        }
    }

    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    pub fn depth(&self) -> usize {
        self.indices.len()
    }

    /// The account index, meaning the third path element with the hardened bit removed.
    pub fn account(&self) -> Option<u32> {
        self.indices.get(2).map(|i| i & !HARDENED)
    }

    /// The address index, meaning the final element with the hardened bit removed.
    pub fn address_index(&self) -> Option<u32> {
        self.indices.last().map(|i| i & !HARDENED)
    }
}

impl core::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("m")?;
        for index in &self.indices {
            if index & HARDENED != 0 {
                write!(f, "/{}'", index & !HARDENED)?;
            } else {
                write!(f, "/{index}")?;
            }
        }
        Ok(())
    }
}

/// An extended key: a private scalar plus its chain code.
///
/// Both halves are secret. The chain code is not a key, but combined with a public key it lets
/// an attacker derive every non-hardened child, so it is treated as key material.
pub struct ExtendedKey {
    curve: Curve,
    secret: SecretBytes,
    chain_code: SecretBytes,
}

impl ExtendedKey {
    /// BIP-32 and SLIP-0010 master key generation from a BIP-39 seed.
    pub fn master(curve: Curve, seed: &[u8]) -> Result<Self> {
        // BIP-32 requires 128 to 512 bits of seed. A shorter seed is a caller bug and is
        // rejected rather than stretched.
        if seed.len() < 16 || seed.len() > 64 {
            return Err(KernelError::InvalidKey);
        }

        let mut mac =
            HmacSha512::new_from_slice(curve.master_key()).map_err(|_| KernelError::InvalidKey)?;
        mac.update(seed);
        let mut digest = Zeroizing::new(mac.finalize().into_bytes());
        let (left, right) = digest.split_at(32);

        let secret = match curve {
            Curve::Secp256k1 => {
                // Per BIP-32, if IL is zero or >= n the seed is unusable. The specification
                // says to fail rather than retry at the master level.
                SecretKey::from_slice(left).map_err(|_| KernelError::InvalidKey)?;
                SecretBytes::from_slice(left)
            }
            // SLIP-0010 ed25519 accepts any 32 bytes as a private key.
            Curve::Ed25519 => SecretBytes::from_slice(left),
        };
        let chain_code = SecretBytes::from_slice(right);
        digest.zeroize();

        Ok(Self {
            curve,
            secret,
            chain_code,
        })
    }

    /// Derives one child.
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let hardened = index & HARDENED != 0;

        if self.curve == Curve::Ed25519 && !hardened {
            // SLIP-0010 defines only hardened derivation for ed25519. Silently hardening the
            // index would produce addresses that no other wallet reproduces.
            return Err(KernelError::PathUnsupported);
        }

        let mut mac = HmacSha512::new_from_slice(self.chain_code.expose())
            .map_err(|_| KernelError::InvalidKey)?;

        if hardened {
            mac.update(&[0x00]);
            mac.update(self.secret.expose());
        } else {
            let public = self.public_key_bytes()?;
            mac.update(&public);
        }
        mac.update(&index.to_be_bytes());

        let mut digest = Zeroizing::new(mac.finalize().into_bytes());
        let (left, right) = digest.split_at(32);

        let secret = match self.curve {
            Curve::Secp256k1 => {
                // child = (IL + parent) mod n, rejecting IL >= n and a zero result.
                let tweak =
                    SecretKey::from_slice(left).map_err(|_| KernelError::DerivationRetry)?;
                let parent = SecretKey::from_slice(self.secret.expose())
                    .map_err(|_| KernelError::InvalidKey)?;
                let sum =
                    *tweak.to_nonzero_scalar().as_ref() + *parent.to_nonzero_scalar().as_ref();
                let nonzero: Option<NonZeroScalar> = NonZeroScalar::new(sum).into();
                let nonzero = nonzero.ok_or(KernelError::DerivationRetry)?;
                SecretBytes::from_slice(&SecretKey::from(nonzero).to_bytes())
            }
            // SLIP-0010: the child key is IL directly, no scalar addition.
            Curve::Ed25519 => SecretBytes::from_slice(left),
        };
        let chain_code = SecretBytes::from_slice(right);
        digest.zeroize();

        Ok(Self {
            curve: self.curve,
            secret,
            chain_code,
        })
    }

    /// Walks a full path from this node.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self> {
        let mut current = Self {
            curve: self.curve,
            secret: self.secret.clone(),
            chain_code: self.chain_code.clone(),
        };
        for index in path.indices() {
            current = current.derive_child(*index)?;
        }
        Ok(current)
    }

    /// Master key plus path in one call, the shape callers actually want.
    pub fn from_seed_and_path(curve: Curve, seed: &[u8], path: &DerivationPath) -> Result<Self> {
        Self::master(curve, seed)?.derive_path(path)
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn private_key(&self) -> &SecretBytes {
        &self.secret
    }

    pub fn chain_code(&self) -> &SecretBytes {
        &self.chain_code
    }

    /// Public key bytes: 33-byte compressed SEC1 for secp256k1, 32 bytes for ed25519.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        match self.curve {
            Curve::Secp256k1 => {
                let secret = SecretKey::from_slice(self.secret.expose())
                    .map_err(|_| KernelError::InvalidKey)?;
                Ok(secret
                    .public_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec())
            }
            Curve::Ed25519 => {
                let bytes: [u8; 32] = self.secret.as_array()?;
                let signing = ed25519_dalek::SigningKey::from_bytes(&bytes);
                Ok(signing.verifying_key().to_bytes().to_vec())
            }
        }
    }

    /// Uncompressed 65-byte SEC1 public key. Only meaningful for secp256k1, and needed for
    /// Ethereum address derivation.
    pub fn public_key_uncompressed(&self) -> Result<Vec<u8>> {
        if self.curve != Curve::Secp256k1 {
            return Err(KernelError::InvalidKey);
        }
        let secret =
            SecretKey::from_slice(self.secret.expose()).map_err(|_| KernelError::InvalidKey)?;
        Ok(secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }
}

impl core::fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExtendedKey({:?}, redacted)", self.curve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_paths() {
        let path = DerivationPath::parse("m/44'/118'/0'/0/0").unwrap();
        assert_eq!(path.to_string(), "m/44'/118'/0'/0/0");
        assert_eq!(path.depth(), 5);
        assert_eq!(path.account(), Some(0));
        assert_eq!(path.address_index(), Some(0));

        // h and H are accepted for hardened, and render back as an apostrophe.
        assert_eq!(
            DerivationPath::parse("m/44h/60H/1'/0/7")
                .unwrap()
                .to_string(),
            "m/44'/60'/1'/0/7"
        );
    }

    #[test]
    fn rejects_malformed_paths() {
        for bad in ["", "44'/118'", "n/44'", "m/", "m//0", "m/x", "m/2147483648"] {
            assert_eq!(
                DerivationPath::parse(bad).unwrap_err(),
                KernelError::PathSyntax,
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn the_master_path_is_valid() {
        // "m" alone is the master key. The official BIP-32 vectors start every chain with it,
        // so rejecting it as empty would make those vectors unrunnable.
        let path = DerivationPath::parse("m").unwrap();
        assert_eq!(path.depth(), 0);
        assert_eq!(path.indices(), &[] as &[u32]);
        assert_eq!(path.to_string(), "m");
        assert_eq!(path.account(), None);
        assert_eq!(path.address_index(), None);
    }

    #[test]
    fn builders_match_expected_shape() {
        assert_eq!(
            DerivationPath::bip44(118, 0, 0).to_string(),
            "m/44'/118'/0'/0/0"
        );
        assert_eq!(
            DerivationPath::bip44(60, 2, 5).to_string(),
            "m/44'/60'/2'/0/5"
        );
        assert_eq!(
            DerivationPath::slip10_ed25519(501, 0).to_string(),
            "m/44'/501'/0'/0'"
        );
    }

    // BIP-32 test vector 1: seed 000102030405060708090a0b0c0d0e0f
    const BIP32_SEED_1: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn bip32_vector_1_master() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        let master = ExtendedKey::master(Curve::Secp256k1, &seed).unwrap();
        assert_eq!(
            hex::encode(master.private_key().expose()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(master.chain_code().expose()),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
    }

    #[test]
    fn bip32_vector_1_hardened_child() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        let master = ExtendedKey::master(Curve::Secp256k1, &seed).unwrap();
        // m/0'
        let child = master.derive_child(HARDENED).unwrap();
        assert_eq!(
            hex::encode(child.private_key().expose()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(child.chain_code().expose()),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
    }

    #[test]
    fn bip32_vector_1_non_hardened_child() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        // m/0'/1
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            &seed,
            &DerivationPath::parse("m/0'/1").unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(key.private_key().expose()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(
            hex::encode(key.public_key_bytes().unwrap()),
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
        );
    }

    #[test]
    fn bip32_vector_1_deep_path() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        // m/0'/1/2'/2/1000000000
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            &seed,
            &DerivationPath::parse("m/0'/1/2'/2/1000000000").unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(key.private_key().expose()),
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
    }

    // SLIP-0010 ed25519 test vector 1, same seed.
    #[test]
    fn slip10_ed25519_vector_1_master() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        let master = ExtendedKey::master(Curve::Ed25519, &seed).unwrap();
        assert_eq!(
            hex::encode(master.private_key().expose()),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(master.chain_code().expose()),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
    }

    #[test]
    fn slip10_ed25519_vector_1_hardened_chain() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        // m/0'
        let child = ExtendedKey::master(Curve::Ed25519, &seed)
            .unwrap()
            .derive_child(HARDENED)
            .unwrap();
        assert_eq!(
            hex::encode(child.private_key().expose()),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        // SLIP-0010 prefixes ed25519 public keys with 0x00; we return the raw 32 bytes.
        assert_eq!(
            hex::encode(child.public_key_bytes().unwrap()),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
    }

    #[test]
    fn ed25519_rejects_non_hardened_derivation() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        let master = ExtendedKey::master(Curve::Ed25519, &seed).unwrap();
        assert_eq!(
            master.derive_child(0).unwrap_err(),
            KernelError::PathUnsupported
        );
        assert_eq!(
            master
                .derive_path(&DerivationPath::parse("m/44'/501'/0'/0").unwrap())
                .unwrap_err(),
            KernelError::PathUnsupported
        );
    }

    #[test]
    fn rejects_out_of_range_seed() {
        assert_eq!(
            ExtendedKey::master(Curve::Secp256k1, &[0u8; 8]).unwrap_err(),
            KernelError::InvalidKey
        );
        assert_eq!(
            ExtendedKey::master(Curve::Secp256k1, &[0u8; 65]).unwrap_err(),
            KernelError::InvalidKey
        );
    }

    #[test]
    fn ed25519_has_no_uncompressed_form() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        let master = ExtendedKey::master(Curve::Ed25519, &seed).unwrap();
        assert!(master.public_key_uncompressed().is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let seed = hex::decode(BIP32_SEED_1).unwrap();
        let master = ExtendedKey::master(Curve::Secp256k1, &seed).unwrap();
        let rendered = format!("{master:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("e8f32e"));
    }
}
