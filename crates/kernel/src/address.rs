use bech32::{Bech32, Hrp};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::{KernelError, Result};

/// How a chain turns a public key into an account address.
///
/// Cosmos chains are not uniform here. Most use the Bitcoin-derived
/// `ripemd160(sha256(compressed_pubkey))`, but the Ethermint family (Injective, Evmos, Kava
/// and others) uses `keccak256(uncompressed_pubkey[1..])[12..]`, the Ethereum rule, and then
/// bech32-encodes the result. Deriving an Injective address with the Cosmos rule produces a
/// valid-looking bech32 string for an account that does not exist, which is exactly the kind
/// of silent failure that loses funds. The scheme comes from the chain registry, not a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScheme {
    /// ripemd160(sha256(pubkey)), the Cosmos SDK default.
    Cosmos,
    /// keccak256(pubkey)[12..], the Ethermint and Ethereum rule.
    Ethermint,
}

/// 20-byte account identifier, before encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountId([u8; 20]);

impl AccountId {
    /// Wraps 20 bytes that already are an account identifier.
    ///
    /// For values that came from decoding an address, not from a public key. There is nothing to
    /// validate: every 20-byte string is a syntactically valid account, and whether it is one
    /// anybody holds the key to is not knowable here.
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Derives the account id from a public key under the given scheme.
    ///
    /// `Cosmos` expects the 33-byte compressed key. `Ethermint` accepts either the 65-byte
    /// uncompressed key or the 33-byte compressed key, decompressing when needed, because
    /// callers hold the compressed form far more often.
    pub fn from_public_key(scheme: AddressScheme, public_key: &[u8]) -> Result<Self> {
        match scheme {
            AddressScheme::Cosmos => {
                if public_key.len() != 33 {
                    return Err(KernelError::InvalidKey);
                }
                let sha = Sha256::digest(public_key);
                let ripemd = Ripemd160::digest(sha);
                let mut out = [0u8; 20];
                out.copy_from_slice(&ripemd);
                Ok(Self(out))
            }
            AddressScheme::Ethermint => {
                let uncompressed = match public_key.len() {
                    65 => public_key.to_vec(),
                    33 => decompress_secp256k1(public_key)?,
                    _ => return Err(KernelError::InvalidKey),
                };
                // Skip the 0x04 SEC1 tag; Ethereum hashes only the 64 coordinate bytes.
                let hash = Keccak256::digest(&uncompressed[1..]);
                let mut out = [0u8; 20];
                out.copy_from_slice(&hash[12..]);
                Ok(Self(out))
            }
        }
    }

    /// Encodes as bech32 with the chain's human-readable prefix, for example `cosmos` or
    /// `safro`.
    pub fn to_bech32(&self, prefix: &str) -> Result<String> {
        let hrp = Hrp::parse(prefix).map_err(|_| KernelError::InvalidPrefix)?;
        bech32::encode::<Bech32>(hrp, &self.0).map_err(|_| KernelError::InvalidAddress)
    }

    /// Encodes as an EIP-55 checksummed hex address.
    pub fn to_eth_hex(&self) -> String {
        let lower = hex::encode(self.0);
        let hash = Keccak256::digest(lower.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, ch) in lower.chars().enumerate() {
            if ch.is_ascii_digit() {
                out.push(ch);
                continue;
            }
            // EIP-55: uppercase the hex letter when the corresponding hash nibble is >= 8.
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}

/// A decoded bech32 address plus the prefix it carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAddress {
    pub prefix: String,
    pub account: AccountId,
}

/// Decodes a bech32 address and enforces the 20-byte account length.
///
/// Does not check the prefix against a chain. Use [`validate_address`] for that, which is what
/// every send flow must call.
pub fn decode_bech32(address: &str) -> Result<DecodedAddress> {
    let (hrp, data) = bech32::decode(address).map_err(|_| KernelError::InvalidAddress)?;
    if data.len() != 20 {
        return Err(KernelError::InvalidAddress);
    }
    let mut account = [0u8; 20];
    account.copy_from_slice(&data);
    Ok(DecodedAddress {
        prefix: hrp.to_lowercase(),
        account: AccountId(account),
    })
}

/// Validates an address against the prefix a specific chain expects.
///
/// This is the guard that stops a cross-chain paste. A `cosmos1...` address is structurally
/// perfect on Osmosis and sending there burns the funds, so the prefix check is not optional
/// and cannot be left to the UI.
pub fn validate_address(address: &str, expected_prefix: &str) -> Result<DecodedAddress> {
    let decoded = decode_bech32(address)?;
    if decoded.prefix != expected_prefix.to_lowercase() {
        return Err(KernelError::InvalidAddress);
    }
    Ok(decoded)
}

/// Re-encodes an address under a different prefix.
///
/// Useful for showing the same account across chains, and for the interchain accounts case.
/// It is not a substitute for a prefix check: converting a user's pasted address to the target
/// prefix would defeat the protection in [`validate_address`], so this is only ever called on
/// an address the wallet itself derived.
pub fn convert_prefix(address: &str, new_prefix: &str) -> Result<String> {
    decode_bech32(address)?.account.to_bech32(new_prefix)
}

/// Validates an EIP-55 hex address, accepting all-lowercase and all-uppercase as unchecksummed.
pub fn validate_eth_address(address: &str) -> Result<AccountId> {
    let stripped = address
        .strip_prefix("0x")
        .ok_or(KernelError::InvalidAddress)?;
    if stripped.len() != 40 {
        return Err(KernelError::InvalidAddress);
    }
    let bytes = hex::decode(stripped).map_err(|_| KernelError::InvalidAddress)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    let account = AccountId(out);

    let has_upper = stripped.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = stripped.chars().any(|c| c.is_ascii_lowercase());
    if has_upper && has_lower {
        // Mixed case means a checksum is present and must verify. A wrong checksum is a
        // corrupted address, not a stylistic choice.
        if account.to_eth_hex() != address {
            return Err(KernelError::InvalidAddress);
        }
    }
    Ok(account)
}

/// Base58 encodes an ed25519 public key, the Solana address format.
pub fn solana_address(public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        return Err(KernelError::InvalidKey);
    }
    Ok(bs58::encode(public_key).into_string())
}

/// Decompresses a 33-byte SEC1 point to its 65-byte form.
fn decompress_secp256k1(compressed: &[u8]) -> Result<Vec<u8>> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let point =
        k256::PublicKey::from_sec1_bytes(compressed).map_err(|_| KernelError::InvalidKey)?;
    Ok(point.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{Curve, DerivationPath, ExtendedKey};
    use crate::mnemonic::ZuniaMnemonic;

    const TREZOR_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn cosmos_key() -> ExtendedKey {
        let seed = ZuniaMnemonic::parse(TREZOR_12).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::bip44(118, 0, 0),
        )
        .unwrap()
    }

    #[test]
    fn derives_known_cosmos_address() {
        // m/44'/118'/0'/0/0 from the all-abandon mnemonic, generated with CosmJS
        // DirectSecp256k1HdWallet and recorded in tests/vectors/cosmos-addresses.json.
        let key = cosmos_key();
        assert_eq!(
            hex::encode(key.public_key_bytes().unwrap()),
            "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62"
        );
        let account =
            AccountId::from_public_key(AddressScheme::Cosmos, &key.public_key_bytes().unwrap())
                .unwrap();
        assert_eq!(
            account.to_bech32("cosmos").unwrap(),
            "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4"
        );
        // Safrochain uses the multi-character prefix `addr_safro`, which is unusual and worth
        // asserting because a prefix parser that assumes a short alphabetic HRP breaks on it.
        assert_eq!(
            account.to_bech32("addr_safro").unwrap(),
            "addr_safro19rl4cm2hmr8afy4kldpxz3fka4jguq0ayvv259"
        );
    }

    #[test]
    fn same_account_reencodes_across_prefixes() {
        let key = cosmos_key();
        let account =
            AccountId::from_public_key(AddressScheme::Cosmos, &key.public_key_bytes().unwrap())
                .unwrap();
        let cosmos = account.to_bech32("cosmos").unwrap();
        let osmo = account.to_bech32("osmo").unwrap();
        let safro = account.to_bech32("safro").unwrap();

        assert!(osmo.starts_with("osmo1"));
        assert!(safro.starts_with("safro1"));
        assert_eq!(convert_prefix(&cosmos, "osmo").unwrap(), osmo);
        assert_eq!(
            decode_bech32(&osmo).unwrap().account,
            decode_bech32(&safro).unwrap().account
        );
    }

    #[test]
    fn ethermint_scheme_differs_from_cosmos() {
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            ZuniaMnemonic::parse(TREZOR_12)
                .unwrap()
                .to_seed("")
                .expose(),
            &DerivationPath::bip44(60, 0, 0),
        )
        .unwrap();
        let compressed = key.public_key_bytes().unwrap();

        let cosmos = AccountId::from_public_key(AddressScheme::Cosmos, &compressed).unwrap();
        let ethermint = AccountId::from_public_key(AddressScheme::Ethermint, &compressed).unwrap();

        assert_ne!(
            cosmos.as_bytes(),
            ethermint.as_bytes(),
            "using the wrong scheme must not silently produce the same account"
        );

        // Ethermint chains bech32-encode the Ethereum-derived bytes.
        let inj = ethermint.to_bech32("inj").unwrap();
        assert!(inj.starts_with("inj1"));
    }

    #[test]
    fn ethermint_accepts_compressed_and_uncompressed() {
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            ZuniaMnemonic::parse(TREZOR_12)
                .unwrap()
                .to_seed("")
                .expose(),
            &DerivationPath::bip44(60, 0, 0),
        )
        .unwrap();
        let from_compressed =
            AccountId::from_public_key(AddressScheme::Ethermint, &key.public_key_bytes().unwrap())
                .unwrap();
        let from_uncompressed = AccountId::from_public_key(
            AddressScheme::Ethermint,
            &key.public_key_uncompressed().unwrap(),
        )
        .unwrap();
        assert_eq!(from_compressed, from_uncompressed);
    }

    #[test]
    fn derives_known_eth_address() {
        // m/44'/60'/0'/0/0 from the all-abandon mnemonic is a widely published vector.
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            ZuniaMnemonic::parse(TREZOR_12)
                .unwrap()
                .to_seed("")
                .expose(),
            &DerivationPath::bip44(60, 0, 0),
        )
        .unwrap();
        let account =
            AccountId::from_public_key(AddressScheme::Ethermint, &key.public_key_bytes().unwrap())
                .unwrap();
        assert_eq!(
            account.to_eth_hex(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn eip55_checksum_round_trips() {
        // Canonical EIP-55 examples.
        for address in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let account = validate_eth_address(address).unwrap();
            assert_eq!(account.to_eth_hex(), address);
        }
    }

    #[test]
    fn rejects_bad_eth_checksum() {
        // One letter case flipped from a valid checksum.
        assert!(validate_eth_address("0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed").is_err());
        // Unchecksummed forms are accepted.
        assert!(validate_eth_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_ok());
        assert!(validate_eth_address("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED").is_ok());
        // Structural failures.
        assert!(validate_eth_address("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_err());
        assert!(validate_eth_address("0xdeadbeef").is_err());
        assert!(validate_eth_address("0xzzzzb6053f3e94c9b9a09f33669435e7ef1beaed").is_err());
    }

    #[test]
    fn validate_address_enforces_the_prefix() {
        let key = cosmos_key();
        let account =
            AccountId::from_public_key(AddressScheme::Cosmos, &key.public_key_bytes().unwrap())
                .unwrap();
        let cosmos = account.to_bech32("cosmos").unwrap();

        assert!(validate_address(&cosmos, "cosmos").is_ok());
        assert!(
            validate_address(&cosmos, "COSMOS").is_ok(),
            "case insensitive"
        );
        assert_eq!(
            validate_address(&cosmos, "osmo").unwrap_err(),
            KernelError::InvalidAddress,
            "a cosmos address must not validate on osmosis"
        );
    }

    #[test]
    fn rejects_corrupt_bech32() {
        assert!(decode_bech32("cosmos1nsqz24klmz0mkuvxjjdd3ptzhsfmhs0wcp5rrx").is_err());
        assert!(decode_bech32("not-an-address").is_err());
        assert!(decode_bech32("").is_err());
        // Valid bech32 carrying the wrong payload length, such as a validator consensus key.
        assert!(decode_bech32("cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq").is_err());
    }

    #[test]
    fn rejects_wrong_pubkey_length() {
        assert!(AccountId::from_public_key(AddressScheme::Cosmos, &[0u8; 32]).is_err());
        assert!(AccountId::from_public_key(AddressScheme::Ethermint, &[0u8; 20]).is_err());
    }

    #[test]
    fn rejects_invalid_prefix() {
        let account = AccountId([0u8; 20]);
        assert_eq!(
            account.to_bech32("").unwrap_err(),
            KernelError::InvalidPrefix
        );
        assert_eq!(
            account.to_bech32("has space").unwrap_err(),
            KernelError::InvalidPrefix
        );
    }

    #[test]
    fn solana_address_is_base58_of_the_pubkey() {
        let seed = ZuniaMnemonic::parse(TREZOR_12).unwrap().to_seed("");
        let key = ExtendedKey::from_seed_and_path(
            Curve::Ed25519,
            seed.expose(),
            &DerivationPath::slip10_ed25519(501, 0),
        )
        .unwrap();
        let address = solana_address(&key.public_key_bytes().unwrap()).unwrap();
        // Base58 of 32 bytes is 32 to 44 characters and never contains 0, O, I or l.
        assert!((32..=44).contains(&address.len()));
        assert!(!address.contains(['0', 'O', 'I', 'l']));
        assert!(solana_address(&[0u8; 31]).is_err());
    }
}
