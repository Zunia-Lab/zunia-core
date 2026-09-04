//! Solana public keys: 32 raw bytes, displayed as base58 with no checksum.

use crate::error::{Result, SvmError};
use core::fmt;

/// A 32-byte Solana account address.
///
/// Solana addresses carry no checksum and no human-readable prefix, unlike bech32 or EIP-55. A
/// single mistyped base58 character is a different, entirely valid address, which is why the
/// send flow must show the full address rather than a truncated one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    /// The system program, all zero bytes.
    pub const SYSTEM_PROGRAM: Self = Self([0u8; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SvmError::InvalidPubkey(format!("{} bytes", bytes.len())))?;
        Ok(Self(array))
    }

    /// Parses a base58 address.
    pub fn parse(text: &str) -> Result<Self> {
        let bytes = bs58::decode(text)
            .into_vec()
            .map_err(|_| SvmError::InvalidPubkey(text.to_string()))?;
        if bytes.len() != 32 {
            return Err(SvmError::InvalidPubkey(text.to_string()));
        }
        Self::from_slice(&bytes)
    }

    /// Derives an address from an ed25519 public key.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        Self::from_slice(public_key)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Whether these bytes fail to decompress to a point on the ed25519 curve.
    ///
    /// Program-derived addresses are chosen to be off-curve precisely so that no private key
    /// exists for them, so this is useful UI signal: an off-curve address definitively cannot
    /// sign, which distinguishes a program vault from a typo.
    ///
    /// It is a one-way test, not a classifier. `false` does not mean "somebody holds the key":
    /// roughly half of all 32-byte strings decompress successfully, and low-order points do too.
    /// The system program's all-zero address is on-curve by this test despite being unsignable.
    /// So treat `true` as proof of no key and `false` as no information.
    pub fn is_off_curve(&self) -> bool {
        zunia_kernel::verify_ed25519(&self.0, b"", &[0u8; 64]).is_err()
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_program_is_the_all_ones_string() {
        // Base58 of 32 zero bytes. Every Solana transaction that moves SOL names it, so it is
        // the most published address in the ecosystem.
        assert_eq!(
            Pubkey::SYSTEM_PROGRAM.to_base58(),
            "11111111111111111111111111111111"
        );
        assert_eq!(
            Pubkey::parse("11111111111111111111111111111111").unwrap(),
            Pubkey::SYSTEM_PROGRAM
        );
    }

    #[test]
    fn base58_round_trips() {
        let key = Pubkey::from_bytes([7u8; 32]);
        assert_eq!(Pubkey::parse(&key.to_base58()).unwrap(), key);
    }

    #[test]
    fn malformed_addresses_are_refused() {
        // 0 is not in the base58 alphabet.
        assert!(Pubkey::parse("0000000000000000000000000000000000000000000").is_err());
        // Right alphabet, wrong length.
        assert!(Pubkey::parse("abc").is_err());
        assert!(Pubkey::parse("").is_err());
        assert!(Pubkey::from_slice(&[0u8; 31]).is_err());
        assert!(Pubkey::from_slice(&[0u8; 33]).is_err());
    }

    #[test]
    fn derived_keys_are_never_reported_off_curve() {
        use zunia_kernel::{Curve, DerivationPath, ExtendedKey, ZuniaMnemonic};

        let seed = ZuniaMnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed("");

        // A false positive here would tell the user their own account cannot sign.
        for index in 0..8 {
            let key = ExtendedKey::from_seed_and_path(
                Curve::Ed25519,
                seed.expose(),
                &DerivationPath::slip10_ed25519(501, index),
            )
            .unwrap();
            let address = Pubkey::from_public_key(&key.public_key_bytes().unwrap()).unwrap();
            assert!(!address.is_off_curve(), "index {index}");
        }
    }

    #[test]
    fn the_curve_test_detects_some_addresses_and_admits_nothing_about_the_rest() {
        // Roughly half of all 32-byte strings are off-curve, so a sweep must find both kinds.
        // This pins the documented semantics: `true` is proof of no key, `false` is silence.
        let off_curve = (0u8..64)
            .filter(|byte| Pubkey::from_bytes([*byte; 32]).is_off_curve())
            .count();
        assert!(off_curve > 0, "the test never fires, so it is useless");
        assert!(
            off_curve < 64,
            "the test fires on everything, so it is useless"
        );

        // The system program is unsignable but on-curve, which is why `false` cannot be read as
        // "somebody holds the key".
        assert!(!Pubkey::SYSTEM_PROGRAM.is_off_curve());
    }
}
