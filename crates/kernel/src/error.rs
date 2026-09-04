use core::fmt;

/// Every fallible kernel operation returns this.
///
/// Variants deliberately carry no secret material and no attacker-controlled input. An error
/// string can reach a log, a crash report or a dApp, so it must never contain a mnemonic, a
/// key, a decrypted payload, or enough detail to distinguish "wrong password" from "corrupt
/// ciphertext" in a way that helps an oracle attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// Word count is not 12, 15, 18, 21 or 24.
    MnemonicLength(usize),
    /// A word is not in the BIP-39 English wordlist.
    MnemonicWord,
    /// The BIP-39 checksum does not match. Usually a typo or a transcription error.
    MnemonicChecksum,
    /// Entropy length is not 128, 160, 192, 224 or 256 bits.
    EntropyLength(usize),
    /// A derivation path is syntactically invalid.
    PathSyntax,
    /// A derivation path is valid syntax but not usable for this curve, for example a
    /// non-hardened index on ed25519 where SLIP-0010 only defines hardened derivation.
    PathUnsupported,
    /// Derivation produced an invalid scalar. Astronomically unlikely, and per BIP-32 the
    /// caller must skip to the next index rather than treat it as fatal.
    DerivationRetry,
    /// A public or private key was not the expected length or was not on the curve.
    InvalidKey,
    /// Signature creation or verification failed.
    Signature,
    /// A bech32 human-readable part was empty or contained invalid characters.
    InvalidPrefix,
    /// An address failed to decode, or its prefix did not match the expected chain.
    InvalidAddress,
    /// Decryption failed. Covers a wrong password and a tampered envelope on purpose: the
    /// caller must not be able to tell them apart.
    Decrypt,
    /// The keyring envelope version is newer than this build understands.
    EnvelopeVersion(u16),
    /// The keyring envelope is structurally invalid.
    EnvelopeFormat,
    /// KDF parameters are outside the accepted range. Rejected rather than clamped, because a
    /// silently weakened KDF is worse than a hard failure.
    KdfParams,
    /// The platform random number generator failed. Never fall back to a weaker source.
    Random,
    /// A hex, base64 or bech32 input could not be decoded.
    Encoding,
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MnemonicLength(n) => {
                write!(f, "mnemonic must be 12, 15, 18, 21 or 24 words, got {n}")
            }
            Self::MnemonicWord => f.write_str("mnemonic contains a word outside the wordlist"),
            Self::MnemonicChecksum => f.write_str("mnemonic checksum is invalid"),
            Self::EntropyLength(n) => {
                write!(f, "entropy must be 16, 20, 24, 28 or 32 bytes, got {n}")
            }
            Self::PathSyntax => f.write_str("derivation path is malformed"),
            Self::PathUnsupported => f.write_str(
                "derivation path is not supported for this curve: ed25519 requires every \
                 index to be hardened",
            ),
            Self::DerivationRetry => f.write_str("derivation produced an invalid key, retry"),
            Self::InvalidKey => f.write_str("key is invalid"),
            Self::Signature => f.write_str("signature operation failed"),
            Self::InvalidPrefix => f.write_str("bech32 prefix is invalid"),
            Self::InvalidAddress => f.write_str("address is invalid"),
            Self::Decrypt => f.write_str("could not decrypt"),
            Self::EnvelopeVersion(v) => {
                write!(
                    f,
                    "keyring envelope version {v} is not supported by this build"
                )
            }
            Self::EnvelopeFormat => f.write_str("keyring envelope is malformed"),
            Self::KdfParams => f.write_str("key derivation parameters are out of range"),
            Self::Random => f.write_str("platform random number generator failed"),
            Self::Encoding => f.write_str("could not decode input"),
        }
    }
}

impl core::error::Error for KernelError {}

pub type Result<T> = core::result::Result<T, KernelError>;
