use core::fmt;

/// Failures assembling or signing a Solana transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvmError {
    /// A base58 string was not a 32-byte public key.
    InvalidPubkey(String),
    /// A blockhash was not 32 bytes.
    InvalidBlockhash,
    /// More than 256 accounts, or more than 255 signers. Solana indexes accounts with a single
    /// byte, so these are hard protocol limits, not our own.
    TooManyAccounts(usize),
    /// An instruction referenced an account that is not in the compiled key list. Only reachable
    /// through the low-level API; `Message::compile` cannot produce it.
    UnknownAccount(String),
    /// The fee payer was not among the accounts, or was not a writable signer.
    InvalidFeePayer,
    /// A signature was supplied for an account that is not a required signer, or a required
    /// signature is missing.
    SignerMismatch,
    /// The serialised transaction exceeded the 1232-byte packet limit, so no validator would
    /// accept it.
    TransactionTooLarge(usize),
    /// The kernel refused, usually a curve mismatch.
    Kernel(zunia_kernel::KernelError),
}

impl fmt::Display for SvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPubkey(s) => write!(f, "not a valid Solana public key: {s}"),
            Self::InvalidBlockhash => write!(f, "a blockhash must be 32 bytes"),
            Self::TooManyAccounts(n) => {
                write!(f, "{n} accounts exceeds the single-byte index limit of 256")
            }
            Self::UnknownAccount(s) => {
                write!(f, "instruction references an uncompiled account: {s}")
            }
            Self::InvalidFeePayer => {
                write!(
                    f,
                    "the fee payer must be the first account and a writable signer"
                )
            }
            Self::SignerMismatch => {
                write!(
                    f,
                    "signatures do not match the required signers of the message"
                )
            }
            Self::TransactionTooLarge(n) => write!(
                f,
                "serialised transaction is {n} bytes, over the 1232-byte packet limit"
            ),
            Self::Kernel(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SvmError {}

impl From<zunia_kernel::KernelError> for SvmError {
    fn from(e: zunia_kernel::KernelError) -> Self {
        Self::Kernel(e)
    }
}

pub type Result<T> = core::result::Result<T, SvmError>;
