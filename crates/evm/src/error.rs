/// Why an Ethereum operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmError {
    /// A quantity exceeded 32 bytes, so it cannot be a valid EVM word.
    QuantityTooLarge,
    /// An address was not 20 bytes, or was not valid hex.
    InvalidAddress,
    /// A chain id of zero. EIP-155 replay protection depends on a real chain id, and zero would
    /// make a signature valid on any chain that also used zero.
    InvalidChainId,
    /// A typed-data document was structurally invalid: a missing type, a cycle, or a value that
    /// does not match its declared type.
    TypedData(String),
    /// A signing operation failed in the kernel.
    Kernel(zunia_kernel::KernelError),
}

impl core::fmt::Display for EvmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::QuantityTooLarge => f.write_str("quantity does not fit in 32 bytes"),
            Self::InvalidAddress => f.write_str("address is not 20 bytes of hex"),
            Self::InvalidChainId => f.write_str("chain id must not be zero"),
            Self::TypedData(reason) => write!(f, "typed data is invalid: {reason}"),
            Self::Kernel(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for EvmError {}

impl From<zunia_kernel::KernelError> for EvmError {
    fn from(inner: zunia_kernel::KernelError) -> Self {
        Self::Kernel(inner)
    }
}

pub type Result<T> = core::result::Result<T, EvmError>;
