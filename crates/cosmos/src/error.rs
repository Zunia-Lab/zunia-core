/// Failures in transaction building, encoding and decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosmosError {
    /// A protobuf or JSON payload could not be decoded.
    Decode,
    /// An amount was not a non-negative integer string, or overflowed.
    ///
    /// Cosmos amounts are arbitrary-precision integers encoded as decimal strings. Parsing one
    /// into a float is the classic way to lose precision on an 18-decimal token and send the
    /// wrong amount.
    Amount,
    /// A denom did not match the Cosmos SDK denom rules.
    Denom,
    /// A chain id was empty, or did not match the chain the wallet is signing for.
    ChainId,
    /// An address was structurally invalid or carried the wrong prefix.
    Address,
    /// A message type URL is not one this build can decode into human-readable form.
    UnknownMessage(String),
    /// A sign document was structurally invalid.
    SignDoc,
    /// A gas limit or fee was missing or nonsensical.
    Fee,
    /// The kernel rejected a key or signing operation.
    Kernel(zunia_kernel::KernelError),
}

impl core::fmt::Display for CosmosError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode => f.write_str("could not decode payload"),
            Self::Amount => f.write_str("amount is not a valid non-negative integer"),
            Self::Denom => f.write_str("denom is invalid"),
            Self::ChainId => f.write_str("chain id is missing or does not match"),
            Self::Address => f.write_str("address is invalid for this chain"),
            Self::UnknownMessage(url) => write!(f, "cannot decode message type {url}"),
            Self::SignDoc => f.write_str("sign document is invalid"),
            Self::Fee => f.write_str("fee or gas limit is invalid"),
            Self::Kernel(inner) => write!(f, "kernel: {inner}"),
        }
    }
}

impl core::error::Error for CosmosError {}

impl From<zunia_kernel::KernelError> for CosmosError {
    fn from(value: zunia_kernel::KernelError) -> Self {
        Self::Kernel(value)
    }
}

pub type Result<T> = core::result::Result<T, CosmosError>;
