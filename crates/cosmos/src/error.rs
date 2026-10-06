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
    /// A swap was refused before signing, for the reason given.
    ///
    /// Covers what a swap's amounts and denoms cannot say on their own: no route, a pool that
    /// cannot exist, a route longer than the wallet will sign, split legs that disagree, and
    /// above all no minimum output. The reason names the field at fault, because "sign document
    /// is invalid" sends an integrator looking at the wrong half of the payload.
    Swap(&'static str),
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
            Self::Swap(reason) => write!(f, "swap refused: {reason}"),
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
