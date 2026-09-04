//! Solana support: address derivation, legacy message compilation and ed25519 signing.
//!
//! # Why this is feature gated
//!
//! Solana is not in the launch scope. Gating it behind `solana` keeps it out of the WASM bundle
//! that ships to every extension user rather than merely hidden in the UI, so the code that is
//! not needed is not shipped, and the attack surface stays proportional to what the wallet
//! actually does. Build with `--features solana` to enable it.
//!
//! # Scope
//!
//! Legacy messages only, deliberately. Versioned (v0) messages move accounts into on-chain
//! address lookup tables, so the signer cannot see every account it is authorising from the
//! message bytes alone. Supporting them safely needs table resolution plus a UI that shows the
//! resolved result, and shipping them without that would be blind signing with extra steps.
//!
//! Nothing here touches the network. Blockhashes, fees and account state come from the JavaScript
//! layer per ADR-0004; this crate is pure functions over bytes.
//!
//! # Differences from the Cosmos and Ethereum paths
//!
//! Solana signs the serialised message directly with ed25519, so there is no digest step and no
//! opportunity for a caller to substitute a hash. In exchange, privileges are encoded
//! positionally in the account table, which means a mistake in message compilation grants the
//! wrong privileges rather than producing an invalid signature. `message::Message::compile` is
//! therefore the security boundary in this crate, and it is where the tests concentrate.

#![deny(clippy::arithmetic_side_effects)]

#[cfg(feature = "solana")]
pub mod error;
#[cfg(feature = "solana")]
pub mod message;
#[cfg(feature = "solana")]
pub mod pubkey;
#[cfg(feature = "solana")]
pub mod shortvec;
#[cfg(feature = "solana")]
pub mod summary;
#[cfg(feature = "solana")]
pub mod system;
#[cfg(feature = "solana")]
pub mod tx;

#[cfg(feature = "solana")]
pub use error::{Result, SvmError};
#[cfg(feature = "solana")]
pub use message::{AccountMeta, CompiledInstruction, Instruction, Message, MessageHeader};
#[cfg(feature = "solana")]
pub use pubkey::Pubkey;
#[cfg(feature = "solana")]
pub use summary::{summarize, InstructionSummary, MessageSummary};
#[cfg(feature = "solana")]
pub use tx::{Transaction, PACKET_DATA_SIZE, SIGNATURE_LEN};

/// Solana's BIP-44 coin type, as registered in SLIP-0044.
pub const SOL_COIN_TYPE: u32 = 501;

/// The derivation path Phantom, Solflare and the Solana CLI all use: `m/44'/501'/index'/0'`.
///
/// Every index is hardened because SLIP-0010 defines only hardened derivation for ed25519. Also
/// note the trailing `0'`: the CLI's `--derivation-path` default omits it, so a wallet that gets
/// this wrong shows an empty account for a funded seed. Provided by the kernel; re-exported here
/// so callers do not have to know the shape.
#[cfg(feature = "solana")]
pub fn derivation_path(index: u32) -> zunia_kernel::DerivationPath {
    zunia_kernel::DerivationPath::slip10_ed25519(SOL_COIN_TYPE, index)
}

/// Derives a Solana address from a seed.
#[cfg(feature = "solana")]
pub fn address_from_seed(seed: &[u8], index: u32) -> Result<Pubkey> {
    let key = zunia_kernel::ExtendedKey::from_seed_and_path(
        zunia_kernel::Curve::Ed25519,
        seed,
        &derivation_path(index),
    )?;
    Pubkey::from_public_key(&key.public_key_bytes()?)
}

#[cfg(all(test, feature = "solana"))]
mod tests {
    use super::*;
    use zunia_kernel::ZuniaMnemonic;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn the_path_matches_what_the_ecosystem_wallets_use() {
        assert_eq!(derivation_path(0).to_string(), "m/44'/501'/0'/0'");
        assert_eq!(derivation_path(3).to_string(), "m/44'/501'/3'/0'");
    }

    #[test]
    fn addresses_are_base58_and_distinct_per_index() {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let mut seen = std::collections::HashSet::new();
        for index in 0..5 {
            let address = address_from_seed(seed.expose(), index).unwrap();
            let text = address.to_base58();
            assert!(
                (32..=44).contains(&text.len()),
                "odd address length: {text}"
            );
            // Base58 excludes these four characters precisely because they are confusable.
            assert!(!text.contains(['0', 'O', 'I', 'l']));
            assert!(seen.insert(address), "index {index} collided");
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        assert_eq!(
            address_from_seed(seed.expose(), 0).unwrap(),
            address_from_seed(seed.expose(), 0).unwrap()
        );
    }

    #[test]
    fn a_passphrase_changes_the_address() {
        let plain = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let with_passphrase = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("zunia");
        assert_ne!(
            address_from_seed(plain.expose(), 0).unwrap(),
            address_from_seed(with_passphrase.expose(), 0).unwrap()
        );
    }
}
