//! Ethereum support: transaction encoding, message signing and typed data.
//!
//! Needed because a large part of the Cosmos ecosystem is Ethermint based. Injective, Evmos, Kava
//! and roughly fifty other chains in `zunia-chain-registry` derive addresses the Ethereum way and
//! expect Ethereum signing, so this is not a separate product surface but a requirement for
//! supporting the chains the wallet already lists.
//!
//! Key derivation and address formatting live in `zunia-kernel`; this crate is only encoding and
//! signing.
//!
//! # What is deliberately absent
//!
//! No RPC client, no gas estimation, no nonce management. Those need the network, and per
//! ADR-0004 network I/O stays in the JavaScript layer where it can be tested against a real node.
//! This crate is pure functions over bytes, which is what makes it testable against published
//! vectors.

#![deny(clippy::arithmetic_side_effects)]

pub mod eip712;
pub mod error;
pub mod personal;
pub mod rlp;
pub mod tx;

pub use eip712::{sign_typed_data, sign_typed_data_hex, Field, TypedData};
pub use error::{EvmError, Result};
pub use personal::{
    personal_sign, personal_sign_hash, personal_sign_hex, personal_sign_payload,
    personal_sign_payload_is_safe,
};
pub use rlp::RlpStream;
pub use tx::{AccessListItem, Address, SignedTx, TxKind, UnsignedTx, U256};

/// Coin type 60, the Ethereum BIP-44 registration.
///
/// Exposed for callers that need a default, but the registry is authoritative: several Cosmos
/// chains use 60 while others use 118 with Ethermint addresses, and hardcoding either one derives
/// the wrong account for somebody.
pub const ETH_COIN_TYPE: u32 = 60;

/// Derives an Ethereum address from a public key.
///
/// Accepts the compressed or uncompressed form, since callers hold whichever the kernel gave
/// them.
pub fn address_from_public_key(public_key: &[u8]) -> Result<Address> {
    let account = zunia_kernel::AccountId::from_public_key(
        zunia_kernel::AddressScheme::Ethermint,
        public_key,
    )?;
    Ok(Address::from_bytes(*account.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zunia_kernel::{Curve, DerivationPath, ExtendedKey, ZuniaMnemonic};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derives_the_well_known_test_address() {
        // The all-abandon mnemonic at m/44'/60'/0'/0/0 is the first account of every Ethereum
        // development tool, so this address is widely published and independently checkable.
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::bip44(ETH_COIN_TYPE, 0, 0),
        )
        .unwrap();

        let address = address_from_public_key(&key.public_key_bytes().unwrap()).unwrap();
        assert_eq!(
            address.to_checksummed(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn compressed_and_uncompressed_keys_agree() {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let key = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::bip44(ETH_COIN_TYPE, 0, 0),
        )
        .unwrap();

        assert_eq!(
            address_from_public_key(&key.public_key_bytes().unwrap()).unwrap(),
            address_from_public_key(&key.public_key_uncompressed().unwrap()).unwrap()
        );
    }

    #[test]
    fn successive_indices_give_distinct_addresses() {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let mut seen = std::collections::HashSet::new();
        for index in 0..5 {
            let key = ExtendedKey::from_seed_and_path(
                Curve::Secp256k1,
                seed.expose(),
                &DerivationPath::bip44(ETH_COIN_TYPE, 0, index),
            )
            .unwrap();
            let address = address_from_public_key(&key.public_key_bytes().unwrap()).unwrap();
            assert!(seen.insert(address), "index {index} collided");
        }
    }
}
