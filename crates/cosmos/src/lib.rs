//! Cosmos transaction building and signing.
//!
//! Per [ADR-0004](../../../docs/adr/0004-cosmos-client-libs.md), all signing and encoding
//! happens here in Rust. CosmJS is used by the TypeScript clients for network I/O only: account
//! and sequence lookup, simulation and broadcast. It never constructs a sign document.
//!
//! # Layout
//!
//! - [`proto`]: a small protobuf writer and reader, hand rolled for byte-level control.
//! - [`amino`]: canonical JSON for `SIGN_MODE_LEGACY_AMINO_JSON`.
//! - [`amount`]: string-based coin arithmetic, because Cosmos amounts exceed `u64`.
//! - [`msg`]: the message set, each with both encodings.
//! - [`tx`]: transaction assembly, both sign documents, and ADR-36.
//! - [`decode`]: turning bytes the wallet did not build into something a user can read.
//!
//! # The signing contract
//!
//! Nothing in this crate holds a private key. It produces sign bytes, the kernel signs them,
//! and this crate assembles the result. That split is what keeps key material inside
//! `zunia-kernel` and out of the transaction logic.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod amino;
pub mod amount;
pub mod decode;
pub mod error;
pub mod msg;
pub mod proto;
pub mod tx;

pub use amount::{fee_from_gas, validate_amount, validate_denom, Coin};
pub use decode::{decode_direct_sign_doc, DecodedMsg, DecodedTx};
pub use error::{CosmosError, Result};
pub use msg::{Height, Msg, VoteOption};
pub use tx::{
    adr36_payload_is_safe, adr36_sign_bytes, adr36_sign_doc, Fee, SignMode, SignerData,
    SigningPreview, UnsignedTx,
};

/// Signs a transaction with an account from the kernel.
///
/// The one function that ties the two crates together. Returns the broadcastable `TxRaw`
/// bytes.
///
/// `mode` is not defaulted. The caller must decide, because a Ledger signer requires Amino and
/// a modern dApp expects Direct, and picking silently is how a wallet ends up signing the wrong
/// document.
pub fn sign_tx(
    account: &zunia_kernel::Account,
    tx: &UnsignedTx,
    signer: &SignerData,
    mode: SignMode,
) -> Result<Vec<u8>> {
    let sign_bytes = tx.sign_bytes(signer, mode)?;
    let signature = account.sign_cosmos(&sign_bytes)?;
    tx.into_tx_raw(signer, mode, signature.as_bytes())
}

/// Signs an ADR-36 arbitrary message.
///
/// Refuses a payload that is shaped like a transaction, so `signArbitrary` cannot be used to
/// smuggle a transfer past a prompt that says "sign this message".
pub fn sign_arbitrary(
    account: &zunia_kernel::Account,
    signer_address: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    if !adr36_payload_is_safe(data) {
        return Err(CosmosError::SignDoc);
    }
    let sign_bytes = adr36_sign_bytes(signer_address, data);
    Ok(account.sign_cosmos(&sign_bytes)?.to_vec())
}

/// Verifies an ADR-36 signature, for `verifyArbitrary` in the provider API.
pub fn verify_arbitrary(
    public_key: &[u8],
    signer_address: &str,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use sha2::{Digest, Sha256};
    let sign_bytes = adr36_sign_bytes(signer_address, data);
    let digest: [u8; 32] = Sha256::digest(&sign_bytes).into();
    Ok(zunia_kernel::verify_digest_secp256k1(
        public_key, &digest, signature,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zunia_kernel::{Account, AddressScheme, Curve, DerivationPath, ZuniaMnemonic};

    const TREZOR_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn account() -> Account {
        let seed = ZuniaMnemonic::parse(TREZOR_12).unwrap().to_seed("");
        Account::derive(
            seed.expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "cosmos",
        )
        .unwrap()
    }

    fn signer(account: &Account) -> SignerData {
        SignerData {
            chain_id: "cosmoshub-4".to_owned(),
            account_number: 12345,
            sequence: 7,
            public_key: account.public_key().unwrap(),
            eth_key_type: false,
        }
    }

    fn transfer(account: &Account) -> UnsignedTx {
        UnsignedTx::new(
            vec![Msg::Send {
                from_address: account.address().unwrap(),
                to_address: "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz".to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }],
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            "",
        )
        .unwrap()
    }

    #[test]
    fn signs_a_transfer_in_both_modes() {
        let account = account();
        let signer = signer(&account);
        let tx = transfer(&account);

        for mode in [SignMode::Direct, SignMode::LegacyAminoJson] {
            let raw = sign_tx(&account, &tx, &signer, mode).unwrap();
            let fields = proto::decode_fields(&raw).unwrap();
            assert_eq!(fields.len(), 3, "TxRaw has body, auth_info and signatures");
            assert_eq!(
                proto::find_field(&fields, 3)
                    .unwrap()
                    .as_bytes()
                    .unwrap()
                    .len(),
                64
            );
        }
    }

    #[test]
    fn signature_verifies_against_the_sign_bytes() {
        use sha2::{Digest, Sha256};
        let account = account();
        let signer = signer(&account);
        let tx = transfer(&account);

        for mode in [SignMode::Direct, SignMode::LegacyAminoJson] {
            let sign_bytes = tx.sign_bytes(&signer, mode).unwrap();
            let raw = sign_tx(&account, &tx, &signer, mode).unwrap();
            let fields = proto::decode_fields(&raw).unwrap();
            let signature = proto::find_field(&fields, 3).unwrap().as_bytes().unwrap();

            let digest: [u8; 32] = Sha256::digest(&sign_bytes).into();
            assert!(
                zunia_kernel::verify_digest_secp256k1(
                    &account.public_key().unwrap(),
                    &digest,
                    signature
                )
                .unwrap(),
                "signature must verify for {mode:?}"
            );
        }
    }

    #[test]
    fn the_two_modes_produce_different_signatures() {
        let account = account();
        let signer = signer(&account);
        let tx = transfer(&account);
        assert_ne!(
            sign_tx(&account, &tx, &signer, SignMode::Direct).unwrap(),
            sign_tx(&account, &tx, &signer, SignMode::LegacyAminoJson).unwrap()
        );
    }

    #[test]
    fn changing_any_input_changes_the_signature() {
        // Guards against a builder that silently drops a field. If the memo, the sequence or
        // the account number did not reach the sign bytes, these would collide.
        let account = account();
        let base_signer = signer(&account);
        let base = sign_tx(
            &account,
            &transfer(&account),
            &base_signer,
            SignMode::Direct,
        )
        .unwrap();

        let mut other_sequence = base_signer.clone();
        other_sequence.sequence += 1;
        assert_ne!(
            base,
            sign_tx(
                &account,
                &transfer(&account),
                &other_sequence,
                SignMode::Direct
            )
            .unwrap()
        );

        let mut other_account = base_signer.clone();
        other_account.account_number += 1;
        assert_ne!(
            base,
            sign_tx(
                &account,
                &transfer(&account),
                &other_account,
                SignMode::Direct
            )
            .unwrap()
        );

        let mut other_chain = base_signer.clone();
        other_chain.chain_id = "cosmoshub-3".to_owned();
        assert_ne!(
            base,
            sign_tx(
                &account,
                &transfer(&account),
                &other_chain,
                SignMode::Direct
            )
            .unwrap()
        );

        let mut with_memo = transfer(&account);
        with_memo.memo = "hello".to_owned();
        assert_ne!(
            base,
            sign_tx(&account, &with_memo, &base_signer, SignMode::Direct).unwrap()
        );
    }

    #[test]
    fn adr36_round_trip() {
        let account = account();
        let address = account.address().unwrap();
        let message = b"Sign in to Zunia at 2026-08-31T12:00:00Z";

        let signature = sign_arbitrary(&account, &address, message).unwrap();
        assert_eq!(signature.len(), 64);
        assert!(verify_arbitrary(
            &account.public_key().unwrap(),
            &address,
            message,
            &signature
        )
        .unwrap());
        // A different message must not verify.
        assert!(!verify_arbitrary(
            &account.public_key().unwrap(),
            &address,
            b"different",
            &signature
        )
        .unwrap());
        // Nor a different claimed signer.
        assert!(!verify_arbitrary(
            &account.public_key().unwrap(),
            "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz",
            message,
            &signature
        )
        .unwrap());
    }

    #[test]
    fn adr36_refuses_a_transaction_shaped_payload() {
        let account = account();
        let address = account.address().unwrap();
        let disguised = br#"{"account_number":"1","chain_id":"cosmoshub-4","fee":{},"memo":"","msgs":[{"type":"cosmos-sdk/MsgSend","value":{}}],"sequence":"1"}"#;
        assert_eq!(
            sign_arbitrary(&account, &address, disguised).unwrap_err(),
            CosmosError::SignDoc
        );
    }

    #[test]
    fn wrong_chain_prefix_is_caught_before_signing() {
        let account = account();
        let tx = UnsignedTx::new(
            vec![Msg::Send {
                from_address: account.address().unwrap(),
                // Valid osmo address in a cosmoshub transaction.
                to_address: "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8".to_owned(),
                amount: vec![Coin::new("uatom", "1").unwrap()],
            }],
            Fee::new(vec![], 200_000).unwrap(),
            "",
        )
        .unwrap();
        assert_eq!(tx.validate("cosmos").unwrap_err(), CosmosError::Address);
    }

    #[test]
    fn preview_and_signature_describe_the_same_bytes() {
        let account = account();
        let signer = signer(&account);
        let tx = transfer(&account);

        let preview = tx.preview(&signer, SignMode::Direct).unwrap();
        let raw = sign_tx(&account, &tx, &signer, SignMode::Direct).unwrap();

        // The body inside the broadcast transaction must be the body the preview described.
        let fields = proto::decode_fields(&raw).unwrap();
        let body = proto::find_field(&fields, 1).unwrap().as_bytes().unwrap();
        assert_eq!(body, tx.encode_body().as_slice());
        assert_eq!(preview.summaries.len(), tx.msgs.len());
    }
}
