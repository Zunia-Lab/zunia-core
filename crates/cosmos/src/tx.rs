//! Transaction assembly and the two sign documents.
//!
//! Direct and Amino are not two encodings of one document, they are two different documents.
//! Direct signs protobuf bytes; Amino signs a JSON string. A wallet must produce whichever the
//! chain and the dApp agreed on, and must show the user the same content either way.

use serde_json::{json, Value};

use crate::amino;
use crate::amount::Coin;
use crate::error::{CosmosError, Result};
use crate::msg::Msg;
use crate::proto::ProtoWriter;

/// `cosmos.tx.signing.v1beta1.SignMode`, restricted to the two a wallet uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMode {
    /// `SIGN_MODE_DIRECT`, protobuf. The default for anything modern.
    Direct = 1,
    /// `SIGN_MODE_LEGACY_AMINO_JSON`. Required by Ledger and by older dApps.
    LegacyAminoJson = 127,
}

/// The transaction fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas_limit: u64,
    /// Fee grant payer. Empty means the signer pays.
    pub payer: String,
    /// Fee grant granter. Empty means no grant.
    pub granter: String,
}

impl Fee {
    pub fn new(amount: Vec<Coin>, gas_limit: u64) -> Result<Self> {
        if gas_limit == 0 {
            return Err(CosmosError::Fee);
        }
        Ok(Self {
            amount,
            gas_limit,
            payer: String::new(),
            granter: String::new(),
        })
    }

    fn encode_proto(&self) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        let coins: Vec<Vec<u8>> = self
            .amount
            .iter()
            .map(|coin| {
                let mut w = ProtoWriter::new();
                w.string(1, &coin.denom).string(2, &coin.amount);
                w.into_bytes()
            })
            .collect();
        writer
            .repeated_message(1, &coins)
            .uint64(2, self.gas_limit)
            .string(3, &self.payer)
            .string(4, &self.granter);
        writer.into_bytes()
    }

    fn encode_amino(&self) -> Value {
        // `gas` in Amino, `gas_limit` in protobuf. The field is also always present, even at
        // zero, because the SDK's StdFee has no omitempty on it.
        let coins: Vec<Value> = self
            .amount
            .iter()
            .map(|c| json!({ "amount": c.amount, "denom": c.denom }))
            .collect();
        let mut entries = vec![
            ("amount", Value::Array(coins)),
            ("gas", json!(self.gas_limit.to_string())),
        ];
        if !self.payer.is_empty() {
            entries.push(("payer", json!(self.payer)));
        }
        if !self.granter.is_empty() {
            entries.push(("granter", json!(self.granter)));
        }
        amino::object(entries)
    }
}

/// Everything needed to build and sign a transaction.
#[derive(Debug, Clone)]
pub struct SignerData {
    pub chain_id: String,
    pub account_number: u64,
    pub sequence: u64,
    /// Compressed secp256k1 public key, 33 bytes.
    pub public_key: Vec<u8>,
    /// True on Ethermint chains, which advertise `ethsecp256k1` instead of `secp256k1`.
    pub eth_key_type: bool,
}

impl SignerData {
    /// The protobuf `Any` type URL for this signer's public key.
    pub fn pubkey_type_url(&self) -> &'static str {
        if self.eth_key_type {
            "/ethermint.crypto.v1.ethsecp256k1.PubKey"
        } else {
            "/cosmos.crypto.secp256k1.PubKey"
        }
    }

    /// The Amino registry name for this signer's public key.
    pub fn pubkey_amino_type(&self) -> &'static str {
        if self.eth_key_type {
            "ethermint/PubKeyEthSecp256k1"
        } else {
            "tendermint/PubKeySecp256k1"
        }
    }

    fn encode_pubkey_any(&self) -> Vec<u8> {
        let mut inner = ProtoWriter::new();
        inner.bytes(1, &self.public_key);
        let inner = inner.into_bytes();

        let mut any = ProtoWriter::new();
        any.string(1, self.pubkey_type_url()).bytes(2, &inner);
        any.into_bytes()
    }
}

/// An unsigned transaction.
#[derive(Debug, Clone)]
pub struct UnsignedTx {
    pub msgs: Vec<Msg>,
    pub fee: Fee,
    pub memo: String,
    pub timeout_height: u64,
}

impl UnsignedTx {
    pub fn new(msgs: Vec<Msg>, fee: Fee, memo: impl Into<String>) -> Result<Self> {
        if msgs.is_empty() {
            return Err(CosmosError::SignDoc);
        }
        let memo = memo.into();
        // The SDK caps memo length at 256 bytes by default. Rejecting here beats a rejected
        // broadcast after the user has already signed.
        if memo.len() > 256 {
            return Err(CosmosError::SignDoc);
        }
        Ok(Self {
            msgs,
            fee,
            memo,
            timeout_height: 0,
        })
    }

    /// `cosmos.tx.v1beta1.TxBody`
    pub fn encode_body(&self) -> Vec<u8> {
        let anys: Vec<Vec<u8>> = self
            .msgs
            .iter()
            .map(|msg| {
                let mut any = ProtoWriter::new();
                any.string(1, msg.type_url()).bytes(2, &msg.encode_proto());
                any.into_bytes()
            })
            .collect();

        let mut writer = ProtoWriter::new();
        writer
            .repeated_message(1, &anys)
            .string(2, &self.memo)
            .uint64(3, self.timeout_height);
        writer.into_bytes()
    }

    /// `cosmos.tx.v1beta1.AuthInfo` for a single signer.
    pub fn encode_auth_info(&self, signer: &SignerData, mode: SignMode) -> Vec<u8> {
        // ModeInfo.Single.mode. Note that Direct is enum value 1, so it encodes; if it were 0
        // the field would be omitted and the chain would read SIGN_MODE_UNSPECIFIED.
        let mut single = ProtoWriter::new();
        single.int32(1, mode as i32);
        let single = single.into_bytes();

        let mut mode_info = ProtoWriter::new();
        // message_always: an empty ModeInfo.Single is meaningful and must be present.
        mode_info.message_always(1, &single);
        let mode_info = mode_info.into_bytes();

        let mut signer_info = ProtoWriter::new();
        signer_info
            .message(1, &signer.encode_pubkey_any())
            .message(2, &mode_info)
            .uint64(3, signer.sequence);
        let signer_info = signer_info.into_bytes();

        let mut writer = ProtoWriter::new();
        writer
            .repeated_message(1, &[signer_info])
            .message(2, &self.fee.encode_proto());
        writer.into_bytes()
    }

    /// `SIGN_MODE_DIRECT` sign bytes, meaning the serialised `cosmos.tx.v1beta1.SignDoc`.
    pub fn direct_sign_bytes(&self, signer: &SignerData) -> Result<Vec<u8>> {
        if signer.chain_id.trim().is_empty() {
            return Err(CosmosError::ChainId);
        }
        let body = self.encode_body();
        let auth_info = self.encode_auth_info(signer, SignMode::Direct);

        let mut writer = ProtoWriter::new();
        writer
            .bytes(1, &body)
            .bytes(2, &auth_info)
            .string(3, &signer.chain_id)
            .uint64(4, signer.account_number);
        Ok(writer.into_bytes())
    }

    /// `SIGN_MODE_LEGACY_AMINO_JSON` sign bytes.
    ///
    /// `StdSignDoc` always carries all seven keys, including `"memo":""` and
    /// `"account_number":"0"`, because the SDK's struct has no omitempty on them. Dropping an
    /// empty memo here is the single most common Amino signing bug.
    pub fn amino_sign_bytes(&self, signer: &SignerData) -> Result<Vec<u8>> {
        Ok(amino::to_sign_bytes(&self.amino_sign_doc(signer)?))
    }

    /// The Amino sign document as JSON, for display and for tests.
    pub fn amino_sign_doc(&self, signer: &SignerData) -> Result<Value> {
        if signer.chain_id.trim().is_empty() {
            return Err(CosmosError::ChainId);
        }
        let msgs: Vec<Value> = self.msgs.iter().map(|m| m.encode_amino()).collect();

        let mut entries = vec![
            ("account_number", json!(signer.account_number.to_string())),
            ("chain_id", json!(signer.chain_id)),
            ("fee", self.fee.encode_amino()),
            ("memo", json!(self.memo)),
            ("msgs", Value::Array(msgs)),
            ("sequence", json!(signer.sequence.to_string())),
        ];
        if self.timeout_height != 0 {
            entries.push(("timeout_height", json!(self.timeout_height.to_string())));
        }
        Ok(amino::object(entries))
    }

    /// Sign bytes for the requested mode.
    pub fn sign_bytes(&self, signer: &SignerData, mode: SignMode) -> Result<Vec<u8>> {
        match mode {
            SignMode::Direct => self.direct_sign_bytes(signer),
            SignMode::LegacyAminoJson => self.amino_sign_bytes(signer),
        }
    }

    /// Assembles a broadcastable `cosmos.tx.v1beta1.TxRaw`.
    ///
    /// The `auth_info_bytes` here must be byte-identical to the ones inside the signed
    /// `SignDoc`, which is why the sign mode is passed through rather than assumed. A signature
    /// over Direct auth info attached to Amino auth info verifies against nothing.
    pub fn into_tx_raw(
        &self,
        signer: &SignerData,
        mode: SignMode,
        signature: &[u8],
    ) -> Result<Vec<u8>> {
        if signature.len() != 64 {
            return Err(CosmosError::SignDoc);
        }
        let body = self.encode_body();
        let auth_info = self.encode_auth_info(signer, mode);

        let mut writer = ProtoWriter::new();
        writer
            .bytes(1, &body)
            .bytes(2, &auth_info)
            .repeated_message(3, &[signature.to_vec()]);
        Ok(writer.into_bytes())
    }

    /// Validates every message against the chain's bech32 prefix.
    pub fn validate(&self, prefix: &str) -> Result<()> {
        for msg in &self.msgs {
            msg.validate_addresses(prefix)?;
        }
        if self.fee.gas_limit == 0 {
            return Err(CosmosError::Fee);
        }
        Ok(())
    }
}

/// ADR-36 `signArbitrary`, the standard for proving address ownership off chain.
///
/// The document is a `MsgSignData` inside an otherwise empty Amino `StdSignDoc`: chain id
/// empty, account number and sequence zero, zero fee, no memo. Those values are fixed by the
/// specification precisely so that an ADR-36 signature can never be replayed as a real
/// transaction: a transaction with an empty chain id is invalid everywhere.
///
/// The data is base64 encoded inside the document.
pub fn adr36_sign_doc(signer_address: &str, data: &[u8]) -> Value {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);

    amino::object([
        ("account_number", json!("0")),
        ("chain_id", json!("")),
        (
            "fee",
            amino::object([("amount", json!([])), ("gas", json!("0"))]),
        ),
        ("memo", json!("")),
        (
            "msgs",
            json!([{
                "type": "sign/MsgSignData",
                "value": {
                    "data": encoded,
                    "signer": signer_address,
                }
            }]),
        ),
        ("sequence", json!("0")),
    ])
}

/// ADR-36 sign bytes.
pub fn adr36_sign_bytes(signer_address: &str, data: &[u8]) -> Vec<u8> {
    amino::to_sign_bytes(&adr36_sign_doc(signer_address, data))
}

/// Rejects an ADR-36 payload that could be mistaken for a transaction.
///
/// A dApp that asks for `signArbitrary` over something that parses as a `StdSignDoc` is
/// attempting to have the user authorise a transfer while the prompt says "sign this message".
/// The check is cheap and the attack is not hypothetical.
pub fn adr36_payload_is_safe(data: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(data) else {
        // Non-UTF-8 cannot be a JSON sign document.
        return true;
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return true;
    };
    let Some(map) = value.as_object() else {
        return true;
    };
    // The tell is a sign-document shape: msgs plus the sequencing fields.
    let looks_like_sign_doc = map.contains_key("msgs")
        && (map.contains_key("sequence") || map.contains_key("account_number"));
    !looks_like_sign_doc
}

/// A "what am I signing" view built from an unsigned transaction.
///
/// Everything the signing prompt needs, computed once so the UI cannot drift from the bytes.
#[derive(Debug, Clone)]
pub struct SigningPreview {
    pub chain_id: String,
    pub mode: SignMode,
    pub summaries: Vec<String>,
    pub fee: Vec<Coin>,
    pub gas_limit: u64,
    pub memo: String,
    pub spends_funds: bool,
    pub counterparties: Vec<String>,
    /// SHA-256 of the sign bytes, hex encoded. Lets a user or a support engineer confirm that
    /// the prompt and the broadcast transaction are the same thing.
    pub sign_bytes_hash: String,
}

impl UnsignedTx {
    /// Builds the preview shown before signing.
    pub fn preview(&self, signer: &SignerData, mode: SignMode) -> Result<SigningPreview> {
        use sha2::{Digest, Sha256};

        let sign_bytes = self.sign_bytes(signer, mode)?;
        let mut counterparties: Vec<String> = Vec::new();
        for msg in &self.msgs {
            for address in msg.addresses() {
                if !counterparties.iter().any(|c| c == address) {
                    counterparties.push(address.to_owned());
                }
            }
        }

        Ok(SigningPreview {
            chain_id: signer.chain_id.clone(),
            mode,
            summaries: self.msgs.iter().map(|m| m.summary()).collect(),
            fee: self.fee.amount.clone(),
            gas_limit: self.fee.gas_limit,
            memo: self.memo.clone(),
            spends_funds: self.msgs.iter().any(|m| m.spends_funds()),
            counterparties,
            sign_bytes_hash: hex::encode(Sha256::digest(&sign_bytes)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amino::to_canonical_string;

    const FROM: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
    const TO: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
    const PUBKEY: &str = "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

    fn signer() -> SignerData {
        SignerData {
            chain_id: "cosmoshub-4".to_owned(),
            account_number: 12345,
            sequence: 7,
            public_key: hex::decode(PUBKEY).unwrap(),
            eth_key_type: false,
        }
    }

    fn tx() -> UnsignedTx {
        UnsignedTx::new(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }],
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            "",
        )
        .unwrap()
    }

    #[test]
    fn amino_sign_doc_keeps_every_required_key() {
        // Dropping "memo":"" is the single most common Amino signing bug. The document must
        // carry all six keys even when empty or zero.
        assert_eq!(
            to_canonical_string(&tx().amino_sign_doc(&signer()).unwrap()),
            r#"{"account_number":"12345","chain_id":"cosmoshub-4","fee":{"amount":[{"amount":"5000","denom":"uatom"}],"gas":"200000"},"memo":"","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"1000000","denom":"uatom"}],"from_address":"cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4","to_address":"cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz"}}],"sequence":"7"}"#
        );
    }

    #[test]
    fn amino_uses_gas_not_gas_limit() {
        let rendered = to_canonical_string(&tx().amino_sign_doc(&signer()).unwrap());
        assert!(rendered.contains(r#""gas":"200000""#));
        assert!(!rendered.contains("gas_limit"));
    }

    #[test]
    fn amino_zero_account_number_is_present_as_a_string() {
        let mut fresh = signer();
        fresh.account_number = 0;
        fresh.sequence = 0;
        let rendered = to_canonical_string(&tx().amino_sign_doc(&fresh).unwrap());
        assert!(rendered.contains(r#""account_number":"0""#));
        assert!(rendered.contains(r#""sequence":"0""#));
    }

    #[test]
    fn direct_sign_doc_has_the_four_fields_in_order() {
        let bytes = tx().direct_sign_bytes(&signer()).unwrap();
        let fields = crate::proto::decode_fields(&bytes).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].tag, 1, "body_bytes");
        assert_eq!(fields[1].tag, 2, "auth_info_bytes");
        assert_eq!(fields[2].tag, 3, "chain_id");
        assert_eq!(fields[3].tag, 4, "account_number");
        assert_eq!(fields[2].value.as_string().unwrap(), "cosmoshub-4");
        assert_eq!(fields[3].value.as_varint().unwrap(), 12345);
    }

    #[test]
    fn direct_and_amino_produce_different_bytes() {
        // Two documents, not two encodings. Signing one and broadcasting with the other is a
        // real failure mode, so this asserts they are distinguishable.
        let tx = tx();
        let signer = signer();
        assert_ne!(
            tx.direct_sign_bytes(&signer).unwrap(),
            tx.amino_sign_bytes(&signer).unwrap()
        );
    }

    #[test]
    fn auth_info_differs_between_modes() {
        // The sign mode is encoded inside auth_info, so the bytes attached to a broadcast must
        // match the mode that was signed.
        let tx = tx();
        let signer = signer();
        assert_ne!(
            tx.encode_auth_info(&signer, SignMode::Direct),
            tx.encode_auth_info(&signer, SignMode::LegacyAminoJson)
        );
    }

    #[test]
    fn mode_info_single_is_present_even_when_empty() {
        // ModeInfo.Single with mode 0 would encode to nothing; the field must still exist or
        // the chain reads SIGN_MODE_UNSPECIFIED and rejects the transaction.
        let auth = tx().encode_auth_info(&signer(), SignMode::Direct);
        let fields = crate::proto::decode_fields(&auth).unwrap();
        let signer_info = crate::proto::decode_fields(
            crate::proto::find_field(&fields, 1)
                .unwrap()
                .as_bytes()
                .unwrap(),
        )
        .unwrap();
        let mode_info = crate::proto::decode_fields(
            crate::proto::find_field(&signer_info, 2)
                .unwrap()
                .as_bytes()
                .unwrap(),
        )
        .unwrap();
        assert!(crate::proto::find_field(&mode_info, 1).is_some());
    }

    #[test]
    fn ethermint_signers_advertise_a_different_key_type() {
        let mut eth = signer();
        eth.eth_key_type = true;
        assert_eq!(
            eth.pubkey_type_url(),
            "/ethermint.crypto.v1.ethsecp256k1.PubKey"
        );
        assert_eq!(eth.pubkey_amino_type(), "ethermint/PubKeyEthSecp256k1");
        // Which changes the signed bytes, so it cannot be an afterthought.
        assert_ne!(
            tx().direct_sign_bytes(&eth).unwrap(),
            tx().direct_sign_bytes(&signer()).unwrap()
        );
    }

    #[test]
    fn empty_chain_id_is_refused() {
        let mut bad = signer();
        bad.chain_id = "  ".to_owned();
        assert_eq!(
            tx().direct_sign_bytes(&bad).unwrap_err(),
            CosmosError::ChainId
        );
        assert_eq!(
            tx().amino_sign_bytes(&bad).unwrap_err(),
            CosmosError::ChainId
        );
    }

    #[test]
    fn empty_message_list_is_refused() {
        assert_eq!(
            UnsignedTx::new(vec![], Fee::new(vec![], 200_000).unwrap(), "").unwrap_err(),
            CosmosError::SignDoc
        );
    }

    #[test]
    fn zero_gas_is_refused() {
        assert_eq!(Fee::new(vec![], 0).unwrap_err(), CosmosError::Fee);
    }

    #[test]
    fn oversized_memo_is_refused_before_signing() {
        let long = "a".repeat(257);
        assert!(UnsignedTx::new(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1").unwrap()],
            }],
            Fee::new(vec![], 200_000).unwrap(),
            long,
        )
        .is_err());
    }

    #[test]
    fn tx_raw_requires_a_64_byte_signature() {
        let tx = tx();
        assert!(tx
            .into_tx_raw(&signer(), SignMode::Direct, &[0u8; 64])
            .is_ok());
        assert!(tx
            .into_tx_raw(&signer(), SignMode::Direct, &[0u8; 65])
            .is_err());
        assert!(tx.into_tx_raw(&signer(), SignMode::Direct, &[]).is_err());
    }

    #[test]
    fn tx_raw_shape() {
        let raw = tx()
            .into_tx_raw(&signer(), SignMode::Direct, &[9u8; 64])
            .unwrap();
        let fields = crate::proto::decode_fields(&raw).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(
            crate::proto::find_field(&fields, 3)
                .unwrap()
                .as_bytes()
                .unwrap(),
            &[9u8; 64]
        );
    }

    #[test]
    fn adr36_document_is_fixed_by_the_specification() {
        // Empty chain id, zero account number and sequence, zero fee. These values are what
        // make an ADR-36 signature unusable as a transaction.
        assert_eq!(
            to_canonical_string(&adr36_sign_doc(FROM, b"Sign in to Zunia")),
            r#"{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"U2lnbiBpbiB0byBadW5pYQ==","signer":"cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4"}}],"sequence":"0"}"#
        );
        assert_eq!(
            adr36_sign_bytes(FROM, b"x"),
            to_canonical_string(&adr36_sign_doc(FROM, b"x")).into_bytes()
        );
    }

    #[test]
    fn adr36_rejects_a_payload_shaped_like_a_transaction() {
        // The attack: ask for signArbitrary over a real StdSignDoc, so the user sees "sign
        // this message" and authorises a transfer.
        let disguised = br#"{"account_number":"1","chain_id":"cosmoshub-4","fee":{"amount":[],"gas":"200000"},"memo":"","msgs":[{"type":"cosmos-sdk/MsgSend","value":{}}],"sequence":"1"}"#;
        assert!(!adr36_payload_is_safe(disguised));

        assert!(adr36_payload_is_safe(
            b"Sign in to Zunia at 2026-08-31T12:00:00Z"
        ));
        assert!(adr36_payload_is_safe(
            br#"{"nonce":"abc","domain":"app.example"}"#
        ));
        assert!(
            adr36_payload_is_safe(&[0xff, 0xfe, 0x00]),
            "non-UTF-8 is fine"
        );
        assert!(adr36_payload_is_safe(b""));
    }

    #[test]
    fn preview_reflects_the_bytes_that_will_be_signed() {
        let tx = tx();
        let signer = signer();
        let preview = tx.preview(&signer, SignMode::Direct).unwrap();

        assert_eq!(preview.chain_id, "cosmoshub-4");
        assert_eq!(preview.summaries.len(), 1);
        assert!(preview.summaries[0].starts_with("Send 1000000 uatom"));
        assert_eq!(preview.gas_limit, 200_000);
        assert!(preview.spends_funds);
        assert_eq!(preview.counterparties, vec![FROM, TO]);

        // The hash must be of the actual sign bytes, so it changes with the mode.
        use sha2::{Digest, Sha256};
        assert_eq!(
            preview.sign_bytes_hash,
            hex::encode(Sha256::digest(tx.direct_sign_bytes(&signer).unwrap()))
        );
        let amino_preview = tx.preview(&signer, SignMode::LegacyAminoJson).unwrap();
        assert_ne!(preview.sign_bytes_hash, amino_preview.sign_bytes_hash);
    }

    #[test]
    fn preview_deduplicates_counterparties() {
        let tx = UnsignedTx::new(
            vec![
                Msg::Send {
                    from_address: FROM.to_owned(),
                    to_address: TO.to_owned(),
                    amount: vec![Coin::new("uatom", "1").unwrap()],
                },
                Msg::Send {
                    from_address: FROM.to_owned(),
                    to_address: TO.to_owned(),
                    amount: vec![Coin::new("uatom", "2").unwrap()],
                },
            ],
            Fee::new(vec![], 200_000).unwrap(),
            "",
        )
        .unwrap();
        let preview = tx.preview(&signer(), SignMode::Direct).unwrap();
        assert_eq!(preview.counterparties.len(), 2);
        assert_eq!(preview.summaries.len(), 2);
    }

    #[test]
    fn validation_runs_over_every_message() {
        assert!(tx().validate("cosmos").is_ok());
        assert_eq!(tx().validate("osmo").unwrap_err(), CosmosError::Address);
    }

    #[test]
    fn timeout_height_appears_in_both_documents_when_set() {
        let mut tx = tx();
        tx.timeout_height = 20_000_000;

        let rendered = to_canonical_string(&tx.amino_sign_doc(&signer()).unwrap());
        assert!(rendered.contains(r#""timeout_height":"20000000""#));

        let body = crate::proto::decode_fields(&tx.encode_body()).unwrap();
        assert_eq!(
            crate::proto::find_field(&body, 3)
                .unwrap()
                .as_varint()
                .unwrap(),
            20_000_000
        );
    }

    #[test]
    fn absent_timeout_height_is_omitted_from_both() {
        let tx = tx();
        assert!(
            !to_canonical_string(&tx.amino_sign_doc(&signer()).unwrap()).contains("timeout_height")
        );
        let body = crate::proto::decode_fields(&tx.encode_body()).unwrap();
        assert!(crate::proto::find_field(&body, 3).is_none());
    }
}
