//! Anchors the JSON bridge to the CosmJS golden vectors.
//!
//! `tests/golden_vectors.rs` proves the encoders match CosmJS byte for byte. This file proves
//! the other half: that a message reconstructed from the proto-JSON a client actually sends
//! encodes to those same bytes. A round-trip test alone would only show the bridge is
//! self-consistent, which a bridge that drops a field is too. The assertion that matters is
//! that `msgs_from_json` output produces the golden sign bytes, because that is the property a
//! silent field-order, timeout, vote-option or base64 bug would break, and the on-chain symptom
//! of breaking it is an opaque "unauthorized" after the user has already approved.
//!
//! The message inputs below are constructed rather than decoded, and deliberately duplicate
//! `golden_vectors.rs`. Decoding this crate's own output and re-encoding it would test nothing,
//! and duplicating the inputs means a change to the generator that nobody mirrors here shows up
//! as a failure rather than passing silently.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use zunia_cosmos::amount::Coin;
use zunia_cosmos::json::{
    fee_from_json, msg_from_proto_json, msg_to_proto_json, msgs_from_json, msgs_to_json,
    sign_mode_from_str,
};
use zunia_cosmos::msg::{Height, Msg, VoteOption};
use zunia_cosmos::tx::{Fee, SignMode, SignerData, UnsignedTx};
use zunia_cosmos::CosmosError;

/// The one vector this bridge deliberately refuses to rebuild.
///
/// The encoding is correct and pinned; the client-facing door is closed. See the module
/// documentation on `zunia_cosmos::json`.
const NO_TIMEOUT: &str = "msg_transfer_no_timeout";

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/cosmos-signing.json")
}

fn load() -> Value {
    let text = std::fs::read_to_string(vectors_path()).expect(
        "tests/vectors/cosmos-signing.json is missing; run \
         `cd tests/vectors/generate && pnpm install && pnpm generate`",
    );
    serde_json::from_str(&text).expect("vector file is not valid JSON")
}

fn str_at(value: &Value, path: &[&str]) -> String {
    let mut cursor = value;
    for key in path {
        cursor = &cursor[*key];
    }
    cursor
        .as_str()
        .unwrap_or_else(|| panic!("expected a string at {path:?}, got {cursor}"))
        .to_owned()
}

fn message_for(name: &str, addresses: &Value) -> Msg {
    let from = str_at(addresses, &["cosmos"]);
    let valoper = str_at(addresses, &["cosmosvaloper"]);
    let safro = str_at(addresses, &["addr_safro"]);
    let to = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz".to_owned();

    match name {
        "msg_send" => Msg::Send {
            from_address: from,
            to_address: to,
            amount: vec![Coin::new("uatom", "1000000").unwrap()],
        },
        "msg_send_with_memo" => Msg::Send {
            from_address: from,
            to_address: to,
            amount: vec![Coin::new("uatom", "1").unwrap()],
        },
        "msg_delegate" => Msg::Delegate {
            delegator_address: from,
            validator_address: valoper,
            amount: Coin::new("uatom", "5000000").unwrap(),
        },
        "msg_undelegate" => Msg::Undelegate {
            delegator_address: from,
            validator_address: valoper,
            amount: Coin::new("uatom", "1000000").unwrap(),
        },
        "msg_begin_redelegate" => Msg::BeginRedelegate {
            delegator_address: from,
            validator_src_address: valoper.clone(),
            validator_dst_address: valoper,
            amount: Coin::new("uatom", "1000000").unwrap(),
        },
        "msg_withdraw_delegator_reward" => Msg::WithdrawDelegatorReward {
            delegator_address: from,
            validator_address: valoper,
        },
        "msg_vote" => Msg::Vote {
            proposal_id: 848,
            voter: from,
            option: VoteOption::NoWithVeto,
        },
        "msg_transfer_no_timeout" => Msg::IbcTransfer {
            source_port: "transfer".to_owned(),
            source_channel: "channel-141".to_owned(),
            token: Coin::new("uatom", "1000000").unwrap(),
            sender: from,
            receiver: safro,
            timeout_height: Height::default(),
            timeout_timestamp: 0,
            memo: String::new(),
        },
        "msg_transfer_with_timeout" => Msg::IbcTransfer {
            source_port: "transfer".to_owned(),
            source_channel: "channel-141".to_owned(),
            token: Coin::new("uatom", "1000000").unwrap(),
            sender: from,
            receiver: safro,
            timeout_height: Height {
                revision_number: 1,
                revision_height: 20_000_000,
            },
            timeout_timestamp: 1_700_000_000_000_000_000,
            memo: "forward".to_owned(),
        },
        "msg_execute_contract" => Msg::ExecuteContract {
            sender: from,
            contract: to,
            msg: br#"{"swap":{"offer":"100"}}"#.to_vec(),
            funds: vec![Coin::new("uatom", "100").unwrap()],
        },
        other => panic!(
            "vector \"{other}\" has no Rust counterpart; add it to message_for or remove it \
             from the generator"
        ),
    }
}

fn signer_from(vectors: &Value) -> SignerData {
    SignerData {
        chain_id: str_at(vectors, &["signer", "chain_id"]),
        account_number: vectors["signer"]["account_number"].as_u64().unwrap(),
        sequence: vectors["signer"]["sequence"].as_u64().unwrap(),
        public_key: hex::decode(str_at(vectors, &["key", "pubkey_compressed_hex"])).unwrap(),
        eth_key_type: false,
    }
}

/// The fee the generator used, expressed the way a client sends it.
fn golden_fee_json() -> &'static str {
    r#"{"amount":[{"denom":"uatom","amount":"5000"}],"gas_limit":"200000"}"#
}

#[test]
fn every_vector_round_trips_through_proto_json() {
    let vectors = load();
    let addresses = &vectors["key"]["addresses"];
    let mut checked = 0usize;

    for case in vectors["cases"].as_array().unwrap() {
        let name = str_at(case, &["name"]);
        let msg = message_for(&name, addresses);
        let value = msg_to_proto_json(&msg);

        if name == NO_TIMEOUT {
            continue;
        }
        assert_eq!(
            msg_from_proto_json(msg.type_url(), &value).unwrap(),
            msg,
            "{name}: round trip through proto-JSON lost or changed a field"
        );
        checked = checked.saturating_add(1);
    }

    assert!(
        checked >= 9,
        "expected the full vector set minus {NO_TIMEOUT}"
    );
}

#[test]
fn messages_parsed_from_json_produce_the_golden_sign_bytes() {
    // The assertion that matters. If the bridge mis-parsed a timeout, a vote option, a
    // base64 payload or an amount, these bytes diverge and every signature made through the
    // bindings would verify against nothing.
    let vectors = load();
    let addresses = &vectors["key"]["addresses"];
    let signer = signer_from(&vectors);
    let fee = fee_from_json(golden_fee_json()).unwrap();
    assert_eq!(
        fee,
        Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
        "the fee bridge must reproduce the fee the generator used"
    );

    for case in vectors["cases"].as_array().unwrap() {
        let name = str_at(case, &["name"]);
        if name == NO_TIMEOUT {
            continue;
        }

        let envelope = msgs_to_json(&[message_for(&name, addresses)]).to_string();
        let msgs = msgs_from_json(&envelope).unwrap();
        let tx = UnsignedTx::new(msgs, fee.clone(), str_at(case, &["memo"])).unwrap();

        assert_eq!(
            hex::encode(tx.direct_sign_bytes(&signer).unwrap()),
            str_at(case, &["direct", "sign_bytes_hex"]),
            "{name}: Direct sign bytes diverged after a JSON round trip"
        );
        assert_eq!(
            hex::encode(tx.amino_sign_bytes(&signer).unwrap()),
            str_at(case, &["amino", "sign_bytes_hex"]),
            "{name}: Amino sign bytes diverged after a JSON round trip"
        );
    }
}

#[test]
fn a_hand_written_envelope_matches_the_golden_send() {
    // The vectors are reachable from JSON this file did not generate, which is the situation
    // in production: the payload comes from @zunialab/interchain, not from msg_to_proto_json.
    let vectors = load();
    let from = str_at(&vectors, &["key", "addresses", "cosmos"]);
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == json!("msg_send"))
        .unwrap()
        .clone();

    let envelope = json!([{
        "typeUrl": "/cosmos.bank.v1beta1.MsgSend",
        "value": {
            "from_address": from,
            "to_address": "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz",
            "amount": [{ "denom": "uatom", "amount": "1000000" }],
        },
    }])
    .to_string();

    let tx = UnsignedTx::new(
        msgs_from_json(&envelope).unwrap(),
        fee_from_json(golden_fee_json()).unwrap(),
        "",
    )
    .unwrap();

    let signer = signer_from(&vectors);
    for (mode, key) in [
        (SignMode::Direct, "direct"),
        (SignMode::LegacyAminoJson, "amino"),
    ] {
        assert_eq!(
            hex::encode(tx.sign_bytes(&signer, mode).unwrap()),
            str_at(&case, &[key, "sign_bytes_hex"]),
            "{key}: a hand-written envelope diverged from CosmJS"
        );
    }
    assert_eq!(sign_mode_from_str("direct").unwrap(), SignMode::Direct);
    assert_eq!(
        sign_mode_from_str("amino").unwrap(),
        SignMode::LegacyAminoJson
    );
}

#[test]
fn the_contract_call_vector_survives_base64() {
    // The bridge decodes on the way in and encodes on the way out. Getting that backwards
    // makes every swap and NFT transfer an invalid contract call, so it is asserted against
    // the CosmJS vector rather than against a local expectation.
    let vectors = load();
    let addresses = &vectors["key"]["addresses"];
    let msg = message_for("msg_execute_contract", addresses);

    let value = msg_to_proto_json(&msg);
    assert_eq!(
        value["msg"].as_str().unwrap(),
        "eyJzd2FwIjp7Im9mZmVyIjoiMTAwIn19",
        "the payload must leave as standard base64 of the contract JSON"
    );

    let parsed = msg_from_proto_json(msg.type_url(), &value).unwrap();
    assert_eq!(parsed, msg);
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == json!("msg_execute_contract"))
        .unwrap()
        .clone();
    assert_eq!(
        hex::encode(parsed.encode_proto()),
        str_at(&case, &["direct", "msg_proto_hex"]),
        "the decoded payload must re-encode to the CosmJS bytes"
    );
}

#[test]
fn the_no_timeout_transfer_vector_is_refused_by_the_bridge() {
    // Deliberate and load-bearing. The encoder can still produce this message, and
    // golden_vectors.rs pins its bytes, because the wallet must be able to decode and display
    // one that arrives from a dApp. What it will not do is build one: an ICS-20 packet with
    // neither a height nor a timestamp timeout never expires, so the escrowed tokens can
    // never be refunded if no relayer delivers it.
    let vectors = load();
    let addresses = &vectors["key"]["addresses"];
    let msg = message_for(NO_TIMEOUT, addresses);

    // The encoder is untouched: these are still the CosmJS bytes.
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == json!(NO_TIMEOUT))
        .unwrap()
        .clone();
    assert_eq!(
        hex::encode(msg.encode_proto()),
        str_at(&case, &["direct", "msg_proto_hex"])
    );

    // The bridge refuses it in both spellings: rendered with explicit zeros, and with the
    // timeout keys absent entirely.
    let rendered = msg_to_proto_json(&msg);
    assert_eq!(
        msg_from_proto_json(msg.type_url(), &rendered).unwrap_err(),
        CosmosError::SignDoc
    );
    assert_eq!(
        msgs_from_json(&msgs_to_json(&[msg]).to_string()).unwrap_err(),
        CosmosError::SignDoc
    );
}
