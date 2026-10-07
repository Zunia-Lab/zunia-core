//! Amino documents rebuilt by the kernel, checked against signatures the chain accepted.
//!
//! The golden vectors prove agreement with a reference library. These prove agreement with the
//! chain: each case is a real amino-signed cosmoshub-4 transaction, with the signer's public key
//! and the signature from the block. The kernel rebuilds the sign document from the message's
//! fields alone, and the test passes only if the chain's own signature verifies over those bytes.
//! A reference library and a hand-written vector can agree with each other and still be wrong;
//! a signature cannot.

use std::path::Path;

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zunia_cosmos::amount::Coin;
use zunia_cosmos::msg::{Height, Msg, VoteOption};
use zunia_cosmos::tx::{Fee, SignMode, SignerData, UnsignedTx};

fn load() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/chain-verified-amino.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}

fn u(value: &Value) -> u64 {
    value
        .as_str()
        .filter(|t| !t.is_empty())
        .map_or(0, |t| t.parse().unwrap())
}

fn coin(value: &Value) -> Coin {
    Coin::new(s(&value["denom"]), s(&value["amount"])).unwrap()
}

fn message(value: &Value) -> Msg {
    match value["@type"].as_str().unwrap() {
        "/cosmos.gov.v1beta1.MsgVote" => Msg::Vote {
            proposal_id: u(&value["proposal_id"]),
            voter: s(&value["voter"]),
            option: match value["option"].as_str().unwrap() {
                "VOTE_OPTION_YES" => VoteOption::Yes,
                "VOTE_OPTION_ABSTAIN" => VoteOption::Abstain,
                "VOTE_OPTION_NO" => VoteOption::No,
                "VOTE_OPTION_NO_WITH_VETO" => VoteOption::NoWithVeto,
                other => panic!("option {other}"),
            },
        },
        "/ibc.applications.transfer.v1.MsgTransfer" => Msg::IbcTransfer {
            source_port: s(&value["source_port"]),
            source_channel: s(&value["source_channel"]),
            token: coin(&value["token"]),
            sender: s(&value["sender"]),
            receiver: s(&value["receiver"]),
            timeout_height: Height {
                revision_number: u(&value["timeout_height"]["revision_number"]),
                revision_height: u(&value["timeout_height"]["revision_height"]),
            },
            timeout_timestamp: u(&value["timeout_timestamp"]),
            memo: s(&value["memo"]),
        },
        other => panic!("no builder for {other}"),
    }
}

#[test]
fn rebuilt_amino_documents_verify_against_real_on_chain_signatures() {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut failures = Vec::new();
    for case in load()["cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let fee = Fee::new(
            case["fee"]["amount"]
                .as_array()
                .unwrap()
                .iter()
                .map(coin)
                .collect(),
            u(&case["fee"]["gas"]),
        )
        .unwrap();
        let mut tx =
            UnsignedTx::new(vec![message(&case["message"])], fee, s(&case["memo"])).unwrap();
        tx.timeout_height = u(&case["timeoutHeight"]);
        let public_key = b64.decode(s(&case["pubKey"])).unwrap();
        let signature = b64.decode(s(&case["signature"])).unwrap();
        let signer = SignerData {
            chain_id: s(&case["chainId"]),
            account_number: u(&case["accountNumber"]),
            sequence: u(&case["sequence"]),
            public_key: public_key.clone(),
            eth_key_type: false,
            eth_pub_key_type_url: None,
        };
        let bytes = tx.sign_bytes(&signer, SignMode::LegacyAminoJson).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let verifies =
            zunia_kernel::verify_digest_secp256k1(&public_key, &digest, &signature).unwrap();
        if !verifies || hex::encode(&bytes) != s(&case["signBytesHex"]) {
            failures.push(format!(
                "{name}: kernel signed {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
