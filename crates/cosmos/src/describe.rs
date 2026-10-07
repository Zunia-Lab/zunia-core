//! What the signing prompt is handed about a decoded transaction, beyond its summaries.
//!
//! A summary names the action. It cannot carry everything a user has to read before approving
//! it: a contract call's message can name its own recipient (a cw20 `transfer` does), and an IBC
//! transfer's packet memo can forward the tokens to another chain and another receiver entirely.
//! Kernel 0.1.0 returned the summaries alone, so neither reached the prompt. This module adds
//! them per message, with the message's type URL, the address it pays, the fee and the account
//! fields, and assembles the payload both bindings return: `decodeDirectTx` in `crates/wasm` and
//! `zunia_decode_direct_tx` in `crates/ffi`. One function builds it for both, so they cannot
//! drift.
//!
//! # Payload v2
//!
//! ```text
//! { chainId, memo, hasUnknownMsgs, safeWithoutBlindSigning, summaries, addresses,
//!   accountNumber, sequence, timeoutHeight,
//!   fee: { amount: [{ denom, amount }], gasLimit },
//!   messages: [{ typeUrl, summary, unknown, recipient?, detail? }] }
//! ```
//!
//! It is additive. The first six keys are what the wasm binding returned in 0.1.0, value for
//! value, so a caller written for 0.1.0 reads what it read before, and a caller can tell a v2
//! payload by `messages`. Every `u64` (`accountNumber`, `sequence`, `timeoutHeight`, `gasLimit`)
//! is a decimal string, because a JavaScript number above 2^53 has already lost precision.
//! `messages[i].summary` is `summaries[i]`, word for word.
//!
//! `recipient` and `detail` appear only on a message the wallet understood, and only where they
//! apply: [`recipient`] for a send and an IBC transfer, [`message_detail`] for a contract call
//! and an IBC transfer. An unknown message carries its type URL, its summary and `unknown: true`
//! and nothing else, because nothing else in it was read.

use serde_json::{json, Map, Value};

use crate::amount::Coin;
use crate::decode::{DecodedMsg, DecodedTx};

/// The address a message sends funds to: a send's `to_address`, an IBC transfer's `receiver`.
///
/// For the first-time-recipient warning, which compares it with the addresses a user has paid
/// before. `None` for every other message, and for an unknown one. A contract call's recipients
/// live inside its message, which [`message_detail`] carries whole.
pub fn recipient(msg: &DecodedMsg) -> Option<&str> {
    match msg {
        DecodedMsg::Send { to, .. } => Some(to),
        DecodedMsg::IbcTransfer { receiver, .. } => Some(receiver),
        DecodedMsg::Delegate { .. }
        | DecodedMsg::Undelegate { .. }
        | DecodedMsg::Redelegate { .. }
        | DecodedMsg::ClaimRewards { .. }
        | DecodedMsg::Vote { .. }
        | DecodedMsg::ExecuteContract { .. }
        | DecodedMsg::SwapExactAmountIn { .. }
        | DecodedMsg::SplitRouteSwapExactAmountIn { .. }
        | DecodedMsg::SwapExactAmountOut { .. }
        | DecodedMsg::SplitRouteSwapExactAmountOut { .. }
        | DecodedMsg::Unknown { .. } => None,
    }
}

/// What a contract call or an IBC transfer carries that its summary does not say.
///
/// A contract call: `{ kind: "execute-contract", contract, msg, funds }`, with `msg` the
/// contract message parsed as JSON. An IBC transfer: `{ kind: "ibc-transfer", sourceChannel,
/// receiver, token, memo }`, with `memo` the packet memo, where packet-forward and ibc-hooks
/// instructions for the receiving chain live. `None` for every other message, and for an unknown
/// one, whose fields the wallet cannot vouch for.
pub fn message_detail(msg: &DecodedMsg) -> Option<Value> {
    match msg {
        DecodedMsg::ExecuteContract {
            contract,
            msg,
            funds,
            ..
        } => Some(json!({
            "kind": "execute-contract",
            "contract": contract,
            // Parsed, in the order the dApp wrote it. A call whose bytes are not JSON never gets
            // here: the decoder demotes it to unknown.
            "msg": msg,
            "funds": coins_json(funds),
        })),
        DecodedMsg::IbcTransfer {
            channel,
            token,
            receiver,
            memo,
            ..
        } => Some(json!({
            "kind": "ibc-transfer",
            "sourceChannel": channel,
            "receiver": receiver,
            "token": token.as_ref().map(coin_json),
            "memo": memo,
        })),
        DecodedMsg::Send { .. }
        | DecodedMsg::Delegate { .. }
        | DecodedMsg::Undelegate { .. }
        | DecodedMsg::Redelegate { .. }
        | DecodedMsg::ClaimRewards { .. }
        | DecodedMsg::Vote { .. }
        | DecodedMsg::SwapExactAmountIn { .. }
        | DecodedMsg::SplitRouteSwapExactAmountIn { .. }
        | DecodedMsg::SwapExactAmountOut { .. }
        | DecodedMsg::SplitRouteSwapExactAmountOut { .. }
        | DecodedMsg::Unknown { .. } => None,
    }
}

/// The payload v2 both bindings return for a decoded transaction. See the module documentation.
pub fn decoded_tx_payload(decoded: &DecodedTx) -> Value {
    let summaries = decoded.summaries();
    let messages: Vec<Value> = decoded
        .msgs
        .iter()
        .zip(&summaries)
        .enumerate()
        .map(|(index, (msg, summary))| message_json(type_url(decoded, index, msg), msg, summary))
        .collect();

    json!({
        "chainId": decoded.chain_id,
        "memo": decoded.memo,
        "hasUnknownMsgs": decoded.has_unknown_msgs,
        "safeWithoutBlindSigning": decoded.is_safe_to_sign_without_blind_signing(),
        "summaries": summaries,
        "addresses": decoded.msgs.iter().flat_map(|m| m.addresses()).collect::<Vec<_>>(),
        "accountNumber": decoded.account_number.to_string(),
        "sequence": decoded.sequence.to_string(),
        "timeoutHeight": decoded.timeout_height.to_string(),
        "fee": {
            "amount": coins_json(&decoded.fee),
            "gasLimit": decoded.gas_limit.to_string(),
        },
        "messages": messages,
    })
}

/// The type URL the message's `Any` carried, which the decoder records for every message in
/// [`DecodedTx::type_urls`]. An unknown message also carries its own.
fn type_url<'a>(decoded: &'a DecodedTx, index: usize, msg: &'a DecodedMsg) -> &'a str {
    match (decoded.type_urls.get(index), msg) {
        (Some(type_url), _) | (None, DecodedMsg::Unknown { type_url, .. }) => type_url,
        (None, _) => "",
    }
}

fn message_json(type_url: &str, msg: &DecodedMsg, summary: &str) -> Value {
    let mut out = Map::new();
    out.insert("typeUrl".to_owned(), json!(type_url));
    out.insert("summary".to_owned(), json!(summary));
    out.insert("unknown".to_owned(), json!(msg.is_unknown()));
    if let Some(recipient) = recipient(msg) {
        out.insert("recipient".to_owned(), json!(recipient));
    }
    if let Some(detail) = message_detail(msg) {
        out.insert("detail".to_owned(), detail);
    }
    Value::Object(out)
}

fn coin_json(coin: &Coin) -> Value {
    json!({ "denom": coin.denom, "amount": coin.amount })
}

fn coins_json(coins: &[Coin]) -> Vec<Value> {
    coins.iter().map(coin_json).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode_direct_sign_doc;
    use crate::msg::{Height, Msg, VoteOption};
    use crate::proto::ProtoWriter;
    use crate::tx::{Fee, SignMode, SignerData, UnsignedTx};

    const FROM: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
    const TO: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
    const VALOPER: &str = "cosmosvaloper19rl4cm2hmr8afy4kldpxz3fka4jguq0ae5egnx";
    /// A 32-byte contract on the hub: Osmosis crosschain-swaps' bytes under the `cosmos` prefix.
    const CONTRACT: &str = "cosmos1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3s4mk53k";

    fn signer() -> SignerData {
        SignerData {
            chain_id: "cosmoshub-4".to_owned(),
            account_number: 12345,
            sequence: 7,
            public_key: vec![2u8; 33],
            eth_key_type: false,
            eth_pub_key_type_url: None,
        }
    }

    fn unsigned(msgs: Vec<Msg>, memo: &str) -> UnsignedTx {
        UnsignedTx::new(
            msgs,
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            memo,
        )
        .unwrap()
    }

    fn decoded(msgs: Vec<Msg>, memo: &str) -> DecodedTx {
        let bytes = unsigned(msgs, memo)
            .sign_bytes(&signer(), SignMode::Direct)
            .unwrap();
        decode_direct_sign_doc(&bytes).unwrap()
    }

    /// A sign document around raw `Any`s, for the messages the builder cannot write.
    fn decoded_anys(anys: &[(&str, &[u8])]) -> DecodedTx {
        let send = Msg::Send {
            from_address: FROM.to_owned(),
            to_address: TO.to_owned(),
            amount: vec![Coin::new("uatom", "1").unwrap()],
        };
        let auth_info = unsigned(vec![send], "").encode_auth_info(&signer(), SignMode::Direct);
        let anys: Vec<Vec<u8>> = anys
            .iter()
            .map(|(type_url, value)| {
                let mut any = ProtoWriter::new();
                any.string(1, type_url).bytes(2, value);
                any.into_bytes()
            })
            .collect();
        let mut body = ProtoWriter::new();
        body.repeated_message(1, &anys);
        let mut doc = ProtoWriter::new();
        doc.bytes(1, body.as_bytes())
            .bytes(2, &auth_info)
            .string(3, "cosmoshub-4")
            .uint64(4, 12345);
        decode_direct_sign_doc(doc.as_bytes()).unwrap()
    }

    fn transfer(memo: &str) -> Msg {
        Msg::IbcTransfer {
            source_port: "transfer".to_owned(),
            source_channel: "channel-141".to_owned(),
            token: Coin::new("uatom", "1000000").unwrap(),
            sender: FROM.to_owned(),
            receiver: "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8".to_owned(),
            timeout_height: Height::default(),
            timeout_timestamp: 1_791_400_000_000_000_000,
            memo: memo.to_owned(),
        }
    }

    #[test]
    fn a_send_and_a_transfer_name_their_recipient_and_nothing_else_does() {
        let tx = decoded(
            vec![
                Msg::Send {
                    from_address: FROM.to_owned(),
                    to_address: TO.to_owned(),
                    amount: vec![Coin::new("uatom", "1").unwrap()],
                },
                transfer(""),
                Msg::Delegate {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                    amount: Coin::new("uatom", "1").unwrap(),
                },
                Msg::Vote {
                    proposal_id: 848,
                    voter: FROM.to_owned(),
                    option: VoteOption::Yes,
                },
                Msg::ExecuteContract {
                    sender: FROM.to_owned(),
                    contract: CONTRACT.to_owned(),
                    msg: br#"{"recover":{}}"#.to_vec(),
                    funds: vec![],
                },
            ],
            "",
        );
        let recipients: Vec<Option<&str>> = tx.msgs.iter().map(recipient).collect();
        assert_eq!(
            recipients,
            vec![
                Some(TO),
                Some("osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8"),
                None,
                None,
                None
            ]
        );
    }

    #[test]
    fn a_contract_call_carries_its_message_and_funds() {
        // The cw20 case a summary hides: "Execute \"transfer\" on <token>" does not say to whom.
        let tx = decoded(
            vec![Msg::ExecuteContract {
                sender: FROM.to_owned(),
                contract: CONTRACT.to_owned(),
                msg: br#"{"transfer":{"recipient":"cosmos1attacker","amount":"999999999"}}"#
                    .to_vec(),
                funds: vec![Coin::new("uatom", "100").unwrap()],
            }],
            "",
        );
        assert_eq!(
            tx.summaries()[0],
            format!("Execute \"transfer\" on {CONTRACT} sending 100 uatom")
        );
        assert_eq!(
            message_detail(&tx.msgs[0]),
            Some(json!({
                "kind": "execute-contract",
                "contract": CONTRACT,
                "msg": { "transfer": { "recipient": "cosmos1attacker", "amount": "999999999" } },
                "funds": [{ "denom": "uatom", "amount": "100" }],
            }))
        );
    }

    #[test]
    fn a_transfer_carries_its_packet_memo() {
        let memo =
            r#"{"forward":{"receiver":"stride1attacker","port":"transfer","channel":"channel-5"}}"#;
        let tx = decoded(vec![transfer(memo)], "");
        assert_eq!(
            message_detail(&tx.msgs[0]),
            Some(json!({
                "kind": "ibc-transfer",
                "sourceChannel": "channel-141",
                "receiver": "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8",
                "token": { "denom": "uatom", "amount": "1000000" },
                "memo": memo,
            }))
        );
    }

    #[test]
    fn the_payload_keeps_the_0_1_0_keys_and_adds_the_rest() {
        let tx = decoded(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }],
            "for lunch",
        );
        assert_eq!(
            decoded_tx_payload(&tx),
            json!({
                "chainId": "cosmoshub-4",
                "memo": "for lunch",
                "hasUnknownMsgs": false,
                "safeWithoutBlindSigning": true,
                "summaries": [format!("Send 1000000 uatom to {TO}")],
                "addresses": [FROM, TO],
                "accountNumber": "12345",
                "sequence": "7",
                "timeoutHeight": "0",
                "fee": { "amount": [{ "denom": "uatom", "amount": "5000" }], "gasLimit": "200000" },
                "messages": [{
                    "typeUrl": "/cosmos.bank.v1beta1.MsgSend",
                    "summary": format!("Send 1000000 uatom to {TO}"),
                    "unknown": false,
                    "recipient": TO,
                }],
            })
        );
    }

    #[test]
    fn every_u64_is_a_string_even_above_two_to_the_53() {
        // 2^53 + 1 is the first integer a JavaScript number cannot hold.
        let mut tx = decoded(vec![transfer("")], "");
        tx.account_number = 9_007_199_254_740_993;
        tx.sequence = u64::MAX;
        tx.timeout_height = 9_007_199_254_740_993;
        tx.gas_limit = u64::MAX;
        let payload = decoded_tx_payload(&tx);
        assert_eq!(payload["accountNumber"], json!("9007199254740993"));
        assert_eq!(payload["sequence"], json!("18446744073709551615"));
        assert_eq!(payload["timeoutHeight"], json!("9007199254740993"));
        assert_eq!(payload["fee"]["gasLimit"], json!("18446744073709551615"));
    }

    #[test]
    fn an_unknown_message_is_named_and_carries_nothing_else() {
        // A type this build cannot read, and a send demoted to unknown because its recipient is
        // missing: both are named, and nothing read from either body is offered as a recipient
        // or a detail.
        let mut coin = ProtoWriter::new();
        coin.string(1, "uatom").string(2, "1");
        let mut no_recipient = ProtoWriter::new();
        no_recipient
            .string(1, FROM)
            .repeated_message(3, &[coin.into_bytes()]);
        let tx = decoded_anys(&[
            ("/cosmos.authz.v1beta1.MsgGrant", &[1, 2, 3]),
            ("/cosmos.bank.v1beta1.MsgSend", no_recipient.as_bytes()),
        ]);
        let summaries = tx.summaries();
        let payload = decoded_tx_payload(&tx);
        assert_eq!(
            payload["messages"],
            json!([
                {
                    "typeUrl": "/cosmos.authz.v1beta1.MsgGrant",
                    "summary": summaries[0],
                    "unknown": true,
                },
                {
                    "typeUrl": "/cosmos.bank.v1beta1.MsgSend",
                    "summary": summaries[1],
                    "unknown": true,
                },
            ])
        );
        assert!(summaries.iter().all(|s| s.starts_with("UNKNOWN ACTION:")));
        assert_eq!(payload["safeWithoutBlindSigning"], json!(false));
        assert_eq!(payload["addresses"], json!([]));
    }

    #[test]
    fn messages_follow_the_summaries_one_for_one() {
        let tx = decoded(
            vec![
                Msg::WithdrawDelegatorReward {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                },
                transfer("forward"),
            ],
            "",
        );
        let payload = decoded_tx_payload(&tx);
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        for (message, summary) in messages
            .iter()
            .zip(payload["summaries"].as_array().unwrap())
        {
            assert_eq!(&message["summary"], summary);
        }
        assert_eq!(
            messages[0]["typeUrl"],
            json!("/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward")
        );
        assert_eq!(
            messages[1]["typeUrl"],
            json!("/ibc.applications.transfer.v1.MsgTransfer")
        );
    }
}
