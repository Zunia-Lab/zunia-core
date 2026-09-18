//! The JSON bridge between a client's `{ typeUrl, value }` payload and [`Msg`].
//!
//! Every binding (WASM, FFI) receives messages as proto-JSON, because that is what
//! `@zunialab/interchain` emits and what a dApp's `signDirect` request already carries. This
//! module is the single place that turns those strings into the typed [`Msg`] values the
//! encoders in [`crate::msg`] accept. Nothing here encodes anything for the chain: the proven
//! encodings stay where they are, so a bug in this file surfaces as a refusal rather than as
//! wrong bytes.
//!
//! # Why the parsing is strict
//!
//! A wallet that guesses at a payload it does not understand is a blind signer. So an unknown
//! `typeUrl` is refused by name rather than passed through, an amount that is not an integer is
//! refused rather than rounded, and a contract call whose payload is not JSON is refused rather
//! than forwarded. The failure mode being avoided is a user approving a prompt that describes
//! something other than the bytes they signed.
//!
//! Unknown keys inside a `value` object are ignored, which is safe here for a reason worth
//! stating: the sign bytes are produced from the typed [`Msg`] and from nothing else, so a
//! field this module did not parse cannot reach the chain. Silently dropping a field can only
//! ever produce a transaction that does less than the caller asked, never more.
//!
//! # The base64 trap
//!
//! `MsgExecuteContract.msg` is a protobuf `bytes` field, so proto-JSON carries it base64
//! encoded, and [`crate::msg::Msg::ExecuteContract`] holds the decoded JSON bytes. The two
//! encoders then disagree on purpose: protobuf writes those bytes raw, Amino embeds them as
//! parsed JSON. Both start from the decoded form, which is why this bridge decodes on the way
//! in and encodes on the way out. Getting the direction wrong makes every swap and every NFT
//! transfer an invalid contract call that the chain rejects after the user has already signed.
//!
//! # The one deliberate asymmetry
//!
//! [`msg_to_proto_json`] is a lossless inverse of [`msg_from_proto_json`] for every message a
//! caller can build through this bridge, with one exception. An IBC transfer with no timeout at
//! all encodes correctly, and `tests/vectors/cosmos-signing.json` pins those bytes against
//! CosmJS, but it cannot be constructed here: a transfer carrying neither a height nor a
//! timestamp timeout can sit in escrow indefinitely if no relayer ever picks it up, and the
//! funds are not recoverable by the sender. The encoder keeps that capability for decoding and
//! for tests; the client-facing door does not offer it.

use base64::Engine;
use serde_json::{json, Map, Value};

use crate::amount::Coin;
use crate::error::{CosmosError, Result};
use crate::msg::{Height, Msg, VoteOption};
use crate::tx::{Fee, SignMode};

/// The largest number of messages this bridge accepts in one transaction.
///
/// Not an SDK limit. It bounds what an untrusted caller can make the wallet allocate and parse,
/// and it bounds what a signing prompt has to render: a user cannot meaningfully approve a list
/// longer than they will read. The ceiling is set well above the largest batch a wallet builds
/// legitimately, which is one `MsgWithdrawDelegatorReward` per validator a user has delegated
/// to.
pub const MAX_MSGS: usize = 128;

/// Parses one proto-JSON message into a [`Msg`].
///
/// `value` is the `value` half of the `{ typeUrl, value }` envelope: snake_case field names,
/// amounts as decimal strings, exactly as `@zunialab/interchain` emits them.
///
/// An unrecognised `type_url` is returned as [`CosmosError::UnknownMessage`] naming the URL,
/// never approximated. Signing a message this build cannot describe is the blind-signing
/// failure the whole crate exists to prevent, and the on-chain consequence of guessing wrong is
/// not recoverable.
pub fn msg_from_proto_json(type_url: &str, value: &Value) -> Result<Msg> {
    match type_url {
        "/cosmos.bank.v1beta1.MsgSend" => Ok(Msg::Send {
            from_address: string_field(value, "from_address")?,
            to_address: string_field(value, "to_address")?,
            amount: coins_field(value, "amount")?,
        }),
        "/cosmos.staking.v1beta1.MsgDelegate" => Ok(Msg::Delegate {
            delegator_address: string_field(value, "delegator_address")?,
            validator_address: string_field(value, "validator_address")?,
            amount: coin_field(value, "amount")?,
        }),
        "/cosmos.staking.v1beta1.MsgUndelegate" => Ok(Msg::Undelegate {
            delegator_address: string_field(value, "delegator_address")?,
            validator_address: string_field(value, "validator_address")?,
            amount: coin_field(value, "amount")?,
        }),
        "/cosmos.staking.v1beta1.MsgBeginRedelegate" => Ok(Msg::BeginRedelegate {
            delegator_address: string_field(value, "delegator_address")?,
            validator_src_address: string_field(value, "validator_src_address")?,
            validator_dst_address: string_field(value, "validator_dst_address")?,
            amount: coin_field(value, "amount")?,
        }),
        "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward" => {
            Ok(Msg::WithdrawDelegatorReward {
                delegator_address: string_field(value, "delegator_address")?,
                validator_address: string_field(value, "validator_address")?,
            })
        }
        "/cosmos.gov.v1beta1.MsgVote" => Ok(Msg::Vote {
            proposal_id: u64_from_json(field(value, "proposal_id")?)?,
            voter: string_field(value, "voter")?,
            option: vote_option_from_json(field(value, "option")?)?,
        }),
        "/ibc.applications.transfer.v1.MsgTransfer" => {
            let timeout_height = height_field(value, "timeout_height")?;
            let timeout_timestamp = optional_u64_field(value, "timeout_timestamp")?;
            if timeout_height.is_zero() && timeout_timestamp == 0 {
                // An ICS-20 packet with no timeout of either kind never expires. The tokens
                // are escrowed on the source chain the moment the transfer is committed, and
                // if no relayer ever delivers the packet there is nothing to time out and
                // nothing to refund: the funds stay in escrow indefinitely. Callers must
                // choose a height, a timestamp, or both.
                return Err(CosmosError::SignDoc);
            }
            Ok(Msg::IbcTransfer {
                source_port: string_field(value, "source_port")?,
                source_channel: string_field(value, "source_channel")?,
                token: coin_field(value, "token")?,
                sender: string_field(value, "sender")?,
                receiver: string_field(value, "receiver")?,
                timeout_height,
                timeout_timestamp,
                memo: optional_string_field(value, "memo")?,
            })
        }
        "/cosmwasm.wasm.v1.MsgExecuteContract" => Ok(Msg::ExecuteContract {
            sender: string_field(value, "sender")?,
            contract: string_field(value, "contract")?,
            msg: contract_msg_from_json(field(value, "msg")?)?,
            funds: optional_coins_field(value, "funds")?,
        }),
        other => Err(CosmosError::UnknownMessage(other.to_owned())),
    }
}

/// Renders a [`Msg`] back into the `value` half of the proto-JSON envelope.
///
/// The inverse of [`msg_from_proto_json`], base64 encoding the `MsgExecuteContract` payload
/// that the typed message holds decoded. Every field is emitted, including zero-valued ones, so
/// that the result round-trips: this is a bridge format for previews and for tests, not a wire
/// format, and the wire encodings live in [`crate::msg`].
///
/// Pair it with [`Msg::type_url`] to rebuild the full envelope, or use [`msgs_to_json`].
pub fn msg_to_proto_json(msg: &Msg) -> Value {
    match msg {
        Msg::Send {
            from_address,
            to_address,
            amount,
        } => json!({
            "from_address": from_address,
            "to_address": to_address,
            "amount": coins_to_json(amount),
        }),
        Msg::Delegate {
            delegator_address,
            validator_address,
            amount,
        }
        | Msg::Undelegate {
            delegator_address,
            validator_address,
            amount,
        } => json!({
            "delegator_address": delegator_address,
            "validator_address": validator_address,
            "amount": coin_to_json(amount),
        }),
        Msg::BeginRedelegate {
            delegator_address,
            validator_src_address,
            validator_dst_address,
            amount,
        } => json!({
            "delegator_address": delegator_address,
            "validator_src_address": validator_src_address,
            "validator_dst_address": validator_dst_address,
            "amount": coin_to_json(amount),
        }),
        Msg::WithdrawDelegatorReward {
            delegator_address,
            validator_address,
        } => json!({
            "delegator_address": delegator_address,
            "validator_address": validator_address,
        }),
        Msg::Vote {
            proposal_id,
            voter,
            option,
        } => json!({
            // Stringified for the same reason the Amino document stringifies it: every uint64
            // on this wire is a string, and a proposal id that arrived as a JSON number has
            // already passed through a double on the JavaScript side.
            "proposal_id": proposal_id.to_string(),
            "voter": voter,
            // The proto enum name, which is also what the Amino document carries.
            "option": option.amino_name(),
        }),
        Msg::IbcTransfer {
            source_port,
            source_channel,
            token,
            sender,
            receiver,
            timeout_height,
            timeout_timestamp,
            memo,
        } => json!({
            "source_port": source_port,
            "source_channel": source_channel,
            "token": coin_to_json(token),
            "sender": sender,
            "receiver": receiver,
            "timeout_height": {
                "revision_number": timeout_height.revision_number.to_string(),
                "revision_height": timeout_height.revision_height.to_string(),
            },
            "timeout_timestamp": timeout_timestamp.to_string(),
            "memo": memo,
        }),
        Msg::ExecuteContract {
            sender,
            contract,
            msg,
            funds,
        } => json!({
            "sender": sender,
            "contract": contract,
            // Base64 on the way out, decoded on the way in. See the module documentation.
            "msg": base64::engine::general_purpose::STANDARD.encode(msg),
            "funds": coins_to_json(funds),
        }),
    }
}

/// Parses the top-level `[{ typeUrl, value }, ...]` array a binding is handed.
///
/// Refuses an empty array: a transaction with no messages pays a fee to do nothing, so it is
/// never what the caller meant, and letting it through would produce a signing prompt with
/// nothing to show. Refuses more than [`MAX_MSGS`] for the reasons given there.
pub fn msgs_from_json(msgs_json: &str) -> Result<Vec<Msg>> {
    let parsed: Value = serde_json::from_str(msgs_json).map_err(|_| CosmosError::Decode)?;
    let items = parsed.as_array().ok_or(CosmosError::Decode)?;
    if items.is_empty() || items.len() > MAX_MSGS {
        return Err(CosmosError::SignDoc);
    }

    let mut msgs = Vec::with_capacity(items.len());
    for item in items {
        let type_url = string_field(item, "typeUrl")?;
        let value = field(item, "value")?;
        if !value.is_object() {
            return Err(CosmosError::Decode);
        }
        msgs.push(msg_from_proto_json(&type_url, value)?);
    }
    Ok(msgs)
}

/// Renders messages back into the envelope array [`msgs_from_json`] accepts.
///
/// Exists so a preview or a test can show the caller precisely what was parsed, in the same
/// shape it was given. Round-tripping through this and [`msgs_from_json`] is the identity for
/// every message this bridge can build.
pub fn msgs_to_json(msgs: &[Msg]) -> Value {
    Value::Array(
        msgs.iter()
            .map(|msg| json!({ "typeUrl": msg.type_url(), "value": msg_to_proto_json(msg) }))
            .collect(),
    )
}

/// Parses `{ "amount": [Coin], "gas_limit": "200000" }` into a [`Fee`].
///
/// `gas_limit` may arrive as a string or a number, because JavaScript callers differ on which
/// they emit, but it must be present and non-zero. A zero gas limit is rejected here rather
/// than at broadcast: the chain's error for it arrives after the user has signed, and says
/// "out of gas" rather than naming the real problem.
///
/// `amount` may be absent or empty. A zero-fee transaction is legal wherever the chain's
/// minimum gas price is zero, which is the normal case on a devnet.
pub fn fee_from_json(fee_json: &str) -> Result<Fee> {
    let parsed: Value = serde_json::from_str(fee_json).map_err(|_| CosmosError::Decode)?;
    let amount = optional_coins_field(&parsed, "amount")?;
    let gas_limit = match optional_field(&parsed, "gas_limit")? {
        Some(found) => u64_from_json(found).map_err(|_| CosmosError::Fee)?,
        None => return Err(CosmosError::Fee),
    };
    Fee::new(amount, gas_limit)
}

/// Parses `"direct"` or `"amino"` into a [`SignMode`], case-insensitively.
///
/// Anything else is an error rather than a default. A Ledger signer requires Amino and a modern
/// dApp expects Direct; picking silently is how a wallet ends up signing the wrong document,
/// and the two documents produce signatures that verify against nothing when swapped.
pub fn sign_mode_from_str(s: &str) -> Result<SignMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(SignMode::Direct),
        "amino" => Ok(SignMode::LegacyAminoJson),
        _ => Err(CosmosError::SignDoc),
    }
}

/* -------------------------------------------------------------------------- *
 * Field readers
 * -------------------------------------------------------------------------- */

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or(CosmosError::Decode)
}

/// A required field. `null` counts as absent, because that is what a JavaScript caller writes
/// for a value it does not have.
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    optional_field(value, key)?.ok_or(CosmosError::Decode)
}

fn optional_field<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>> {
    Ok(object(value)?.get(key).filter(|found| !found.is_null()))
}

fn string_field(value: &Value, key: &str) -> Result<String> {
    field(value, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or(CosmosError::Decode)
}

/// An optional string field, defaulting to empty. Used for `memo`, which proto3 defaults to
/// `""` and which `JSON.stringify` drops entirely when the caller leaves it undefined.
fn optional_string_field(value: &Value, key: &str) -> Result<String> {
    match optional_field(value, key)? {
        None => Ok(String::new()),
        Some(found) => found.as_str().map(str::to_owned).ok_or(CosmosError::Decode),
    }
}

/// Reads a `uint64` that may arrive as a decimal string or as a JSON number.
///
/// A number that is not a non-negative integer within `u64` is refused rather than truncated. A
/// JavaScript number above 2^53 has already lost precision by the time it reaches this
/// function, and a rounded IBC timeout or proposal id is a different value than the caller
/// meant.
fn u64_from_json(value: &Value) -> Result<u64> {
    match value {
        Value::String(text) => text.trim().parse::<u64>().map_err(|_| CosmosError::Decode),
        Value::Number(number) => number.as_u64().ok_or(CosmosError::Decode),
        _ => Err(CosmosError::Decode),
    }
}

/// An optional `uint64`, defaulting to zero. An empty string is treated as absent, because
/// that is what a form-driven caller sends for "no timeout".
fn optional_u64_field(value: &Value, key: &str) -> Result<u64> {
    match optional_field(value, key)? {
        None => Ok(0),
        Some(Value::String(text)) if text.trim().is_empty() => Ok(0),
        Some(found) => u64_from_json(found),
    }
}

/// Reads a Cosmos amount, which is canonically a decimal string.
///
/// A JSON number is tolerated because callers are sloppy, but only when it is a non-negative
/// integer that survived JSON parsing intact. Anything that arrived as a float has already lost
/// precision: an 18-decimal token balance passes 2^53 at roughly 0.009 tokens, which is small
/// enough to look right in the UI and wrong enough to be a different transfer. The string is
/// then validated by [`Coin::new`], which rejects signs, exponents, decimal points and leading
/// zeros, so what this bridge stores is always canonical.
fn amount_from_json(value: &Value) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => number
            .as_u64()
            .map(|integral| integral.to_string())
            .ok_or(CosmosError::Amount),
        _ => Err(CosmosError::Amount),
    }
}

fn coin_from_json(value: &Value) -> Result<Coin> {
    let denom = string_field(value, "denom")?;
    let amount = match optional_field(value, "amount")? {
        Some(found) => amount_from_json(found)?,
        None => return Err(CosmosError::Amount),
    };
    Coin::new(denom, amount)
}

fn coin_field(value: &Value, key: &str) -> Result<Coin> {
    coin_from_json(field(value, key)?)
}

fn coins_from_json(value: &Value) -> Result<Vec<Coin>> {
    value
        .as_array()
        .ok_or(CosmosError::Decode)?
        .iter()
        .map(coin_from_json)
        .collect()
}

fn coins_field(value: &Value, key: &str) -> Result<Vec<Coin>> {
    coins_from_json(field(value, key)?)
}

/// Repeated fields default to `[]` in proto3, so an absent `funds` is not an error.
fn optional_coins_field(value: &Value, key: &str) -> Result<Vec<Coin>> {
    match optional_field(value, key)? {
        None => Ok(Vec::new()),
        Some(found) => coins_from_json(found),
    }
}

fn height_field(value: &Value, key: &str) -> Result<Height> {
    match optional_field(value, key)? {
        None => Ok(Height::default()),
        Some(found) => Ok(Height {
            revision_number: optional_u64_field(found, "revision_number")?,
            revision_height: optional_u64_field(found, "revision_height")?,
        }),
    }
}

/// Reads a vote option, permissively on input and canonically on output.
///
/// The proto enum name, the short label and the integer are all accepted, because dApps send
/// all three. `VOTE_OPTION_UNSPECIFIED` and zero are not accepted: the chain reads an
/// unspecified option as an invalid vote, and a wallet that silently forwarded it would show
/// the user a vote that never counted.
fn vote_option_from_json(value: &Value) -> Result<VoteOption> {
    match value {
        Value::Number(number) => match number.as_u64() {
            Some(1) => Ok(VoteOption::Yes),
            Some(2) => Ok(VoteOption::Abstain),
            Some(3) => Ok(VoteOption::No),
            Some(4) => Ok(VoteOption::NoWithVeto),
            _ => Err(CosmosError::Decode),
        },
        Value::String(text) => {
            let upper = text.trim().to_ascii_uppercase();
            match upper.strip_prefix("VOTE_OPTION_").unwrap_or(&upper) {
                "YES" | "1" => Ok(VoteOption::Yes),
                "ABSTAIN" | "2" => Ok(VoteOption::Abstain),
                "NO" | "3" => Ok(VoteOption::No),
                "NO_WITH_VETO" | "NOWITHVETO" | "4" => Ok(VoteOption::NoWithVeto),
                _ => Err(CosmosError::Decode),
            }
        }
        _ => Err(CosmosError::Decode),
    }
}

/// Decodes a `MsgExecuteContract.msg` from base64 and proves it is a JSON object.
///
/// The check is not cosmetic. A CosmWasm `ExecuteMsg` is always a JSON object keyed by the
/// action name, the Amino encoder re-parses these bytes and embeds them inline, and
/// [`Msg::summary`] reads the top-level key to tell the user which action they are approving. A
/// payload that is not a JSON object breaks all three: the Amino document would carry `{}` in
/// place of the call, and the prompt would say "unknown action" while the Direct path signed
/// something else entirely.
fn contract_msg_from_json(value: &Value) -> Result<Vec<u8>> {
    let encoded = value.as_str().ok_or(CosmosError::Decode)?;
    let bytes = decode_base64(encoded)?;
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|_| CosmosError::Decode)?;
    if !parsed.is_object() {
        return Err(CosmosError::Decode);
    }
    Ok(bytes)
}

/// Standard-alphabet base64, tolerating a missing pad.
///
/// `@zunialab/interchain` emits padded standard base64, but hand-written callers and some
/// JavaScript helpers strip the `=`, and refusing those would break a valid contract call for a
/// reason the caller cannot see. The alphabet itself is not negotiable: base64url would decode
/// to different bytes.
fn decode_base64(text: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    STANDARD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .map_err(|_| CosmosError::Decode)
}

fn coin_to_json(coin: &Coin) -> Value {
    json!({ "denom": coin.denom, "amount": coin.amount })
}

fn coins_to_json(coins: &[Coin]) -> Value {
    Value::Array(coins.iter().map(coin_to_json).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
    const TO: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
    const VALOPER: &str = "cosmosvaloper19rl4cm2hmr8afy4kldpxz3fka4jguq0ae5egnx";

    fn parse(type_url: &str, value: Value) -> Result<Msg> {
        msg_from_proto_json(type_url, &value)
    }

    fn send_json() -> Value {
        json!({
            "from_address": FROM,
            "to_address": TO,
            "amount": [{ "denom": "uatom", "amount": "1000000" }],
        })
    }

    fn execute_json(inner: &str, funds: Value) -> Value {
        json!({
            "sender": FROM,
            "contract": TO,
            "msg": base64::engine::general_purpose::STANDARD.encode(inner),
            "funds": funds,
        })
    }

    #[test]
    fn parses_a_bank_send() {
        assert_eq!(
            parse("/cosmos.bank.v1beta1.MsgSend", send_json()).unwrap(),
            Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }
        );
    }

    #[test]
    fn round_trips_every_variant() {
        // Covered again against the CosmJS goldens in tests/json_bridge.rs; this keeps the
        // property local to the module so a regression is diagnosed here first.
        let msgs = vec![
            Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            },
            Msg::Delegate {
                delegator_address: FROM.to_owned(),
                validator_address: VALOPER.to_owned(),
                amount: Coin::new("uatom", "5000000").unwrap(),
            },
            Msg::Undelegate {
                delegator_address: FROM.to_owned(),
                validator_address: VALOPER.to_owned(),
                amount: Coin::new("uatom", "1").unwrap(),
            },
            Msg::BeginRedelegate {
                delegator_address: FROM.to_owned(),
                validator_src_address: VALOPER.to_owned(),
                validator_dst_address: VALOPER.to_owned(),
                amount: Coin::new("uatom", "1").unwrap(),
            },
            Msg::WithdrawDelegatorReward {
                delegator_address: FROM.to_owned(),
                validator_address: VALOPER.to_owned(),
            },
            Msg::Vote {
                proposal_id: 848,
                voter: FROM.to_owned(),
                option: VoteOption::NoWithVeto,
            },
            Msg::IbcTransfer {
                source_port: "transfer".to_owned(),
                source_channel: "channel-141".to_owned(),
                token: Coin::new("uatom", "1000000").unwrap(),
                sender: FROM.to_owned(),
                receiver: "addr_safro19rl4cm2hmr8afy4kldpxz3fka4jguq0ayvv259".to_owned(),
                timeout_height: Height {
                    revision_number: 1,
                    revision_height: 20_000_000,
                },
                timeout_timestamp: 1_700_000_000_000_000_000,
                memo: "forward".to_owned(),
            },
            Msg::ExecuteContract {
                sender: FROM.to_owned(),
                contract: TO.to_owned(),
                msg: br#"{"swap":{"offer":"100"}}"#.to_vec(),
                funds: vec![Coin::new("uatom", "100").unwrap()],
            },
        ];

        for msg in &msgs {
            let json = msg_to_proto_json(msg);
            assert_eq!(
                &msg_from_proto_json(msg.type_url(), &json).unwrap(),
                msg,
                "round trip lost information for {}",
                msg.type_url()
            );
        }

        // And through the envelope form the bindings actually receive.
        let rendered = msgs_to_json(&msgs).to_string();
        assert_eq!(msgs_from_json(&rendered).unwrap(), msgs);
    }

    #[test]
    fn an_unknown_type_url_is_refused_by_name() {
        assert_eq!(
            parse("/cosmos.bank.v1beta1.MsgMultiSend", json!({})).unwrap_err(),
            CosmosError::UnknownMessage("/cosmos.bank.v1beta1.MsgMultiSend".to_owned())
        );
        // Which is what the caller sees, so the message names the URL rather than saying
        // "invalid".
        assert!(parse("/nope.Msg", json!({}))
            .unwrap_err()
            .to_string()
            .contains("/nope.Msg"));
    }

    #[test]
    fn amounts_may_be_integral_numbers_but_never_floats_or_negatives() {
        let numeric = json!({
            "from_address": FROM,
            "to_address": TO,
            "amount": [{ "denom": "uatom", "amount": 1000000 }],
        });
        let Msg::Send { amount, .. } = parse("/cosmos.bank.v1beta1.MsgSend", numeric).unwrap()
        else {
            panic!("expected a send")
        };
        assert_eq!(
            amount[0].amount, "1000000",
            "stored canonically as a string"
        );

        for bad in [
            json!(-1),
            json!(1.5),
            json!(1e30),
            json!("-1"),
            json!("1.5"),
        ] {
            let value = json!({
                "from_address": FROM,
                "to_address": TO,
                "amount": [{ "denom": "uatom", "amount": bad }],
            });
            assert_eq!(
                parse("/cosmos.bank.v1beta1.MsgSend", value).unwrap_err(),
                CosmosError::Amount,
                "{bad} should not be an amount"
            );
        }
    }

    #[test]
    fn a_leading_zero_amount_is_refused() {
        // "007" and "7" are the same number and different bytes, and Amino signs the bytes.
        let value = json!({
            "from_address": FROM,
            "to_address": TO,
            "amount": [{ "denom": "uatom", "amount": "007" }],
        });
        assert_eq!(
            parse("/cosmos.bank.v1beta1.MsgSend", value).unwrap_err(),
            CosmosError::Amount
        );
    }

    #[test]
    fn contract_payloads_must_be_base64_encoded_json_objects() {
        let good = parse(
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            execute_json(r#"{"swap":{"offer":"100"}}"#, json!([])),
        )
        .unwrap();
        let Msg::ExecuteContract { msg, funds, .. } = good else {
            panic!("expected a contract call")
        };
        assert_eq!(msg, br#"{"swap":{"offer":"100"}}"#);
        assert!(funds.is_empty(), "absent funds default to empty");

        // Not base64 at all.
        assert_eq!(
            parse(
                "/cosmwasm.wasm.v1.MsgExecuteContract",
                json!({ "sender": FROM, "contract": TO, "msg": "not base64!!", "funds": [] }),
            )
            .unwrap_err(),
            CosmosError::Decode
        );
        // Valid base64 that is not JSON.
        assert_eq!(
            parse(
                "/cosmwasm.wasm.v1.MsgExecuteContract",
                execute_json("not json", json!([])),
            )
            .unwrap_err(),
            CosmosError::Decode
        );
        // Valid JSON that is not an object, so there is no action name to show the user.
        assert_eq!(
            parse(
                "/cosmwasm.wasm.v1.MsgExecuteContract",
                execute_json("[1,2,3]", json!([])),
            )
            .unwrap_err(),
            CosmosError::Decode
        );
        // The raw object, unencoded, is refused rather than guessed at: accepting both forms
        // would make the field's encoding ambiguous, and the two encoders disagree on it.
        assert_eq!(
            parse(
                "/cosmwasm.wasm.v1.MsgExecuteContract",
                json!({ "sender": FROM, "contract": TO, "msg": { "swap": {} }, "funds": [] }),
            )
            .unwrap_err(),
            CosmosError::Decode
        );
    }

    #[test]
    fn unpadded_base64_is_tolerated() {
        let inner = r#"{"a":1}"#;
        let padded = base64::engine::general_purpose::STANDARD.encode(inner);
        let stripped = padded.trim_end_matches('=').to_owned();
        assert_ne!(
            padded, stripped,
            "this fixture needs padding to be meaningful"
        );
        let msg = parse(
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            json!({ "sender": FROM, "contract": TO, "msg": stripped, "funds": [] }),
        )
        .unwrap();
        let Msg::ExecuteContract { msg, .. } = msg else {
            panic!("expected a contract call")
        };
        assert_eq!(msg, inner.as_bytes());
    }

    #[test]
    fn a_transfer_without_any_timeout_is_refused() {
        // The failure mode: tokens are escrowed on the source chain when the packet is
        // committed, and a packet that can never expire can never be refunded.
        let value = json!({
            "source_port": "transfer",
            "source_channel": "channel-141",
            "token": { "denom": "uatom", "amount": "1000000" },
            "sender": FROM,
            "receiver": "addr_safro19rl4cm2hmr8afy4kldpxz3fka4jguq0ayvv259",
            "memo": "",
        });
        assert_eq!(
            parse("/ibc.applications.transfer.v1.MsgTransfer", value).unwrap_err(),
            CosmosError::SignDoc
        );

        // An explicit all-zero height with a zero timestamp is the same thing spelled out.
        let zeroed = json!({
            "source_port": "transfer",
            "source_channel": "channel-141",
            "token": { "denom": "uatom", "amount": "1000000" },
            "sender": FROM,
            "receiver": "addr_safro19rl4cm2hmr8afy4kldpxz3fka4jguq0ayvv259",
            "timeout_height": { "revision_number": "0", "revision_height": "0" },
            "timeout_timestamp": "0",
            "memo": "",
        });
        assert_eq!(
            parse("/ibc.applications.transfer.v1.MsgTransfer", zeroed).unwrap_err(),
            CosmosError::SignDoc
        );
    }

    #[test]
    fn either_timeout_alone_is_enough() {
        let base = json!({
            "source_port": "transfer",
            "source_channel": "channel-141",
            "token": { "denom": "uatom", "amount": "1000000" },
            "sender": FROM,
            "receiver": "addr_safro19rl4cm2hmr8afy4kldpxz3fka4jguq0ayvv259",
        });

        let mut height_only = base.clone();
        height_only["timeout_height"] =
            json!({ "revision_number": 1, "revision_height": 20000000 });
        let Msg::IbcTransfer {
            timeout_height,
            timeout_timestamp,
            memo,
            ..
        } = parse("/ibc.applications.transfer.v1.MsgTransfer", height_only).unwrap()
        else {
            panic!("expected a transfer")
        };
        assert_eq!(
            timeout_height,
            Height {
                revision_number: 1,
                revision_height: 20_000_000
            },
            "numbers are accepted as well as strings"
        );
        assert_eq!(timeout_timestamp, 0);
        assert_eq!(memo, "", "an absent memo defaults to empty");

        let mut timestamp_only = base;
        timestamp_only["timeout_timestamp"] = json!("1700000000000000000");
        let Msg::IbcTransfer {
            timeout_timestamp, ..
        } = parse("/ibc.applications.transfer.v1.MsgTransfer", timestamp_only).unwrap()
        else {
            panic!("expected a transfer")
        };
        assert_eq!(timeout_timestamp, 1_700_000_000_000_000_000);
    }

    #[test]
    fn vote_options_are_permissive_on_input_and_canonical_on_output() {
        for (input, expected) in [
            (json!("VOTE_OPTION_YES"), VoteOption::Yes),
            (json!("yes"), VoteOption::Yes),
            (json!("Yes"), VoteOption::Yes),
            (json!(1), VoteOption::Yes),
            (json!("1"), VoteOption::Yes),
            (json!("VOTE_OPTION_ABSTAIN"), VoteOption::Abstain),
            (json!("abstain"), VoteOption::Abstain),
            (json!(2), VoteOption::Abstain),
            (json!("VOTE_OPTION_NO"), VoteOption::No),
            (json!("no"), VoteOption::No),
            (json!(3), VoteOption::No),
            (json!("VOTE_OPTION_NO_WITH_VETO"), VoteOption::NoWithVeto),
            (json!("no_with_veto"), VoteOption::NoWithVeto),
            (json!(4), VoteOption::NoWithVeto),
        ] {
            let value = json!({ "proposal_id": "848", "voter": FROM, "option": input });
            let Msg::Vote { option, .. } = parse("/cosmos.gov.v1beta1.MsgVote", value).unwrap()
            else {
                panic!("expected a vote")
            };
            assert_eq!(option, expected, "{input} should parse");
        }

        // Canonical on the way out, whatever came in.
        let value = json!({ "proposal_id": 848, "voter": FROM, "option": "yes" });
        let msg = parse("/cosmos.gov.v1beta1.MsgVote", value).unwrap();
        assert_eq!(
            msg_to_proto_json(&msg),
            json!({ "proposal_id": "848", "voter": FROM, "option": "VOTE_OPTION_YES" })
        );
    }

    #[test]
    fn unknown_vote_options_are_refused() {
        // Including UNSPECIFIED, which the chain counts as no vote at all.
        for bad in [
            json!("VOTE_OPTION_UNSPECIFIED"),
            json!("maybe"),
            json!(0),
            json!(5),
            json!(null),
            json!(true),
        ] {
            let value = json!({ "proposal_id": "1", "voter": FROM, "option": bad });
            assert!(
                parse("/cosmos.gov.v1beta1.MsgVote", value).is_err(),
                "{bad} should not be a vote option"
            );
        }
    }

    #[test]
    fn missing_required_fields_are_refused() {
        for value in [
            json!({ "to_address": TO, "amount": [] }),
            json!({ "from_address": FROM, "amount": [] }),
            json!({ "from_address": FROM, "to_address": TO }),
            json!({ "from_address": FROM, "to_address": TO, "amount": null }),
            json!({ "from_address": 7, "to_address": TO, "amount": [] }),
        ] {
            assert_eq!(
                parse("/cosmos.bank.v1beta1.MsgSend", value.clone()).unwrap_err(),
                CosmosError::Decode,
                "{value} should be refused"
            );
        }
    }

    #[test]
    fn the_message_array_must_be_a_non_empty_envelope_list() {
        assert_eq!(msgs_from_json("[]").unwrap_err(), CosmosError::SignDoc);
        assert_eq!(msgs_from_json("{}").unwrap_err(), CosmosError::Decode);
        assert_eq!(msgs_from_json("not json").unwrap_err(), CosmosError::Decode);
        // The envelope keys are required; a bare value object is not a message.
        assert_eq!(
            msgs_from_json(&Value::Array(vec![send_json()]).to_string()).unwrap_err(),
            CosmosError::Decode
        );
        assert_eq!(
            msgs_from_json(r#"[{"typeUrl":"/cosmos.bank.v1beta1.MsgSend","value":"x"}]"#)
                .unwrap_err(),
            CosmosError::Decode
        );
    }

    #[test]
    fn the_message_count_is_bounded() {
        let one = json!({ "typeUrl": "/cosmos.bank.v1beta1.MsgSend", "value": send_json() });

        let at_limit = Value::Array(vec![one.clone(); MAX_MSGS]).to_string();
        assert_eq!(msgs_from_json(&at_limit).unwrap().len(), MAX_MSGS);

        let over = Value::Array(vec![one; MAX_MSGS.saturating_add(1)]).to_string();
        assert_eq!(msgs_from_json(&over).unwrap_err(), CosmosError::SignDoc);
    }

    #[test]
    fn fees_accept_a_string_or_a_number_gas_limit() {
        let expected = Fee::new(vec![Coin::new("usaf", "1200").unwrap()], 200_000).unwrap();
        assert_eq!(
            fee_from_json(r#"{"amount":[{"denom":"usaf","amount":"1200"}],"gas_limit":"200000"}"#)
                .unwrap(),
            expected
        );
        assert_eq!(
            fee_from_json(r#"{"amount":[{"denom":"usaf","amount":"1200"}],"gas_limit":200000}"#)
                .unwrap(),
            expected
        );
        // A zero-fee transaction is legal wherever the minimum gas price is zero.
        assert_eq!(
            fee_from_json(r#"{"gas_limit":"200000"}"#).unwrap().amount,
            Vec::new()
        );
    }

    #[test]
    fn nonsense_fees_are_refused() {
        for bad in [
            r#"{"amount":[],"gas_limit":"0"}"#,
            r#"{"amount":[],"gas_limit":0}"#,
            r#"{"amount":[],"gas_limit":"-1"}"#,
            r#"{"amount":[],"gas_limit":"abc"}"#,
            r#"{"amount":[]}"#,
            r#"{"amount":[],"gas_limit":null}"#,
        ] {
            assert_eq!(
                fee_from_json(bad).unwrap_err(),
                CosmosError::Fee,
                "{bad} should be refused"
            );
        }
        assert_eq!(fee_from_json("[]").unwrap_err(), CosmosError::Decode);
        assert_eq!(fee_from_json("").unwrap_err(), CosmosError::Decode);
        assert_eq!(
            fee_from_json(r#"{"amount":[{"denom":"usaf","amount":"-1"}],"gas_limit":"1"}"#)
                .unwrap_err(),
            CosmosError::Amount
        );
    }

    #[test]
    fn sign_modes_are_named_never_defaulted() {
        assert_eq!(sign_mode_from_str("direct").unwrap(), SignMode::Direct);
        assert_eq!(sign_mode_from_str("DIRECT").unwrap(), SignMode::Direct);
        assert_eq!(sign_mode_from_str(" Direct ").unwrap(), SignMode::Direct);
        assert_eq!(
            sign_mode_from_str("amino").unwrap(),
            SignMode::LegacyAminoJson
        );
        assert_eq!(
            sign_mode_from_str("Amino").unwrap(),
            SignMode::LegacyAminoJson
        );

        for bad in [
            "",
            "  ",
            "SIGN_MODE_DIRECT",
            "legacy_amino_json",
            "textual",
            "auto",
        ] {
            assert_eq!(
                sign_mode_from_str(bad).unwrap_err(),
                CosmosError::SignDoc,
                "{bad:?} should not select a sign mode"
            );
        }
    }
}
