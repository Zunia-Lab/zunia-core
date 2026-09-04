//! Decoding transactions the wallet did not build.
//!
//! When a dApp hands over `SIGN_MODE_DIRECT` bytes, the wallet has no structured view of what
//! it is about to sign. Showing "Approve transaction" at that point is blind signing, which
//! `PRE-DEVELOPMENT.md` §4 forbids by default.
//!
//! The rule this module enforces: anything that cannot be decoded into a specific, named action
//! is marked [`DecodedMsg::Unknown`], and the signing UI must refuse it unless the user has
//! explicitly enabled blind signing. Failing loudly is the point. A decoder that guesses is
//! worse than one that admits ignorance, because a wrong summary is a lie the user acts on.

use serde_json::Value;

use crate::amount::Coin;
use crate::error::{CosmosError, Result};
use crate::msg::VoteOption;
use crate::proto::{decode_fields, find_all, find_field};

/// One message from a transaction, decoded as far as this build can manage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedMsg {
    Send {
        from: String,
        to: String,
        amount: Vec<Coin>,
    },
    Delegate {
        delegator: String,
        validator: String,
        amount: Option<Coin>,
    },
    Undelegate {
        delegator: String,
        validator: String,
        amount: Option<Coin>,
    },
    Redelegate {
        delegator: String,
        from_validator: String,
        to_validator: String,
        amount: Option<Coin>,
    },
    ClaimRewards {
        delegator: String,
        validator: String,
    },
    Vote {
        proposal_id: u64,
        voter: String,
        option: Option<VoteOption>,
    },
    IbcTransfer {
        channel: String,
        token: Option<Coin>,
        sender: String,
        receiver: String,
        memo: String,
    },
    ExecuteContract {
        sender: String,
        contract: String,
        /// The contract message, parsed if it is valid JSON.
        msg: Option<Value>,
        /// The top-level key, which is the action by CosmWasm convention.
        action: Option<String>,
        funds: Vec<Coin>,
    },
    /// A message this build cannot decode.
    ///
    /// Carries the type URL so the UI can name it, and the raw length so a user can see that
    /// something substantial is hiding in there. Must never be summarised as anything reassuring.
    Unknown {
        type_url: String,
        byte_length: usize,
    },
}

impl DecodedMsg {
    /// True when the wallet could not determine what this message does.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// A summary for the signing prompt.
    pub fn summary(&self) -> String {
        match self {
            Self::Send { to, amount, .. } => {
                let coins: Vec<String> = amount
                    .iter()
                    .map(|c| format!("{} {}", c.amount, c.denom))
                    .collect();
                format!("Send {} to {}", coins.join(", "), to)
            }
            Self::Delegate {
                validator, amount, ..
            } => format!("Delegate {} to {validator}", describe_coin(amount)),
            Self::Undelegate {
                validator, amount, ..
            } => format!("Undelegate {} from {validator}", describe_coin(amount)),
            Self::Redelegate {
                from_validator,
                to_validator,
                amount,
                ..
            } => format!(
                "Redelegate {} from {from_validator} to {to_validator}",
                describe_coin(amount)
            ),
            Self::ClaimRewards { validator, .. } => {
                format!("Claim staking rewards from {validator}")
            }
            Self::Vote {
                proposal_id,
                option,
                ..
            } => match option {
                Some(option) => format!("Vote {} on proposal {proposal_id}", option.label()),
                None => format!("Vote on proposal {proposal_id} with an unrecognised option"),
            },
            Self::IbcTransfer {
                channel,
                token,
                receiver,
                ..
            } => format!(
                "IBC transfer {} to {receiver} over {channel}",
                describe_coin(token)
            ),
            Self::ExecuteContract {
                contract,
                action,
                funds,
                ..
            } => {
                let action = action.as_deref().unwrap_or("an unreadable action");
                let funds_text = if funds.is_empty() {
                    String::new()
                } else {
                    let coins: Vec<String> = funds
                        .iter()
                        .map(|c| format!("{} {}", c.amount, c.denom))
                        .collect();
                    format!(" sending {}", coins.join(", "))
                };
                format!("Execute \"{action}\" on {contract}{funds_text}")
            }
            // Deliberately alarming. The user is being asked to authorise something the wallet
            // cannot read, and the prompt must say so rather than soften it.
            Self::Unknown {
                type_url,
                byte_length,
            } => format!("UNKNOWN ACTION: {type_url} ({byte_length} bytes the wallet cannot read)"),
        }
    }

    /// Addresses referenced, for the first-time-recipient warning.
    pub fn addresses(&self) -> Vec<&str> {
        match self {
            Self::Send { from, to, .. } => vec![from, to],
            Self::Delegate {
                delegator,
                validator,
                ..
            }
            | Self::Undelegate {
                delegator,
                validator,
                ..
            }
            | Self::ClaimRewards {
                delegator,
                validator,
            } => vec![delegator, validator],
            Self::Redelegate {
                delegator,
                from_validator,
                to_validator,
                ..
            } => vec![delegator, from_validator, to_validator],
            Self::Vote { voter, .. } => vec![voter],
            Self::IbcTransfer {
                sender, receiver, ..
            } => vec![sender, receiver],
            Self::ExecuteContract {
                sender, contract, ..
            } => vec![sender, contract],
            Self::Unknown { .. } => Vec::new(),
        }
    }
}

fn describe_coin(coin: &Option<Coin>) -> String {
    match coin {
        Some(coin) => format!("{} {}", coin.amount, coin.denom),
        None => "an unreadable amount".to_owned(),
    }
}

/// A fully decoded transaction, ready to render in a signing prompt.
#[derive(Debug, Clone)]
pub struct DecodedTx {
    pub chain_id: String,
    pub account_number: u64,
    pub sequence: u64,
    pub msgs: Vec<DecodedMsg>,
    pub fee: Vec<Coin>,
    pub gas_limit: u64,
    pub memo: String,
    pub timeout_height: u64,
    /// True if any message could not be decoded. The signing UI must gate on this.
    pub has_unknown_msgs: bool,
}

impl DecodedTx {
    /// Every summary, in order.
    pub fn summaries(&self) -> Vec<String> {
        self.msgs.iter().map(|m| m.summary()).collect()
    }

    /// Whether this transaction may be signed without the blind-signing toggle.
    pub fn is_safe_to_sign_without_blind_signing(&self) -> bool {
        !self.has_unknown_msgs
    }
}

/// Decodes `SIGN_MODE_DIRECT` sign bytes, meaning a serialised `cosmos.tx.v1beta1.SignDoc`.
pub fn decode_direct_sign_doc(sign_bytes: &[u8]) -> Result<DecodedTx> {
    let fields = decode_fields(sign_bytes)?;

    let body_bytes = find_field(&fields, 1)
        .ok_or(CosmosError::SignDoc)?
        .as_bytes()?;
    let auth_info_bytes = find_field(&fields, 2)
        .ok_or(CosmosError::SignDoc)?
        .as_bytes()?;
    let chain_id = find_field(&fields, 3)
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_default();
    let account_number = find_field(&fields, 4)
        .map(|v| v.as_varint())
        .transpose()?
        .unwrap_or(0);

    if chain_id.trim().is_empty() {
        // An empty chain id in a Direct document is either malformed or an attempt to build
        // something replayable. Either way it is not signable.
        return Err(CosmosError::ChainId);
    }

    let body = decode_fields(body_bytes)?;
    let memo = find_field(&body, 2)
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_default();
    let timeout_height = find_field(&body, 3)
        .map(|v| v.as_varint())
        .transpose()?
        .unwrap_or(0);

    let mut msgs = Vec::new();
    for any in find_all(&body, 1) {
        msgs.push(decode_any(any.as_bytes()?)?);
    }
    if msgs.is_empty() {
        return Err(CosmosError::SignDoc);
    }

    let auth_info = decode_fields(auth_info_bytes)?;
    let sequence = match find_field(&auth_info, 1) {
        Some(signer_info) => {
            let signer_info = decode_fields(signer_info.as_bytes()?)?;
            find_field(&signer_info, 3)
                .map(|v| v.as_varint())
                .transpose()?
                .unwrap_or(0)
        }
        None => 0,
    };

    let (fee, gas_limit) = match find_field(&auth_info, 2) {
        Some(fee_bytes) => {
            let fee_fields = decode_fields(fee_bytes.as_bytes()?)?;
            let mut coins = Vec::new();
            for coin in find_all(&fee_fields, 1) {
                coins.push(decode_coin(coin.as_bytes()?)?);
            }
            let gas = find_field(&fee_fields, 2)
                .map(|v| v.as_varint())
                .transpose()?
                .unwrap_or(0);
            (coins, gas)
        }
        None => (Vec::new(), 0),
    };

    let has_unknown_msgs = msgs.iter().any(|m| m.is_unknown());

    Ok(DecodedTx {
        chain_id,
        account_number,
        sequence,
        msgs,
        fee,
        gas_limit,
        memo,
        timeout_height,
        has_unknown_msgs,
    })
}

/// Decodes a `google.protobuf.Any` holding a message.
fn decode_any(any_bytes: &[u8]) -> Result<DecodedMsg> {
    let fields = decode_fields(any_bytes)?;
    let type_url = find_field(&fields, 1)
        .ok_or(CosmosError::Decode)?
        .as_string()?;
    let value = find_field(&fields, 2)
        .map(|v| v.as_bytes().map(|b| b.to_vec()))
        .transpose()?
        .unwrap_or_default();

    // A message whose body fails to decode becomes Unknown rather than an error. Refusing the
    // whole transaction would hide the other messages from the user, and one malformed message
    // is itself worth showing.
    let decoded = decode_known(&type_url, &value).unwrap_or(None);

    Ok(decoded.unwrap_or(DecodedMsg::Unknown {
        type_url,
        byte_length: value.len(),
    }))
}

fn decode_known(type_url: &str, value: &[u8]) -> Result<Option<DecodedMsg>> {
    let fields = decode_fields(value)?;

    let string_at = |tag: u32| -> Result<String> {
        Ok(find_field(&fields, tag)
            .map(|v| v.as_string())
            .transpose()?
            .unwrap_or_default())
    };
    let coin_at = |tag: u32| -> Result<Option<Coin>> {
        match find_field(&fields, tag) {
            Some(v) => Ok(Some(decode_coin(v.as_bytes()?)?)),
            None => Ok(None),
        }
    };
    let coins_at = |tag: u32| -> Result<Vec<Coin>> {
        let mut out = Vec::new();
        for v in find_all(&fields, tag) {
            out.push(decode_coin(v.as_bytes()?)?);
        }
        Ok(out)
    };

    let decoded = match type_url {
        "/cosmos.bank.v1beta1.MsgSend" => DecodedMsg::Send {
            from: string_at(1)?,
            to: string_at(2)?,
            amount: coins_at(3)?,
        },
        "/cosmos.staking.v1beta1.MsgDelegate" => DecodedMsg::Delegate {
            delegator: string_at(1)?,
            validator: string_at(2)?,
            amount: coin_at(3)?,
        },
        "/cosmos.staking.v1beta1.MsgUndelegate" => DecodedMsg::Undelegate {
            delegator: string_at(1)?,
            validator: string_at(2)?,
            amount: coin_at(3)?,
        },
        "/cosmos.staking.v1beta1.MsgBeginRedelegate" => DecodedMsg::Redelegate {
            delegator: string_at(1)?,
            from_validator: string_at(2)?,
            to_validator: string_at(3)?,
            amount: coin_at(4)?,
        },
        "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward" => DecodedMsg::ClaimRewards {
            delegator: string_at(1)?,
            validator: string_at(2)?,
        },
        "/cosmos.gov.v1beta1.MsgVote" | "/cosmos.gov.v1.MsgVote" => {
            let raw = find_field(&fields, 3)
                .map(|v| v.as_varint())
                .transpose()?
                .unwrap_or(0);
            DecodedMsg::Vote {
                proposal_id: find_field(&fields, 1)
                    .map(|v| v.as_varint())
                    .transpose()?
                    .unwrap_or(0),
                voter: string_at(2)?,
                option: match raw {
                    1 => Some(VoteOption::Yes),
                    2 => Some(VoteOption::Abstain),
                    3 => Some(VoteOption::No),
                    4 => Some(VoteOption::NoWithVeto),
                    // An option outside the enum is surfaced as unrecognised rather than
                    // defaulted to Yes, which would be catastrophic.
                    _ => None,
                },
            }
        }
        "/ibc.applications.transfer.v1.MsgTransfer" => DecodedMsg::IbcTransfer {
            channel: string_at(2)?,
            token: coin_at(3)?,
            sender: string_at(4)?,
            receiver: string_at(5)?,
            memo: string_at(8)?,
        },
        "/cosmwasm.wasm.v1.MsgExecuteContract" => {
            let raw = find_field(&fields, 3)
                .map(|v| v.as_bytes().map(|b| b.to_vec()))
                .transpose()?
                .unwrap_or_default();
            let parsed = serde_json::from_slice::<Value>(&raw).ok();
            let action = parsed
                .as_ref()
                .and_then(|v| v.as_object())
                .and_then(|m| m.keys().next().cloned());
            DecodedMsg::ExecuteContract {
                sender: string_at(1)?,
                contract: string_at(2)?,
                msg: parsed,
                action,
                funds: coins_at(5)?,
            }
        }
        _ => return Ok(None),
    };

    // A recognised type URL is not the same as a message the wallet understood. Protobuf omits
    // default values, so a field whose tag has been altered, truncated away, or simply never
    // written decodes to an empty string or a `None` amount, and the decoder above would happily
    // build a `Send` with no recipient or an `IbcTransfer` with a blank receiver. Presented as a
    // known message, that reaches the prompt as "IBC transfer 1000000 uatom to  over channel-141"
    // and, worse, passes `is_safe_to_sign_without_blind_signing`, so the user is asked to approve
    // something the wallet did not actually read.
    //
    // Anything incomplete is therefore demoted to `Unknown`, which is what the blind-signing gate
    // is for. Found by the corpus replay in `zunia-properties`, from a single flipped bit in a
    // real `MsgTransfer`.
    if !is_complete(&decoded) {
        return Ok(None);
    }

    Ok(Some(decoded))
}

/// Whether every field the prompt needs in order to describe a message is actually present.
///
/// Only fields the user must see to evaluate the transaction count as required. A memo is
/// genuinely optional, so its absence is not incompleteness; a recipient is not.
/// Whether an address string can be shown to a user as-is.
///
/// The prompt renders these and the user compares them by eye against an address they got from
/// somewhere else. A control character breaks that comparison outright: a NUL or a bidirectional
/// override can truncate the rendered string or reorder it, so what the user reads is not what
/// the transaction says. Non-ASCII is refused for the same reason, since every Cosmos address
/// format in use is ASCII and a homoglyph has no legitimate reason to appear in one.
///
/// This is deliberately weaker than "is valid bech32". IBC transfer receivers are not always
/// bech32: packet-forward middleware and the EVM bridges put hex addresses and forwarding
/// strings in that field, and rejecting those would demote real transfers to unreadable. The
/// bech32 check is applied separately, only to the fields that are definitionally accounts on
/// the chain being signed for.
///
/// Found by the mutation sweep in `crates/properties/examples/mutate.rs`, which spliced a NUL
/// byte into the middle of a validator address and watched it reach the prompt intact.
fn is_renderable_address(address: &str) -> bool {
    !address.is_empty() && address.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Whether every address that must be a local-chain account actually decodes as bech32.
///
/// Applied only to fields whose proto contract is an account or validator address on the chain
/// being signed for. A field that fails this could never execute on chain, so describing it
/// confidently would be describing a transaction that cannot happen, while the bytes the user
/// signed might still be replayable somewhere the wallet did not check.
fn local_addresses_are_bech32(msg: &DecodedMsg) -> bool {
    let must_be_bech32: Vec<&str> = match msg {
        DecodedMsg::Send { from, to, .. } => vec![from, to],
        DecodedMsg::Delegate {
            delegator,
            validator,
            ..
        }
        | DecodedMsg::Undelegate {
            delegator,
            validator,
            ..
        }
        | DecodedMsg::ClaimRewards {
            delegator,
            validator,
        } => vec![delegator, validator],
        DecodedMsg::Redelegate {
            delegator,
            from_validator,
            to_validator,
            ..
        } => vec![delegator, from_validator, to_validator],
        DecodedMsg::Vote { voter, .. } => vec![voter],
        DecodedMsg::ExecuteContract {
            sender, contract, ..
        } => vec![sender, contract],
        // The sender is a local account, but the receiver may legitimately be an address on
        // another chain entirely, so only the sender is checked here.
        DecodedMsg::IbcTransfer { sender, .. } => vec![sender],
        DecodedMsg::Unknown { .. } => Vec::new(),
    };

    must_be_bech32
        .iter()
        .all(|address| zunia_kernel::decode_bech32(address).is_ok())
}

fn is_complete(msg: &DecodedMsg) -> bool {
    let addresses_present = msg.addresses().iter().all(|a| is_renderable_address(a));

    let specifics = match msg {
        DecodedMsg::Send { amount, .. } => !amount.is_empty(),
        DecodedMsg::Delegate { amount, .. }
        | DecodedMsg::Undelegate { amount, .. }
        | DecodedMsg::Redelegate { amount, .. } => amount.is_some(),
        DecodedMsg::ClaimRewards { .. } => true,
        // A proposal id of zero does not exist on chain, so it means the field was absent. An
        // unrecognised option is not approvable either: "vote with an unrecognised option" tells
        // the user nothing about what their stake would be doing.
        DecodedMsg::Vote {
            proposal_id,
            option,
            ..
        } => *proposal_id != 0 && option.is_some(),
        DecodedMsg::IbcTransfer { channel, token, .. } => !channel.is_empty() && token.is_some(),
        // A contract call whose payload will not parse cannot be described, and "execute an
        // unreadable action" is the definition of blind signing.
        DecodedMsg::ExecuteContract { msg, action, .. } => msg.is_some() && action.is_some(),
        // Already the honest answer.
        DecodedMsg::Unknown { .. } => true,
    };

    addresses_present && specifics && local_addresses_are_bech32(msg)
}

fn decode_coin(bytes: &[u8]) -> Result<Coin> {
    let fields = decode_fields(bytes)?;
    let denom = find_field(&fields, 1)
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_default();
    let amount = find_field(&fields, 2)
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_else(|| "0".to_owned());
    // Constructed without validation on purpose: this is describing bytes that already exist,
    // and a malformed denom is exactly what the user needs to see rather than an error that
    // hides the whole message.
    Ok(Coin { denom, amount })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Height, Msg};
    use crate::proto::ProtoWriter;
    use crate::tx::{Fee, SignMode, SignerData, UnsignedTx};

    const FROM: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
    const TO: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
    const VALOPER: &str = "cosmosvaloper19rl4cm2hmr8afy4kldpxz3fka4jguq0ae5egnx";

    fn signer() -> SignerData {
        SignerData {
            chain_id: "cosmoshub-4".to_owned(),
            account_number: 12345,
            sequence: 7,
            public_key: vec![2u8; 33],
            eth_key_type: false,
        }
    }

    fn round_trip(msgs: Vec<Msg>, memo: &str) -> DecodedTx {
        let tx = UnsignedTx::new(
            msgs,
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            memo,
        )
        .unwrap();
        let bytes = tx.sign_bytes(&signer(), SignMode::Direct).unwrap();
        decode_direct_sign_doc(&bytes).unwrap()
    }

    /// Assembles a `SignDoc` from raw `Any` bytes.
    ///
    /// Needed for the adversarial cases, which carry message types [`UnsignedTx`] cannot
    /// build. The `auth_info` is a real one rather than an empty placeholder: an empty
    /// `auth_info_bytes` field is omitted under proto3 default-value rules, and no genuine
    /// `SignDoc` ever has one, so the decoder correctly rejects it.
    fn hand_built_doc(anys: Vec<Vec<u8>>) -> Vec<u8> {
        let tx = UnsignedTx::new(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1").unwrap()],
            }],
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            "",
        )
        .unwrap();
        let auth_info = tx.encode_auth_info(&signer(), SignMode::Direct);

        let mut body = ProtoWriter::new();
        body.repeated_message(1, &anys);

        let mut doc = ProtoWriter::new();
        doc.bytes(1, body.as_bytes())
            .bytes(2, &auth_info)
            .string(3, "cosmoshub-4")
            .uint64(4, 12345);
        doc.into_bytes()
    }

    fn any_of(type_url: &str, value: &[u8]) -> Vec<u8> {
        let mut any = ProtoWriter::new();
        any.string(1, type_url).bytes(2, value);
        any.into_bytes()
    }

    #[test]
    fn decodes_a_send_it_built_itself() {
        let decoded = round_trip(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }],
            "for lunch",
        );

        assert_eq!(decoded.chain_id, "cosmoshub-4");
        assert_eq!(decoded.account_number, 12345);
        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.memo, "for lunch");
        assert_eq!(decoded.gas_limit, 200_000);
        assert_eq!(decoded.fee, vec![Coin::new("uatom", "5000").unwrap()]);
        assert!(!decoded.has_unknown_msgs);
        assert!(decoded.is_safe_to_sign_without_blind_signing());

        assert_eq!(
            decoded.msgs[0],
            DecodedMsg::Send {
                from: FROM.to_owned(),
                to: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }
        );
        assert_eq!(
            decoded.summaries()[0],
            format!("Send 1000000 uatom to {TO}")
        );
    }

    #[test]
    fn decodes_every_supported_message() {
        let cases: Vec<Msg> = vec![
            Msg::Delegate {
                delegator_address: FROM.to_owned(),
                validator_address: VALOPER.to_owned(),
                amount: Coin::new("uatom", "5000000").unwrap(),
            },
            Msg::Undelegate {
                delegator_address: FROM.to_owned(),
                validator_address: VALOPER.to_owned(),
                amount: Coin::new("uatom", "1000000").unwrap(),
            },
            Msg::BeginRedelegate {
                delegator_address: FROM.to_owned(),
                validator_src_address: VALOPER.to_owned(),
                validator_dst_address: VALOPER.to_owned(),
                amount: Coin::new("uatom", "1000000").unwrap(),
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
                timeout_timestamp: 0,
                memo: String::new(),
            },
            Msg::ExecuteContract {
                sender: FROM.to_owned(),
                contract: TO.to_owned(),
                msg: br#"{"swap":{"offer":"100"}}"#.to_vec(),
                funds: vec![Coin::new("uatom", "100").unwrap()],
            },
        ];

        for msg in cases {
            let expected_summary = msg.summary();
            let decoded = round_trip(vec![msg.clone()], "");
            assert!(
                !decoded.has_unknown_msgs,
                "{} decoded as unknown",
                msg.type_url()
            );
            // The decoder's summary must match the builder's summary. If they diverge, the
            // signing prompt describes something different depending on who built the
            // transaction, which is exactly the bug this test exists to prevent.
            assert_eq!(
                decoded.summaries()[0],
                expected_summary,
                "summary mismatch for {}",
                msg.type_url()
            );
        }
    }

    #[test]
    fn contract_action_is_extracted() {
        let decoded = round_trip(
            vec![Msg::ExecuteContract {
                sender: FROM.to_owned(),
                contract: TO.to_owned(),
                msg: br#"{"increase_allowance":{"spender":"x","amount":"999999999"}}"#.to_vec(),
                funds: vec![],
            }],
            "",
        );
        match &decoded.msgs[0] {
            DecodedMsg::ExecuteContract { action, msg, .. } => {
                assert_eq!(action.as_deref(), Some("increase_allowance"));
                assert!(msg.is_some(), "the contract body must be shown in full");
            }
            other => panic!("expected a contract execution, got {other:?}"),
        }
        assert!(decoded.summaries()[0].contains("increase_allowance"));
    }

    #[test]
    fn unknown_message_types_are_flagged_not_guessed() {
        // An unregistered type URL. The user must be told the wallet cannot read it.
        let mut inner = ProtoWriter::new();
        inner.string(1, "some payload");
        let doc = hand_built_doc(vec![any_of(
            "/some.unknown.v1.MsgDoSomething",
            inner.as_bytes(),
        )]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.has_unknown_msgs);
        assert!(!decoded.is_safe_to_sign_without_blind_signing());

        let summary = decoded.summaries()[0].clone();
        assert!(summary.contains("UNKNOWN ACTION"));
        assert!(summary.contains("/some.unknown.v1.MsgDoSomething"));
        // The summary must not read as reassuring.
        assert!(!summary.to_lowercase().contains("approve transaction"));
    }

    #[test]
    fn a_malformed_known_message_becomes_unknown_not_an_error() {
        // Correct type URL, garbage body. The other messages in the transaction still matter,
        // so this must degrade rather than abort.
        let doc = hand_built_doc(vec![any_of(
            "/cosmos.bank.v1beta1.MsgSend",
            &[0xff, 0xff, 0xff],
        )]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.has_unknown_msgs);
        assert!(decoded.msgs[0].is_unknown());
    }

    #[test]
    fn an_out_of_range_vote_option_is_not_defaulted_to_yes() {
        let mut inner = ProtoWriter::new();
        inner.uint64(1, 1).string(2, FROM).int32(3, 99);
        let doc = hand_built_doc(vec![any_of(
            "/cosmos.gov.v1beta1.MsgVote",
            inner.as_bytes(),
        )]);

        // Not merely "not defaulted to Yes": a vote whose option the wallet cannot name is not
        // something the user can approve, so it is demoted to an unknown message and the
        // blind-signing gate closes.
        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.msgs[0].is_unknown(), "got {:?}", decoded.msgs[0]);
        assert!(decoded.has_unknown_msgs);
        assert!(!decoded.is_safe_to_sign_without_blind_signing());
        assert!(decoded.summaries()[0].contains("UNKNOWN ACTION"));
    }

    #[test]
    fn a_known_type_url_with_a_missing_recipient_is_not_treated_as_understood() {
        // The regression that the corpus replay found. Flipping one bit in a real `MsgTransfer`
        // changed the `sender` field's tag, so sender and receiver both decoded as empty and the
        // prompt read "IBC transfer 1000000 uatom to  over channel-141" while reporting the
        // transaction as safe to sign.
        let mut inner = ProtoWriter::new();
        inner
            .string(1, "transfer")
            .string(2, "channel-141")
            .message_always(3, &{
                let mut coin = ProtoWriter::new();
                coin.string(1, "uatom").string(2, "1000000");
                coin.into_bytes()
            });
        // Fields 4 (sender) and 5 (receiver) deliberately absent.
        let doc = hand_built_doc(vec![any_of(
            "/ibc.applications.transfer.v1.MsgTransfer",
            inner.as_bytes(),
        )]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(
            decoded.msgs[0].is_unknown(),
            "a transfer with no sender or receiver must not be presented as understood, got {:?}",
            decoded.msgs[0]
        );
        assert!(!decoded.is_safe_to_sign_without_blind_signing());

        // And no address reaching the UI may be blank, since the first-time-recipient warning
        // compares addresses by string equality.
        for msg in &decoded.msgs {
            for address in msg.addresses() {
                assert!(!address.is_empty());
            }
        }
    }

    #[test]
    fn an_address_containing_a_control_character_is_not_treated_as_understood() {
        // The mutation sweep spliced a NUL byte into the middle of a validator address. Protobuf
        // strings permit it and the decoder faithfully reproduced it, so the prompt would have
        // rendered "cosmosvaloper19rl4cm2hmr8afy4kldpxz3fka4jguq0a" followed by an invisible
        // break and the rest. A user comparing that against an address from a validator's website
        // would see a match that is not one.
        for injected in ["\u{0}", "\u{7}", "\u{202e}", " ", "\n"] {
            let poisoned = format!("cosmos19rl4cm2hmr8afy4kl{injected}dpxz3fka4jguq0auqdal4");

            let mut inner = ProtoWriter::new();
            inner
                .string(1, &poisoned)
                .string(2, TO)
                .message_always(3, &{
                    let mut coin = ProtoWriter::new();
                    coin.string(1, "uatom").string(2, "1");
                    coin.into_bytes()
                });
            let doc = hand_built_doc(vec![any_of(
                "/cosmos.bank.v1beta1.MsgSend",
                inner.as_bytes(),
            )]);

            let decoded = decode_direct_sign_doc(&doc).unwrap();
            assert!(
                decoded.msgs[0].is_unknown(),
                "an address containing {injected:?} was presented as understood: {:?}",
                decoded.msgs[0]
            );
            assert!(!decoded.is_safe_to_sign_without_blind_signing());
        }
    }

    #[test]
    fn an_address_that_is_not_valid_bech32_is_not_treated_as_understood() {
        // Same shape as the finding above but with a printable substitution rather than a control
        // character: one character of the checksum changed. A wallet that renders this has told
        // the user a specific recipient for a transaction the chain will reject, and the bytes
        // they signed are still bytes they signed.
        let mut inner = ProtoWriter::new();
        inner
            .string(1, "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal5")
            .string(2, TO)
            .message_always(3, &{
                let mut coin = ProtoWriter::new();
                coin.string(1, "uatom").string(2, "1");
                coin.into_bytes()
            });
        let doc = hand_built_doc(vec![any_of(
            "/cosmos.bank.v1beta1.MsgSend",
            inner.as_bytes(),
        )]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.msgs[0].is_unknown(), "got {:?}", decoded.msgs[0]);
    }

    #[test]
    fn an_ibc_receiver_on_another_chain_is_still_understood() {
        // The counterweight to the two tests above. Packet-forward middleware and the EVM bridges
        // put non-bech32 receivers in this field, so demoting them would mark ordinary
        // cross-chain transfers unreadable and push users toward the blind-signing toggle, which
        // is the opposite of the intent.
        for receiver in [
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0aqm2krz",
            "penumbra1abcdefghijklmnop",
        ] {
            let mut inner = ProtoWriter::new();
            inner
                .string(1, "transfer")
                .string(2, "channel-141")
                .message_always(3, &{
                    let mut coin = ProtoWriter::new();
                    coin.string(1, "uatom").string(2, "1000000");
                    coin.into_bytes()
                })
                .string(4, FROM)
                .string(5, receiver);
            let doc = hand_built_doc(vec![any_of(
                "/ibc.applications.transfer.v1.MsgTransfer",
                inner.as_bytes(),
            )]);

            let decoded = decode_direct_sign_doc(&doc).unwrap();
            assert!(
                !decoded.msgs[0].is_unknown(),
                "a transfer to {receiver} was marked unreadable"
            );
            assert!(decoded.summaries()[0].contains(receiver));
        }
    }

    #[test]
    fn a_send_with_no_amount_is_not_treated_as_understood() {
        let mut inner = ProtoWriter::new();
        inner.string(1, FROM).string(2, TO);
        let doc = hand_built_doc(vec![any_of(
            "/cosmos.bank.v1beta1.MsgSend",
            inner.as_bytes(),
        )]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.msgs[0].is_unknown(), "got {:?}", decoded.msgs[0]);
    }

    #[test]
    fn a_contract_call_with_an_unparseable_payload_is_not_treated_as_understood() {
        // "Execute an unreadable action on cosmos1..." is blind signing with extra steps.
        let mut inner = ProtoWriter::new();
        inner
            .string(1, FROM)
            .string(2, TO)
            .bytes(3, &[0xff, 0xfe, 0xfd]);
        let doc = hand_built_doc(vec![any_of(
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            inner.as_bytes(),
        )]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.msgs[0].is_unknown(), "got {:?}", decoded.msgs[0]);
    }

    #[test]
    fn decodes_a_multi_message_transaction() {
        let decoded = round_trip(
            vec![
                Msg::WithdrawDelegatorReward {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                },
                Msg::Delegate {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                    amount: Coin::new("uatom", "1000000").unwrap(),
                },
            ],
            "",
        );
        assert_eq!(decoded.msgs.len(), 2);
        assert!(decoded.summaries()[0].starts_with("Claim staking rewards"));
        assert!(decoded.summaries()[1].starts_with("Delegate"));
    }

    #[test]
    fn one_unknown_message_taints_the_whole_transaction() {
        // The attack: bundle a legitimate-looking send with an undecodable message and hope the
        // user reads only the first line.
        let mut good = ProtoWriter::new();
        good.string(1, FROM).string(2, TO).repeated_message(
            3,
            &[{
                let mut c = ProtoWriter::new();
                c.string(1, "uatom").string(2, "1");
                c.into_bytes()
            }],
        );
        let doc = hand_built_doc(vec![
            any_of("/cosmos.bank.v1beta1.MsgSend", good.as_bytes()),
            any_of("/x.y.MsgDrainEverything", &[1, 2, 3]),
        ]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert_eq!(decoded.msgs.len(), 2);
        assert!(!decoded.msgs[0].is_unknown());
        assert!(decoded.msgs[1].is_unknown());
        assert!(
            !decoded.is_safe_to_sign_without_blind_signing(),
            "a single undecodable message must block the whole signature"
        );
    }

    #[test]
    fn rejects_structurally_invalid_documents() {
        assert!(decode_direct_sign_doc(&[]).is_err());
        assert!(decode_direct_sign_doc(&[0xff, 0xff]).is_err());

        // Missing chain id, which would be replayable.
        let mut no_chain = ProtoWriter::new();
        no_chain.bytes(1, &[]).bytes(2, &[]);
        assert!(decode_direct_sign_doc(no_chain.as_bytes()).is_err());

        // Present chain id but no messages at all.
        let mut empty_body = ProtoWriter::new();
        empty_body
            .bytes(1, &[])
            .bytes(2, &[])
            .string(3, "cosmoshub-4");
        assert_eq!(
            decode_direct_sign_doc(empty_body.as_bytes()).unwrap_err(),
            CosmosError::SignDoc
        );
    }

    #[test]
    fn decoded_addresses_are_enumerated() {
        let decoded = round_trip(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1").unwrap()],
            }],
            "",
        );
        assert_eq!(decoded.msgs[0].addresses(), vec![FROM, TO]);
        assert!(DecodedMsg::Unknown {
            type_url: "x".into(),
            byte_length: 1
        }
        .addresses()
        .is_empty());
    }
}
