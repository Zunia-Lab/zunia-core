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
//!
//! # A singular field written twice
//!
//! Protobuf permits a singular field to occur more than once, and the chain reads the last
//! occurrence: gogoproto keeps the last value of a scalar, string or bytes field and merges
//! repeated occurrences of an embedded message. A decoder that reads the first occurrence can
//! therefore be shown one `MsgSend` recipient while the chain pays another, one fee while the
//! chain charges another, or one message type in an `Any` while the chain runs another. No
//! encoder writes a singular field twice, so this module never chooses between occurrences: every
//! singular field it reads goes through [`find_unique_field`], and the singular fields it does
//! not read, which the chain executes all the same, are checked with [`require_unique`].
//!
//! Where the duplicate sits decides the outcome. Inside a message body it makes that message
//! [`DecodedMsg::Unknown`], like any other body the wallet cannot read, so the blind-signing gate
//! closes and the rest of the transaction is still shown. Anywhere in the envelope around the
//! messages (the `SignDoc`, the `TxBody`, an `Any`, the `AuthInfo`, a `SignerInfo` or the `Fee`)
//! there is no message to name and no fee or memo to trust, so the whole document is refused.

use serde_json::Value;

use crate::amount::Coin;
use crate::error::{CosmosError, Result};
use crate::msg::{
    contract_action, describe_hops, describe_out_hops, describe_out_split, describe_split,
    is_plain_contract_action, out_route_input, route_output, split_input, split_out_total,
    split_output, validate_split_route_swap_exact_amount_in,
    validate_split_route_swap_exact_amount_out, validate_swap_exact_amount_in,
    validate_swap_exact_amount_out, SwapAmountInRoute, SwapAmountInSplitRoute, SwapAmountOutRoute,
    SwapAmountOutSplitRoute, VoteOption,
};
use crate::proto::{decode_fields, find_all, find_unique_field, require_unique};

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
        /// The top-level key, which is the action by CosmWasm convention, when it is a plain
        /// name. See [`contract_action`].
        action: Option<String>,
        funds: Vec<Coin>,
    },
    /// `osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn`, the swap the Osmosis app signs for a
    /// single route.
    SwapExactAmountIn {
        sender: String,
        /// The hops in order; the last one's `token_out_denom` is what the sender receives.
        routes: Vec<SwapAmountInRoute>,
        token_in: Option<Coin>,
        token_out_min_amount: String,
    },
    /// `osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn`, the same swap with its
    /// input divided across several routes.
    SplitRouteSwapExactAmountIn {
        sender: String,
        routes: Vec<SwapAmountInSplitRoute>,
        token_in_denom: String,
        token_out_min_amount: String,
    },
    /// `osmosis.poolmanager.v1beta1.MsgSwapExactAmountOut`: an exact amount out, for at most a
    /// ceiling in. What other Osmosis front ends sign to buy a precise amount.
    SwapExactAmountOut {
        sender: String,
        /// The hops in order; the first one's `token_in_denom` is what the sender spends.
        routes: Vec<SwapAmountOutRoute>,
        /// The most the swap may spend. The only price limit the message carries.
        token_in_max_amount: String,
        token_out: Option<Coin>,
    },
    /// `osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountOut`.
    SplitRouteSwapExactAmountOut {
        sender: String,
        routes: Vec<SwapAmountOutSplitRoute>,
        token_out_denom: String,
        token_in_max_amount: String,
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
                // The decoder sets `action` only to a plain name. The filter holds a value built
                // some other way to the same rule, so the sentence never quotes anything else.
                let action = action
                    .as_deref()
                    .filter(|action| is_plain_contract_action(action))
                    .unwrap_or("an unreadable action");
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
            // Word for word what `Msg::summary` says, so the prompt reads the same whether the
            // wallet or a dApp built the swap.
            Self::SwapExactAmountIn {
                routes,
                token_in,
                token_out_min_amount,
                ..
            } => format!(
                "Swap {} for at least {token_out_min_amount} {} through {}",
                describe_coin(token_in),
                route_output(routes),
                describe_hops(routes)
            ),
            Self::SplitRouteSwapExactAmountIn {
                routes,
                token_in_denom,
                token_out_min_amount,
                ..
            } => format!(
                "Swap {} {token_in_denom} for at least {token_out_min_amount} {} through {}",
                split_input(routes),
                split_output(routes),
                describe_split(routes)
            ),
            // The ceiling first: it is what a user must check, as the floor is for exact-in.
            Self::SwapExactAmountOut {
                routes,
                token_in_max_amount,
                token_out,
                ..
            } => format!(
                "Swap at most {token_in_max_amount} {} for exactly {} through {}",
                out_route_input(routes),
                describe_coin(token_out),
                describe_out_hops(routes)
            ),
            Self::SplitRouteSwapExactAmountOut {
                routes,
                token_out_denom,
                token_in_max_amount,
                ..
            } => format!(
                "Swap at most {token_in_max_amount} {} for exactly {} {token_out_denom} through {}",
                routes
                    .first()
                    .map_or("an unreadable denom", |leg| out_route_input(&leg.pools)),
                split_out_total(routes),
                describe_out_split(routes)
            ),
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
            Self::SwapExactAmountIn { sender, .. }
            | Self::SplitRouteSwapExactAmountIn { sender, .. }
            | Self::SwapExactAmountOut { sender, .. }
            | Self::SplitRouteSwapExactAmountOut { sender, .. } => vec![sender],
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
    /// Each message's `Any.type_url`, in the order of [`Self::msgs`], whether or not the message
    /// was understood. A known message's variant implies its type, but not which one: gov
    /// v1beta1 and v1 votes decode to the same [`DecodedMsg::Vote`], and the prompt names what the
    /// chain will run.
    pub type_urls: Vec<String>,
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
///
/// Refuses the document outright when any singular field of the `SignDoc`, the `TxBody`, an
/// `Any`, the `AuthInfo`, a `SignerInfo` or the `Fee` occurs more than once. See the module
/// documentation.
pub fn decode_direct_sign_doc(sign_bytes: &[u8]) -> Result<DecodedTx> {
    let fields = decode_fields(sign_bytes)?;

    // SignDoc: body_bytes 1, auth_info_bytes 2, chain_id 3 and account_number 4, all singular
    // and all read.
    let body_bytes = find_unique_field(&fields, 1)?
        .ok_or(CosmosError::SignDoc)?
        .as_bytes()?;
    let auth_info_bytes = find_unique_field(&fields, 2)?
        .ok_or(CosmosError::SignDoc)?
        .as_bytes()?;
    let chain_id = find_unique_field(&fields, 3)?
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_default();
    let account_number = find_unique_field(&fields, 4)?
        .map(|v| v.as_varint())
        .transpose()?
        .unwrap_or(0);

    if chain_id.trim().is_empty() {
        // An empty chain id in a Direct document is either malformed or an attempt to build
        // something replayable. Either way it is not signable.
        return Err(CosmosError::ChainId);
    }

    // TxBody: messages 1 and the extension options are repeated. memo 2 and timeout_height 3
    // are read; unordered 4 and timeout_timestamp 5 are not shown, but they decide whether and
    // until when the transaction can execute.
    let body = decode_fields(body_bytes)?;
    require_unique(&body, &[4, 5])?;
    let memo = find_unique_field(&body, 2)?
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_default();
    let timeout_height = find_unique_field(&body, 3)?
        .map(|v| v.as_varint())
        .transpose()?
        .unwrap_or(0);

    let mut msgs = Vec::new();
    let mut type_urls = Vec::new();
    for any in find_all(&body, 1) {
        let (type_url, msg) = decode_any(any.as_bytes()?)?;
        type_urls.push(type_url);
        msgs.push(msg);
    }
    if msgs.is_empty() {
        return Err(CosmosError::SignDoc);
    }

    // AuthInfo: signer_infos 1 is repeated, fee 2 is read, and tip 3 is not shown but pays out.
    let auth_info = decode_fields(auth_info_bytes)?;
    require_unique(&auth_info, &[3])?;
    let mut sequence = None;
    for signer_info in find_all(&auth_info, 1) {
        // SignerInfo: public_key 1 and mode_info 2 are not shown but decide how the signature
        // is checked; sequence 3 is read, from the first signer, who is the one signing here.
        let signer_info = decode_fields(signer_info.as_bytes()?)?;
        require_unique(&signer_info, &[1, 2])?;
        let this_sequence = find_unique_field(&signer_info, 3)?
            .map(|v| v.as_varint())
            .transpose()?
            .unwrap_or(0);
        sequence.get_or_insert(this_sequence);
    }
    let sequence = sequence.unwrap_or(0);

    let (fee, gas_limit) = match find_unique_field(&auth_info, 2)? {
        Some(fee_bytes) => {
            // Fee: amount 1 is repeated and gas_limit 2 is read. payer 3 and granter 4 are not
            // shown, but they decide who is charged.
            let fee_fields = decode_fields(fee_bytes.as_bytes()?)?;
            require_unique(&fee_fields, &[3, 4])?;
            let mut coins = Vec::new();
            for coin in find_all(&fee_fields, 1) {
                coins.push(decode_coin(coin.as_bytes()?)?);
            }
            let gas = find_unique_field(&fee_fields, 2)?
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
        type_urls,
        fee,
        gas_limit,
        memo,
        timeout_height,
        has_unknown_msgs,
    })
}

/// Decodes a `google.protobuf.Any` holding a message, and returns its type URL with it.
///
/// A second `type_url` or `value` is an error for the whole document rather than an unknown
/// message: with two type URLs the prompt would name one message while the chain ran the other,
/// and there is no honest name to put on the result.
fn decode_any(any_bytes: &[u8]) -> Result<(String, DecodedMsg)> {
    let fields = decode_fields(any_bytes)?;
    let type_url = find_unique_field(&fields, 1)?
        .ok_or(CosmosError::Decode)?
        .as_string()?;
    let value = find_unique_field(&fields, 2)?
        .map(|v| v.as_bytes().map(|b| b.to_vec()))
        .transpose()?
        .unwrap_or_default();

    // A message whose body fails to decode becomes Unknown rather than an error. Refusing the
    // whole transaction would hide the other messages from the user, and one malformed message
    // is itself worth showing.
    let decoded = decode_known(&type_url, &value).unwrap_or(None);

    let msg = decoded.unwrap_or_else(|| DecodedMsg::Unknown {
        type_url: type_url.clone(),
        byte_length: value.len(),
    });
    Ok((type_url, msg))
}

/// Decodes the body of a message whose type URL this build knows.
///
/// Every singular field read here goes through [`find_unique_field`], by way of `string_at`,
/// `varint_at` and `coin_at`; repeated fields go through `coins_at` and [`find_all`]. An error
/// anywhere, a duplicated singular field included, makes the caller show the message as
/// [`DecodedMsg::Unknown`].
fn decode_known(type_url: &str, value: &[u8]) -> Result<Option<DecodedMsg>> {
    let fields = decode_fields(value)?;

    let string_at = |tag: u32| -> Result<String> {
        Ok(find_unique_field(&fields, tag)?
            .map(|v| v.as_string())
            .transpose()?
            .unwrap_or_default())
    };
    let varint_at = |tag: u32| -> Result<u64> {
        Ok(find_unique_field(&fields, tag)?
            .map(|v| v.as_varint())
            .transpose()?
            .unwrap_or(0))
    };
    let coin_at = |tag: u32| -> Result<Option<Coin>> {
        match find_unique_field(&fields, tag)? {
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
            // gov v1 adds metadata 4, which is not shown. v1beta1 has no field 4, and the chain
            // refuses one as unknown, so checking it there costs nothing.
            require_unique(&fields, &[4])?;
            let raw = varint_at(3)?;
            DecodedMsg::Vote {
                proposal_id: varint_at(1)?,
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
        "/ibc.applications.transfer.v1.MsgTransfer" => {
            // Not shown, but they decide where the packet goes and when the escrow can be
            // refunded: source_port 1, timeout_height 6 and timeout_timestamp 7.
            require_unique(&fields, &[1, 7])?;
            if let Some(height) = find_unique_field(&fields, 6)? {
                // ibc.core.client.v1.Height: revision_number 1, revision_height 2. A height that
                // does not decode at all is refused too, since the chain cannot decode it either.
                require_unique(&decode_fields(height.as_bytes()?)?, &[1, 2])?;
            }
            DecodedMsg::IbcTransfer {
                channel: string_at(2)?,
                token: coin_at(3)?,
                sender: string_at(4)?,
                receiver: string_at(5)?,
                memo: string_at(8)?,
            }
        }
        "/cosmwasm.wasm.v1.MsgExecuteContract" => {
            let raw = find_unique_field(&fields, 3)?
                .map(|v| v.as_bytes().map(|b| b.to_vec()))
                .transpose()?
                .unwrap_or_default();
            let parsed = serde_json::from_slice::<Value>(&raw).ok();
            // Unset unless the message leads with a plain name, and `is_complete` demotes a call
            // without one.
            let action = parsed.as_ref().and_then(contract_action).map(str::to_owned);
            DecodedMsg::ExecuteContract {
                sender: string_at(1)?,
                contract: string_at(2)?,
                msg: parsed,
                action,
                funds: coins_at(5)?,
            }
        }
        "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn" => {
            let mut routes = Vec::new();
            for hop in find_all(&fields, 2) {
                routes.push(decode_hop(hop.as_bytes()?)?);
            }
            DecodedMsg::SwapExactAmountIn {
                sender: string_at(1)?,
                routes,
                token_in: coin_at(3)?,
                // The field most worth forging in a swap: a respectable floor first, zero second.
                token_out_min_amount: string_at(4)?,
            }
        }
        "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn" => {
            let mut routes = Vec::new();
            for leg in find_all(&fields, 2) {
                routes.push(decode_split_leg(leg.as_bytes()?)?);
            }
            DecodedMsg::SplitRouteSwapExactAmountIn {
                sender: string_at(1)?,
                routes,
                token_in_denom: string_at(3)?,
                token_out_min_amount: string_at(4)?,
            }
        }
        "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountOut" => {
            let mut routes = Vec::new();
            for hop in find_all(&fields, 2) {
                routes.push(decode_out_hop(hop.as_bytes()?)?);
            }
            DecodedMsg::SwapExactAmountOut {
                sender: string_at(1)?,
                routes,
                // The field most worth forging in an exact-out swap: a modest ceiling first, a
                // ruinous one second.
                token_in_max_amount: string_at(3)?,
                token_out: coin_at(4)?,
            }
        }
        "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountOut" => {
            let mut routes = Vec::new();
            for leg in find_all(&fields, 2) {
                routes.push(decode_out_split_leg(leg.as_bytes()?)?);
            }
            DecodedMsg::SplitRouteSwapExactAmountOut {
                sender: string_at(1)?,
                routes,
                token_out_denom: string_at(3)?,
                token_in_max_amount: string_at(4)?,
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

/// Whether every address that must be on the chain being signed for actually decodes as bech32.
///
/// Applied only to fields whose proto contract is an address on that chain: an account or a
/// validator, which is 20 bytes, or a send's recipient or a contract, which may also be a
/// 32-byte module-derived address under the signer's prefix. A field that fails this could never
/// execute on chain, so describing it confidently would be describing a transaction that cannot
/// happen, while the bytes the user signed might still be replayable somewhere the wallet did not
/// check.
fn local_addresses_are_bech32(msg: &DecodedMsg) -> bool {
    // `accounts` are keyed accounts and validators: 20 bytes, always. `derived` may also be a
    // module-derived address, which is 32 bytes: a CosmWasm contract, an interchain account, a
    // group policy. The first account is the signer, and a derived address must carry its
    // prefix, since a contract on another chain cannot be called or paid from this one.
    let (accounts, derived): (Vec<&str>, Vec<&str>) = match msg {
        DecodedMsg::Send { from, to, .. } => (vec![from], vec![to]),
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
        } => (vec![delegator, validator], Vec::new()),
        DecodedMsg::Redelegate {
            delegator,
            from_validator,
            to_validator,
            ..
        } => (vec![delegator, from_validator, to_validator], Vec::new()),
        DecodedMsg::Vote { voter, .. } => (vec![voter], Vec::new()),
        DecodedMsg::ExecuteContract {
            sender, contract, ..
        } => (vec![sender], vec![contract]),
        // The sender is a local account, but the receiver may legitimately be an address on
        // another chain entirely, so only the sender is checked here.
        DecodedMsg::IbcTransfer { sender, .. } => (vec![sender], Vec::new()),
        DecodedMsg::SwapExactAmountIn { sender, .. }
        | DecodedMsg::SplitRouteSwapExactAmountIn { sender, .. }
        | DecodedMsg::SwapExactAmountOut { sender, .. }
        | DecodedMsg::SplitRouteSwapExactAmountOut { sender, .. } => (vec![sender], Vec::new()),
        DecodedMsg::Unknown { .. } => (Vec::new(), Vec::new()),
    };

    if !accounts
        .iter()
        .all(|address| zunia_kernel::decode_bech32(address).is_ok())
    {
        return false;
    }
    match accounts
        .first()
        .map(|signer| zunia_kernel::decode_bech32(signer))
    {
        Some(Ok(signer)) => derived.iter().all(|address| {
            zunia_kernel::validate_contract_address(address, &signer.prefix).is_ok()
        }),
        _ => derived.is_empty(),
    }
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
        // unreadable action" is the definition of blind signing. Nor can one whose action is
        // not a plain name, which the decoder leaves unset: the prompt quotes the action and
        // nothing on chain checks it, so a bidirectional override or a line separator in it
        // would rewrite the sentence that names the contract and the coins.
        DecodedMsg::ExecuteContract { msg, action, .. } => msg.is_some() && action.is_some(),
        // The same rules the bridge builds under. A swap that breaks one either cannot execute
        // or is outside what this wallet signs, and neither is something to describe
        // confidently: "for at least 0" reads like a number while meaning "at any price".
        // Demoted, it reaches the blind-signing gate instead.
        DecodedMsg::SwapExactAmountIn {
            routes,
            token_in,
            token_out_min_amount,
            ..
        } => token_in.as_ref().is_some_and(|token_in| {
            validate_swap_exact_amount_in(routes, token_in, token_out_min_amount).is_ok()
        }),
        DecodedMsg::SplitRouteSwapExactAmountIn {
            routes,
            token_in_denom,
            token_out_min_amount,
            ..
        } => {
            validate_split_route_swap_exact_amount_in(routes, token_in_denom, token_out_min_amount)
                .is_ok()
        }
        DecodedMsg::SwapExactAmountOut {
            routes,
            token_in_max_amount,
            token_out,
            ..
        } => token_out.as_ref().is_some_and(|token_out| {
            validate_swap_exact_amount_out(routes, token_in_max_amount, token_out).is_ok()
        }),
        DecodedMsg::SplitRouteSwapExactAmountOut {
            routes,
            token_out_denom,
            token_in_max_amount,
            ..
        } => {
            validate_split_route_swap_exact_amount_out(routes, token_out_denom, token_in_max_amount)
                .is_ok()
        }
        // Already the honest answer.
        DecodedMsg::Unknown { .. } => true,
    };

    addresses_present && specifics && local_addresses_are_bech32(msg)
}

/// `osmosis.poolmanager.v1beta1.SwapAmountInRoute`. An absent pool id reads as 0 and an absent
/// denom as empty, both of which the swap rules refuse.
fn decode_hop(bytes: &[u8]) -> Result<SwapAmountInRoute> {
    let fields = decode_fields(bytes)?;
    Ok(SwapAmountInRoute {
        pool_id: find_unique_field(&fields, 1)?
            .map(|v| v.as_varint())
            .transpose()?
            .unwrap_or(0),
        token_out_denom: find_unique_field(&fields, 2)?
            .map(|v| v.as_string())
            .transpose()?
            .unwrap_or_default(),
    })
}

/// `osmosis.poolmanager.v1beta1.SwapAmountInSplitRoute`.
fn decode_split_leg(bytes: &[u8]) -> Result<SwapAmountInSplitRoute> {
    let fields = decode_fields(bytes)?;
    let mut pools = Vec::new();
    for hop in find_all(&fields, 1) {
        pools.push(decode_hop(hop.as_bytes()?)?);
    }
    Ok(SwapAmountInSplitRoute {
        pools,
        token_in_amount: find_unique_field(&fields, 2)?
            .map(|v| v.as_string())
            .transpose()?
            .unwrap_or_default(),
    })
}

/// `osmosis.poolmanager.v1beta1.SwapAmountOutRoute`: pool_id 1, token_in_denom 2.
fn decode_out_hop(bytes: &[u8]) -> Result<SwapAmountOutRoute> {
    let fields = decode_fields(bytes)?;
    Ok(SwapAmountOutRoute {
        pool_id: find_unique_field(&fields, 1)?
            .map(|v| v.as_varint())
            .transpose()?
            .unwrap_or(0),
        token_in_denom: find_unique_field(&fields, 2)?
            .map(|v| v.as_string())
            .transpose()?
            .unwrap_or_default(),
    })
}

/// `osmosis.poolmanager.v1beta1.SwapAmountOutSplitRoute`: pools 1, token_out_amount 2.
fn decode_out_split_leg(bytes: &[u8]) -> Result<SwapAmountOutSplitRoute> {
    let fields = decode_fields(bytes)?;
    let mut pools = Vec::new();
    for hop in find_all(&fields, 1) {
        pools.push(decode_out_hop(hop.as_bytes()?)?);
    }
    Ok(SwapAmountOutSplitRoute {
        pools,
        token_out_amount: find_unique_field(&fields, 2)?
            .map(|v| v.as_string())
            .transpose()?
            .unwrap_or_default(),
    })
}

/// `cosmos.base.v1beta1.Coin`, wherever it appears: a fee, a send, a delegation, a swap input.
/// Two amounts in one coin would show one figure while the chain moves the other.
fn decode_coin(bytes: &[u8]) -> Result<Coin> {
    let fields = decode_fields(bytes)?;
    let denom = find_unique_field(&fields, 1)?
        .map(|v| v.as_string())
        .transpose()?
        .unwrap_or_default();
    let amount = find_unique_field(&fields, 2)?
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
            eth_pub_key_type_url: None,
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
            Msg::SwapExactAmountIn {
                sender: OSMO.to_owned(),
                routes: vec![hop(1, ATOM), hop(3586, OUT)],
                token_in: Coin::new("uosmo", "10000000").unwrap(),
                token_out_min_amount: "340000".to_owned(),
            },
            Msg::SplitRouteSwapExactAmountIn {
                sender: OSMO.to_owned(),
                routes: vec![
                    SwapAmountInSplitRoute {
                        pools: vec![hop(3498, OUT)],
                        token_in_amount: "5970000".to_owned(),
                    },
                    SwapAmountInSplitRoute {
                        pools: vec![hop(3586, OUT)],
                        token_in_amount: "3980000".to_owned(),
                    },
                ],
                token_in_denom: "uosmo".to_owned(),
                token_out_min_amount: "350000".to_owned(),
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
    fn every_message_keeps_its_type_url_in_order() {
        // The prompt names the message the chain will run, and the variant alone cannot say
        // which: a gov v1 vote and a v1beta1 vote decode to the same Vote. Unknown messages keep
        // theirs too, the demoted ones included, so a refusal can say what it refused.
        let mut send = ProtoWriter::new();
        send.string(1, FROM)
            .string(2, TO)
            .repeated_message(3, &[coin_bytes("uatom", "1")]);
        let mut vote = ProtoWriter::new();
        vote.uint64(1, 848).string(2, FROM).int32(3, 1);
        let mut no_recipient = ProtoWriter::new();
        no_recipient
            .string(1, FROM)
            .repeated_message(3, &[coin_bytes("uatom", "1")]);
        let doc = hand_built_doc(vec![
            any_of("/cosmos.bank.v1beta1.MsgSend", send.as_bytes()),
            any_of("/cosmos.gov.v1.MsgVote", vote.as_bytes()),
            any_of("/cosmos.authz.v1beta1.MsgGrant", &[1, 2, 3]),
            any_of("/cosmos.bank.v1beta1.MsgSend", no_recipient.as_bytes()),
        ]);

        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert_eq!(
            decoded.type_urls,
            vec![
                "/cosmos.bank.v1beta1.MsgSend",
                "/cosmos.gov.v1.MsgVote",
                "/cosmos.authz.v1beta1.MsgGrant",
                "/cosmos.bank.v1beta1.MsgSend",
            ]
        );
        assert_eq!(decoded.type_urls.len(), decoded.msgs.len());
        assert!(matches!(decoded.msgs[1], DecodedMsg::Vote { .. }));
        for index in [2, 3] {
            match &decoded.msgs[index] {
                DecodedMsg::Unknown { type_url, .. } => {
                    assert_eq!(type_url, &decoded.type_urls[index]);
                }
                other => panic!("message {index} decoded as {other:?}"),
            }
        }

        // And a transaction the wallet built itself reports the builder's own type URLs.
        let built = round_trip(
            vec![
                Msg::WithdrawDelegatorReward {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                },
                Msg::Vote {
                    proposal_id: 848,
                    voter: FROM.to_owned(),
                    option: VoteOption::Yes,
                },
            ],
            "",
        );
        assert_eq!(
            built.type_urls,
            vec![
                "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward",
                "/cosmos.gov.v1beta1.MsgVote",
            ]
        );
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

    const OSMO: &str = "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8";
    const ATOM: &str = "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2";
    const OUT: &str = "ibc/794C7D7F3B857713878A3A1927251FA6AC1EEE520424C1F6FAFE9BA26D476138";
    const SWAP: &str = "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn";
    const SPLIT: &str = "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn";

    fn hop(pool_id: u64, token_out_denom: &str) -> SwapAmountInRoute {
        SwapAmountInRoute {
            pool_id,
            token_out_denom: token_out_denom.to_owned(),
        }
    }

    fn hop_bytes(pool_id: u64, token_out_denom: &str) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer.uint64(1, pool_id).string(2, token_out_denom);
        writer.into_bytes()
    }

    fn coin_bytes(denom: &str, amount: &str) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer.string(1, denom).string(2, amount);
        writer.into_bytes()
    }

    /// A `MsgSwapExactAmountIn` assembled by hand, so a test can break it in ways no encoder
    /// would: a missing coin, a minimum written twice.
    fn swap_bytes(hops: &[Vec<u8>], token_in: Option<Vec<u8>>, minimums: &[&str]) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer.string(1, OSMO).repeated_message(2, hops);
        if let Some(coin) = token_in {
            writer.message_always(3, &coin);
        }
        for minimum in minimums {
            writer.string(4, minimum);
        }
        writer.into_bytes()
    }

    fn split_leg_bytes(hops: &[Vec<u8>], amounts: &[&str]) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer.repeated_message(1, hops);
        for amount in amounts {
            writer.string(2, amount);
        }
        writer.into_bytes()
    }

    fn split_bytes(legs: &[Vec<u8>], minimum: &str) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer
            .string(1, OSMO)
            .repeated_message(2, legs)
            .string(3, "uosmo")
            .string(4, minimum);
        writer.into_bytes()
    }

    fn decode_one(type_url: &str, value: &[u8]) -> DecodedMsg {
        let decoded =
            decode_direct_sign_doc(&hand_built_doc(vec![any_of(type_url, value)])).unwrap();
        assert_eq!(decoded.has_unknown_msgs, decoded.msgs[0].is_unknown());
        decoded.msgs[0].clone()
    }

    #[test]
    fn a_dapp_swap_decodes_into_a_named_swap() {
        // How the Osmosis app's swap reaches the wallet: SIGN_MODE_DIRECT bytes, built by
        // someone else. The golden vectors cover osmojs's own bytes; this pins the fields.
        let decoded = decode_one(
            SWAP,
            &swap_bytes(
                &[hop_bytes(3586, OUT)],
                Some(coin_bytes("uosmo", "9950000")),
                &["350000"],
            ),
        );
        assert_eq!(
            decoded,
            DecodedMsg::SwapExactAmountIn {
                sender: OSMO.to_owned(),
                routes: vec![hop(3586, OUT)],
                token_in: Some(Coin::new("uosmo", "9950000").unwrap()),
                token_out_min_amount: "350000".to_owned(),
            }
        );
        assert_eq!(
            decoded.summary(),
            format!("Swap 9950000 uosmo for at least 350000 {OUT} through pool 3586")
        );
        assert_eq!(decoded.addresses(), vec![OSMO]);

        let decoded = decode_one(
            SPLIT,
            &split_bytes(
                &[
                    split_leg_bytes(&[hop_bytes(3498, OUT)], &["5970000"]),
                    split_leg_bytes(&[hop_bytes(3586, OUT)], &["3980000"]),
                ],
                "350000",
            ),
        );
        assert!(!decoded.is_unknown(), "got {decoded:?}");
        assert_eq!(
            decoded.summary(),
            format!(
                "Swap 9950000 uosmo for at least 350000 {OUT} through 2 routes (pools 3498; 3586)"
            )
        );
    }

    #[test]
    fn a_swap_whose_minimum_is_written_twice_is_not_treated_as_understood() {
        // The chain keeps the last value of a repeated singular field and this decoder would
        // otherwise read the first, so the prompt could promise a floor of 350000 for a swap
        // that executes with a floor of 1.
        let decoded = decode_one(
            SWAP,
            &swap_bytes(
                &[hop_bytes(3586, OUT)],
                Some(coin_bytes("uosmo", "9950000")),
                &["350000", "1"],
            ),
        );
        assert!(decoded.is_unknown(), "got {decoded:?}");

        let decoded = decode_one(SPLIT, &{
            let mut writer = ProtoWriter::new();
            writer
                .string(1, OSMO)
                .repeated_message(2, &[split_leg_bytes(&[hop_bytes(3586, OUT)], &["9950000"])])
                .string(3, "uosmo")
                .string(4, "350000")
                .string(4, "1");
            writer.into_bytes()
        });
        assert!(decoded.is_unknown(), "got {decoded:?}");
    }

    #[test]
    fn any_repeated_singular_field_in_a_swap_is_refused() {
        // Every level: the message, the coin, a hop, a split leg.
        let doubled_sender = {
            let mut writer = ProtoWriter::new();
            writer
                .string(1, OSMO)
                .string(1, "osmo1jrkmdcwgq94uaamx6zax2luewlhf7u4kufy8q2")
                .repeated_message(2, &[hop_bytes(3586, OUT)])
                .message_always(3, &coin_bytes("uosmo", "9950000"))
                .string(4, "350000");
            writer.into_bytes()
        };
        let doubled_coin = swap_bytes(
            &[hop_bytes(3586, OUT)],
            Some({
                let mut writer = ProtoWriter::new();
                writer
                    .string(1, "uosmo")
                    .string(2, "1")
                    .string(2, "9950000");
                writer.into_bytes()
            }),
            &["350000"],
        );
        let doubled_pool = swap_bytes(
            &[{
                let mut writer = ProtoWriter::new();
                writer.uint64(1, 3586).uint64(1, 3498).string(2, OUT);
                writer.into_bytes()
            }],
            Some(coin_bytes("uosmo", "9950000")),
            &["350000"],
        );
        let doubled_token_in = {
            let mut writer = ProtoWriter::new();
            writer
                .string(1, OSMO)
                .repeated_message(2, &[hop_bytes(3586, OUT)])
                .message_always(3, &coin_bytes("uosmo", "1"))
                .message_always(3, &coin_bytes("uosmo", "9950000"))
                .string(4, "350000");
            writer.into_bytes()
        };
        for (label, bytes) in [
            ("sender", doubled_sender),
            ("coin amount", doubled_coin),
            ("pool id", doubled_pool),
            ("token_in", doubled_token_in),
        ] {
            assert!(
                decode_one(SWAP, &bytes).is_unknown(),
                "a repeated {label} was presented as understood"
            );
        }

        let doubled_leg_amount = split_bytes(
            &[split_leg_bytes(&[hop_bytes(3586, OUT)], &["1", "9950000"])],
            "350000",
        );
        assert!(decode_one(SPLIT, &doubled_leg_amount).is_unknown());
    }

    #[test]
    fn a_swap_with_no_floor_is_not_treated_as_understood() {
        // "for at least 0" reads like a number and means "at any price". The chain refuses it
        // as well, but a prompt that describes it confidently is still describing a blank cheque.
        for minimums in [&["0"][..], &[][..]] {
            let decoded = decode_one(
                SWAP,
                &swap_bytes(
                    &[hop_bytes(3586, OUT)],
                    Some(coin_bytes("uosmo", "9950000")),
                    minimums,
                ),
            );
            assert!(decoded.is_unknown(), "{minimums:?}: got {decoded:?}");
            assert!(decoded.summary().contains("UNKNOWN ACTION"));
        }
        let decoded = decode_one(
            SPLIT,
            &split_bytes(
                &[split_leg_bytes(&[hop_bytes(3586, OUT)], &["9950000"])],
                "0",
            ),
        );
        assert!(decoded.is_unknown(), "got {decoded:?}");
    }

    #[test]
    fn a_swap_the_chain_could_not_execute_is_not_treated_as_understood() {
        let coin = || Some(coin_bytes("uosmo", "9950000"));
        let too_long: Vec<Vec<u8>> = (1..=crate::msg::MAX_SWAP_HOPS as u64 + 1)
            .map(|id| hop_bytes(id, OUT))
            .collect();
        let pool_id_as_bytes = {
            let mut writer = ProtoWriter::new();
            writer.bytes(1, &[0x82, 0x1c]).string(2, OUT);
            writer.into_bytes()
        };
        let singles: Vec<(&str, Vec<u8>)> = vec![
            ("no route", swap_bytes(&[], coin(), &["350000"])),
            (
                "pool 0",
                swap_bytes(&[hop_bytes(0, OUT)], coin(), &["350000"]),
            ),
            (
                "an empty denom",
                swap_bytes(&[hop_bytes(3586, "")], coin(), &["350000"]),
            ),
            (
                "a control character in a denom",
                swap_bytes(&[hop_bytes(3586, "ibc/794C\u{0}")], coin(), &["350000"]),
            ),
            (
                "no token_in",
                swap_bytes(&[hop_bytes(3586, OUT)], None, &["350000"]),
            ),
            (
                "a zero token_in",
                swap_bytes(
                    &[hop_bytes(3586, OUT)],
                    Some(coin_bytes("uosmo", "0")),
                    &["350000"],
                ),
            ),
            (
                "a token_in with no amount",
                swap_bytes(
                    &[hop_bytes(3586, OUT)],
                    Some({
                        let mut writer = ProtoWriter::new();
                        writer.string(1, "uosmo");
                        writer.into_bytes()
                    }),
                    &["350000"],
                ),
            ),
            (
                "a non-canonical minimum",
                swap_bytes(&[hop_bytes(3586, OUT)], coin(), &["0350000"]),
            ),
            (
                "a route over the cap",
                swap_bytes(&too_long, coin(), &["350000"]),
            ),
            (
                "a pool id with the wrong wire type",
                swap_bytes(&[pool_id_as_bytes], coin(), &["350000"]),
            ),
        ];
        for (label, bytes) in singles {
            assert!(
                decode_one(SWAP, &bytes).is_unknown(),
                "a swap with {label} was presented as understood"
            );
        }

        let splits: Vec<(&str, Vec<Vec<u8>>)> = vec![
            ("no legs", vec![]),
            ("a leg with no pools", vec![split_leg_bytes(&[], &["1"])]),
            (
                "a leg that spends nothing",
                vec![split_leg_bytes(&[hop_bytes(3586, OUT)], &["0"])],
            ),
            (
                "legs ending in different denoms",
                vec![
                    split_leg_bytes(&[hop_bytes(3498, OUT)], &["6000000"]),
                    split_leg_bytes(&[hop_bytes(1, ATOM)], &["4000000"]),
                ],
            ),
            (
                "the same legs twice",
                vec![
                    split_leg_bytes(&[hop_bytes(3498, OUT)], &["6000000"]),
                    split_leg_bytes(&[hop_bytes(3498, OUT)], &["4000000"]),
                ],
            ),
        ];
        for (label, legs) in splits {
            assert!(
                decode_one(SPLIT, &split_bytes(&legs, "350000")).is_unknown(),
                "a split swap with {label} was presented as understood"
            );
        }
    }

    #[test]
    fn a_swap_from_a_sender_that_is_not_bech32_is_not_treated_as_understood() {
        let mut writer = ProtoWriter::new();
        writer
            .string(1, "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df9")
            .repeated_message(2, &[hop_bytes(3586, OUT)])
            .message_always(3, &coin_bytes("uosmo", "9950000"))
            .string(4, "350000");
        assert!(decode_one(SWAP, writer.as_bytes()).is_unknown());
    }

    /* ------------------------------------------------------------------------------------ *
     * A singular field written twice
     * ------------------------------------------------------------------------------------ */

    use crate::proto::{Field, FieldValue};

    /// Re-encodes a decoded field list exactly, zero values and empty bytes included. The
    /// wallet's encoders write minimal varints in field order, so decoding a document and
    /// re-encoding it reproduces it byte for byte, which `the_rewriter_is_faithful` pins.
    fn encode_raw(fields: &[Field]) -> Vec<u8> {
        fn varint(out: &mut Vec<u8>, mut value: u64) {
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                if value == 0 {
                    out.push(byte);
                    return;
                }
                out.push(byte | 0x80);
            }
        }
        let mut out = Vec::new();
        for field in fields {
            match &field.value {
                FieldValue::Varint(value) => {
                    varint(&mut out, u64::from(field.tag) << 3);
                    varint(&mut out, *value);
                }
                FieldValue::Bytes(bytes) => {
                    varint(&mut out, (u64::from(field.tag) << 3) | 2);
                    varint(&mut out, bytes.len() as u64);
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }

    /// Follows `path`, field numbers from the outside in, and gives the field at its end a
    /// second occurrence directly after the first, re-framing every enclosing message. The second
    /// occurrence carries `second`, or repeats the first's value when that is `None`.
    fn with_second(bytes: &[u8], path: &[u32], second: Option<FieldValue>) -> Vec<u8> {
        let mut fields = decode_fields(bytes).unwrap();
        let index = fields
            .iter()
            .position(|field| field.tag == path[0])
            .unwrap_or_else(|| panic!("field {} is not in this message", path[0]));
        if path.len() == 1 {
            let value = second.unwrap_or_else(|| fields[index].value.clone());
            fields.insert(
                index + 1,
                Field {
                    tag: path[0],
                    value,
                },
            );
        } else {
            let inner = with_second(fields[index].value.as_bytes().unwrap(), &path[1..], second);
            fields[index].value = FieldValue::Bytes(inner);
        }
        encode_raw(&fields)
    }

    /// Appends `field` to the message at `path`, for fields the wallet's encoders never write,
    /// such as a fee payer. Called twice, it writes the field twice.
    fn with_field(bytes: &[u8], path: &[u32], field: Field) -> Vec<u8> {
        let mut fields = decode_fields(bytes).unwrap();
        match path.split_first() {
            None => fields.push(field),
            Some((&tag, rest)) => {
                let index = fields.iter().position(|f| f.tag == tag).unwrap();
                let inner = with_field(fields[index].value.as_bytes().unwrap(), rest, field);
                fields[index].value = FieldValue::Bytes(inner);
            }
        }
        encode_raw(&fields)
    }

    fn doc_of(msgs: Vec<Msg>, memo: &str) -> Vec<u8> {
        UnsignedTx::new(
            msgs,
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            memo,
        )
        .unwrap()
        .sign_bytes(&signer(), SignMode::Direct)
        .unwrap()
    }

    /// Where a message's own fields sit inside a `SignDoc`: body_bytes 1, the first Any in
    /// messages 1, its value 2.
    const MSG: [u32; 3] = [1, 1, 2];

    fn at(path: &[u32]) -> Vec<u32> {
        MSG.iter().chain(path).copied().collect()
    }

    /// Every message the decoder knows, built by the wallet's own encoders with every field set,
    /// alongside the field numbers its proto declares singular. Repeated fields (a send's coins,
    /// a contract call's funds, a swap's routes) are left out: two coins are two coins.
    fn every_known_message() -> Vec<(Msg, &'static [u32])> {
        vec![
            (
                Msg::Send {
                    from_address: FROM.to_owned(),
                    to_address: TO.to_owned(),
                    amount: vec![Coin::new("uatom", "1000000").unwrap()],
                },
                &[1, 2],
            ),
            (
                Msg::Delegate {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                    amount: Coin::new("uatom", "5000000").unwrap(),
                },
                &[1, 2, 3],
            ),
            (
                Msg::Undelegate {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                    amount: Coin::new("uatom", "1000000").unwrap(),
                },
                &[1, 2, 3],
            ),
            (
                Msg::BeginRedelegate {
                    delegator_address: FROM.to_owned(),
                    validator_src_address: VALOPER.to_owned(),
                    validator_dst_address: VALOPER.to_owned(),
                    amount: Coin::new("uatom", "1000000").unwrap(),
                },
                &[1, 2, 3, 4],
            ),
            (
                Msg::WithdrawDelegatorReward {
                    delegator_address: FROM.to_owned(),
                    validator_address: VALOPER.to_owned(),
                },
                &[1, 2],
            ),
            (
                Msg::Vote {
                    proposal_id: 848,
                    voter: FROM.to_owned(),
                    option: VoteOption::Yes,
                },
                &[1, 2, 3],
            ),
            (
                // Every field set, timeouts and memo included, so all eight are on the wire.
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
                &[1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                Msg::ExecuteContract {
                    sender: FROM.to_owned(),
                    contract: TO.to_owned(),
                    msg: br#"{"swap":{"offer":"100"}}"#.to_vec(),
                    funds: vec![Coin::new("uatom", "100").unwrap()],
                },
                &[1, 2, 3],
            ),
            (
                Msg::SwapExactAmountIn {
                    sender: OSMO.to_owned(),
                    routes: vec![hop(1, ATOM), hop(3586, OUT)],
                    token_in: Coin::new("uosmo", "10000000").unwrap(),
                    token_out_min_amount: "340000".to_owned(),
                },
                &[1, 3, 4],
            ),
            (
                Msg::SplitRouteSwapExactAmountIn {
                    sender: OSMO.to_owned(),
                    routes: vec![
                        SwapAmountInSplitRoute {
                            pools: vec![hop(3498, OUT)],
                            token_in_amount: "6000000".to_owned(),
                        },
                        SwapAmountInSplitRoute {
                            pools: vec![hop(1, ATOM), hop(3586, OUT)],
                            token_in_amount: "4000000".to_owned(),
                        },
                    ],
                    token_in_denom: "uosmo".to_owned(),
                    token_out_min_amount: "350000".to_owned(),
                },
                &[1, 3, 4],
            ),
        ]
    }

    #[track_caller]
    fn assert_not_understood(doc: &[u8], what: &str) {
        let decoded = decode_direct_sign_doc(doc).unwrap_or_else(|e| {
            panic!("{what}: refused outright ({e}), expected an unknown message")
        });
        assert!(
            decoded.msgs[0].is_unknown(),
            "{what} was presented as understood: {:?}",
            decoded.msgs[0]
        );
        assert!(decoded.has_unknown_msgs, "{what}");
        assert!(!decoded.is_safe_to_sign_without_blind_signing(), "{what}");
        assert!(
            decoded.summaries()[0].starts_with("UNKNOWN ACTION"),
            "{what}"
        );
    }

    #[track_caller]
    fn assert_refused(doc: &[u8], what: &str) {
        assert!(
            decode_direct_sign_doc(doc).is_err(),
            "{what} was not refused: {:?}",
            decode_direct_sign_doc(doc)
        );
    }

    #[test]
    fn the_rewriter_is_faithful() {
        // The helpers above rebuild documents from decoded fields. Unless that is the identity on
        // an untouched document, a refusal below could be the rewriter's fault rather than the
        // duplicate's.
        for (msg, _) in every_known_message() {
            let doc = doc_of(vec![msg], "memo");
            assert_eq!(encode_raw(&decode_fields(&doc).unwrap()), doc);
            assert_eq!(
                with_field(
                    &doc,
                    &[],
                    Field {
                        tag: 9,
                        value: FieldValue::Varint(1)
                    }
                )[..doc.len()],
                doc[..]
            );
        }
    }

    #[test]
    fn every_singular_field_of_every_message_written_twice_is_not_understood() {
        for (msg, singular) in every_known_message() {
            let doc = doc_of(vec![msg.clone()], "");
            let untouched = decode_direct_sign_doc(&doc).unwrap();
            assert!(
                !untouched.has_unknown_msgs,
                "{} must decode before it is broken",
                msg.type_url()
            );

            for &tag in singular {
                assert_not_understood(
                    &with_second(&doc, &at(&[tag]), None),
                    &format!("{} with field {tag} twice", msg.type_url()),
                );
            }
        }
    }

    #[test]
    fn a_coin_written_with_two_amounts_or_two_denoms_is_not_understood_anywhere() {
        // The coin inside each message that carries one: a send's first coin, a delegation's
        // amount, a transfer's token, a contract call's first fund, a swap's input.
        let coin_fields: [(usize, u32); 7] =
            [(0, 3), (1, 3), (2, 3), (3, 4), (6, 3), (7, 5), (8, 3)];
        let messages = every_known_message();
        for (index, coin_tag) in coin_fields {
            let msg = messages[index].0.clone();
            let doc = doc_of(vec![msg.clone()], "");
            for coin_field in [1, 2] {
                assert_not_understood(
                    &with_second(&doc, &at(&[coin_tag, coin_field]), None),
                    &format!("{} with a coin field {coin_field} twice", msg.type_url()),
                );
            }
        }
    }

    #[test]
    fn nested_singular_fields_are_held_to_the_same_rule() {
        let messages = every_known_message();

        // MsgTransfer's timeout height: revision_number 1, revision_height 2.
        let transfer = doc_of(vec![messages[6].0.clone()], "");
        for counter in [1, 2] {
            assert_not_understood(
                &with_second(&transfer, &at(&[6, counter]), Some(FieldValue::Varint(1))),
                &format!("a transfer whose timeout height has field {counter} twice"),
            );
        }

        // A swap hop's pool_id and token_out_denom, and a split leg's token_in_amount and the
        // pool ids inside it.
        let swap = doc_of(vec![messages[8].0.clone()], "");
        for hop_field in [1, 2] {
            assert_not_understood(
                &with_second(&swap, &at(&[2, hop_field]), None),
                &format!("a swap hop with field {hop_field} twice"),
            );
        }
        let split = doc_of(vec![messages[9].0.clone()], "");
        assert_not_understood(
            &with_second(&split, &at(&[2, 2]), None),
            "a split leg with two token_in_amounts",
        );
        assert_not_understood(
            &with_second(&split, &at(&[2, 1, 1]), Some(FieldValue::Varint(3586))),
            "a split leg hop with two pool ids",
        );

        // gov v1's MsgVote adds metadata 4, which the prompt does not show.
        let mut vote = ProtoWriter::new();
        vote.uint64(1, 848)
            .string(2, FROM)
            .int32(3, 1)
            .string(4, "first")
            .string(4, "second");
        let doc = hand_built_doc(vec![any_of("/cosmos.gov.v1.MsgVote", vote.as_bytes())]);
        assert_not_understood(&doc, "a gov v1 vote with two metadata fields");
    }

    #[test]
    fn a_send_with_two_recipients_is_not_treated_as_understood() {
        // The attack the rule exists for: the recipient a first-occurrence reader shows, then
        // the one the chain pays.
        let doc = doc_of(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1000000").unwrap()],
            }],
            "",
        );
        let attacker = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
        let forged = with_second(
            &doc,
            &at(&[2]),
            Some(FieldValue::Bytes(attacker.as_bytes().to_vec())),
        );
        assert_not_understood(&forged, "a MsgSend with two to_address fields");
        assert!(!decode_direct_sign_doc(&forged).unwrap().summaries()[0].contains(TO));

        // And a coin whose second amount is the real one.
        let forged = with_second(
            &doc,
            &at(&[3, 2]),
            Some(FieldValue::Bytes(b"999999999999".to_vec())),
        );
        assert_not_understood(&forged, "a MsgSend whose coin has two amounts");
    }

    #[test]
    fn an_any_with_two_type_urls_or_two_values_is_refused_outright() {
        // The worst case: the prompt would name one message while the chain ran another, and
        // there is no honest name to give the result, so the document is refused rather than
        // shown with an unknown message.
        let doc = doc_of(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1").unwrap()],
            }],
            "",
        );
        assert_refused(
            &with_second(
                &doc,
                &[1, 1, 1],
                Some(FieldValue::Bytes(b"/cosmos.authz.v1beta1.MsgExec".to_vec())),
            ),
            "an Any with two type URLs",
        );
        assert_refused(
            &with_second(&doc, &[1, 1, 1], None),
            "an Any with its type URL twice",
        );
        assert_refused(
            &with_second(&doc, &[1, 1, 2], None),
            "an Any with two values",
        );
    }

    #[test]
    fn a_repeated_field_in_the_envelope_refuses_the_whole_document() {
        let mut tx = UnsignedTx::new(
            vec![Msg::Send {
                from_address: FROM.to_owned(),
                to_address: TO.to_owned(),
                amount: vec![Coin::new("uatom", "1").unwrap()],
            }],
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            "deposit-id:1234567890",
        )
        .unwrap();
        tx.timeout_height = 20_000_000;
        let doc = tx.sign_bytes(&signer(), SignMode::Direct).unwrap();
        assert!(decode_direct_sign_doc(&doc).is_ok(), "the control decodes");

        let bytes = |value: &str| Some(FieldValue::Bytes(value.as_bytes().to_vec()));
        for (path, second, what) in [
            // SignDoc: body_bytes, auth_info_bytes, chain_id, account_number.
            (vec![1], None, "a SignDoc with two bodies"),
            (vec![2], None, "a SignDoc with two auth infos"),
            (vec![3], bytes("osmosis-1"), "a SignDoc with two chain ids"),
            (
                vec![4],
                Some(FieldValue::Varint(1)),
                "a SignDoc with two account numbers",
            ),
            // TxBody: a memo the exchange reads twice, and a timeout height.
            (
                vec![1, 2],
                bytes("deposit-id:0000000000"),
                "a TxBody with two memos",
            ),
            (
                vec![1, 3],
                Some(FieldValue::Varint(1)),
                "a TxBody with two timeout heights",
            ),
            // AuthInfo: the fee.
            (vec![2, 2], None, "an AuthInfo with two fees"),
            // Fee: the gas limit, and a fee coin's amount.
            (
                vec![2, 2, 2],
                Some(FieldValue::Varint(1)),
                "a Fee with two gas limits",
            ),
            (vec![2, 2, 1, 2], bytes("1"), "a fee coin with two amounts"),
            (
                vec![2, 2, 1, 1],
                bytes("uosmo"),
                "a fee coin with two denoms",
            ),
            // SignerInfo: public key, mode info, sequence.
            (vec![2, 1, 1], None, "a SignerInfo with two public keys"),
            (vec![2, 1, 2], None, "a SignerInfo with two mode infos"),
            (
                vec![2, 1, 3],
                Some(FieldValue::Varint(8)),
                "a SignerInfo with two sequences",
            ),
        ] {
            assert_refused(&with_second(&doc, &path, second), what);
        }

        // Singular fields the wallet never writes, written twice by someone else.
        let twice = |doc: &[u8], path: &[u32], tag: u32, value: FieldValue| {
            let once = with_field(
                doc,
                path,
                Field {
                    tag,
                    value: value.clone(),
                },
            );
            with_field(&once, path, Field { tag, value })
        };
        for (path, tag, value, what) in [
            (
                vec![1],
                4,
                FieldValue::Varint(1),
                "a TxBody with unordered twice",
            ),
            (
                vec![1],
                5,
                FieldValue::Bytes(vec![0x08, 0x01]),
                "a TxBody with two timeout timestamps",
            ),
            (
                vec![2],
                3,
                FieldValue::Bytes(vec![]),
                "an AuthInfo with two tips",
            ),
            (
                vec![2, 2],
                3,
                FieldValue::Bytes(FROM.as_bytes().to_vec()),
                "a Fee with two payers",
            ),
            (
                vec![2, 2],
                4,
                FieldValue::Bytes(TO.as_bytes().to_vec()),
                "a Fee with two granters",
            ),
        ] {
            assert_refused(&twice(&doc, &path, tag, value), what);
        }
    }

    #[test]
    fn repeated_fields_still_repeat() {
        // The rule is about singular fields. A send of two coins, two messages, a fee in two
        // denoms and a second signer are all legitimate, and still decode as before.
        let doc = doc_of(
            vec![
                Msg::Send {
                    from_address: FROM.to_owned(),
                    to_address: TO.to_owned(),
                    amount: vec![
                        Coin::new("uatom", "1").unwrap(),
                        Coin::new("uosmo", "2").unwrap(),
                    ],
                },
                Msg::ExecuteContract {
                    sender: FROM.to_owned(),
                    contract: TO.to_owned(),
                    msg: br#"{"swap":{}}"#.to_vec(),
                    funds: vec![
                        Coin::new("uatom", "3").unwrap(),
                        Coin::new("uosmo", "4").unwrap(),
                    ],
                },
            ],
            "",
        );
        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert!(decoded.is_safe_to_sign_without_blind_signing());
        assert_eq!(
            decoded.summaries()[0],
            format!("Send 1 uatom, 2 uosmo to {TO}")
        );
        assert_eq!(
            decoded.summaries()[1],
            format!("Execute \"swap\" on {TO} sending 3 uatom, 4 uosmo")
        );

        // A second fee coin and a second signer, added to the AuthInfo by hand.
        let fee_coin = {
            let mut coin = ProtoWriter::new();
            coin.string(1, "uosmo").string(2, "7");
            coin.into_bytes()
        };
        let second_signer = {
            let mut signer_info = ProtoWriter::new();
            signer_info.uint64(3, 99);
            signer_info.into_bytes()
        };
        let doc = with_field(
            &doc,
            &[2, 2],
            Field {
                tag: 1,
                value: FieldValue::Bytes(fee_coin),
            },
        );
        let doc = with_field(
            &doc,
            &[2],
            Field {
                tag: 1,
                value: FieldValue::Bytes(second_signer),
            },
        );
        let decoded = decode_direct_sign_doc(&doc).unwrap();
        assert_eq!(
            decoded.fee,
            vec![
                Coin::new("uatom", "5000").unwrap(),
                Coin::new("uosmo", "7").unwrap()
            ]
        );
        assert_eq!(
            decoded.sequence, 7,
            "the first signer's sequence, as before"
        );
        assert!(decoded.is_safe_to_sign_without_blind_signing());

        // A second signer is checked like the first: a sequence written twice inside it is a
        // duplicate, even though the prompt reads only the first signer's.
        let doubled_signer = {
            let mut signer_info = ProtoWriter::new();
            signer_info.uint64(3, 99).uint64(3, 100);
            signer_info.into_bytes()
        };
        assert_refused(
            &with_field(
                &doc,
                &[2],
                Field {
                    tag: 1,
                    value: FieldValue::Bytes(doubled_signer),
                },
            ),
            "a second SignerInfo with two sequences",
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

    /* ------------------------------------------------------------------------------------ *
     * 32-byte addresses: CosmWasm contracts and other module-derived accounts
     * ------------------------------------------------------------------------------------ */

    /// Osmosis crosschain-swaps, a real contract. wasmd derives every instantiated contract's
    /// address as 32 bytes; only an account is 20.
    const XCS: &str = "osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3sqxwvxs";

    fn execute_bytes(sender: &str, contract: &str, msg: &[u8]) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer.string(1, sender).string(2, contract).bytes(3, msg);
        writer.into_bytes()
    }

    #[test]
    fn a_call_to_a_32_byte_contract_is_understood() {
        // The regression: the contract was checked with the 20-byte account rule, so every real
        // contract call (a crosschain swap, its recovery, an NFT transfer) came back Unknown and
        // was refused unless the user had turned blind signing on.
        let decoded = decode_one(
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            &execute_bytes(OSMO, XCS, br#"{"recover":{}}"#),
        );
        assert_eq!(
            decoded,
            DecodedMsg::ExecuteContract {
                sender: OSMO.to_owned(),
                contract: XCS.to_owned(),
                msg: Some(serde_json::json!({ "recover": {} })),
                action: Some("recover".to_owned()),
                funds: vec![],
            }
        );
        assert_eq!(decoded.summary(), format!("Execute \"recover\" on {XCS}"));
    }

    #[test]
    fn the_builder_and_the_decoder_agree_on_a_32_byte_contract() {
        // The builder has accepted 32-byte contracts since a77d04b; the decoder must describe
        // what the builder builds.
        let msg = Msg::ExecuteContract {
            sender: OSMO.to_owned(),
            contract: XCS.to_owned(),
            msg: br#"{"osmosis_swap":{"output_denom":"uatom"}}"#.to_vec(),
            funds: vec![Coin::new("uosmo", "1000000").unwrap()],
        };
        assert!(msg.validate_addresses("osmo").is_ok());
        let decoded = round_trip(vec![msg.clone()], "");
        assert!(
            decoded.is_safe_to_sign_without_blind_signing(),
            "got {:?}",
            decoded.msgs
        );
        assert_eq!(decoded.summaries()[0], msg.summary());
    }

    #[test]
    fn a_send_to_a_32_byte_address_is_understood() {
        // A contract, an interchain account or a group policy receiving funds: a DAO treasury,
        // an ICA being topped up. Ordinary transfers, and 32 bytes on the same chain.
        let mut writer = ProtoWriter::new();
        writer
            .string(1, OSMO)
            .string(2, XCS)
            .repeated_message(3, &[coin_bytes("uosmo", "1")]);
        let decoded = decode_one("/cosmos.bank.v1beta1.MsgSend", writer.as_bytes());
        assert!(!decoded.is_unknown(), "got {decoded:?}");
    }

    #[test]
    fn a_contract_that_cannot_exist_on_the_signing_chain_is_not_understood() {
        for (label, contract) in [
            // The same 32 bytes under another chain's prefix.
            (
                "another chain's prefix",
                "cosmos1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3s4mk53k",
            ),
            // Neither an account nor a derived address.
            (
                "31 bytes",
                "osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcn59qqmwg",
            ),
            (
                "33 bytes",
                "osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3swy4t0nt",
            ),
            // One checksum character changed.
            (
                "a bad checksum",
                "osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3sqxwvxt",
            ),
        ] {
            let decoded = decode_one(
                "/cosmwasm.wasm.v1.MsgExecuteContract",
                &execute_bytes(OSMO, contract, br#"{"recover":{}}"#),
            );
            assert!(
                decoded.is_unknown(),
                "a contract with {label} was understood"
            );
        }
        // And the signer is still an account: a 32-byte sender is not one this wallet holds.
        let decoded = decode_one(
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            &execute_bytes(XCS, XCS, br#"{"recover":{}}"#),
        );
        assert!(decoded.is_unknown(), "a 32-byte sender was understood");
    }

    #[test]
    fn a_contract_action_that_would_rewrite_the_prompt_is_not_understood() {
        // Found in security review once 32-byte contracts decoded. Nothing on chain checks the
        // action before the contract reads it, so on a contract the requester owns, a call like
        // this one runs and keeps the 5,000 OSMO it carries. The decoder quoted the key as it was
        // and reported the call safe to sign: U+202E reversed what followed it in the prompt, and
        // U+2028 broke the line, which also hid the coins from the extension's reading of the
        // sentence.
        let call = |msg: &[u8]| {
            let mut writer = ProtoWriter::new();
            writer
                .string(1, OSMO)
                .string(2, XCS)
                .bytes(3, msg)
                .repeated_message(5, &[coin_bytes("uosmo", "5000000000")]);
            decode_one("/cosmwasm.wasm.v1.MsgExecuteContract", writer.as_bytes())
        };
        let keyed = |key: &str| call(serde_json::json!({ key: {} }).to_string().as_bytes());

        let too_long = "a".repeat(129);
        for (label, key) in [
            (
                "the reported override and line separators",
                "\u{202e}swap\u{2028}\u{2028}",
            ),
            ("a right-to-left override", "\u{202e}paws"),
            ("an isolate", "swap\u{2066}"),
            ("a paragraph separator", "swap\u{2029}"),
            ("a zero-width space", "sw\u{200b}ap"),
            ("a NUL", "swap\u{0}"),
            ("a second line", "swap\nSend 1 uosmo to osmo1friend"),
            ("a space", "swap now"),
            ("a quote", "swap\" on osmo1legit"),
            ("fullwidth letters", "ｓｗａｐ"),
            ("an accented letter", "swäp"),
            ("no name", ""),
            ("129 letters", too_long.as_str()),
        ] {
            let decoded = keyed(key);
            assert!(
                decoded.is_unknown(),
                "an action with {label} was understood: {decoded:?}"
            );
            assert!(decoded
                .summary()
                .starts_with("UNKNOWN ACTION: /cosmwasm.wasm.v1.MsgExecuteContract"));
        }

        // The key is read after JSON unescaping, so writing the override as a JSON escape changes
        // nothing, and a plain name written after it does not stand in for it.
        assert!(call(b"{\"\\u202eswap\":{}}").is_unknown());
        assert!(call(b"{\"\\u202eswap\":{},\"swap\":{}}").is_unknown());

        // The names contracts use read as before.
        for key in [
            "swap",
            "transfer_nft",
            "executeSwapOperations",
            "swap-exact-in",
        ] {
            assert_eq!(
                keyed(key).summary(),
                format!("Execute \"{key}\" on {XCS} sending 5000000000 uosmo")
            );
        }
    }

    /* ------------------------------------------------------------------------------------ *
     * Exact-out swaps
     * ------------------------------------------------------------------------------------ */

    const SWAP_OUT: &str = "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountOut";
    const SPLIT_OUT: &str = "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountOut";

    #[test]
    fn a_dapp_exact_out_swap_decodes_into_a_named_swap() {
        // osmojs 16.15 MsgSwapExactAmountOut.encode: buy 340000 of OUT through pools 1 then 3586,
        // spending at most 10 OSMO.
        let single = hex::decode("0a2b6f736d6f3139726c34636d32686d7238616679346b6c6470787a33666b61346a6775713061356d37646638120908011205756f736d6f124908821c12446962632f323733393446423039324432454343443536313233433734463336453443314639323630303143454144413943413937454136323242323546343145354542321a083130303030303030224e0a446962632f373934433744374633423835373731333837384133413139323732353146413641433145454535323034323443314636464146453942413236443437363133381206333430303030").unwrap();
        let decoded = decode_one(SWAP_OUT, &single);
        assert!(!decoded.is_unknown(), "got {decoded:?}");
        assert_eq!(
            decoded.summary(),
            format!("Swap at most 10000000 uosmo for exactly 340000 {OUT} through pools 1 → 3586")
        );
        assert_eq!(decoded.addresses(), vec![OSMO]);

        // osmojs MsgSplitRouteSwapExactAmountOut.encode: 210000 through 3498, 140000 through 3586.
        let split = hex::decode("0a2b6f736d6f3139726c34636d32686d7238616679346b6c6470787a33666b61346a6775713061356d3764663812140a0a08aa1b1205756f736d6f120632313030303012140a0a08821c1205756f736d6f12063134303030301a446962632f3739344337443746334238353737313338373841334131393237323531464136414331454545353230343234433146364641464539424132364434373631333822083130303030303030").unwrap();
        let decoded = decode_one(SPLIT_OUT, &split);
        assert!(!decoded.is_unknown(), "got {decoded:?}");
        assert_eq!(
            decoded.summary(),
            format!(
                "Swap at most 10000000 uosmo for exactly 350000 {OUT} through 2 routes (pools 3498; 3586)"
            )
        );
    }

    fn out_swap_bytes(hops: &[Vec<u8>], ceilings: &[&str], token_out: Option<Vec<u8>>) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer.string(1, OSMO).repeated_message(2, hops);
        for ceiling in ceilings {
            writer.string(3, ceiling);
        }
        if let Some(coin) = token_out {
            writer.message_always(4, &coin);
        }
        writer.into_bytes()
    }

    #[test]
    fn an_exact_out_swap_the_chain_would_refuse_is_not_understood() {
        // The wire shape of SwapAmountOutRoute is SwapAmountInRoute's: pool_id 1, a denom 2.
        let route = || vec![hop_bytes(1, "uosmo")];
        let out = || Some(coin_bytes(OUT, "340000"));
        for (label, bytes) in [
            ("a zero ceiling", out_swap_bytes(&route(), &["0"], out())),
            ("no ceiling", out_swap_bytes(&route(), &[], out())),
            // The chain keeps the last value: the prompt must not promise the first.
            (
                "a ceiling written twice",
                out_swap_bytes(&route(), &["1", "999999999999"], out()),
            ),
            (
                "nothing out",
                out_swap_bytes(&route(), &["10000000"], Some(coin_bytes(OUT, "0"))),
            ),
            (
                "no token_out",
                out_swap_bytes(&route(), &["10000000"], None),
            ),
            ("no route", out_swap_bytes(&[], &["10000000"], out())),
            (
                "pool 0",
                out_swap_bytes(&[hop_bytes(0, "uosmo")], &["10000000"], out()),
            ),
        ] {
            assert!(
                decode_one(SWAP_OUT, &bytes).is_unknown(),
                "an exact-out swap with {label} was presented as understood"
            );
        }

        let split = |legs: &[Vec<u8>], ceiling: &str| {
            let mut writer = ProtoWriter::new();
            writer
                .string(1, OSMO)
                .repeated_message(2, legs)
                .string(3, OUT)
                .string(4, ceiling);
            writer.into_bytes()
        };
        let leg = |pool: u64, denom: &str, amount: &str| {
            let mut writer = ProtoWriter::new();
            writer
                .repeated_message(1, &[hop_bytes(pool, denom)])
                .string(2, amount);
            writer.into_bytes()
        };
        for (label, bytes) in [
            ("a zero ceiling", split(&[leg(3498, "uosmo", "1")], "0")),
            (
                "a leg that delivers nothing",
                split(&[leg(3498, "uosmo", "0")], "10"),
            ),
            (
                "legs spending different denoms",
                split(&[leg(3498, "uosmo", "1"), leg(1, ATOM, "1")], "10"),
            ),
            (
                "the same legs twice",
                split(&[leg(3498, "uosmo", "1"), leg(3498, "uosmo", "2")], "10"),
            ),
        ] {
            assert!(
                decode_one(SPLIT_OUT, &bytes).is_unknown(),
                "a split exact-out swap with {label} was presented as understood"
            );
        }
    }
}
