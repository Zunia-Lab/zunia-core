//! The message set a wallet needs, each with both encodings.
//!
//! Every message implements `type_url` (protobuf `Any`), `amino_type` (the Amino registry
//! name), `encode_proto` and `encode_amino`. Both encodings are asserted against golden
//! vectors, because a message that encodes correctly in one mode and not the other fails only
//! on the chains that use the other mode.
//!
//! # The Amino name trap
//!
//! Amino type names are not derived from proto type URLs, they are registered separately, and
//! several differ in ways that look like typos:
//!
//! | Proto | Amino |
//! |---|---|
//! | `MsgWithdrawDelegatorReward` | `cosmos-sdk/MsgWithdrawDelegationReward` |
//! | `MsgSwapExactAmountIn` | `osmosis/poolmanager/swap-exact-amount-in` |
//! | `MsgSplitRouteSwapExactAmountIn` | `osmosis/poolmanager/split-amount-in` |
//!
//! `Delegator` in protobuf, `Delegation` in Amino. Osmosis registers kebab-case names under a
//! module path, and the split swap's drops "route", "swap" and "exact" altogether. Deriving one
//! name from the other produces a signature the chain rejects, and the mistake is nearly
//! invisible on review, so the names are written out literally and pinned by test.
//!
//! # Osmosis swaps
//!
//! [`Msg::SwapExactAmountIn`] and [`Msg::SplitRouteSwapExactAmountIn`] are the poolmanager's own
//! swap messages, the ones the Osmosis app signs, and they reach any pair its router can price.
//! Their proto is `osmosis/poolmanager/v1beta1/tx.proto`, their Amino names are registered in the
//! poolmanager's `codec.go`, and both encodings are pinned to osmojs, whose telescope-generated
//! encoders and Amino converters are what that app signs with.
//!
//! A swap is checked before it is built, described or signed. Every rule in the poolmanager's
//! `ValidateBasic` is enforced here, a positive minimum output among them, so a swap the chain
//! would refuse after the user approved it is refused first. Three rules are the wallet's own:
//! pool 0 is refused and so is a split leg that spends nothing, both of which the chain only
//! discovers mid-execution, and route length and split count are capped, which the chain does
//! not do at all. See [`validate_swap_exact_amount_in`] and
//! [`validate_split_route_swap_exact_amount_in`].

use serde_json::{json, Value};

use crate::amino::{object_omit_empty, typed};
use crate::amount::{add_amounts, validate_amount, validate_denom, Coin};
use crate::error::{CosmosError, Result};
use crate::proto::ProtoWriter;

/// A governance vote option, `cosmos.gov.v1beta1.VoteOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteOption {
    Yes = 1,
    Abstain = 2,
    No = 3,
    NoWithVeto = 4,
}

impl VoteOption {
    /// The Amino JSON spelling, which is the full enum name and not the short form.
    pub fn amino_name(self) -> &'static str {
        match self {
            Self::Yes => "VOTE_OPTION_YES",
            Self::Abstain => "VOTE_OPTION_ABSTAIN",
            Self::No => "VOTE_OPTION_NO",
            Self::NoWithVeto => "VOTE_OPTION_NO_WITH_VETO",
        }
    }

    /// Short label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Yes => "Yes",
            Self::Abstain => "Abstain",
            Self::No => "No",
            Self::NoWithVeto => "No with veto",
        }
    }
}

/// An IBC timeout height, `ibc.core.client.v1.Height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Height {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl Height {
    pub fn is_zero(&self) -> bool {
        self.revision_number == 0 && self.revision_height == 0
    }

    fn encode_proto(&self) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer
            .uint64(1, self.revision_number)
            .uint64(2, self.revision_height);
        writer.into_bytes()
    }

    fn encode_amino(&self) -> Value {
        // Both fields are omitempty in the SDK, so a zero height serialises as `{}` rather
        // than as explicit zeros.
        object_omit_empty([
            ("revision_number", stringify_nonzero(self.revision_number)),
            ("revision_height", stringify_nonzero(self.revision_height)),
        ])
    }
}

fn stringify_nonzero(value: u64) -> Value {
    if value == 0 {
        Value::Null
    } else {
        Value::String(value.to_string())
    }
}

/// The most pools one swap route may pass through.
///
/// Not a chain limit: the poolmanager's `ValidateBasic` accepts a route of any length. It bounds
/// what an untrusted caller can make the wallet parse and what a signing prompt has to render,
/// and it sits at twice what Osmosis's own router produces, which stops a route at four pools.
pub const MAX_SWAP_HOPS: usize = 8;

/// The most legs a split-route swap may divide its input across.
///
/// Not a chain limit either. Osmosis's router splits a swap across at most three routes, so
/// sixteen leaves room for any aggregator while keeping the prompt's list of pools short enough
/// that a user reads all of it.
pub const MAX_SWAP_SPLITS: usize = 16;

/// One hop of an Osmosis swap, `osmosis.poolmanager.v1beta1.SwapAmountInRoute`.
///
/// Names the pool to swap through and the denom that comes out of it. The denom going in is
/// implicit: the swap's input for the first hop, the previous hop's output after that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapAmountInRoute {
    pub pool_id: u64,
    pub token_out_denom: String,
}

impl SwapAmountInRoute {
    fn encode_proto(&self) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer
            .uint64(1, self.pool_id)
            .string(2, &self.token_out_denom);
        writer.into_bytes()
    }

    fn encode_amino(&self) -> Value {
        // A uint64, so quoted like every other 64-bit integer in an Amino document.
        object_omit_empty([
            ("pool_id", stringify_nonzero(self.pool_id)),
            ("token_out_denom", json!(self.token_out_denom)),
        ])
    }
}

/// One leg of a split swap, `osmosis.poolmanager.v1beta1.SwapAmountInSplitRoute`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapAmountInSplitRoute {
    /// The pools this leg passes through, in order.
    pub pools: Vec<SwapAmountInRoute>,
    /// This leg's share of the input, a `cosmossdk.io/math.Int` as a decimal string. The shares
    /// add up to the whole amount swapped; there is no separate total on the wire.
    pub token_in_amount: String,
}

impl SwapAmountInSplitRoute {
    fn encode_proto(&self) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        writer
            .repeated_message(1, &encode_hops(&self.pools))
            .string(2, &self.token_in_amount);
        writer.into_bytes()
    }

    fn encode_amino(&self) -> Value {
        object_omit_empty([
            ("pools", amino_hops(&self.pools)),
            ("token_in_amount", json!(self.token_in_amount)),
        ])
    }
}

/// The rules a single-route swap must meet before the wallet builds, describes or signs it.
///
/// The poolmanager's `ValidateBasic` for `MsgSwapExactAmountIn`, plus the wallet's own rules:
///
/// - `routes` is not empty, and passes through at most [`MAX_SWAP_HOPS`] pools;
/// - no hop names pool 0, which does not exist, and every `token_out_denom` is a valid denom;
/// - `token_in` is a valid coin of more than zero;
/// - `token_out_min_amount` is a canonical integer greater than zero.
///
/// The last is the one that protects the user. The minimum output is the only price limit a
/// swap carries, and a swap without one is a blank cheque: whoever orders the block, or
/// sandwiches the transaction, decides what it returns. The chain's `ValidateBasic` refuses zero
/// as well, but only once the user has already approved and signed it.
///
/// The sender is not checked here, because its expected prefix depends on the chain being
/// signed for. [`Msg::validate_addresses`] checks it.
pub fn validate_swap_exact_amount_in(
    routes: &[SwapAmountInRoute],
    token_in: &Coin,
    token_out_min_amount: &str,
) -> Result<()> {
    if routes.is_empty() {
        return Err(CosmosError::Swap("routes is empty"));
    }
    validate_hops(routes)?;
    validate_denom(&token_in.denom)?;
    validate_nonzero_amount(&token_in.amount, "token_in is zero")?;
    validate_minimum_out(token_out_min_amount)
}

/// The rules a split-route swap must meet before the wallet builds, describes or signs it.
///
/// The poolmanager's `ValidateBasic` for `MsgSplitRouteSwapExactAmountIn`, plus the wallet's
/// own rules:
///
/// - `routes` holds between one and [`MAX_SWAP_SPLITS`] legs;
/// - every leg passes the single-route hop rules: at least one pool, at most [`MAX_SWAP_HOPS`],
///   no pool 0, every `token_out_denom` valid;
/// - every leg spends more than zero;
/// - every leg ends in the same denom, since the legs' outputs are summed and compared against
///   one minimum;
/// - no two legs take the same pools, which the chain refuses as duplicate routes;
/// - `token_in_denom` is a valid denom, and `token_out_min_amount` is greater than zero, for
///   the reason given on [`validate_swap_exact_amount_in`].
pub fn validate_split_route_swap_exact_amount_in(
    routes: &[SwapAmountInSplitRoute],
    token_in_denom: &str,
    token_out_min_amount: &str,
) -> Result<()> {
    if routes.is_empty() {
        return Err(CosmosError::Swap("routes is empty"));
    }
    if routes.len() > MAX_SWAP_SPLITS {
        return Err(CosmosError::Swap("routes has more than 16 split legs"));
    }
    validate_denom(token_in_denom)?;

    let mut output: Option<&str> = None;
    for (index, leg) in routes.iter().enumerate() {
        if leg.pools.is_empty() {
            return Err(CosmosError::Swap("a split route has no pools"));
        }
        let leg_output = validate_hops(&leg.pools)?;
        validate_nonzero_amount(
            &leg.token_in_amount,
            "a split route's token_in_amount is zero",
        )?;
        if output.is_some_and(|first| first != leg_output) {
            return Err(CosmosError::Swap(
                "the split routes end in different denoms",
            ));
        }
        output = Some(leg_output);
        if routes[..index]
            .iter()
            .any(|earlier| earlier.pools == leg.pools)
        {
            return Err(CosmosError::Swap("two split routes take the same pools"));
        }
    }
    validate_minimum_out(token_out_min_amount)
}

/// Checks one route's hops and returns the denom the route ends in.
fn validate_hops(hops: &[SwapAmountInRoute]) -> Result<&str> {
    if hops.len() > MAX_SWAP_HOPS {
        return Err(CosmosError::Swap(
            "a route passes through more than 8 pools",
        ));
    }
    for hop in hops {
        if hop.pool_id == 0 {
            return Err(CosmosError::Swap("pool_id 0 does not exist"));
        }
        validate_denom(&hop.token_out_denom)?;
    }
    hops.last()
        .map(|hop| hop.token_out_denom.as_str())
        .ok_or(CosmosError::Swap("routes is empty"))
}

/// A canonical amount that is not zero. Canonical means "0" is the only way to spell zero.
fn validate_nonzero_amount(amount: &str, zero: &'static str) -> Result<()> {
    validate_amount(amount)?;
    if amount == "0" {
        return Err(CosmosError::Swap(zero));
    }
    Ok(())
}

fn validate_minimum_out(token_out_min_amount: &str) -> Result<()> {
    validate_nonzero_amount(
        token_out_min_amount,
        "token_out_min_amount is zero, so the swap would fill at any price",
    )
}

/// The pools a route passes through, for a signing prompt: `pool 3586`, or `pools 1 → 3586`.
pub(crate) fn describe_hops(hops: &[SwapAmountInRoute]) -> String {
    let label = if hops.len() == 1 { "pool" } else { "pools" };
    format!("{label} {}", hop_ids(hops))
}

/// The legs of a split swap, for a signing prompt: `2 routes (pools 3498; 3586)`.
pub(crate) fn describe_split(legs: &[SwapAmountInSplitRoute]) -> String {
    let pools: usize = legs.iter().map(|leg| leg.pools.len()).sum();
    let ids: Vec<String> = legs.iter().map(|leg| hop_ids(&leg.pools)).collect();
    format!(
        "{} {} ({} {})",
        legs.len(),
        if legs.len() == 1 { "route" } else { "routes" },
        if pools == 1 { "pool" } else { "pools" },
        ids.join("; ")
    )
}

fn hop_ids(hops: &[SwapAmountInRoute]) -> String {
    let ids: Vec<String> = hops.iter().map(|hop| hop.pool_id.to_string()).collect();
    ids.join(" → ")
}

/// The denom a route delivers: the last hop's output.
pub(crate) fn route_output(hops: &[SwapAmountInRoute]) -> &str {
    hops.last()
        .map(|hop| hop.token_out_denom.as_str())
        .unwrap_or(UNREADABLE_DENOM)
}

/// The denom a split swap delivers, if every leg agrees on it.
pub(crate) fn split_output(legs: &[SwapAmountInSplitRoute]) -> &str {
    let mut outputs = legs.iter().map(|leg| route_output(&leg.pools));
    match outputs.next() {
        Some(first) if outputs.all(|other| other == first) => first,
        _ => UNREADABLE_DENOM,
    }
}

/// What a split swap spends in total: the sum of its legs.
pub(crate) fn split_input(legs: &[SwapAmountInSplitRoute]) -> String {
    legs.iter()
        .try_fold("0".to_owned(), |total, leg| {
            add_amounts(&total, &leg.token_in_amount)
        })
        .unwrap_or_else(|| "an unreadable amount of".to_owned())
}

/// Shown in place of a denom the summary cannot name. Only a swap that fails the rules above can
/// produce it, and such a swap is never built by the bridge nor described by the decoder.
const UNREADABLE_DENOM: &str = "an unreadable denom";

fn encode_hops(hops: &[SwapAmountInRoute]) -> Vec<Vec<u8>> {
    hops.iter().map(SwapAmountInRoute::encode_proto).collect()
}

fn amino_hops(hops: &[SwapAmountInRoute]) -> Value {
    Value::Array(hops.iter().map(SwapAmountInRoute::encode_amino).collect())
}

/// Every message the wallet can build and sign.
///
/// A closed enum rather than a trait object on purpose: the set of things a wallet will sign
/// should be enumerable and reviewable. Adding a variant is a deliberate change with a test,
/// which is the opposite of blind signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// `cosmos.bank.v1beta1.MsgSend`
    Send {
        from_address: String,
        to_address: String,
        amount: Vec<Coin>,
    },
    /// `cosmos.staking.v1beta1.MsgDelegate`
    Delegate {
        delegator_address: String,
        validator_address: String,
        amount: Coin,
    },
    /// `cosmos.staking.v1beta1.MsgUndelegate`
    Undelegate {
        delegator_address: String,
        validator_address: String,
        amount: Coin,
    },
    /// `cosmos.staking.v1beta1.MsgBeginRedelegate`
    BeginRedelegate {
        delegator_address: String,
        validator_src_address: String,
        validator_dst_address: String,
        amount: Coin,
    },
    /// `cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward`
    WithdrawDelegatorReward {
        delegator_address: String,
        validator_address: String,
    },
    /// `cosmos.gov.v1beta1.MsgVote`
    Vote {
        proposal_id: u64,
        voter: String,
        option: VoteOption,
    },
    /// `ibc.applications.transfer.v1.MsgTransfer`, an ICS-20 cross-chain transfer.
    IbcTransfer {
        source_port: String,
        source_channel: String,
        token: Coin,
        sender: String,
        receiver: String,
        timeout_height: Height,
        /// Nanoseconds since the Unix epoch. Zero means no timestamp timeout.
        timeout_timestamp: u64,
        memo: String,
    },
    /// `cosmwasm.wasm.v1.MsgExecuteContract`
    ExecuteContract {
        sender: String,
        contract: String,
        /// The contract message as raw JSON bytes.
        msg: Vec<u8>,
        funds: Vec<Coin>,
    },
    /// `osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn`, a swap along one route of pools.
    ///
    /// `routes` is the proto's name for what is a single route: the hops in order, each one's
    /// output feeding the next, so the last hop's `token_out_denom` is what the sender receives.
    SwapExactAmountIn {
        sender: String,
        routes: Vec<SwapAmountInRoute>,
        token_in: Coin,
        /// The least the swap may return, a `cosmossdk.io/math.Int` as a decimal string. The
        /// chain fails the whole swap rather than deliver less. Never zero; see
        /// [`validate_swap_exact_amount_in`].
        token_out_min_amount: String,
    },
    /// `osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn`, one swap whose input is
    /// divided across several routes that all end in the same denom.
    ///
    /// The amount swapped is the sum of the legs' `token_in_amount`s; the message carries only
    /// the denom. The minimum applies to the legs' combined output.
    SplitRouteSwapExactAmountIn {
        sender: String,
        routes: Vec<SwapAmountInSplitRoute>,
        token_in_denom: String,
        /// The least the legs may return together. Never zero, for the same reason as above.
        token_out_min_amount: String,
    },
}

impl Msg {
    pub fn type_url(&self) -> &'static str {
        match self {
            Self::Send { .. } => "/cosmos.bank.v1beta1.MsgSend",
            Self::Delegate { .. } => "/cosmos.staking.v1beta1.MsgDelegate",
            Self::Undelegate { .. } => "/cosmos.staking.v1beta1.MsgUndelegate",
            Self::BeginRedelegate { .. } => "/cosmos.staking.v1beta1.MsgBeginRedelegate",
            Self::WithdrawDelegatorReward { .. } => {
                "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward"
            }
            Self::Vote { .. } => "/cosmos.gov.v1beta1.MsgVote",
            Self::IbcTransfer { .. } => "/ibc.applications.transfer.v1.MsgTransfer",
            Self::ExecuteContract { .. } => "/cosmwasm.wasm.v1.MsgExecuteContract",
            Self::SwapExactAmountIn { .. } => "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn",
            Self::SplitRouteSwapExactAmountIn { .. } => {
                "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn"
            }
        }
    }

    /// The Amino registry name. Written literally, never derived from [`Self::type_url`].
    pub fn amino_type(&self) -> &'static str {
        match self {
            Self::Send { .. } => "cosmos-sdk/MsgSend",
            Self::Delegate { .. } => "cosmos-sdk/MsgDelegate",
            Self::Undelegate { .. } => "cosmos-sdk/MsgUndelegate",
            Self::BeginRedelegate { .. } => "cosmos-sdk/MsgBeginRedelegate",
            // Delegation, not Delegator. See the module documentation.
            Self::WithdrawDelegatorReward { .. } => "cosmos-sdk/MsgWithdrawDelegationReward",
            Self::Vote { .. } => "cosmos-sdk/MsgVote",
            Self::IbcTransfer { .. } => "cosmos-sdk/MsgTransfer",
            Self::ExecuteContract { .. } => "wasm/MsgExecuteContract",
            Self::SwapExactAmountIn { .. } => "osmosis/poolmanager/swap-exact-amount-in",
            // "split-amount-in", not "split-route-swap-exact-amount-in". See the module
            // documentation.
            Self::SplitRouteSwapExactAmountIn { .. } => "osmosis/poolmanager/split-amount-in",
        }
    }

    /// Protobuf encoding, for `SIGN_MODE_DIRECT`.
    pub fn encode_proto(&self) -> Vec<u8> {
        let mut writer = ProtoWriter::new();
        match self {
            Self::Send {
                from_address,
                to_address,
                amount,
            } => {
                writer
                    .string(1, from_address)
                    .string(2, to_address)
                    .repeated_message(3, &encode_coins(amount));
            }
            Self::Delegate {
                delegator_address,
                validator_address,
                amount,
            }
            | Self::Undelegate {
                delegator_address,
                validator_address,
                amount,
            } => {
                // Non-nullable `amount`, so always emitted. See the note on `IbcTransfer`.
                writer
                    .string(1, delegator_address)
                    .string(2, validator_address)
                    .message_always(3, &encode_coin(amount));
            }
            Self::BeginRedelegate {
                delegator_address,
                validator_src_address,
                validator_dst_address,
                amount,
            } => {
                writer
                    .string(1, delegator_address)
                    .string(2, validator_src_address)
                    .string(3, validator_dst_address)
                    .message_always(4, &encode_coin(amount));
            }
            Self::WithdrawDelegatorReward {
                delegator_address,
                validator_address,
            } => {
                writer
                    .string(1, delegator_address)
                    .string(2, validator_address);
            }
            Self::Vote {
                proposal_id,
                voter,
                option,
            } => {
                writer
                    .uint64(1, *proposal_id)
                    .string(2, voter)
                    .int32(3, *option as i32);
            }
            Self::IbcTransfer {
                source_port,
                source_channel,
                token,
                sender,
                receiver,
                timeout_height,
                timeout_timestamp,
                memo,
            } => {
                // `token` and `timeout_height` carry `(gogoproto.nullable) = false` in
                // ibc-go's proto, so both are always emitted, even when the height is
                // 0-0 and encodes to zero bytes. Omitting an all-zero `timeout_height`
                // under the usual proto3 default rule produces sign bytes two bytes
                // shorter than the chain's, and the signature then verifies against
                // nothing. Asserted against CosmJS in `tests/golden_vectors.rs`.
                writer
                    .string(1, source_port)
                    .string(2, source_channel)
                    .message_always(3, &encode_coin(token))
                    .string(4, sender)
                    .string(5, receiver)
                    .message_always(6, &timeout_height.encode_proto())
                    .uint64(7, *timeout_timestamp)
                    .string(8, memo);
            }
            Self::ExecuteContract {
                sender,
                contract,
                msg,
                funds,
            } => {
                // Field 5, not 4: the removed `callback_code_hash` field left a gap.
                writer
                    .string(1, sender)
                    .string(2, contract)
                    .bytes(3, msg)
                    .repeated_message(5, &encode_coins(funds));
            }
            Self::SwapExactAmountIn {
                sender,
                routes,
                token_in,
                token_out_min_amount,
            } => {
                // `token_in` is `(gogoproto.nullable) = false`, so always emitted, as for
                // `Delegate`. The minimum is a `math.Int` carried as a string, and never empty
                // once validated, so it is always emitted too.
                writer
                    .string(1, sender)
                    .repeated_message(2, &encode_hops(routes))
                    .message_always(3, &encode_coin(token_in))
                    .string(4, token_out_min_amount);
            }
            Self::SplitRouteSwapExactAmountIn {
                sender,
                routes,
                token_in_denom,
                token_out_min_amount,
            } => {
                let legs: Vec<Vec<u8>> = routes
                    .iter()
                    .map(SwapAmountInSplitRoute::encode_proto)
                    .collect();
                writer
                    .string(1, sender)
                    .repeated_message(2, &legs)
                    .string(3, token_in_denom)
                    .string(4, token_out_min_amount);
            }
        }
        writer.into_bytes()
    }

    /// Amino JSON encoding, for `SIGN_MODE_LEGACY_AMINO_JSON`.
    pub fn encode_amino(&self) -> Value {
        let value = match self {
            Self::Send {
                from_address,
                to_address,
                amount,
            } => object_omit_empty([
                ("amount", amino_coins(amount)),
                ("from_address", json!(from_address)),
                ("to_address", json!(to_address)),
            ]),
            Self::Delegate {
                delegator_address,
                validator_address,
                amount,
            }
            | Self::Undelegate {
                delegator_address,
                validator_address,
                amount,
            } => object_omit_empty([
                ("amount", amino_coin(amount)),
                ("delegator_address", json!(delegator_address)),
                ("validator_address", json!(validator_address)),
            ]),
            Self::BeginRedelegate {
                delegator_address,
                validator_src_address,
                validator_dst_address,
                amount,
            } => object_omit_empty([
                ("amount", amino_coin(amount)),
                ("delegator_address", json!(delegator_address)),
                ("validator_dst_address", json!(validator_dst_address)),
                ("validator_src_address", json!(validator_src_address)),
            ]),
            Self::WithdrawDelegatorReward {
                delegator_address,
                validator_address,
            } => object_omit_empty([
                ("delegator_address", json!(delegator_address)),
                ("validator_address", json!(validator_address)),
            ]),
            Self::Vote {
                proposal_id,
                voter,
                option,
            } => object_omit_empty([
                // Quoted: proposal ids exceed 2^53 on no chain today, but the wire format
                // stringifies every uint64 and consistency is what keeps the bytes right.
                ("proposal_id", json!(proposal_id.to_string())),
                ("option", json!(option.amino_name())),
                ("voter", json!(voter)),
            ]),
            Self::IbcTransfer {
                source_port,
                source_channel,
                token,
                sender,
                receiver,
                timeout_height,
                timeout_timestamp,
                memo,
            } => {
                let height = timeout_height.encode_amino();
                object_omit_empty([
                    ("memo", json!(memo)),
                    ("receiver", json!(receiver)),
                    ("sender", json!(sender)),
                    ("source_channel", json!(source_channel)),
                    ("source_port", json!(source_port)),
                    (
                        "timeout_height",
                        if timeout_height.is_zero() {
                            Value::Null
                        } else {
                            height
                        },
                    ),
                    ("timeout_timestamp", stringify_nonzero(*timeout_timestamp)),
                    ("token", amino_coin(token)),
                ])
            }
            Self::ExecuteContract {
                sender,
                contract,
                msg,
                funds,
            } => {
                // Amino embeds the contract message as parsed JSON, not as a base64 string,
                // which is the opposite of the protobuf encoding. Getting this backwards
                // produces a document the chain will not accept.
                let inner: Value = serde_json::from_slice(msg)
                    .unwrap_or_else(|_| Value::Object(Default::default()));
                object_omit_empty([
                    ("contract", json!(contract)),
                    ("funds", amino_coins(funds)),
                    ("msg", inner),
                    ("sender", json!(sender)),
                ])
            }
            Self::SwapExactAmountIn {
                sender,
                routes,
                token_in,
                token_out_min_amount,
            } => object_omit_empty([
                ("routes", amino_hops(routes)),
                ("sender", json!(sender)),
                ("token_in", amino_coin(token_in)),
                ("token_out_min_amount", json!(token_out_min_amount)),
            ]),
            Self::SplitRouteSwapExactAmountIn {
                sender,
                routes,
                token_in_denom,
                token_out_min_amount,
            } => object_omit_empty([
                (
                    "routes",
                    Value::Array(
                        routes
                            .iter()
                            .map(SwapAmountInSplitRoute::encode_amino)
                            .collect(),
                    ),
                ),
                ("sender", json!(sender)),
                ("token_in_denom", json!(token_in_denom)),
                ("token_out_min_amount", json!(token_out_min_amount)),
            ]),
        };
        typed(self.amino_type(), value)
    }

    /// A short human-readable summary for a signing prompt.
    ///
    /// Deliberately plain and specific. "Contract execution" tells a user nothing; naming the
    /// contract and the action is what lets them notice that they are approving something
    /// other than what they clicked.
    pub fn summary(&self) -> String {
        match self {
            Self::Send {
                to_address, amount, ..
            } => {
                let coins: Vec<String> = amount
                    .iter()
                    .map(|c| format!("{} {}", c.amount, c.denom))
                    .collect();
                format!("Send {} to {}", coins.join(", "), to_address)
            }
            Self::Delegate {
                validator_address,
                amount,
                ..
            } => format!(
                "Delegate {} {} to {}",
                amount.amount, amount.denom, validator_address
            ),
            Self::Undelegate {
                validator_address,
                amount,
                ..
            } => format!(
                "Undelegate {} {} from {}",
                amount.amount, amount.denom, validator_address
            ),
            Self::BeginRedelegate {
                validator_src_address,
                validator_dst_address,
                amount,
                ..
            } => format!(
                "Redelegate {} {} from {} to {}",
                amount.amount, amount.denom, validator_src_address, validator_dst_address
            ),
            Self::WithdrawDelegatorReward {
                validator_address, ..
            } => format!("Claim staking rewards from {validator_address}"),
            Self::Vote {
                proposal_id,
                option,
                ..
            } => format!("Vote {} on proposal {proposal_id}", option.label()),
            Self::IbcTransfer {
                token,
                receiver,
                source_channel,
                ..
            } => format!(
                "IBC transfer {} {} to {} over {}",
                token.amount, token.denom, receiver, source_channel
            ),
            Self::ExecuteContract {
                contract,
                msg,
                funds,
                ..
            } => {
                // The top-level key of a CosmWasm ExecuteMsg is the action name by convention,
                // so naming it turns "execute a contract" into "swap on this contract".
                let action = serde_json::from_slice::<Value>(msg)
                    .ok()
                    .and_then(|v| v.as_object().and_then(|m| m.keys().next().cloned()))
                    .unwrap_or_else(|| "unknown action".to_owned());
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
            // What goes in, the floor on what comes out, and the pools in between. The floor is
            // the number a user must check: it is the only price limit the swap carries.
            Self::SwapExactAmountIn {
                routes,
                token_in,
                token_out_min_amount,
                ..
            } => format!(
                "Swap {} {} for at least {} {} through {}",
                token_in.amount,
                token_in.denom,
                token_out_min_amount,
                route_output(routes),
                describe_hops(routes)
            ),
            Self::SplitRouteSwapExactAmountIn {
                routes,
                token_in_denom,
                token_out_min_amount,
                ..
            } => format!(
                "Swap {} {} for at least {} {} through {}",
                split_input(routes),
                token_in_denom,
                token_out_min_amount,
                split_output(routes),
                describe_split(routes)
            ),
        }
    }

    /// True if this message moves funds out of the signer's account.
    ///
    /// Drives the "this transaction spends money" treatment in the signing UI. A vote does
    /// not, a send does, and a contract execution with attached funds does.
    pub fn spends_funds(&self) -> bool {
        match self {
            Self::Send { amount, .. } => !amount.is_empty(),
            // A swap's input leaves the account whatever comes back, and a validated swap never
            // has an input of zero.
            Self::Delegate { .. }
            | Self::IbcTransfer { .. }
            | Self::SwapExactAmountIn { .. }
            | Self::SplitRouteSwapExactAmountIn { .. } => true,
            Self::ExecuteContract { funds, .. } => !funds.is_empty(),
            Self::Undelegate { .. }
            | Self::BeginRedelegate { .. }
            | Self::WithdrawDelegatorReward { .. }
            | Self::Vote { .. } => false,
        }
    }

    /// Every address this message references, for the address-book and first-time-recipient
    /// warnings.
    pub fn addresses(&self) -> Vec<&str> {
        match self {
            Self::Send {
                from_address,
                to_address,
                ..
            } => vec![from_address, to_address],
            Self::Delegate {
                delegator_address,
                validator_address,
                ..
            }
            | Self::Undelegate {
                delegator_address,
                validator_address,
                ..
            }
            | Self::WithdrawDelegatorReward {
                delegator_address,
                validator_address,
            } => vec![delegator_address, validator_address],
            Self::BeginRedelegate {
                delegator_address,
                validator_src_address,
                validator_dst_address,
                ..
            } => vec![
                delegator_address,
                validator_src_address,
                validator_dst_address,
            ],
            Self::Vote { voter, .. } => vec![voter],
            Self::IbcTransfer {
                sender, receiver, ..
            } => vec![sender, receiver],
            Self::ExecuteContract {
                sender, contract, ..
            } => vec![sender, contract],
            // Pools are named by number, not by address, so the sender is the only account a
            // swap touches.
            Self::SwapExactAmountIn { sender, .. }
            | Self::SplitRouteSwapExactAmountIn { sender, .. } => vec![sender],
        }
    }

    /// Validates that every address on this message carries the chain's bech32 prefix.
    ///
    /// The IBC receiver is exempt: an ICS-20 transfer's destination is on another chain and
    /// legitimately has a different prefix. That exemption is the reason this cannot be a blanket
    /// loop over [`Self::addresses`].
    ///
    /// Swaps are also held to their rules here, not only at the JSON bridge: a typed [`Msg`] can
    /// be built without passing through the bridge, and this is the last check before signing.
    pub fn validate_addresses(&self, prefix: &str) -> Result<()> {
        let validator_prefix = format!("{prefix}valoper");

        let check = |address: &str, expected: &str| -> Result<()> {
            zunia_kernel::validate_address(address, expected)
                .map(|_| ())
                .map_err(|_| CosmosError::Address)
        };

        match self {
            Self::Send {
                from_address,
                to_address,
                amount,
            } => {
                check(from_address, prefix)?;
                check(to_address, prefix)?;
                if amount.is_empty() {
                    return Err(CosmosError::Amount);
                }
            }
            Self::Delegate {
                delegator_address,
                validator_address,
                ..
            }
            | Self::Undelegate {
                delegator_address,
                validator_address,
                ..
            }
            | Self::WithdrawDelegatorReward {
                delegator_address,
                validator_address,
            } => {
                check(delegator_address, prefix)?;
                check(validator_address, &validator_prefix)?;
            }
            Self::BeginRedelegate {
                delegator_address,
                validator_src_address,
                validator_dst_address,
                ..
            } => {
                check(delegator_address, prefix)?;
                check(validator_src_address, &validator_prefix)?;
                check(validator_dst_address, &validator_prefix)?;
            }
            Self::Vote { voter, .. } => check(voter, prefix)?,
            Self::IbcTransfer { sender, .. } => {
                check(sender, prefix)?;
                // The receiver is on the counterparty chain, so its prefix is unknown here.
                // The IBC flow validates it against the destination chain's registry entry.
            }
            Self::ExecuteContract {
                sender, contract, ..
            } => {
                check(sender, prefix)?;
                // The contract is 32 bytes. The sender stays a 20-byte account.
                zunia_kernel::validate_contract_address(contract, prefix)?;
            }
            Self::SwapExactAmountIn {
                sender,
                routes,
                token_in,
                token_out_min_amount,
            } => {
                check(sender, prefix)?;
                validate_swap_exact_amount_in(routes, token_in, token_out_min_amount)?;
            }
            Self::SplitRouteSwapExactAmountIn {
                sender,
                routes,
                token_in_denom,
                token_out_min_amount,
            } => {
                check(sender, prefix)?;
                validate_split_route_swap_exact_amount_in(
                    routes,
                    token_in_denom,
                    token_out_min_amount,
                )?;
            }
        }
        Ok(())
    }
}

fn encode_coin(coin: &Coin) -> Vec<u8> {
    let mut writer = ProtoWriter::new();
    writer.string(1, &coin.denom).string(2, &coin.amount);
    writer.into_bytes()
}

fn encode_coins(coins: &[Coin]) -> Vec<Vec<u8>> {
    coins.iter().map(encode_coin).collect()
}

fn amino_coin(coin: &Coin) -> Value {
    json!({ "amount": coin.amount, "denom": coin.denom })
}

fn amino_coins(coins: &[Coin]) -> Value {
    Value::Array(coins.iter().map(amino_coin).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amino::to_canonical_string;

    fn send() -> Msg {
        Msg::Send {
            from_address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            to_address: "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz".to_owned(),
            amount: vec![Coin::new("uatom", "1000000").unwrap()],
        }
    }

    #[test]
    fn amino_names_are_pinned() {
        // Guards the Delegator/Delegation trap and every other name.
        assert_eq!(send().amino_type(), "cosmos-sdk/MsgSend");
        assert_eq!(
            Msg::WithdrawDelegatorReward {
                delegator_address: "a".into(),
                validator_address: "b".into(),
            }
            .amino_type(),
            "cosmos-sdk/MsgWithdrawDelegationReward"
        );
        assert_eq!(
            Msg::WithdrawDelegatorReward {
                delegator_address: "a".into(),
                validator_address: "b".into(),
            }
            .type_url(),
            "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward"
        );
        assert_eq!(
            Msg::ExecuteContract {
                sender: "a".into(),
                contract: "b".into(),
                msg: b"{}".to_vec(),
                funds: vec![],
            }
            .amino_type(),
            "wasm/MsgExecuteContract",
            "CosmWasm messages use the wasm/ prefix, not cosmos-sdk/"
        );
        assert_eq!(
            Msg::IbcTransfer {
                source_port: "transfer".into(),
                source_channel: "channel-0".into(),
                token: Coin::new("uatom", "1").unwrap(),
                sender: "a".into(),
                receiver: "b".into(),
                timeout_height: Height::default(),
                timeout_timestamp: 0,
                memo: String::new(),
            }
            .amino_type(),
            "cosmos-sdk/MsgTransfer"
        );
        assert_eq!(
            swap().type_url(),
            "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn"
        );
        assert_eq!(
            swap().amino_type(),
            "osmosis/poolmanager/swap-exact-amount-in"
        );
        assert_eq!(
            split().type_url(),
            "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn"
        );
        assert_eq!(
            split().amino_type(),
            "osmosis/poolmanager/split-amount-in",
            "not split-route-swap-exact-amount-in: the registered name drops three words"
        );
    }

    const OSMO_SENDER: &str = "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8";
    const ATOM: &str = "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2";
    const OUT: &str = "ibc/794C7D7F3B857713878A3A1927251FA6AC1EEE520424C1F6FAFE9BA26D476138";

    fn hop(pool_id: u64, token_out_denom: &str) -> SwapAmountInRoute {
        SwapAmountInRoute {
            pool_id,
            token_out_denom: token_out_denom.to_owned(),
        }
    }

    fn leg(pools: Vec<SwapAmountInRoute>, token_in_amount: &str) -> SwapAmountInSplitRoute {
        SwapAmountInSplitRoute {
            pools,
            token_in_amount: token_in_amount.to_owned(),
        }
    }

    /// The single-route swap the extension sends.
    fn swap() -> Msg {
        Msg::SwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![hop(3586, OUT)],
            token_in: Coin::new("uosmo", "9950000").unwrap(),
            token_out_min_amount: "350000".to_owned(),
        }
    }

    /// The router's real split for 9.95 OSMO: 5.97 through pool 3498, 3.98 through 3586.
    fn split() -> Msg {
        Msg::SplitRouteSwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![
                leg(vec![hop(3498, OUT)], "5970000"),
                leg(vec![hop(3586, OUT)], "3980000"),
            ],
            token_in_denom: "uosmo".to_owned(),
            token_out_min_amount: "350000".to_owned(),
        }
    }

    #[test]
    fn swap_amino_shapes() {
        // Pinned to osmojs's Amino converter in tests/golden_vectors.rs; spelled out here so the
        // shape is reviewable next to the encoder. pool_id is quoted, like every uint64.
        assert_eq!(
            to_canonical_string(&swap().encode_amino()),
            r#"{"type":"osmosis/poolmanager/swap-exact-amount-in","value":{"routes":[{"pool_id":"3586","token_out_denom":"$OUT"}],"sender":"osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8","token_in":{"amount":"9950000","denom":"uosmo"},"token_out_min_amount":"350000"}}"#
                .replace("$OUT", OUT)
        );
        assert_eq!(
            to_canonical_string(&split().encode_amino()),
            r#"{"type":"osmosis/poolmanager/split-amount-in","value":{"routes":[{"pools":[{"pool_id":"3498","token_out_denom":"$OUT"}],"token_in_amount":"5970000"},{"pools":[{"pool_id":"3586","token_out_denom":"$OUT"}],"token_in_amount":"3980000"}],"sender":"osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8","token_in_denom":"uosmo","token_out_min_amount":"350000"}}"#
                .replace("$OUT", OUT)
        );
    }

    #[test]
    fn swap_proto_field_numbers() {
        use crate::proto::{decode_fields, find_field};

        // MsgSwapExactAmountIn: sender 1, routes 2 (one entry per hop, in order), token_in 3,
        // token_out_min_amount 4.
        let msg = Msg::SwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![hop(1, ATOM), hop(3586, OUT)],
            token_in: Coin::new("uosmo", "10000000").unwrap(),
            token_out_min_amount: "340000".to_owned(),
        };
        let fields = decode_fields(&msg.encode_proto()).unwrap();
        let tags: Vec<u32> = fields.iter().map(|f| f.tag).collect();
        assert_eq!(tags, vec![1, 2, 2, 3, 4]);
        assert_eq!(fields[0].value.as_string().unwrap(), OSMO_SENDER);
        assert_eq!(fields[4].value.as_string().unwrap(), "340000");

        // SwapAmountInRoute: pool_id 1 as a varint, token_out_denom 2.
        let first = decode_fields(fields[1].value.as_bytes().unwrap()).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].tag, 1);
        assert_eq!(first[0].value.as_varint().unwrap(), 1);
        assert_eq!(first[1].tag, 2);
        assert_eq!(first[1].value.as_string().unwrap(), ATOM);
        let second = decode_fields(fields[2].value.as_bytes().unwrap()).unwrap();
        assert_eq!(second[0].value.as_varint().unwrap(), 3586);

        // token_in is a Coin: denom 1, amount 2.
        let coin = decode_fields(fields[3].value.as_bytes().unwrap()).unwrap();
        assert_eq!(find_field(&coin, 1).unwrap().as_string().unwrap(), "uosmo");
        assert_eq!(
            find_field(&coin, 2).unwrap().as_string().unwrap(),
            "10000000"
        );

        // MsgSplitRouteSwapExactAmountIn: sender 1, routes 2 (one entry per leg), token_in_denom
        // 3, token_out_min_amount 4. SwapAmountInSplitRoute: pools 1, token_in_amount 2.
        let fields = decode_fields(&split().encode_proto()).unwrap();
        let tags: Vec<u32> = fields.iter().map(|f| f.tag).collect();
        assert_eq!(tags, vec![1, 2, 2, 3, 4]);
        assert_eq!(fields[3].value.as_string().unwrap(), "uosmo");
        assert_eq!(fields[4].value.as_string().unwrap(), "350000");
        let first_leg = decode_fields(fields[1].value.as_bytes().unwrap()).unwrap();
        let leg_tags: Vec<u32> = first_leg.iter().map(|f| f.tag).collect();
        assert_eq!(leg_tags, vec![1, 2]);
        assert_eq!(first_leg[1].value.as_string().unwrap(), "5970000");
        let leg_hop = decode_fields(first_leg[0].value.as_bytes().unwrap()).unwrap();
        assert_eq!(leg_hop[0].value.as_varint().unwrap(), 3498);
    }

    #[test]
    fn swap_token_in_is_emitted_even_when_empty() {
        // `(gogoproto.nullable) = false`, as on Delegate's amount: the field is present even
        // when the coin encodes to nothing. Never reachable through the bridge, which refuses an
        // empty coin, so this states the encoder's rule rather than a case that ships.
        let msg = Msg::SwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![],
            token_in: Coin {
                denom: String::new(),
                amount: String::new(),
            },
            token_out_min_amount: String::new(),
        };
        let fields = crate::proto::decode_fields(&msg.encode_proto()).unwrap();
        assert_eq!(
            crate::proto::find_field(&fields, 3)
                .unwrap()
                .as_bytes()
                .unwrap(),
            b""
        );
    }

    #[test]
    fn swap_summaries_name_the_input_the_floor_the_output_and_the_pools() {
        assert_eq!(
            swap().summary(),
            format!("Swap 9950000 uosmo for at least 350000 {OUT} through pool 3586")
        );
        // A split shows the total it spends, which no single field on the wire carries.
        assert_eq!(
            split().summary(),
            format!(
                "Swap 9950000 uosmo for at least 350000 {OUT} through 2 routes (pools 3498; 3586)"
            )
        );

        let multi_hop = Msg::SwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![hop(1, ATOM), hop(3586, OUT)],
            token_in: Coin::new("uosmo", "10000000").unwrap(),
            token_out_min_amount: "340000".to_owned(),
        };
        // The output named is the last hop's, not the first's: ATOM is only passed through.
        assert_eq!(
            multi_hop.summary(),
            format!("Swap 10000000 uosmo for at least 340000 {OUT} through pools 1 → 3586")
        );

        let one_leg = Msg::SplitRouteSwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![leg(vec![hop(3586, OUT)], "1")],
            token_in_denom: "uosmo".to_owned(),
            token_out_min_amount: "1".to_owned(),
        };
        assert_eq!(
            one_leg.summary(),
            format!("Swap 1 uosmo for at least 1 {OUT} through 1 route (pool 3586)")
        );

        let mixed = Msg::SplitRouteSwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![
                leg(vec![hop(1, ATOM), hop(3586, OUT)], "6000000"),
                leg(vec![hop(3498, OUT)], "4000000"),
            ],
            token_in_denom: "uosmo".to_owned(),
            token_out_min_amount: "350000".to_owned(),
        };
        assert_eq!(
            mixed.summary(),
            format!(
                "Swap 10000000 uosmo for at least 350000 {OUT} through 2 routes \
                 (pools 1 → 3586; 3498)"
            )
        );
    }

    #[test]
    fn swaps_spend_and_name_only_the_sender() {
        assert!(swap().spends_funds());
        assert!(split().spends_funds());
        assert_eq!(swap().addresses(), vec![OSMO_SENDER]);
        assert_eq!(split().addresses(), vec![OSMO_SENDER]);
    }

    #[test]
    fn a_swap_sender_must_carry_the_chain_prefix() {
        assert!(swap().validate_addresses("osmo").is_ok());
        assert!(split().validate_addresses("osmo").is_ok());
        // The same key's address on Osmosis, offered for a Cosmos Hub transaction.
        assert_eq!(
            swap().validate_addresses("cosmos").unwrap_err(),
            CosmosError::Address
        );
        assert_eq!(
            split().validate_addresses("cosmos").unwrap_err(),
            CosmosError::Address
        );
    }

    #[test]
    fn the_swap_rules_hold_at_the_signing_door_too() {
        // A typed Msg can skip the JSON bridge, so validate_addresses, which runs before every
        // signature the bindings make, applies the swap rules again.
        let Msg::SwapExactAmountIn {
            sender,
            routes,
            token_in,
            ..
        } = swap()
        else {
            unreachable!()
        };
        let no_floor = Msg::SwapExactAmountIn {
            sender,
            routes,
            token_in,
            token_out_min_amount: "0".to_owned(),
        };
        assert!(matches!(
            no_floor.validate_addresses("osmo").unwrap_err(),
            CosmosError::Swap(_)
        ));

        let Msg::SplitRouteSwapExactAmountIn { sender, routes, .. } = split() else {
            unreachable!()
        };
        let bad_denom = Msg::SplitRouteSwapExactAmountIn {
            sender,
            routes,
            token_in_denom: "u".to_owned(),
            token_out_min_amount: "350000".to_owned(),
        };
        assert_eq!(
            bad_denom.validate_addresses("osmo").unwrap_err(),
            CosmosError::Denom
        );
    }

    #[test]
    fn a_swap_with_no_price_floor_is_refused() {
        // The blank cheque: a zero minimum lets whoever orders the block decide the price.
        let token_in = Coin::new("uosmo", "9950000").unwrap();
        let refused = validate_swap_exact_amount_in(&[hop(3586, OUT)], &token_in, "0").unwrap_err();
        assert_eq!(
            refused,
            CosmosError::Swap("token_out_min_amount is zero, so the swap would fill at any price")
        );
        assert_eq!(
            refused.to_string(),
            "swap refused: token_out_min_amount is zero, so the swap would fill at any price"
        );
        assert_eq!(
            validate_split_route_swap_exact_amount_in(
                &[leg(vec![hop(3586, OUT)], "9950000")],
                "uosmo",
                "0"
            )
            .unwrap_err(),
            refused
        );
        // One unit is a floor, however low; the prompt shows it and the user decides.
        assert!(validate_swap_exact_amount_in(&[hop(3586, OUT)], &token_in, "1").is_ok());
    }

    #[test]
    fn single_route_swap_rules() {
        let coin = |denom: &str, amount: &str| Coin {
            denom: denom.to_owned(),
            amount: amount.to_owned(),
        };
        let good = coin("uosmo", "9950000");
        let cases = [
            (
                vec![],
                good.clone(),
                "350000",
                CosmosError::Swap("routes is empty"),
            ),
            (
                vec![hop(0, OUT)],
                good.clone(),
                "350000",
                CosmosError::Swap("pool_id 0 does not exist"),
            ),
            (
                vec![hop(1, ATOM), hop(0, OUT)],
                good.clone(),
                "350000",
                CosmosError::Swap("pool_id 0 does not exist"),
            ),
            (
                vec![hop(3586, "")],
                good.clone(),
                "350000",
                CosmosError::Denom,
            ),
            (
                vec![hop(3586, "1nvalid")],
                good.clone(),
                "350000",
                CosmosError::Denom,
            ),
            (
                vec![hop(3586, "ibc/794C\u{202e}")],
                good.clone(),
                "350000",
                CosmosError::Denom,
            ),
            (
                vec![hop(3586, OUT)],
                coin("uosmo", "0"),
                "350000",
                CosmosError::Swap("token_in is zero"),
            ),
            (
                vec![hop(3586, OUT)],
                coin("uosmo", "09950000"),
                "350000",
                CosmosError::Amount,
            ),
            (
                vec![hop(3586, OUT)],
                coin("u", "9950000"),
                "350000",
                CosmosError::Denom,
            ),
            (vec![hop(3586, OUT)], good.clone(), "", CosmosError::Amount),
            (
                vec![hop(3586, OUT)],
                good.clone(),
                "-1",
                CosmosError::Amount,
            ),
            (
                vec![hop(3586, OUT)],
                good.clone(),
                "1.5",
                CosmosError::Amount,
            ),
            (
                vec![hop(3586, OUT)],
                good.clone(),
                "0350000",
                CosmosError::Amount,
            ),
            (
                vec![hop(3586, OUT)],
                good.clone(),
                "3.5e5",
                CosmosError::Amount,
            ),
        ];
        for (routes, token_in, min, expected) in cases {
            assert_eq!(
                validate_swap_exact_amount_in(&routes, &token_in, min).unwrap_err(),
                expected,
                "{routes:?} {token_in:?} {min:?}"
            );
        }
    }

    #[test]
    fn split_route_swap_rules() {
        let cases = [
            (vec![], "uosmo", CosmosError::Swap("routes is empty")),
            (
                vec![leg(vec![], "1")],
                "uosmo",
                CosmosError::Swap("a split route has no pools"),
            ),
            (
                vec![leg(vec![hop(3498, OUT)], "0")],
                "uosmo",
                CosmosError::Swap("a split route's token_in_amount is zero"),
            ),
            (
                vec![leg(vec![hop(3498, OUT)], "06000000")],
                "uosmo",
                CosmosError::Amount,
            ),
            (
                vec![leg(vec![hop(0, OUT)], "1")],
                "uosmo",
                CosmosError::Swap("pool_id 0 does not exist"),
            ),
            // Every leg's output is summed against one minimum, so they must agree on what it
            // is denominated in. The chain's ValidateBasic refuses this too, after signing.
            (
                vec![
                    leg(vec![hop(3498, OUT)], "6000000"),
                    leg(vec![hop(1, ATOM)], "4000000"),
                ],
                "uosmo",
                CosmosError::Swap("the split routes end in different denoms"),
            ),
            // The chain's ErrDuplicateRoutesNotAllowed: the same pools twice, even with
            // different shares.
            (
                vec![
                    leg(vec![hop(3498, OUT)], "6000000"),
                    leg(vec![hop(3498, OUT)], "4000000"),
                ],
                "uosmo",
                CosmosError::Swap("two split routes take the same pools"),
            ),
            (
                vec![leg(vec![hop(3498, OUT)], "1")],
                "u",
                CosmosError::Denom,
            ),
            (vec![leg(vec![hop(3498, OUT)], "1")], "", CosmosError::Denom),
        ];
        for (routes, token_in_denom, expected) in cases {
            assert_eq!(
                validate_split_route_swap_exact_amount_in(&routes, token_in_denom, "350000")
                    .unwrap_err(),
                expected,
                "{routes:?} {token_in_denom:?}"
            );
        }

        // Legs that share a pool but not a route are different routes, and the chain accepts
        // them.
        assert!(validate_split_route_swap_exact_amount_in(
            &[
                leg(vec![hop(1, ATOM), hop(3586, OUT)], "6000000"),
                leg(vec![hop(3586, OUT)], "4000000"),
            ],
            "uosmo",
            "350000"
        )
        .is_ok());
    }

    #[test]
    fn route_length_and_split_count_are_capped() {
        let token_in = Coin::new("uosmo", "1000000").unwrap();
        let hops = |count: u64| -> Vec<SwapAmountInRoute> {
            (1..=count).map(|pool_id| hop(pool_id, OUT)).collect()
        };
        let max_hops = MAX_SWAP_HOPS as u64;
        assert!(validate_swap_exact_amount_in(&hops(max_hops), &token_in, "1").is_ok());
        let too_long = validate_swap_exact_amount_in(&hops(max_hops + 1), &token_in, "1")
            .unwrap_err()
            .to_string();
        // The reason states the cap literally, so it must agree with the constant.
        assert!(
            too_long.contains(&format!("more than {MAX_SWAP_HOPS} pools")),
            "{too_long}"
        );
        // The hop cap applies inside every split leg as well.
        assert!(validate_split_route_swap_exact_amount_in(
            &[leg(hops(max_hops + 1), "1")],
            "uosmo",
            "1"
        )
        .is_err());

        let legs = |count: u64| -> Vec<SwapAmountInSplitRoute> {
            (1..=count)
                .map(|pool_id| leg(vec![hop(pool_id, OUT)], "1"))
                .collect()
        };
        let max_splits = MAX_SWAP_SPLITS as u64;
        assert!(validate_split_route_swap_exact_amount_in(&legs(max_splits), "uosmo", "1").is_ok());
        let too_many =
            validate_split_route_swap_exact_amount_in(&legs(max_splits + 1), "uosmo", "1")
                .unwrap_err()
                .to_string();
        assert!(
            too_many.contains(&format!("more than {MAX_SWAP_SPLITS} split legs")),
            "{too_many}"
        );
    }

    #[test]
    fn msg_send_amino_shape() {
        assert_eq!(
            to_canonical_string(&send().encode_amino()),
            r#"{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"1000000","denom":"uatom"}],"from_address":"cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4","to_address":"cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz"}}"#
        );
    }

    #[test]
    fn msg_send_proto_is_canonical() {
        let bytes = send().encode_proto();
        let fields = crate::proto::decode_fields(&bytes).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].tag, 1);
        assert_eq!(fields[1].tag, 2);
        assert_eq!(fields[2].tag, 3);

        let coin = crate::proto::decode_fields(fields[2].value.as_bytes().unwrap()).unwrap();
        assert_eq!(
            crate::proto::find_field(&coin, 1)
                .unwrap()
                .as_string()
                .unwrap(),
            "uatom"
        );
        assert_eq!(
            crate::proto::find_field(&coin, 2)
                .unwrap()
                .as_string()
                .unwrap(),
            "1000000"
        );
    }

    #[test]
    fn vote_stringifies_the_proposal_id_and_names_the_option() {
        let msg = Msg::Vote {
            proposal_id: 848,
            voter: "cosmos1abc".to_owned(),
            option: VoteOption::NoWithVeto,
        };
        assert_eq!(
            to_canonical_string(&msg.encode_amino()),
            r#"{"type":"cosmos-sdk/MsgVote","value":{"option":"VOTE_OPTION_NO_WITH_VETO","proposal_id":"848","voter":"cosmos1abc"}}"#
        );
        // Proto encodes the enum as its integer value.
        let fields = crate::proto::decode_fields(&msg.encode_proto()).unwrap();
        assert_eq!(
            crate::proto::find_field(&fields, 3)
                .unwrap()
                .as_varint()
                .unwrap(),
            4
        );
    }

    #[test]
    fn execute_contract_embeds_json_in_amino_and_bytes_in_proto() {
        let msg = Msg::ExecuteContract {
            sender: "cosmos1sender".to_owned(),
            contract: "cosmos1contract".to_owned(),
            msg: br#"{"swap":{"amount":"100"}}"#.to_vec(),
            funds: vec![Coin::new("uatom", "100").unwrap()],
        };

        // Amino: parsed JSON inline.
        assert_eq!(
            to_canonical_string(&msg.encode_amino()),
            r#"{"type":"wasm/MsgExecuteContract","value":{"contract":"cosmos1contract","funds":[{"amount":"100","denom":"uatom"}],"msg":{"swap":{"amount":"100"}},"sender":"cosmos1sender"}}"#
        );

        // Proto: raw bytes at field 3, funds at field 5 not 4.
        let fields = crate::proto::decode_fields(&msg.encode_proto()).unwrap();
        assert_eq!(
            crate::proto::find_field(&fields, 3)
                .unwrap()
                .as_bytes()
                .unwrap(),
            br#"{"swap":{"amount":"100"}}"#
        );
        assert!(
            crate::proto::find_field(&fields, 4).is_none(),
            "field 4 is a gap"
        );
        assert!(
            crate::proto::find_field(&fields, 5).is_some(),
            "funds live at 5"
        );
    }

    /// Amino omits zero timeouts, protobuf does not, and the asymmetry is deliberate.
    ///
    /// Amino follows Go's `json.Marshal` with `omitempty`, so an all-zero `timeout_height`
    /// disappears. Protobuf follows the `(gogoproto.nullable) = false` annotation, so the
    /// field is always present even when it encodes to zero bytes. Both halves are pinned to
    /// CosmJS in `tests/golden_vectors.rs`; this test states the intent so the next reader
    /// does not "fix" one side into agreement with the other.
    #[test]
    fn ibc_transfer_timeout_omission_differs_between_amino_and_proto() {
        let msg = Msg::IbcTransfer {
            source_port: "transfer".to_owned(),
            source_channel: "channel-141".to_owned(),
            token: Coin::new("uatom", "1000000").unwrap(),
            sender: "cosmos1abc".to_owned(),
            receiver: "addr_safro1xyz".to_owned(),
            timeout_height: Height::default(),
            timeout_timestamp: 0,
            memo: String::new(),
        };
        assert_eq!(
            to_canonical_string(&msg.encode_amino()),
            r#"{"type":"cosmos-sdk/MsgTransfer","value":{"receiver":"addr_safro1xyz","sender":"cosmos1abc","source_channel":"channel-141","source_port":"transfer","token":{"amount":"1000000","denom":"uatom"}}}"#
        );
        let fields = crate::proto::decode_fields(&msg.encode_proto()).unwrap();
        assert_eq!(
            crate::proto::find_field(&fields, 6)
                .unwrap()
                .as_bytes()
                .unwrap(),
            b"",
            "timeout_height is non-nullable: present, and empty"
        );
        assert!(
            crate::proto::find_field(&fields, 7).is_none(),
            "timeout_timestamp is a plain uint64, so zero is omitted"
        );
    }

    #[test]
    fn ibc_transfer_includes_present_timeouts() {
        let msg = Msg::IbcTransfer {
            source_port: "transfer".to_owned(),
            source_channel: "channel-141".to_owned(),
            token: Coin::new("uatom", "1").unwrap(),
            sender: "cosmos1abc".to_owned(),
            receiver: "addr_safro1xyz".to_owned(),
            timeout_height: Height {
                revision_number: 1,
                revision_height: 20_000_000,
            },
            timeout_timestamp: 1_700_000_000_000_000_000,
            memo: "forward".to_owned(),
        };
        let rendered = to_canonical_string(&msg.encode_amino());
        assert!(rendered
            .contains(r#""timeout_height":{"revision_height":"20000000","revision_number":"1"}"#));
        assert!(rendered.contains(r#""timeout_timestamp":"1700000000000000000""#));
        assert!(rendered.contains(r#""memo":"forward""#));
    }

    #[test]
    fn summaries_name_the_specifics() {
        assert!(send()
            .summary()
            .starts_with("Send 1000000 uatom to cosmos1jrk"));

        let contract = Msg::ExecuteContract {
            sender: "cosmos1s".to_owned(),
            contract: "cosmos1c".to_owned(),
            msg: br#"{"swap":{}}"#.to_vec(),
            funds: vec![Coin::new("uatom", "5").unwrap()],
        };
        assert_eq!(
            contract.summary(),
            "Execute \"swap\" on cosmos1c sending 5 uatom"
        );

        let vote = Msg::Vote {
            proposal_id: 1,
            voter: "cosmos1v".to_owned(),
            option: VoteOption::Yes,
        };
        assert_eq!(vote.summary(), "Vote Yes on proposal 1");
    }

    #[test]
    fn spend_detection() {
        assert!(send().spends_funds());
        assert!(!Msg::Vote {
            proposal_id: 1,
            voter: "v".into(),
            option: VoteOption::Yes
        }
        .spends_funds());
        assert!(!Msg::WithdrawDelegatorReward {
            delegator_address: "d".into(),
            validator_address: "v".into()
        }
        .spends_funds());
        assert!(Msg::ExecuteContract {
            sender: "s".into(),
            contract: "c".into(),
            msg: b"{}".to_vec(),
            funds: vec![Coin::new("uatom", "1").unwrap()],
        }
        .spends_funds());
        assert!(!Msg::ExecuteContract {
            sender: "s".into(),
            contract: "c".into(),
            msg: b"{}".to_vec(),
            funds: vec![],
        }
        .spends_funds());
    }

    #[test]
    fn address_validation_catches_a_cross_chain_paste() {
        // The failure this prevents: a valid osmo address in a cosmoshub send. Structurally
        // perfect, and the funds are unrecoverable.
        let msg = Msg::Send {
            from_address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            to_address: "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8".to_owned(),
            amount: vec![Coin::new("uatom", "1").unwrap()],
        };
        assert_eq!(
            msg.validate_addresses("cosmos").unwrap_err(),
            CosmosError::Address
        );
        assert!(send().validate_addresses("cosmos").is_ok());
    }

    #[test]
    fn address_validation_expects_valoper_for_validators() {
        let good = Msg::Delegate {
            delegator_address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            validator_address: "cosmosvaloper19rl4cm2hmr8afy4kldpxz3fka4jguq0ae5egnx".to_owned(),
            amount: Coin::new("uatom", "1").unwrap(),
        };
        assert!(good.validate_addresses("cosmos").is_ok());

        // An account address where a validator operator address belongs.
        let bad = Msg::Delegate {
            delegator_address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            validator_address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            amount: Coin::new("uatom", "1").unwrap(),
        };
        assert_eq!(
            bad.validate_addresses("cosmos").unwrap_err(),
            CosmosError::Address
        );
    }

    #[test]
    fn execute_contract_accepts_a_wasm_contract_on_the_same_chain() {
        let msg = Msg::ExecuteContract {
            sender: "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8".to_owned(),
            contract: "osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3sqxwvxs".to_owned(),
            msg: br#"{"osmosis_swap":{}}"#.to_vec(),
            funds: vec![Coin::new("uosmo", "1").unwrap()],
        };
        assert!(msg.validate_addresses("osmo").is_ok());

        let wrong_chain = Msg::ExecuteContract {
            sender: "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8".to_owned(),
            contract: "osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3sqxwvxs".to_owned(),
            msg: br#"{"osmosis_swap":{}}"#.to_vec(),
            funds: vec![],
        };
        assert_eq!(
            wrong_chain.validate_addresses("cosmos").unwrap_err(),
            CosmosError::Address
        );
    }

    #[test]
    fn ibc_receiver_is_exempt_from_the_prefix_check() {
        // The destination is on another chain, so its prefix is legitimately different.
        let msg = Msg::IbcTransfer {
            source_port: "transfer".to_owned(),
            source_channel: "channel-141".to_owned(),
            token: Coin::new("uatom", "1").unwrap(),
            sender: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            receiver: "addr_safro19rl4cm2hmr8afy4kldpxz3fka4jguq0ayvv259".to_owned(),
            timeout_height: Height::default(),
            timeout_timestamp: 0,
            memo: String::new(),
        };
        assert!(msg.validate_addresses("cosmos").is_ok());
    }

    #[test]
    fn empty_send_is_rejected() {
        let msg = Msg::Send {
            from_address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4".to_owned(),
            to_address: "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz".to_owned(),
            amount: vec![],
        };
        assert_eq!(
            msg.validate_addresses("cosmos").unwrap_err(),
            CosmosError::Amount
        );
    }

    #[test]
    fn addresses_are_enumerated() {
        assert_eq!(send().addresses().len(), 2);
        assert_eq!(
            Msg::BeginRedelegate {
                delegator_address: "d".into(),
                validator_src_address: "s".into(),
                validator_dst_address: "t".into(),
                amount: Coin::new("uatom", "1").unwrap(),
            }
            .addresses(),
            vec!["d", "s", "t"]
        );
    }

    #[test]
    fn swap_variants_differ_in_shape_not_just_in_name() {
        // A one-leg split and a single-route swap through the same pool move the same funds,
        // but they are different messages on the wire and in Amino, so neither can stand in for
        // the other.
        let single = swap();
        let one_leg = Msg::SplitRouteSwapExactAmountIn {
            sender: OSMO_SENDER.to_owned(),
            routes: vec![leg(vec![hop(3586, OUT)], "9950000")],
            token_in_denom: "uosmo".to_owned(),
            token_out_min_amount: "350000".to_owned(),
        };
        assert_ne!(single.encode_proto(), one_leg.encode_proto());
        assert_ne!(single.encode_amino(), one_leg.encode_amino());
        assert_ne!(single.type_url(), one_leg.type_url());
        assert_eq!(
            single.summary().replace("pool 3586", ""),
            one_leg.summary().replace("1 route (pool 3586)", ""),
            "the prompt says the same thing about the same swap"
        );
    }

    #[test]
    fn delegate_and_undelegate_differ_only_by_type() {
        let delegate = Msg::Delegate {
            delegator_address: "d".into(),
            validator_address: "v".into(),
            amount: Coin::new("uatom", "1").unwrap(),
        };
        let undelegate = Msg::Undelegate {
            delegator_address: "d".into(),
            validator_address: "v".into(),
            amount: Coin::new("uatom", "1").unwrap(),
        };
        assert_eq!(delegate.encode_proto(), undelegate.encode_proto());
        assert_ne!(delegate.type_url(), undelegate.type_url());
        assert_ne!(delegate.amino_type(), undelegate.amino_type());
        assert_ne!(delegate.encode_amino(), undelegate.encode_amino());
    }
}
