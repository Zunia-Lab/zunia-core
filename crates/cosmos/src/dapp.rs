//! Messages a dApp builds and the wallet reads but does not build.
//!
//! [`crate::decode`] refuses what it cannot read. This module widens what it can read to the
//! messages the Safrochain Hub and the Osmosis front ends send: concentrated liquidity, classic
//! pools, lockups and superfluid staking, plus the Cosmos SDK and CosmWasm messages a dApp is
//! likely to ask for next. Each one is read under the rules the rest of the decoder follows:
//!
//! - every singular field goes through [`find_unique_field`], and the singular fields that are
//!   not shown are checked with [`require_unique`], so a field written twice is never read;
//! - a message that is malformed, incomplete or could not execute is not described. It falls
//!   back to [`DecodedMsg::Unknown`], which the blind-signing gate refuses;
//! - a sentence carries only text the decoder has validated: addresses and denoms of printable
//!   ASCII, integers in canonical form, ids as numbers. Free text (a contract label, a message
//!   type URL) is quoted only when it is a plain name.
//!
//! # Wire formats worth knowing
//!
//! - Osmosis `cosmossdk.io/math.Int` fields are decimal strings. `math.LegacyDec` fields with a
//!   gogoproto custom type (concentrated liquidity's `liquidity_amount`, gov v1beta1's vote
//!   `weight`) are written as the decimal's integer scaled by 10^18, so `1.0` is
//!   `"1000000000000000000"`; gov v1's `weight` is a plain decimal string, `"1.000000000000000000"`.
//!   Sentences always show the 18-place decimal the LCD shows.
//! - `int64` fields (ticks, a creation height, a duration's seconds) are varints in two's
//!   complement, so a negative tick is a ten-byte varint; they are read as `u64` and
//!   reinterpreted.
//! - `repeated uint64` (position ids) may be packed or unpacked. Both are read, and mixed.
//! - A `google.protobuf.Duration` is `seconds` 1 and `nanos` 2. A lock duration with nanoseconds
//!   is not described.
//!
//! # Not here, on purpose
//!
//! `authz` `MsgGrant` and `MsgExec`, `feegrant` `MsgGrantAllowance`, the Osmosis smartaccount
//! authenticator messages, wasm `MsgStoreCode` and gov `MsgSubmitProposal` hand control of the
//! account to someone else or run arbitrary nested messages. They stay unknown, so signing them
//! takes the blind-signing toggle. A test pins that.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::amount::{add_amounts, validate_amount, validate_denom, Coin};
use crate::decode::decode_coin;
use crate::error::{CosmosError, Result};
use crate::msg::VoteOption;
use crate::proto::{
    decode_fields, decode_packed_varints, find_all, find_unique_field, require_unique, Field,
    FieldValue,
};

/// `1` as a gov `Dec`: 10^18.
const DEC_ONE: &str = "1000000000000000000";

/// One input or output of `cosmos.bank.v1beta1.MsgMultiSend`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiSendEntry {
    pub address: String,
    pub coins: Vec<Coin>,
}

/// One entry of a weighted vote. `weight` is the 18-place decimal, `"0.500000000000000000"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedOption {
    pub option: VoteOption,
    pub weight: String,
}

/// A message read by this module. Every variant is named for its proto message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DappMsg {
    /// `osmosis.concentratedliquidity.v1beta1.MsgCreatePosition`
    CreatePosition {
        sender: String,
        pool_id: u64,
        lower_tick: i64,
        upper_tick: i64,
        tokens_provided: Vec<Coin>,
        token_min_amount0: String,
        token_min_amount1: String,
    },
    /// `osmosis.concentratedliquidity.v1beta1.MsgAddToPosition`
    AddToPosition {
        sender: String,
        position_id: u64,
        amount0: String,
        amount1: String,
        token_min_amount0: String,
        token_min_amount1: String,
    },
    /// `osmosis.concentratedliquidity.v1beta1.MsgWithdrawPosition`
    WithdrawPosition {
        sender: String,
        position_id: u64,
        /// The 18-place decimal.
        liquidity_amount: String,
    },
    /// `osmosis.concentratedliquidity.v1beta1.MsgCollectSpreadRewards`
    CollectSpreadRewards {
        sender: String,
        position_ids: Vec<u64>,
    },
    /// `osmosis.concentratedliquidity.v1beta1.MsgCollectIncentives`
    CollectIncentives {
        sender: String,
        position_ids: Vec<u64>,
    },
    /// `osmosis.concentratedliquidity.v1beta1.MsgTransferPositions`
    TransferPositions {
        sender: String,
        position_ids: Vec<u64>,
        new_owner: String,
    },
    /// `osmosis.gamm.v1beta1.MsgJoinPool`
    JoinPool {
        sender: String,
        pool_id: u64,
        share_out_amount: String,
        token_in_maxs: Vec<Coin>,
    },
    /// `osmosis.gamm.v1beta1.MsgExitPool`
    ExitPool {
        sender: String,
        pool_id: u64,
        share_in_amount: String,
        token_out_mins: Vec<Coin>,
    },
    /// `osmosis.gamm.v1beta1.MsgJoinSwapExternAmountIn`
    JoinSwapExternAmountIn {
        sender: String,
        pool_id: u64,
        token_in: Option<Coin>,
        share_out_min_amount: String,
    },
    /// `osmosis.gamm.v1beta1.MsgExitSwapShareAmountIn`
    ExitSwapShareAmountIn {
        sender: String,
        pool_id: u64,
        token_out_denom: String,
        share_in_amount: String,
        token_out_min_amount: String,
    },
    /// `osmosis.gamm.v1beta1.MsgJoinSwapShareAmountOut`
    JoinSwapShareAmountOut {
        sender: String,
        pool_id: u64,
        token_in_denom: String,
        share_out_amount: String,
        token_in_max_amount: String,
    },
    /// `osmosis.gamm.v1beta1.MsgExitSwapExternAmountOut`
    ExitSwapExternAmountOut {
        sender: String,
        pool_id: u64,
        token_out: Option<Coin>,
        share_in_max_amount: String,
    },
    /// `osmosis.lockup.MsgLockTokens`
    LockTokens {
        owner: String,
        duration_seconds: i64,
        coins: Vec<Coin>,
    },
    /// `osmosis.lockup.MsgBeginUnlocking`
    BeginUnlocking {
        owner: String,
        lock_id: u64,
        /// Empty means the whole lock.
        coins: Vec<Coin>,
    },
    /// `osmosis.lockup.MsgBeginUnlockingAll`
    BeginUnlockingAll { owner: String },
    /// `osmosis.superfluid.MsgSuperfluidDelegate`
    SuperfluidDelegate {
        sender: String,
        lock_id: u64,
        validator: String,
    },
    /// `osmosis.superfluid.MsgSuperfluidUndelegate`
    SuperfluidUndelegate { sender: String, lock_id: u64 },
    /// `osmosis.superfluid.MsgLockAndSuperfluidDelegate`
    LockAndSuperfluidDelegate {
        sender: String,
        coins: Vec<Coin>,
        validator: String,
    },
    /// `osmosis.superfluid.MsgSuperfluidUnbondLock`
    SuperfluidUnbondLock { sender: String, lock_id: u64 },
    /// `osmosis.superfluid.MsgSuperfluidUndelegateAndUnbondLock`
    SuperfluidUndelegateAndUnbondLock {
        sender: String,
        lock_id: u64,
        coin: Option<Coin>,
    },
    /// `osmosis.superfluid.MsgCreateFullRangePositionAndSuperfluidDelegate`
    CreateFullRangePositionAndSuperfluidDelegate {
        sender: String,
        coins: Vec<Coin>,
        validator: String,
        pool_id: u64,
    },
    /// `osmosis.superfluid.MsgAddToConcentratedLiquiditySuperfluidPosition`
    AddToConcentratedLiquiditySuperfluidPosition {
        sender: String,
        position_id: u64,
        token_desired0: Option<Coin>,
        token_desired1: Option<Coin>,
    },
    /// `cosmos.bank.v1beta1.MsgMultiSend`
    MultiSend {
        inputs: Vec<MultiSendEntry>,
        outputs: Vec<MultiSendEntry>,
    },
    /// `cosmos.staking.v1beta1.MsgCancelUnbondingDelegation`
    CancelUnbondingDelegation {
        delegator: String,
        validator: String,
        amount: Option<Coin>,
        creation_height: i64,
    },
    /// `cosmos.distribution.v1beta1.MsgSetWithdrawAddress`
    SetWithdrawAddress {
        delegator: String,
        withdraw_address: String,
    },
    /// `cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission`
    WithdrawValidatorCommission { validator: String },
    /// `cosmos.distribution.v1beta1.MsgFundCommunityPool`
    FundCommunityPool {
        depositor: String,
        amount: Vec<Coin>,
    },
    /// `cosmos.gov.v1beta1.MsgDeposit` and `cosmos.gov.v1.MsgDeposit`
    Deposit {
        proposal_id: u64,
        depositor: String,
        amount: Vec<Coin>,
    },
    /// `cosmos.gov.v1beta1.MsgVoteWeighted` and `cosmos.gov.v1.MsgVoteWeighted`
    VoteWeighted {
        proposal_id: u64,
        voter: String,
        options: Vec<WeightedOption>,
    },
    /// `cosmos.authz.v1beta1.MsgRevoke`
    RevokeAuthorization {
        granter: String,
        grantee: String,
        msg_type_url: String,
    },
    /// `cosmos.feegrant.v1beta1.MsgRevokeAllowance`
    RevokeAllowance { granter: String, grantee: String },
    /// `cosmwasm.wasm.v1.MsgInstantiateContract` and, with a salt, `MsgInstantiateContract2`.
    InstantiateContract {
        sender: String,
        /// Empty when the contract has no admin.
        admin: String,
        code_id: u64,
        label: String,
        msg: Option<Value>,
        funds: Vec<Coin>,
        /// `Some((salt, fix_msg))` for `MsgInstantiateContract2`.
        v2: Option<(Vec<u8>, bool)>,
    },
    /// `cosmwasm.wasm.v1.MsgMigrateContract`
    MigrateContract {
        sender: String,
        contract: String,
        code_id: u64,
        msg: Option<Value>,
    },
    /// `cosmwasm.wasm.v1.MsgUpdateAdmin`
    UpdateAdmin {
        sender: String,
        new_admin: String,
        contract: String,
    },
    /// `cosmwasm.wasm.v1.MsgClearAdmin`
    ClearAdmin { sender: String, contract: String },
}

impl DappMsg {
    /// The sentence for the signing prompt. See the table in the pull request for the templates.
    pub fn summary(&self) -> String {
        match self {
            Self::CreatePosition {
                pool_id,
                lower_tick,
                upper_tick,
                tokens_provided,
                token_min_amount0,
                token_min_amount1,
                ..
            } => format!(
                "Create a concentrated liquidity position in pool {pool_id} between ticks \
                 {lower_tick} and {upper_tick} with {}, accepting at least {token_min_amount0} \
                 of the pool's token0 and {token_min_amount1} of its token1",
                coins_text(tokens_provided)
            ),
            Self::AddToPosition {
                position_id,
                amount0,
                amount1,
                token_min_amount0,
                token_min_amount1,
                ..
            } => format!(
                "Add {amount0} of the pool's token0 and {amount1} of its token1 to concentrated \
                 liquidity position {position_id}, using at least {token_min_amount0} and \
                 {token_min_amount1} of them; the message names no denoms"
            ),
            Self::WithdrawPosition {
                position_id,
                liquidity_amount,
                ..
            } => format!(
                "Withdraw {liquidity_amount} liquidity units (the message names no denom) from \
                 concentrated liquidity position {position_id}"
            ),
            Self::CollectSpreadRewards { position_ids, .. } => format!(
                "Collect the spread rewards of concentrated liquidity {}",
                positions_text(position_ids)
            ),
            Self::CollectIncentives { position_ids, .. } => format!(
                "Collect the incentives of concentrated liquidity {}",
                positions_text(position_ids)
            ),
            Self::TransferPositions {
                position_ids,
                new_owner,
                ..
            } => format!(
                "Transfer concentrated liquidity {} to {new_owner}",
                positions_text(position_ids)
            ),
            Self::JoinPool {
                pool_id,
                share_out_amount,
                token_in_maxs,
                ..
            } => format!(
                "Join pool {pool_id} for exactly {share_out_amount} gamm/pool/{pool_id} shares, \
                 paying at most {}",
                coins_text(token_in_maxs)
            ),
            Self::ExitPool {
                pool_id,
                share_in_amount,
                token_out_mins,
                ..
            } => format!(
                "Exit pool {pool_id} by burning {share_in_amount} gamm/pool/{pool_id} shares, \
                 {}",
                if token_out_mins.is_empty() {
                    "with no minimum amount out".to_owned()
                } else {
                    format!("receiving at least {}", coins_text(token_out_mins))
                }
            ),
            Self::JoinSwapExternAmountIn {
                pool_id,
                token_in,
                share_out_min_amount,
                ..
            } => format!(
                "Join pool {pool_id} with {} alone, receiving at least {share_out_min_amount} \
                 gamm/pool/{pool_id} shares",
                coin_text(token_in)
            ),
            Self::ExitSwapShareAmountIn {
                pool_id,
                token_out_denom,
                share_in_amount,
                token_out_min_amount,
                ..
            } => format!(
                "Exit pool {pool_id} by burning {share_in_amount} gamm/pool/{pool_id} shares for \
                 {token_out_denom} alone, receiving at least {token_out_min_amount} \
                 {token_out_denom}"
            ),
            Self::JoinSwapShareAmountOut {
                pool_id,
                token_in_denom,
                share_out_amount,
                token_in_max_amount,
                ..
            } => format!(
                "Join pool {pool_id} with {token_in_denom} alone, paying at most \
                 {token_in_max_amount} {token_in_denom} for exactly {share_out_amount} \
                 gamm/pool/{pool_id} shares"
            ),
            Self::ExitSwapExternAmountOut {
                pool_id,
                token_out,
                share_in_max_amount,
                ..
            } => format!(
                "Exit pool {pool_id} receiving exactly {} alone, burning at most \
                 {share_in_max_amount} gamm/pool/{pool_id} shares",
                coin_text(token_out)
            ),
            Self::LockTokens {
                duration_seconds,
                coins,
                ..
            } => format!("Lock {} for {duration_seconds} seconds", coins_text(coins)),
            Self::BeginUnlocking { lock_id, coins, .. } => {
                if coins.is_empty() {
                    format!("Begin unlocking all the tokens of lock {lock_id}")
                } else {
                    format!("Begin unlocking {} from lock {lock_id}", coins_text(coins))
                }
            }
            Self::BeginUnlockingAll { owner } => {
                format!("Begin unlocking every lock owned by {owner}")
            }
            Self::SuperfluidDelegate {
                lock_id, validator, ..
            } => format!("Superfluid-delegate lock {lock_id} to validator {validator}"),
            Self::SuperfluidUndelegate { lock_id, .. } => {
                format!("Superfluid-undelegate lock {lock_id}")
            }
            Self::LockAndSuperfluidDelegate {
                coins, validator, ..
            } => format!(
                "Lock {} and superfluid-delegate it to validator {validator}",
                coins_text(coins)
            ),
            Self::SuperfluidUnbondLock { lock_id, .. } => {
                format!("Superfluid-unbond lock {lock_id}")
            }
            Self::SuperfluidUndelegateAndUnbondLock { lock_id, coin, .. } => format!(
                "Superfluid-undelegate lock {lock_id} and unbond {} from it",
                coin_text(coin)
            ),
            Self::CreateFullRangePositionAndSuperfluidDelegate {
                coins,
                validator,
                pool_id,
                ..
            } => format!(
                "Create a full-range concentrated liquidity position in pool {pool_id} with {} \
                 and superfluid-delegate it to validator {validator}",
                coins_text(coins)
            ),
            Self::AddToConcentratedLiquiditySuperfluidPosition {
                position_id,
                token_desired0,
                token_desired1,
                ..
            } => format!(
                "Add {} and {} to superfluid concentrated liquidity position {position_id}",
                coin_text(token_desired0),
                coin_text(token_desired1)
            ),
            Self::MultiSend { inputs, outputs } => format!(
                "Send {} in one multi-send paid by {}",
                outputs
                    .iter()
                    .map(|out| format!("{} to {}", coins_text(&out.coins), out.address))
                    .collect::<Vec<_>>()
                    .join("; "),
                inputs
                    .iter()
                    .map(|input| format!("{} ({})", input.address, coins_text(&input.coins)))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::CancelUnbondingDelegation {
                validator,
                amount,
                creation_height,
                ..
            } => format!(
                "Cancel the unbonding of {} from {validator}, created at height {creation_height}",
                coin_text(amount)
            ),
            Self::SetWithdrawAddress {
                withdraw_address, ..
            } => {
                format!("Set the address that receives your staking rewards to {withdraw_address}")
            }
            Self::WithdrawValidatorCommission { validator } => {
                format!("Withdraw the commission of validator {validator}")
            }
            Self::FundCommunityPool { amount, .. } => {
                format!("Fund the community pool with {}", coins_text(amount))
            }
            Self::Deposit {
                proposal_id,
                amount,
                ..
            } => format!("Deposit {} on proposal {proposal_id}", coins_text(amount)),
            Self::VoteWeighted {
                proposal_id,
                options,
                ..
            } => format!(
                "Vote {} on proposal {proposal_id}",
                options
                    .iter()
                    .map(|entry| format!("{} {}", entry.option.label(), entry.weight))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::RevokeAuthorization {
                grantee,
                msg_type_url,
                ..
            } => format!("Revoke the authorization given to {grantee} for {msg_type_url}"),
            Self::RevokeAllowance { grantee, .. } => {
                format!("Revoke the fee allowance given to {grantee}")
            }
            Self::InstantiateContract {
                admin,
                code_id,
                funds,
                v2,
                ..
            } => {
                let mut text = format!(
                    "Instantiate code {code_id} as a new contract{}",
                    if v2.is_some() {
                        " at a salt-derived address"
                    } else {
                        ""
                    }
                );
                if admin.is_empty() {
                    text.push_str(" with no admin");
                } else {
                    text.push_str(&format!(" with admin {admin}"));
                }
                if !funds.is_empty() {
                    text.push_str(&format!(", sending {}", coins_text(funds)));
                }
                text
            }
            Self::MigrateContract {
                contract, code_id, ..
            } => format!("Migrate contract {contract} to code {code_id}"),
            Self::UpdateAdmin {
                new_admin,
                contract,
                ..
            } => format!("Make {new_admin} the admin of contract {contract}"),
            Self::ClearAdmin { contract, .. } => {
                format!("Clear the admin of contract {contract}, so nobody can migrate it again")
            }
        }
    }

    /// Every address the message names, the signer first.
    pub fn addresses(&self) -> Vec<&str> {
        match self {
            Self::CreatePosition { sender, .. }
            | Self::AddToPosition { sender, .. }
            | Self::WithdrawPosition { sender, .. }
            | Self::CollectSpreadRewards { sender, .. }
            | Self::CollectIncentives { sender, .. }
            | Self::JoinPool { sender, .. }
            | Self::ExitPool { sender, .. }
            | Self::JoinSwapExternAmountIn { sender, .. }
            | Self::ExitSwapShareAmountIn { sender, .. }
            | Self::JoinSwapShareAmountOut { sender, .. }
            | Self::ExitSwapExternAmountOut { sender, .. }
            | Self::SuperfluidUndelegate { sender, .. }
            | Self::SuperfluidUnbondLock { sender, .. }
            | Self::SuperfluidUndelegateAndUnbondLock { sender, .. }
            | Self::AddToConcentratedLiquiditySuperfluidPosition { sender, .. } => vec![sender],
            Self::LockTokens { owner, .. }
            | Self::BeginUnlocking { owner, .. }
            | Self::BeginUnlockingAll { owner } => vec![owner],
            Self::TransferPositions {
                sender, new_owner, ..
            } => vec![sender, new_owner],
            Self::SuperfluidDelegate {
                sender, validator, ..
            }
            | Self::LockAndSuperfluidDelegate {
                sender, validator, ..
            }
            | Self::CreateFullRangePositionAndSuperfluidDelegate {
                sender, validator, ..
            } => vec![sender, validator],
            Self::MultiSend { inputs, outputs } => inputs
                .iter()
                .chain(outputs)
                .map(|entry| entry.address.as_str())
                .collect(),
            Self::CancelUnbondingDelegation {
                delegator,
                validator,
                ..
            } => vec![delegator, validator],
            Self::SetWithdrawAddress {
                delegator,
                withdraw_address,
            } => vec![delegator, withdraw_address],
            Self::WithdrawValidatorCommission { validator } => vec![validator],
            Self::FundCommunityPool { depositor, .. } | Self::Deposit { depositor, .. } => {
                vec![depositor]
            }
            Self::VoteWeighted { voter, .. } => vec![voter],
            Self::RevokeAuthorization {
                granter, grantee, ..
            }
            | Self::RevokeAllowance { granter, grantee } => vec![granter, grantee],
            Self::InstantiateContract { sender, admin, .. } => {
                let mut out = vec![sender.as_str()];
                if !admin.is_empty() {
                    out.push(admin);
                }
                out
            }
            Self::MigrateContract {
                sender, contract, ..
            }
            | Self::ClearAdmin { sender, contract } => vec![sender, contract],
            Self::UpdateAdmin {
                sender,
                new_admin,
                contract,
            } => vec![sender, new_admin, contract],
        }
    }

    /// The address that receives funds, ownership or rights from the signer, when exactly one
    /// does.
    ///
    /// - `MsgTransferPositions`: the new owner.
    /// - `MsgSetWithdrawAddress`: the withdraw address.
    /// - `MsgUpdateAdmin`: the new admin.
    /// - An instantiate: its admin, when set.
    /// - `MsgMultiSend`: the one output address that is not also an input, when there is exactly
    ///   one such address. With several, no single address can stand for the payment, so the
    ///   field stays unset; [`Self::addresses`], the sentence and [`Self::detail`] name them all.
    pub fn recipient(&self) -> Option<&str> {
        match self {
            Self::TransferPositions { new_owner, .. } => Some(new_owner),
            Self::SetWithdrawAddress {
                withdraw_address, ..
            } => Some(withdraw_address),
            Self::UpdateAdmin { new_admin, .. } => Some(new_admin),
            Self::InstantiateContract { admin, .. } if !admin.is_empty() => Some(admin),
            Self::MultiSend { inputs, outputs } => {
                let mut others = outputs
                    .iter()
                    .map(|out| out.address.as_str())
                    .filter(|address| inputs.iter().all(|input| input.address != *address));
                let first = others.next()?;
                others.all(|other| other == first).then_some(first)
            }
            _ => None,
        }
    }

    /// What a multi-send, an instantiate or a migrate carries that its summary does not say.
    ///
    /// - `{ kind: "multi-send", inputs: [{ address, coins }], outputs: [{ address, coins }] }`
    /// - `{ kind: "instantiate-contract", codeId, label, admin, msg, funds }`, with `admin` null
    ///   when unset, plus `salt` (hex) and `fixMsg` for `MsgInstantiateContract2`
    /// - `{ kind: "migrate-contract", contract, codeId, msg }`
    ///
    /// `codeId` is a decimal string, and `msg` is the contract message parsed as JSON.
    pub fn detail(&self) -> Option<Value> {
        match self {
            Self::MultiSend { inputs, outputs } => {
                let entries = |list: &[MultiSendEntry]| -> Vec<Value> {
                    list.iter()
                        .map(|entry| {
                            json!({
                                "address": entry.address,
                                "coins": coins_json(&entry.coins),
                            })
                        })
                        .collect()
                };
                Some(json!({
                    "kind": "multi-send",
                    "inputs": entries(inputs),
                    "outputs": entries(outputs),
                }))
            }
            Self::InstantiateContract {
                admin,
                code_id,
                label,
                msg,
                funds,
                v2,
                ..
            } => {
                let mut detail = json!({
                    "kind": "instantiate-contract",
                    "codeId": code_id.to_string(),
                    "label": label,
                    "admin": if admin.is_empty() { Value::Null } else { json!(admin) },
                    "msg": msg,
                    "funds": coins_json(funds),
                });
                if let (Some((salt, fix_msg)), Some(map)) = (v2, detail.as_object_mut()) {
                    map.insert("salt".to_owned(), json!(hex::encode(salt)));
                    map.insert("fixMsg".to_owned(), json!(fix_msg));
                }
                Some(detail)
            }
            Self::MigrateContract {
                contract,
                code_id,
                msg,
                ..
            } => Some(json!({
                "kind": "migrate-contract",
                "contract": contract,
                "codeId": code_id.to_string(),
                "msg": msg,
            })),
            _ => None,
        }
    }

    /// The addresses that must be accounts of the chain being signed for, the signer first.
    pub(crate) fn accounts(&self) -> Vec<&str> {
        match self {
            Self::MultiSend { inputs, .. } => {
                inputs.iter().map(|input| input.address.as_str()).collect()
            }
            Self::TransferPositions { sender, .. }
            | Self::InstantiateContract { sender, .. }
            | Self::MigrateContract { sender, .. }
            | Self::UpdateAdmin { sender, .. }
            | Self::ClearAdmin { sender, .. } => vec![sender],
            Self::SetWithdrawAddress { delegator, .. } => vec![delegator],
            Self::RevokeAuthorization { granter, .. } | Self::RevokeAllowance { granter, .. } => {
                vec![granter]
            }
            other => other.addresses(),
        }
    }

    /// The addresses that may also be module-derived (32 bytes) under the signer's prefix: a
    /// contract, a recipient, a new owner or admin.
    pub(crate) fn derived_addresses(&self) -> Vec<&str> {
        match self {
            Self::MultiSend { outputs, .. } => {
                outputs.iter().map(|out| out.address.as_str()).collect()
            }
            Self::TransferPositions { new_owner, .. } => vec![new_owner],
            Self::SetWithdrawAddress {
                withdraw_address, ..
            } => vec![withdraw_address],
            Self::RevokeAuthorization { grantee, .. } | Self::RevokeAllowance { grantee, .. } => {
                vec![grantee]
            }
            Self::InstantiateContract { admin, .. } if !admin.is_empty() => vec![admin],
            Self::MigrateContract { contract, .. } | Self::ClearAdmin { contract, .. } => {
                vec![contract]
            }
            Self::UpdateAdmin {
                new_admin,
                contract,
                ..
            } => vec![new_admin, contract],
            _ => Vec::new(),
        }
    }

    /// Whether the message is one the chain could execute and the sentence describes honestly.
    ///
    /// A message that fails is demoted to unknown: "for exactly 0 shares" or "at ticks 5 and 3"
    /// describes something that cannot happen, while the bytes might still mean something where
    /// the wallet did not check.
    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::CreatePosition {
                pool_id,
                lower_tick,
                upper_tick,
                tokens_provided,
                token_min_amount0,
                token_min_amount1,
                ..
            } => {
                *pool_id != 0
                    && lower_tick < upper_tick
                    && good_coins(tokens_provided, 1, 2)
                    && is_amount(token_min_amount0)
                    && is_amount(token_min_amount1)
            }
            Self::AddToPosition {
                position_id,
                amount0,
                amount1,
                token_min_amount0,
                token_min_amount1,
                ..
            } => {
                *position_id != 0
                    && is_amount(amount0)
                    && is_amount(amount1)
                    && !(amount0 == "0" && amount1 == "0")
                    && is_amount(token_min_amount0)
                    && is_amount(token_min_amount1)
            }
            Self::WithdrawPosition {
                position_id,
                liquidity_amount,
                ..
            } => {
                *position_id != 0
                    && is_dec_display(liquidity_amount)
                    && !is_zero_dec(liquidity_amount)
            }
            Self::CollectSpreadRewards { position_ids, .. }
            | Self::CollectIncentives { position_ids, .. }
            | Self::TransferPositions { position_ids, .. } => good_ids(position_ids),
            Self::JoinPool {
                pool_id,
                share_out_amount,
                token_in_maxs,
                ..
            } => *pool_id != 0 && is_positive(share_out_amount) && good_coins(token_in_maxs, 1, 64),
            Self::ExitPool {
                pool_id,
                share_in_amount,
                token_out_mins,
                ..
            } => {
                *pool_id != 0
                    && is_positive(share_in_amount)
                    && (token_out_mins.is_empty() || good_coins(token_out_mins, 1, 64))
            }
            Self::JoinSwapExternAmountIn {
                pool_id,
                token_in,
                share_out_min_amount,
                ..
            } => {
                *pool_id != 0
                    && token_in.as_ref().is_some_and(|coin| good_coin(coin, false))
                    && is_positive(share_out_min_amount)
            }
            Self::ExitSwapShareAmountIn {
                pool_id,
                token_out_denom,
                share_in_amount,
                token_out_min_amount,
                ..
            } => {
                *pool_id != 0
                    && validate_denom(token_out_denom).is_ok()
                    && is_positive(share_in_amount)
                    && is_positive(token_out_min_amount)
            }
            Self::JoinSwapShareAmountOut {
                pool_id,
                token_in_denom,
                share_out_amount,
                token_in_max_amount,
                ..
            } => {
                *pool_id != 0
                    && validate_denom(token_in_denom).is_ok()
                    && is_positive(share_out_amount)
                    && is_positive(token_in_max_amount)
            }
            Self::ExitSwapExternAmountOut {
                pool_id,
                token_out,
                share_in_max_amount,
                ..
            } => {
                *pool_id != 0
                    && token_out
                        .as_ref()
                        .is_some_and(|coin| good_coin(coin, false))
                    && is_positive(share_in_max_amount)
            }
            Self::LockTokens {
                duration_seconds,
                coins,
                ..
            } => *duration_seconds > 0 && good_coins(coins, 1, 64),
            Self::BeginUnlocking { lock_id, coins, .. } => {
                *lock_id != 0 && (coins.is_empty() || good_coins(coins, 1, 64))
            }
            Self::BeginUnlockingAll { .. } => true,
            Self::SuperfluidDelegate { lock_id, .. }
            | Self::SuperfluidUndelegate { lock_id, .. }
            | Self::SuperfluidUnbondLock { lock_id, .. } => *lock_id != 0,
            Self::LockAndSuperfluidDelegate { coins, .. } => good_coins(coins, 1, 64),
            Self::SuperfluidUndelegateAndUnbondLock { lock_id, coin, .. } => {
                *lock_id != 0 && coin.as_ref().is_some_and(|coin| good_coin(coin, false))
            }
            Self::CreateFullRangePositionAndSuperfluidDelegate { coins, pool_id, .. } => {
                *pool_id != 0 && good_coins(coins, 1, 2)
            }
            Self::AddToConcentratedLiquiditySuperfluidPosition {
                position_id,
                token_desired0,
                token_desired1,
                ..
            } => match (token_desired0, token_desired1) {
                (Some(first), Some(second)) => {
                    *position_id != 0
                        && good_coin(first, true)
                        && good_coin(second, true)
                        && !(first.amount == "0" && second.amount == "0")
                }
                _ => false,
            },
            Self::MultiSend { inputs, outputs } => multi_send_is_balanced(inputs, outputs),
            Self::CancelUnbondingDelegation {
                amount,
                creation_height,
                ..
            } => *creation_height > 0 && amount.as_ref().is_some_and(|coin| good_coin(coin, false)),
            Self::SetWithdrawAddress { .. }
            | Self::WithdrawValidatorCommission { .. }
            | Self::RevokeAllowance { .. } => true,
            Self::FundCommunityPool { amount, .. } | Self::Deposit { amount, .. } => {
                good_coins(amount, 1, 64)
            }
            Self::RevokeAuthorization { msg_type_url, .. } => is_plain_type_url(msg_type_url),
            Self::VoteWeighted {
                proposal_id,
                options,
                ..
            } => {
                let mut total = "0".to_owned();
                let mut seen = Vec::new();
                for entry in options {
                    let Some(scaled) = scaled_from_display(&entry.weight) else {
                        return false;
                    };
                    if scaled == "0" || seen.contains(&entry.option.proto_name()) {
                        return false;
                    }
                    seen.push(entry.option.proto_name());
                    match add_amounts(&total, &scaled) {
                        Some(sum) => total = sum,
                        None => return false,
                    }
                }
                *proposal_id != 0 && !options.is_empty() && total == DEC_ONE
            }
            Self::InstantiateContract {
                code_id,
                label,
                msg,
                funds,
                v2,
                ..
            } => {
                *code_id != 0
                    && !label.is_empty()
                    && msg.is_some()
                    && (funds.is_empty() || good_coins(funds, 1, 64))
                    && v2
                        .as_ref()
                        .is_none_or(|(salt, _)| !salt.is_empty() && salt.len() <= 64)
            }
            Self::MigrateContract { code_id, msg, .. } => *code_id != 0 && msg.is_some(),
            Self::UpdateAdmin { .. } | Self::ClearAdmin { .. } => true,
        }
    }
}

fn coin_text(coin: &Option<Coin>) -> String {
    match coin {
        Some(coin) => format!("{} {}", coin.amount, coin.denom),
        None => "an unreadable amount".to_owned(),
    }
}

fn coins_text(coins: &[Coin]) -> String {
    coins
        .iter()
        .map(|coin| format!("{} {}", coin.amount, coin.denom))
        .collect::<Vec<_>>()
        .join(", ")
}

fn positions_text(ids: &[u64]) -> String {
    let list = ids
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} {list}",
        if ids.len() == 1 {
            "position"
        } else {
            "positions"
        }
    )
}

fn coins_json(coins: &[Coin]) -> Vec<Value> {
    coins
        .iter()
        .map(|coin| json!({ "denom": coin.denom, "amount": coin.amount }))
        .collect()
}

// -- validation ---------------------------------------------------------------------------------

/// A canonical non-negative integer, as a `math.Int` is written.
fn is_amount(amount: &str) -> bool {
    validate_amount(amount).is_ok()
}

fn is_positive(amount: &str) -> bool {
    is_amount(amount) && amount != "0"
}

fn good_coin(coin: &Coin, allow_zero: bool) -> bool {
    validate_denom(&coin.denom).is_ok()
        && is_amount(&coin.amount)
        && (allow_zero || coin.amount != "0")
}

/// Between `min` and `max` coins, each valid and non-zero, no denom twice.
fn good_coins(coins: &[Coin], min: usize, max: usize) -> bool {
    (min..=max).contains(&coins.len())
        && coins.iter().all(|coin| good_coin(coin, false))
        && coins
            .iter()
            .enumerate()
            .all(|(index, coin)| coins[..index].iter().all(|other| other.denom != coin.denom))
}

/// At least one id, none of them zero, none twice.
fn good_ids(ids: &[u64]) -> bool {
    !ids.is_empty()
        && ids
            .iter()
            .enumerate()
            .all(|(index, id)| *id != 0 && !ids[..index].contains(id))
}

/// A message type URL that is safe to quote: a leading slash and then letters, digits, dots and
/// underscores, which is all a protobuf full name holds.
fn is_plain_type_url(url: &str) -> bool {
    url.len() <= 256
        && url.strip_prefix('/').is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_')
        })
}

/// The multi-send rules the chain applies: at least one input and one output, every coin list
/// valid, and what goes in is what comes out, denom by denom.
fn multi_send_is_balanced(inputs: &[MultiSendEntry], outputs: &[MultiSendEntry]) -> bool {
    let total = |entries: &[MultiSendEntry]| -> Option<BTreeMap<String, String>> {
        let mut sums: BTreeMap<String, String> = BTreeMap::new();
        for entry in entries {
            if !good_coins(&entry.coins, 1, 64) {
                return None;
            }
            for coin in &entry.coins {
                let sum = match sums.get(&coin.denom) {
                    Some(previous) => add_amounts(previous, &coin.amount)?,
                    None => coin.amount.clone(),
                };
                sums.insert(coin.denom.clone(), sum);
            }
        }
        Some(sums)
    };
    !inputs.is_empty()
        && !outputs.is_empty()
        && matches!((total(inputs), total(outputs)), (Some(a), Some(b)) if a == b)
}

// -- decimals -----------------------------------------------------------------------------------

/// `"500000000000000000"` to `"0.500000000000000000"`: a `LegacyDec` as gogoproto writes it, to
/// the decimal the LCD shows.
fn display_from_scaled(scaled: &str) -> Result<String> {
    validate_amount(scaled).map_err(|_| CosmosError::Decode)?;
    let padded = format!("{scaled:0>19}");
    let (whole, fraction) = padded.split_at(padded.len() - 18);
    Ok(format!("{whole}.{fraction}"))
}

/// `"0.5"` to `"500000000000000000"`: a plain decimal string, as gov v1 writes a weight, to the
/// scaled integer. At most 18 decimal places, as the chain accepts.
fn scaled_from_decimal(text: &str) -> Result<String> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 18
        || text.ends_with('.')
    {
        return Err(CosmosError::Decode);
    }
    let digits = format!("{whole}{fraction:0<18}");
    let trimmed = digits.trim_start_matches('0');
    Ok(if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    })
}

/// The scaled integer behind an 18-place display decimal.
fn scaled_from_display(display: &str) -> Option<String> {
    is_dec_display(display)
        .then(|| scaled_from_decimal(display).ok())
        .flatten()
}

fn is_dec_display(display: &str) -> bool {
    display.split_once('.').is_some_and(|(whole, fraction)| {
        !whole.is_empty()
            && whole.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.len() == 18
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn is_zero_dec(display: &str) -> bool {
    display.bytes().all(|byte| byte == b'0' || byte == b'.')
}

// -- decoding -----------------------------------------------------------------------------------

/// Reads a message body field by field. Every singular accessor refuses a second occurrence.
struct Body<'a>(&'a [Field]);

impl Body<'_> {
    fn string(&self, tag: u32) -> Result<String> {
        Ok(find_unique_field(self.0, tag)?
            .map(FieldValue::as_string)
            .transpose()?
            .unwrap_or_default())
    }

    fn u64(&self, tag: u32) -> Result<u64> {
        Ok(find_unique_field(self.0, tag)?
            .map(FieldValue::as_varint)
            .transpose()?
            .unwrap_or(0))
    }

    /// An `int64`: a varint in two's complement, so `-5` is ten bytes and reads as `u64::MAX - 4`.
    fn i64(&self, tag: u32) -> Result<i64> {
        Ok(self.u64(tag)? as i64)
    }

    fn bool(&self, tag: u32) -> Result<bool> {
        match self.u64(tag)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CosmosError::Decode),
        }
    }

    fn bytes(&self, tag: u32) -> Result<Vec<u8>> {
        Ok(find_unique_field(self.0, tag)?
            .map(|value| value.as_bytes().map(<[u8]>::to_vec))
            .transpose()?
            .unwrap_or_default())
    }

    fn coin(&self, tag: u32) -> Result<Option<Coin>> {
        find_unique_field(self.0, tag)?
            .map(|value| decode_coin(value.as_bytes()?))
            .transpose()
    }

    fn coins(&self, tag: u32) -> Result<Vec<Coin>> {
        find_all(self.0, tag)
            .into_iter()
            .map(|value| decode_coin(value.as_bytes()?))
            .collect()
    }

    /// A `repeated uint64`, packed or unpacked or both.
    fn u64s(&self, tag: u32) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        for value in find_all(self.0, tag) {
            match value {
                FieldValue::Varint(id) => out.push(*id),
                FieldValue::Bytes(packed) => out.extend(decode_packed_varints(packed)?),
            }
        }
        Ok(out)
    }

    /// The JSON a contract message holds, `None` when the bytes are not JSON.
    fn json(&self, tag: u32) -> Result<Option<Value>> {
        Ok(serde_json::from_slice(&self.bytes(tag)?).ok())
    }
}

/// `google.protobuf.Duration` as whole seconds. Nanoseconds are refused: a lock lasts whole
/// seconds in practice, and a sentence that rounded them away would not be exact.
fn decode_duration(value: Option<&FieldValue>) -> Result<i64> {
    let Some(value) = value else {
        return Ok(0);
    };
    let fields = decode_fields(value.as_bytes()?)?;
    let body = Body(&fields);
    if body.u64(2)? != 0 {
        return Err(CosmosError::Decode);
    }
    body.i64(1)
}

/// `cosmos.bank.v1beta1.Input` and `Output`: address 1, coins 2.
fn decode_entry(bytes: &[u8]) -> Result<MultiSendEntry> {
    let fields = decode_fields(bytes)?;
    let body = Body(&fields);
    Ok(MultiSendEntry {
        address: body.string(1)?,
        coins: body.coins(2)?,
    })
}

/// `cosmos.gov.v1beta1.WeightedVoteOption` and its v1 twin: option 1, weight 2.
///
/// `scaled` says how the weight is written: gov v1beta1 as the integer scaled by 10^18, gov v1 as
/// a plain decimal string.
fn decode_weighted(bytes: &[u8], scaled: bool) -> Result<Option<WeightedOption>> {
    let fields = decode_fields(bytes)?;
    let body = Body(&fields);
    let option = match body.u64(1)? {
        1 => VoteOption::Yes,
        2 => VoteOption::Abstain,
        3 => VoteOption::No,
        4 => VoteOption::NoWithVeto,
        // Unspecified or outside the enum: not approvable.
        _ => return Ok(None),
    };
    let weight = body.string(2)?;
    let weight = if scaled {
        display_from_scaled(&weight)?
    } else {
        display_from_scaled(&scaled_from_decimal(&weight)?)?
    };
    Ok(Some(WeightedOption { option, weight }))
}

/// Decodes the body of a message this module knows, or `None` for any other type URL.
///
/// An error, a duplicated singular field included, makes the caller show the message as unknown.
pub(crate) fn decode(type_url: &str, fields: &[Field]) -> Result<Option<DappMsg>> {
    let b = Body(fields);
    let msg = match type_url {
        // -- concentrated liquidity ------------------------------------------------------------
        "/osmosis.concentratedliquidity.v1beta1.MsgCreatePosition" => DappMsg::CreatePosition {
            pool_id: b.u64(1)?,
            sender: b.string(2)?,
            lower_tick: b.i64(3)?,
            upper_tick: b.i64(4)?,
            tokens_provided: b.coins(5)?,
            token_min_amount0: b.string(6)?,
            token_min_amount1: b.string(7)?,
        },
        "/osmosis.concentratedliquidity.v1beta1.MsgAddToPosition" => DappMsg::AddToPosition {
            position_id: b.u64(1)?,
            sender: b.string(2)?,
            amount0: b.string(3)?,
            amount1: b.string(4)?,
            token_min_amount0: b.string(5)?,
            token_min_amount1: b.string(6)?,
        },
        "/osmosis.concentratedliquidity.v1beta1.MsgWithdrawPosition" => {
            DappMsg::WithdrawPosition {
                position_id: b.u64(1)?,
                sender: b.string(2)?,
                // A custom-typed LegacyDec: the integer scaled by 10^18.
                liquidity_amount: display_from_scaled(&b.string(3)?)?,
            }
        }
        "/osmosis.concentratedliquidity.v1beta1.MsgCollectSpreadRewards" => {
            DappMsg::CollectSpreadRewards {
                position_ids: b.u64s(1)?,
                sender: b.string(2)?,
            }
        }
        "/osmosis.concentratedliquidity.v1beta1.MsgCollectIncentives" => {
            DappMsg::CollectIncentives {
                position_ids: b.u64s(1)?,
                sender: b.string(2)?,
            }
        }
        "/osmosis.concentratedliquidity.v1beta1.MsgTransferPositions" => {
            DappMsg::TransferPositions {
                position_ids: b.u64s(1)?,
                sender: b.string(2)?,
                new_owner: b.string(3)?,
            }
        }
        // -- classic pools ---------------------------------------------------------------------
        "/osmosis.gamm.v1beta1.MsgJoinPool" => DappMsg::JoinPool {
            sender: b.string(1)?,
            pool_id: b.u64(2)?,
            share_out_amount: b.string(3)?,
            token_in_maxs: b.coins(4)?,
        },
        "/osmosis.gamm.v1beta1.MsgExitPool" => DappMsg::ExitPool {
            sender: b.string(1)?,
            pool_id: b.u64(2)?,
            share_in_amount: b.string(3)?,
            token_out_mins: b.coins(4)?,
        },
        "/osmosis.gamm.v1beta1.MsgJoinSwapExternAmountIn" => DappMsg::JoinSwapExternAmountIn {
            sender: b.string(1)?,
            pool_id: b.u64(2)?,
            token_in: b.coin(3)?,
            share_out_min_amount: b.string(4)?,
        },
        "/osmosis.gamm.v1beta1.MsgExitSwapShareAmountIn" => DappMsg::ExitSwapShareAmountIn {
            sender: b.string(1)?,
            pool_id: b.u64(2)?,
            token_out_denom: b.string(3)?,
            share_in_amount: b.string(4)?,
            token_out_min_amount: b.string(5)?,
        },
        "/osmosis.gamm.v1beta1.MsgJoinSwapShareAmountOut" => DappMsg::JoinSwapShareAmountOut {
            sender: b.string(1)?,
            pool_id: b.u64(2)?,
            token_in_denom: b.string(3)?,
            share_out_amount: b.string(4)?,
            token_in_max_amount: b.string(5)?,
        },
        "/osmosis.gamm.v1beta1.MsgExitSwapExternAmountOut" => DappMsg::ExitSwapExternAmountOut {
            sender: b.string(1)?,
            pool_id: b.u64(2)?,
            token_out: b.coin(3)?,
            share_in_max_amount: b.string(4)?,
        },
        // -- lockup ----------------------------------------------------------------------------
        "/osmosis.lockup.MsgLockTokens" => DappMsg::LockTokens {
            owner: b.string(1)?,
            duration_seconds: decode_duration(find_unique_field(fields, 2)?)?,
            coins: b.coins(3)?,
        },
        "/osmosis.lockup.MsgBeginUnlocking" => DappMsg::BeginUnlocking {
            owner: b.string(1)?,
            lock_id: b.u64(2)?,
            coins: b.coins(3)?,
        },
        "/osmosis.lockup.MsgBeginUnlockingAll" => DappMsg::BeginUnlockingAll {
            owner: b.string(1)?,
        },
        // -- superfluid ------------------------------------------------------------------------
        "/osmosis.superfluid.MsgSuperfluidDelegate" => DappMsg::SuperfluidDelegate {
            sender: b.string(1)?,
            lock_id: b.u64(2)?,
            validator: b.string(3)?,
        },
        "/osmosis.superfluid.MsgSuperfluidUndelegate" => DappMsg::SuperfluidUndelegate {
            sender: b.string(1)?,
            lock_id: b.u64(2)?,
        },
        "/osmosis.superfluid.MsgLockAndSuperfluidDelegate" => DappMsg::LockAndSuperfluidDelegate {
            sender: b.string(1)?,
            coins: b.coins(2)?,
            validator: b.string(3)?,
        },
        "/osmosis.superfluid.MsgSuperfluidUnbondLock" => DappMsg::SuperfluidUnbondLock {
            sender: b.string(1)?,
            lock_id: b.u64(2)?,
        },
        "/osmosis.superfluid.MsgSuperfluidUndelegateAndUnbondLock" => {
            DappMsg::SuperfluidUndelegateAndUnbondLock {
                sender: b.string(1)?,
                lock_id: b.u64(2)?,
                coin: b.coin(3)?,
            }
        }
        "/osmosis.superfluid.MsgCreateFullRangePositionAndSuperfluidDelegate" => {
            DappMsg::CreateFullRangePositionAndSuperfluidDelegate {
                sender: b.string(1)?,
                coins: b.coins(2)?,
                validator: b.string(3)?,
                pool_id: b.u64(4)?,
            }
        }
        "/osmosis.superfluid.MsgAddToConcentratedLiquiditySuperfluidPosition" => {
            DappMsg::AddToConcentratedLiquiditySuperfluidPosition {
                position_id: b.u64(1)?,
                sender: b.string(2)?,
                token_desired0: b.coin(3)?,
                token_desired1: b.coin(4)?,
            }
        }
        // -- Cosmos SDK ------------------------------------------------------------------------
        "/cosmos.bank.v1beta1.MsgMultiSend" => DappMsg::MultiSend {
            inputs: find_all(fields, 1)
                .into_iter()
                .map(|value| decode_entry(value.as_bytes()?))
                .collect::<Result<_>>()?,
            outputs: find_all(fields, 2)
                .into_iter()
                .map(|value| decode_entry(value.as_bytes()?))
                .collect::<Result<_>>()?,
        },
        "/cosmos.staking.v1beta1.MsgCancelUnbondingDelegation" => {
            DappMsg::CancelUnbondingDelegation {
                delegator: b.string(1)?,
                validator: b.string(2)?,
                amount: b.coin(3)?,
                creation_height: b.i64(4)?,
            }
        }
        "/cosmos.distribution.v1beta1.MsgSetWithdrawAddress" => DappMsg::SetWithdrawAddress {
            delegator: b.string(1)?,
            withdraw_address: b.string(2)?,
        },
        "/cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission" => {
            DappMsg::WithdrawValidatorCommission {
                validator: b.string(1)?,
            }
        }
        "/cosmos.distribution.v1beta1.MsgFundCommunityPool" => DappMsg::FundCommunityPool {
            amount: b.coins(1)?,
            depositor: b.string(2)?,
        },
        "/cosmos.gov.v1beta1.MsgDeposit" | "/cosmos.gov.v1.MsgDeposit" => DappMsg::Deposit {
            proposal_id: b.u64(1)?,
            depositor: b.string(2)?,
            amount: b.coins(3)?,
        },
        "/cosmos.gov.v1beta1.MsgVoteWeighted" | "/cosmos.gov.v1.MsgVoteWeighted" => {
            let v1 = type_url == "/cosmos.gov.v1.MsgVoteWeighted";
            if v1 {
                // metadata 4 is not shown.
                require_unique(fields, &[4])?;
            }
            let mut options = Vec::new();
            for value in find_all(fields, 3) {
                match decode_weighted(value.as_bytes()?, !v1)? {
                    Some(entry) => options.push(entry),
                    None => return Ok(None),
                }
            }
            DappMsg::VoteWeighted {
                proposal_id: b.u64(1)?,
                voter: b.string(2)?,
                options,
            }
        }
        "/cosmos.authz.v1beta1.MsgRevoke" => DappMsg::RevokeAuthorization {
            granter: b.string(1)?,
            grantee: b.string(2)?,
            msg_type_url: b.string(3)?,
        },
        "/cosmos.feegrant.v1beta1.MsgRevokeAllowance" => DappMsg::RevokeAllowance {
            granter: b.string(1)?,
            grantee: b.string(2)?,
        },
        // -- CosmWasm --------------------------------------------------------------------------
        "/cosmwasm.wasm.v1.MsgInstantiateContract" => DappMsg::InstantiateContract {
            sender: b.string(1)?,
            admin: b.string(2)?,
            code_id: b.u64(3)?,
            label: b.string(4)?,
            msg: b.json(5)?,
            funds: b.coins(6)?,
            v2: None,
        },
        "/cosmwasm.wasm.v1.MsgInstantiateContract2" => DappMsg::InstantiateContract {
            sender: b.string(1)?,
            admin: b.string(2)?,
            code_id: b.u64(3)?,
            label: b.string(4)?,
            msg: b.json(5)?,
            funds: b.coins(6)?,
            v2: Some((b.bytes(7)?, b.bool(8)?)),
        },
        "/cosmwasm.wasm.v1.MsgMigrateContract" => DappMsg::MigrateContract {
            sender: b.string(1)?,
            contract: b.string(2)?,
            code_id: b.u64(3)?,
            msg: b.json(4)?,
        },
        "/cosmwasm.wasm.v1.MsgUpdateAdmin" => DappMsg::UpdateAdmin {
            sender: b.string(1)?,
            new_admin: b.string(2)?,
            contract: b.string(3)?,
        },
        "/cosmwasm.wasm.v1.MsgClearAdmin" => DappMsg::ClearAdmin {
            sender: b.string(1)?,
            contract: b.string(3)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode_direct_sign_doc, DecodedMsg};
    use crate::describe::{message_detail, recipient};
    use crate::msg::Msg;
    use crate::proto::ProtoWriter;
    use crate::tx::{Fee, SignMode, SignerData, UnsignedTx};

    const FROM: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
    const TO: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
    const VALOPER: &str = "cosmosvaloper19rl4cm2hmr8afy4kldpxz3fka4jguq0ae5egnx";
    const CONTRACT: &str = "cosmos1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3s4mk53k";

    fn coin(denom: &str, amount: &str) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.string(1, denom).string(2, amount);
        w.into_bytes()
    }

    /// Decodes one message the way a dApp's sign document would carry it.
    fn decode_one(type_url: &str, body: &[u8]) -> DecodedMsg {
        let signer = SignerData {
            chain_id: "osmosis-1".to_owned(),
            account_number: 1,
            sequence: 1,
            public_key: vec![2u8; 33],
            eth_key_type: false,
            eth_pub_key_type_url: None,
        };
        let send = Msg::Send {
            from_address: FROM.to_owned(),
            to_address: TO.to_owned(),
            amount: vec![Coin::new("uatom", "1").unwrap()],
        };
        let auth_info = UnsignedTx::new(
            vec![send],
            Fee::new(vec![Coin::new("uatom", "5000").unwrap()], 200_000).unwrap(),
            "",
        )
        .unwrap()
        .encode_auth_info(&signer, SignMode::Direct);
        let mut any = ProtoWriter::new();
        any.string(1, type_url).bytes(2, body);
        let mut tx_body = ProtoWriter::new();
        tx_body.repeated_message(1, &[any.into_bytes()]);
        let mut doc = ProtoWriter::new();
        doc.bytes(1, tx_body.as_bytes())
            .bytes(2, &auth_info)
            .string(3, "osmosis-1")
            .uint64(4, 1);
        decode_direct_sign_doc(doc.as_bytes())
            .unwrap()
            .msgs
            .remove(0)
    }

    fn says(type_url: &str, body: &[u8]) -> String {
        let msg = decode_one(type_url, body);
        assert!(!msg.is_unknown(), "{type_url} decoded as unknown");
        msg.summary()
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    const CL: &str = "/osmosis.concentratedliquidity.v1beta1.";
    const GAMM: &str = "/osmosis.gamm.v1beta1.";
    const SF: &str = "/osmosis.superfluid.";

    #[test]
    fn types_without_a_mainnet_sample_decode_to_their_sentences() {
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .uint64(2, 3600)
            .string(3, "uosmo")
            .string(4, "5000000")
            .string(5, "100000");
        assert_eq!(
            says(&format!("{GAMM}MsgJoinSwapShareAmountOut"), w.as_bytes()),
            "Join pool 3600 with uosmo alone, paying at most 100000 uosmo for exactly 5000000 \
             gamm/pool/3600 shares"
        );

        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .uint64(2, 1)
            .message(3, &coin("uosmo", "1000"))
            .string(4, "77");
        assert_eq!(
            says(&format!("{GAMM}MsgExitSwapExternAmountOut"), w.as_bytes()),
            "Exit pool 1 receiving exactly 1000 uosmo alone, burning at most 77 gamm/pool/1 shares"
        );

        let mut w = ProtoWriter::new();
        w.string(1, FROM);
        assert_eq!(
            says("/osmosis.lockup.MsgBeginUnlockingAll", w.as_bytes()),
            format!("Begin unlocking every lock owned by {FROM}")
        );

        let mut w = ProtoWriter::new();
        w.string(1, FROM).uint64(2, 42).string(3, VALOPER);
        assert_eq!(
            says(&format!("{SF}MsgSuperfluidDelegate"), w.as_bytes()),
            format!("Superfluid-delegate lock 42 to validator {VALOPER}")
        );

        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .message(2, &coin("gamm/pool/1", "5"))
            .string(3, VALOPER);
        assert_eq!(
            says(&format!("{SF}MsgLockAndSuperfluidDelegate"), w.as_bytes()),
            format!("Lock 5 gamm/pool/1 and superfluid-delegate it to validator {VALOPER}")
        );

        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .message(2, &coin("uosmo", "10"))
            .string(3, VALOPER)
            .uint64(4, 1);
        assert_eq!(
            says(
                &format!("{SF}MsgCreateFullRangePositionAndSuperfluidDelegate"),
                w.as_bytes()
            ),
            format!(
                "Create a full-range concentrated liquidity position in pool 1 with 10 uosmo \
                 and superfluid-delegate it to validator {VALOPER}"
            )
        );

        let mut w = ProtoWriter::new();
        w.uint64(1, 9)
            .string(2, FROM)
            .message(3, &coin("uosmo", "10"))
            .message(4, &coin("uatom", "0"));
        assert_eq!(
            says(
                &format!("{SF}MsgAddToConcentratedLiquiditySuperfluidPosition"),
                w.as_bytes()
            ),
            "Add 10 uosmo and 0 uatom to superfluid concentrated liquidity position 9"
        );

        let mut w = ProtoWriter::new();
        w.string(1, FROM).string(3, CONTRACT);
        let msg = decode_one("/cosmwasm.wasm.v1.MsgClearAdmin", w.as_bytes());
        assert_eq!(
            msg.summary(),
            format!("Clear the admin of contract {CONTRACT}, so nobody can migrate it again")
        );
        assert_eq!(recipient(&msg), None);
        assert_eq!(msg.addresses(), vec![FROM, CONTRACT]);
    }

    #[test]
    fn a_weighted_vote_reads_both_wire_formats() {
        let option = |option: u64, weight: &str| {
            let mut w = ProtoWriter::new();
            w.uint64(1, option).string(2, weight);
            w.into_bytes()
        };
        // gov v1beta1 writes a weight as the integer scaled by 10^18.
        let mut w = ProtoWriter::new();
        w.uint64(1, 7).string(2, FROM).repeated_message(
            3,
            &[
                option(1, "700000000000000000"),
                option(3, "300000000000000000"),
            ],
        );
        let expected = "Vote Yes 0.700000000000000000, No 0.300000000000000000 on proposal 7";
        assert_eq!(
            says("/cosmos.gov.v1beta1.MsgVoteWeighted", w.as_bytes()),
            expected
        );

        // gov v1 writes it as a decimal string.
        let mut w = ProtoWriter::new();
        w.uint64(1, 7)
            .string(2, FROM)
            .repeated_message(3, &[option(1, "0.7"), option(3, "0.300000000000000000")]);
        assert_eq!(
            says("/cosmos.gov.v1.MsgVoteWeighted", w.as_bytes()),
            expected
        );

        // A v1 weight in the v1beta1 reading is not a number, and a scaled one in the v1
        // reading overflows 1.0: neither is described.
        let mut w = ProtoWriter::new();
        w.uint64(1, 7)
            .string(2, FROM)
            .repeated_message(3, &[option(1, "0.5"), option(3, "0.5")]);
        assert!(decode_one("/cosmos.gov.v1beta1.MsgVoteWeighted", w.as_bytes()).is_unknown());
        let mut w = ProtoWriter::new();
        w.uint64(1, 7).string(2, FROM).repeated_message(
            3,
            &[
                option(1, "500000000000000000"),
                option(3, "500000000000000000"),
            ],
        );
        assert!(decode_one("/cosmos.gov.v1.MsgVoteWeighted", w.as_bytes()).is_unknown());

        // Weights that do not add up to one, a repeated option, an unspecified option.
        for options in [
            vec![option(1, "0.5"), option(3, "0.4")],
            vec![option(1, "0.5"), option(1, "0.5")],
            vec![option(0, "1.0")],
            vec![option(5, "1.0")],
            vec![],
        ] {
            let mut w = ProtoWriter::new();
            w.uint64(1, 7).string(2, FROM).repeated_message(3, &options);
            assert!(
                decode_one("/cosmos.gov.v1.MsgVoteWeighted", w.as_bytes()).is_unknown(),
                "{options:?}"
            );
        }
    }

    #[test]
    fn a_negative_tick_is_a_ten_byte_varint_and_reads_back_negative() {
        let create = |lower: i64, upper: i64| {
            let mut w = ProtoWriter::new();
            w.uint64(1, 3600)
                .string(2, FROM)
                .uint64(3, lower as u64)
                .uint64(4, upper as u64)
                .repeated_message(5, &[coin("uosmo", "1000")])
                .string(6, "0")
                .string(7, "0");
            w.into_bytes()
        };
        let body = create(-108_000_000, -5);
        // Ten bytes of varint for each negative tick.
        assert!(body
            .windows(10)
            .any(|w| w[..9].iter().all(|b| b & 0x80 != 0)));
        assert_eq!(
            says(&format!("{CL}MsgCreatePosition"), &body),
            "Create a concentrated liquidity position in pool 3600 between ticks -108000000 and \
             -5 with 1000 uosmo, accepting at least 0 of the pool's token0 and 0 of its token1"
        );
        // Ticks that do not ascend cannot make a position.
        assert!(decode_one(&format!("{CL}MsgCreatePosition"), &create(5, -5)).is_unknown());
        assert!(decode_one(&format!("{CL}MsgCreatePosition"), &create(7, 7)).is_unknown());
    }

    #[test]
    fn position_ids_may_be_packed_unpacked_or_mixed() {
        let expected = format!("Transfer concentrated liquidity positions 5, 300, 7 to {TO}");
        let url = format!("{CL}MsgTransferPositions");

        let mut packed = Vec::new();
        for id in [5u64, 300, 7] {
            packed.extend(varint(id));
        }
        let mut w = ProtoWriter::new();
        w.bytes(1, &packed).string(2, FROM).string(3, TO);
        assert_eq!(says(&url, w.as_bytes()), expected);

        // Unpacked: one varint field per id. Written by hand, since the writer skips zeros and
        // this test wants the wire form.
        let mut raw = Vec::new();
        for id in [5u64, 300, 7] {
            raw.push(0x08);
            raw.extend(varint(id));
        }
        let mut tail = ProtoWriter::new();
        tail.string(2, FROM).string(3, TO);
        raw.extend(tail.as_bytes());
        assert_eq!(says(&url, &raw), expected);

        // Mixed: one packed run and one loose id, in either order.
        let mut mixed = Vec::new();
        mixed.push(0x0a);
        mixed.extend(varint(packed.len() as u64 - 1));
        mixed.extend(varint(5));
        mixed.extend(varint(300));
        mixed.push(0x08);
        mixed.extend(varint(7));
        mixed.extend(tail.as_bytes());
        assert_eq!(says(&url, &mixed), expected);

        // A packed run that stops inside a varint, an id of zero, and a repeated id.
        let mut cut = vec![0x0a, 0x01, 0xac];
        cut.extend(tail.as_bytes());
        assert!(decode_one(&url, &cut).is_unknown());
        for ids in [vec![0u64, 5], vec![5, 5], vec![]] {
            let mut run = Vec::new();
            for id in &ids {
                run.extend(varint(*id));
            }
            let mut w = ProtoWriter::new();
            w.bytes(1, &run).string(2, FROM).string(3, TO);
            assert!(decode_one(&url, w.as_bytes()).is_unknown(), "{ids:?}");
        }
    }

    #[test]
    fn liquidity_is_read_as_a_scaled_decimal_and_a_position_amount_names_no_denom() {
        let mut w = ProtoWriter::new();
        w.uint64(1, 15)
            .string(2, FROM)
            // 76229804638.049543160384509824 on the LCD.
            .string(3, "76229804638049543160384509824");
        assert_eq!(
            says(&format!("{CL}MsgWithdrawPosition"), w.as_bytes()),
            "Withdraw 76229804638.049543160384509824 liquidity units (the message names no \
             denom) from concentrated liquidity position 15"
        );
        // Zero liquidity, and a figure with a decimal point (the LCD spelling, which is not
        // what the wire carries).
        for liquidity in ["0", "1.5", "007", ""] {
            let mut w = ProtoWriter::new();
            w.uint64(1, 15).string(2, FROM).string(3, liquidity);
            assert!(
                decode_one(&format!("{CL}MsgWithdrawPosition"), w.as_bytes()).is_unknown(),
                "{liquidity:?}"
            );
        }
        let mut w = ProtoWriter::new();
        w.uint64(1, 15).string(2, FROM).string(3, "5");
        assert!(says(&format!("{CL}MsgWithdrawPosition"), w.as_bytes())
            .starts_with("Withdraw 0.000000000000000005 liquidity units"));
    }

    #[test]
    fn a_lock_duration_is_whole_positive_seconds() {
        let lock = |duration: Vec<u8>| {
            let mut w = ProtoWriter::new();
            w.string(1, FROM)
                .message(2, &duration)
                .repeated_message(3, &[coin("gamm/pool/1", "100")]);
            w.into_bytes()
        };
        let url = "/osmosis.lockup.MsgLockTokens";
        let mut d = ProtoWriter::new();
        d.uint64(1, 1_209_600);
        assert_eq!(
            says(url, &lock(d.into_bytes())),
            "Lock 100 gamm/pool/1 for 1209600 seconds"
        );
        let mut d = ProtoWriter::new();
        d.uint64(1, 1).int32(2, 500);
        assert!(decode_one(url, &lock(d.into_bytes())).is_unknown());
        let mut d = ProtoWriter::new();
        d.uint64(1, (-1i64) as u64);
        assert!(decode_one(url, &lock(d.into_bytes())).is_unknown());
        // No duration at all, and a duration with its seconds written twice.
        assert!(decode_one(url, &lock(Vec::new())).is_unknown());
        let mut d = ProtoWriter::new();
        d.uint64(1, 5);
        let mut twice = d.into_bytes();
        twice.extend([0x08, 0x06]);
        assert!(decode_one(url, &lock(twice)).is_unknown());
    }

    #[test]
    fn a_multi_send_names_every_output_and_must_balance() {
        let entry = |address: &str, coins: &[(&str, &str)]| {
            let mut w = ProtoWriter::new();
            let coins: Vec<Vec<u8>> = coins.iter().map(|(d, a)| coin(d, a)).collect();
            w.string(1, address).repeated_message(2, &coins);
            w.into_bytes()
        };
        let send = |inputs: &[Vec<u8>], outputs: &[Vec<u8>]| {
            let mut w = ProtoWriter::new();
            w.repeated_message(1, inputs).repeated_message(2, outputs);
            w.into_bytes()
        };
        let url = "/cosmos.bank.v1beta1.MsgMultiSend";

        let one = send(
            &[entry(FROM, &[("uatom", "1000")])],
            &[
                entry(TO, &[("uatom", "600")]),
                entry(FROM, &[("uatom", "400")]),
            ],
        );
        let msg = decode_one(url, &one);
        assert_eq!(
            msg.summary(),
            format!(
                "Send 600 uatom to {TO}; 400 uatom to {FROM} in one multi-send paid by {FROM} \
                 (1000 uatom)"
            )
        );
        // One output is not an input: it is the recipient.
        assert_eq!(recipient(&msg), Some(TO));
        assert_eq!(msg.addresses(), vec![FROM, TO, FROM]);
        assert_eq!(
            message_detail(&msg).unwrap()["outputs"][0],
            json!({ "address": TO, "coins": [{ "denom": "uatom", "amount": "600" }] })
        );

        // Two outsiders: no single recipient stands for the payment.
        let two = send(
            &[entry(FROM, &[("uatom", "1000")])],
            &[
                entry(TO, &[("uatom", "600")]),
                entry(CONTRACT, &[("uatom", "400")]),
            ],
        );
        let msg = decode_one(url, &two);
        assert!(!msg.is_unknown());
        assert_eq!(recipient(&msg), None);

        // What goes in must come out.
        for body in [
            send(
                &[entry(FROM, &[("uatom", "1000")])],
                &[entry(TO, &[("uatom", "999")])],
            ),
            send(
                &[entry(FROM, &[("uatom", "1000")])],
                &[entry(TO, &[("uosmo", "1000")])],
            ),
            send(&[], &[entry(TO, &[("uatom", "1")])]),
            send(&[entry(FROM, &[("uatom", "1")])], &[]),
            send(&[entry(FROM, &[])], &[entry(TO, &[])]),
        ] {
            assert!(decode_one(url, &body).is_unknown());
        }
    }

    #[test]
    fn contracts_carry_their_message_label_admin_and_funds_in_the_detail() {
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .string(2, TO)
            .uint64(3, 12)
            .string(4, "my \"label\"")
            .bytes(5, br#"{"owner":"x"}"#)
            .repeated_message(6, &[coin("uatom", "5")]);
        let msg = decode_one("/cosmwasm.wasm.v1.MsgInstantiateContract", w.as_bytes());
        assert_eq!(
            msg.summary(),
            format!("Instantiate code 12 as a new contract with admin {TO}, sending 5 uatom")
        );
        assert_eq!(recipient(&msg), Some(TO));
        assert_eq!(
            message_detail(&msg),
            Some(json!({
                "kind": "instantiate-contract",
                "codeId": "12",
                "label": "my \"label\"",
                "admin": TO,
                "msg": { "owner": "x" },
                "funds": [{ "denom": "uatom", "amount": "5" }],
            }))
        );

        // No admin: no recipient, and the sentence says so.
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .uint64(3, 12)
            .string(4, "l")
            .bytes(5, b"{}");
        let msg = decode_one("/cosmwasm.wasm.v1.MsgInstantiateContract", w.as_bytes());
        assert_eq!(
            msg.summary(),
            "Instantiate code 12 as a new contract with no admin"
        );
        assert_eq!(recipient(&msg), None);
        assert_eq!(msg.addresses(), vec![FROM]);

        // instantiate2 carries its salt and fix_msg.
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .uint64(3, 12)
            .string(4, "l")
            .bytes(5, b"{}")
            .bytes(7, &[0xab, 0xcd])
            .bool(8, true);
        let msg = decode_one("/cosmwasm.wasm.v1.MsgInstantiateContract2", w.as_bytes());
        assert_eq!(
            msg.summary(),
            "Instantiate code 12 as a new contract at a salt-derived address with no admin"
        );
        let detail = message_detail(&msg).unwrap();
        assert_eq!(detail["salt"], "abcd");
        assert_eq!(detail["fixMsg"], true);

        // A message that is not JSON, an empty label, a missing code, an empty salt.
        for body in [
            [&b"{"[..]]
                .iter()
                .map(|bad| {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM).uint64(3, 12).string(4, "l").bytes(5, bad);
                    w.into_bytes()
                })
                .next()
                .unwrap(),
            {
                let mut w = ProtoWriter::new();
                w.string(1, FROM).uint64(3, 12).bytes(5, b"{}");
                w.into_bytes()
            },
            {
                let mut w = ProtoWriter::new();
                w.string(1, FROM).string(4, "l").bytes(5, b"{}");
                w.into_bytes()
            },
        ] {
            assert!(decode_one("/cosmwasm.wasm.v1.MsgInstantiateContract", &body).is_unknown());
        }
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .uint64(3, 12)
            .string(4, "l")
            .bytes(5, b"{}");
        assert!(decode_one("/cosmwasm.wasm.v1.MsgInstantiateContract2", w.as_bytes()).is_unknown());

        // Migrate and update-admin.
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .string(2, CONTRACT)
            .uint64(3, 99)
            .bytes(4, br#"{"a":1}"#);
        let msg = decode_one("/cosmwasm.wasm.v1.MsgMigrateContract", w.as_bytes());
        assert_eq!(
            msg.summary(),
            format!("Migrate contract {CONTRACT} to code 99")
        );
        assert_eq!(
            message_detail(&msg),
            Some(json!({
                "kind": "migrate-contract",
                "contract": CONTRACT,
                "codeId": "99",
                "msg": { "a": 1 },
            }))
        );
        let mut w = ProtoWriter::new();
        w.string(1, FROM).string(2, TO).string(3, CONTRACT);
        let msg = decode_one("/cosmwasm.wasm.v1.MsgUpdateAdmin", w.as_bytes());
        assert_eq!(
            msg.summary(),
            format!("Make {TO} the admin of contract {CONTRACT}")
        );
        assert_eq!(recipient(&msg), Some(TO));
    }

    #[test]
    fn a_field_written_twice_makes_the_message_unknown() {
        let mut w = ProtoWriter::new();
        w.uint64(1, 3600).string(2, FROM);
        let mut first = w.into_bytes();
        let mut tail = ProtoWriter::new();
        tail.int32(3, 1)
            .int32(4, 2)
            .repeated_message(5, &[coin("uosmo", "1")]);
        first.extend(tail.as_bytes());
        let body = {
            let mut w = ProtoWriter::new();
            w.string(6, "0").string(7, "0");
            let mut all = first.clone();
            all.extend(w.as_bytes());
            all
        };
        assert!(!decode_one(&format!("{CL}MsgCreatePosition"), &body).is_unknown());
        // The pool id, the sender, a tick, a minimum: each written a second time.
        for (second, field) in [
            (vec![0x08, 0x01], "pool_id"),
            (vec![0x12, 0x01, b'x'], "sender"),
            (vec![0x18, 0x01], "lower_tick"),
            (vec![0x32, 0x01, b'1'], "token_min_amount0"),
        ] {
            let mut doubled = body.clone();
            doubled.extend(second);
            assert!(
                decode_one(&format!("{CL}MsgCreatePosition"), &doubled).is_unknown(),
                "{field}"
            );
        }
        // gov v1 metadata is not shown, and still may not repeat.
        let option = {
            let mut w = ProtoWriter::new();
            w.uint64(1, 1).string(2, "1.0");
            w.into_bytes()
        };
        let mut w = ProtoWriter::new();
        w.uint64(1, 7)
            .string(2, FROM)
            .repeated_message(3, &[option])
            .string(4, "m");
        let mut doubled = w.as_bytes().to_vec();
        assert!(!decode_one("/cosmos.gov.v1.MsgVoteWeighted", &doubled).is_unknown());
        doubled.extend([0x22, 0x01, b'n']);
        assert!(decode_one("/cosmos.gov.v1.MsgVoteWeighted", &doubled).is_unknown());
    }

    #[test]
    fn a_message_that_cannot_execute_is_not_described() {
        let cases: Vec<(String, Vec<u8>)> = vec![
            (
                // zero shares out
                format!("{GAMM}MsgJoinPool"),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM)
                        .uint64(2, 1)
                        .string(3, "0")
                        .repeated_message(4, &[coin("uosmo", "1")]);
                    w.into_bytes()
                },
            ),
            (
                // no payment at all
                format!("{GAMM}MsgJoinPool"),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM).uint64(2, 1).string(3, "5");
                    w.into_bytes()
                },
            ),
            (
                // pool 0
                format!("{GAMM}MsgExitPool"),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM).string(3, "5");
                    w.into_bytes()
                },
            ),
            (
                // a leading zero is not how an Int is written
                format!("{GAMM}MsgExitSwapShareAmountIn"),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM)
                        .uint64(2, 1)
                        .string(3, "uosmo")
                        .string(4, "05")
                        .string(5, "1");
                    w.into_bytes()
                },
            ),
            (
                // a denom that is not one
                format!("{GAMM}MsgJoinSwapExternAmountIn"),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM)
                        .uint64(2, 1)
                        .message(3, &coin("u o", "1"))
                        .string(4, "1");
                    w.into_bytes()
                },
            ),
            (
                // an unbonding with no creation height
                "/cosmos.staking.v1beta1.MsgCancelUnbondingDelegation".to_owned(),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM)
                        .string(2, VALOPER)
                        .message(3, &coin("uatom", "1"));
                    w.into_bytes()
                },
            ),
            (
                // a revoke naming a type URL that is not one
                "/cosmos.authz.v1beta1.MsgRevoke".to_owned(),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM)
                        .string(2, TO)
                        .string(3, "/cosmos.bank.v1beta1.MsgSend\u{202e}");
                    w.into_bytes()
                },
            ),
            (
                // a recipient that is not an address
                "/cosmos.distribution.v1beta1.MsgSetWithdrawAddress".to_owned(),
                {
                    let mut w = ProtoWriter::new();
                    w.string(1, FROM).string(2, "not-an-address");
                    w.into_bytes()
                },
            ),
            (
                // an owner on another chain
                format!("{CL}MsgTransferPositions"),
                {
                    let mut w = ProtoWriter::new();
                    w.bytes(1, &[5])
                        .string(2, FROM)
                        .string(3, "osmo12eg3pah3vy2whxnr9hn9qkjm0p0l2lcss8rwx4");
                    w.into_bytes()
                },
            ),
        ];
        for (url, body) in cases {
            assert!(decode_one(&url, &body).is_unknown(), "{url}");
        }
        // The same revoke, well formed.
        let mut w = ProtoWriter::new();
        w.string(1, FROM)
            .string(2, TO)
            .string(3, "/cosmos.bank.v1beta1.MsgSend");
        assert_eq!(
            says("/cosmos.authz.v1beta1.MsgRevoke", w.as_bytes()),
            format!("Revoke the authorization given to {TO} for /cosmos.bank.v1beta1.MsgSend")
        );
    }

    #[test]
    fn messages_that_hand_over_the_account_stay_unknown() {
        // Each has a body that parses and names its parties; none may be described, because
        // each gives control of the account away or runs messages the wallet cannot see.
        // Refusing them without blind signing is the intended behaviour.
        let mut grant = ProtoWriter::new();
        grant.string(1, FROM).string(2, TO).message(3, &{
            let mut g = ProtoWriter::new();
            let mut a = ProtoWriter::new();
            a.string(1, "/cosmos.authz.v1beta1.GenericAuthorization")
                .bytes(2, &{
                    let mut m = ProtoWriter::new();
                    m.string(1, "/cosmos.bank.v1beta1.MsgSend");
                    m.into_bytes()
                });
            g.message(1, a.as_bytes());
            g.into_bytes()
        });
        let mut exec = ProtoWriter::new();
        exec.string(1, TO).repeated_message(
            2,
            &[{
                let mut a = ProtoWriter::new();
                a.string(1, "/cosmos.bank.v1beta1.MsgSend").bytes(2, &{
                    let mut m = ProtoWriter::new();
                    m.string(1, FROM).string(2, TO);
                    m.into_bytes()
                });
                a.into_bytes()
            }],
        );
        let mut allowance = ProtoWriter::new();
        allowance.string(1, FROM).string(2, TO).message(3, &{
            let mut a = ProtoWriter::new();
            a.string(1, "/cosmos.feegrant.v1beta1.BasicAllowance");
            a.into_bytes()
        });
        let mut authenticator = ProtoWriter::new();
        authenticator
            .string(1, FROM)
            .string(2, "AllOf")
            .bytes(3, b"[]");
        let mut store_code = ProtoWriter::new();
        store_code.string(1, FROM).bytes(2, &[0, 0x61, 0x73, 0x6d]);
        let mut proposal = ProtoWriter::new();
        proposal
            .string(2, "100uatom")
            .string(3, FROM)
            .string(4, "metadata")
            .string(5, "title")
            .string(6, "summary");

        for (url, body) in [
            ("/cosmos.authz.v1beta1.MsgGrant", grant.into_bytes()),
            ("/cosmos.authz.v1beta1.MsgExec", exec.into_bytes()),
            (
                "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
                allowance.into_bytes(),
            ),
            (
                "/osmosis.smartaccount.v1beta1.MsgAddAuthenticator",
                authenticator.as_bytes().to_vec(),
            ),
            (
                "/osmosis.smartaccount.v1beta1.MsgRemoveAuthenticator",
                authenticator.as_bytes().to_vec(),
            ),
            (
                "/osmosis.smartaccount.v1beta1.MsgSetActiveState",
                authenticator.as_bytes().to_vec(),
            ),
            ("/cosmwasm.wasm.v1.MsgStoreCode", store_code.into_bytes()),
            (
                "/cosmos.gov.v1.MsgSubmitProposal",
                proposal.as_bytes().to_vec(),
            ),
            (
                "/cosmos.gov.v1beta1.MsgSubmitProposal",
                proposal.into_bytes(),
            ),
        ] {
            let msg = decode_one(url, &body);
            assert!(msg.is_unknown(), "{url} was described: {}", msg.summary());
            assert!(msg.summary().starts_with("UNKNOWN ACTION"), "{url}");
            assert_eq!(recipient(&msg), None);
            assert!(message_detail(&msg).is_none());
        }
    }
}
