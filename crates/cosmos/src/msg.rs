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
//! at least one differs in a way that looks like a typo:
//!
//! | Proto | Amino |
//! |---|---|
//! | `MsgWithdrawDelegatorReward` | `cosmos-sdk/MsgWithdrawDelegationReward` |
//!
//! `Delegator` in protobuf, `Delegation` in Amino. Deriving one from the other produces a
//! signature the chain rejects, and the mistake is nearly invisible on review, so the names are
//! written out literally and pinned by test.

use serde_json::{json, Value};

use crate::amino::{object_omit_empty, typed};
use crate::amount::Coin;
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
        }
    }

    /// True if this message moves funds out of the signer's account.
    ///
    /// Drives the "this transaction spends money" treatment in the signing UI. A vote does
    /// not, a send does, and a contract execution with attached funds does.
    pub fn spends_funds(&self) -> bool {
        match self {
            Self::Send { amount, .. } => !amount.is_empty(),
            Self::Delegate { .. } | Self::IbcTransfer { .. } => true,
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
        }
    }

    /// Validates that every address on this message carries the chain's bech32 prefix.
    ///
    /// The IBC receiver is exempt: an ICS-20 transfer's destination is on another chain and
    /// legitimately has a different prefix. That exemption is the reason this cannot be a blanket
    /// loop over [`Self::addresses`].
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
                check(contract, prefix)?;
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
