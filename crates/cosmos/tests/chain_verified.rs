//! Amino documents rebuilt by the kernel, checked against signatures the chain accepted.
//!
//! The golden vectors prove agreement with a reference library. These prove agreement with the
//! chain: each case is a real amino-signed cosmoshub-4 transaction, with the signer's public key
//! and the signature from the block. The kernel rebuilds the sign document from the message's
//! fields alone, and the test passes only if the chain's own signature verifies over those bytes.
//! A reference library and a hand-written vector can agree with each other and still be wrong;
//! a signature cannot.
//!
//! The second half does the same for the decoder: real mainnet transactions carrying the dApp
//! messages the kernel reads in clear text, decoded from the raw bytes the chain's RPC returned
//! and compared field by field with the JSON the chain's LCD returned for the same hash.

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

// -- dApp messages ----------------------------------------------------------------------------

fn dapp_cases() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/chain-verified-dapp-messages.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The `SignDoc` a signer of the raw transaction would have signed in direct mode: the
/// transaction's own body and auth info, which are its first two fields.
fn sign_doc_of(raw_tx: &[u8], chain_id: &str) -> Vec<u8> {
    use zunia_cosmos::proto::{decode_fields, find_unique_field, ProtoWriter};
    let fields = decode_fields(raw_tx).unwrap();
    let body = find_unique_field(&fields, 1)
        .unwrap()
        .unwrap()
        .as_bytes()
        .unwrap();
    let auth_info = find_unique_field(&fields, 2)
        .unwrap()
        .unwrap()
        .as_bytes()
        .unwrap();
    let mut doc = ProtoWriter::new();
    doc.bytes(1, body)
        .bytes(2, auth_info)
        .string(3, chain_id)
        .uint64(4, 1);
    doc.into_bytes()
}

fn coins_line(value: &Value) -> String {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|c| format!("{} {}", s(&c["amount"]), s(&c["denom"])))
        .collect::<Vec<_>>()
        .join(", ")
}

fn ids_line(value: &Value) -> String {
    let ids: Vec<String> = value.as_array().unwrap().iter().map(s).collect();
    format!(
        "{} {}",
        if ids.len() == 1 {
            "position"
        } else {
            "positions"
        },
        ids.join(", ")
    )
}

fn pools_line(routes: &Value) -> String {
    let ids: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| s(&r["pool_id"]))
        .collect();
    format!(
        "{} {}",
        if ids.len() == 1 { "pool" } else { "pools" },
        ids.join(" \u{2192} ")
    )
}

/// The sentence, written from the LCD's JSON alone. The templates are the ones in the pull
/// request description; this is the independent restatement the decoder is held to.
fn expected_summary(type_url: &str, m: &Value) -> String {
    let name = type_url.rsplit('.').next().unwrap();
    let pool = s(&m["pool_id"]);
    match name {
        "MsgCreatePosition" => format!(
            "Create a concentrated liquidity position in pool {pool} between ticks {} and {} \
             with {}, accepting at least {} of the pool's token0 and {} of its token1",
            s(&m["lower_tick"]),
            s(&m["upper_tick"]),
            coins_line(&m["tokens_provided"]),
            s(&m["token_min_amount0"]),
            s(&m["token_min_amount1"])
        ),
        "MsgAddToPosition" => format!(
            "Add {} of the pool's token0 and {} of its token1 to concentrated liquidity position \
             {}, using at least {} and {} of them; the message names no denoms",
            s(&m["amount0"]),
            s(&m["amount1"]),
            s(&m["position_id"]),
            s(&m["token_min_amount0"]),
            s(&m["token_min_amount1"])
        ),
        "MsgWithdrawPosition" => format!(
            "Withdraw {} liquidity units (the message names no denom) from concentrated \
             liquidity position {}",
            s(&m["liquidity_amount"]),
            s(&m["position_id"])
        ),
        "MsgCollectSpreadRewards" => format!(
            "Collect the spread rewards of concentrated liquidity {}",
            ids_line(&m["position_ids"])
        ),
        "MsgCollectIncentives" => format!(
            "Collect the incentives of concentrated liquidity {}",
            ids_line(&m["position_ids"])
        ),
        "MsgTransferPositions" => format!(
            "Transfer concentrated liquidity {} to {}",
            ids_line(&m["position_ids"]),
            s(&m["new_owner"])
        ),
        "MsgJoinPool" => format!(
            "Join pool {pool} for exactly {} gamm/pool/{pool} shares, paying at most {}",
            s(&m["share_out_amount"]),
            coins_line(&m["token_in_maxs"])
        ),
        "MsgExitPool" => format!(
            "Exit pool {pool} by burning {} gamm/pool/{pool} shares, {}",
            s(&m["share_in_amount"]),
            if m["token_out_mins"].as_array().unwrap().is_empty() {
                "with no minimum amount out".to_owned()
            } else {
                format!("receiving at least {}", coins_line(&m["token_out_mins"]))
            }
        ),
        "MsgJoinSwapExternAmountIn" => format!(
            "Join pool {pool} with {} {} alone, receiving at least {} gamm/pool/{pool} shares",
            s(&m["token_in"]["amount"]),
            s(&m["token_in"]["denom"]),
            s(&m["share_out_min_amount"])
        ),
        "MsgExitSwapShareAmountIn" => format!(
            "Exit pool {pool} by burning {} gamm/pool/{pool} shares for {} alone, receiving at \
             least {} {}",
            s(&m["share_in_amount"]),
            s(&m["token_out_denom"]),
            s(&m["token_out_min_amount"]),
            s(&m["token_out_denom"])
        ),
        "MsgSwapExactAmountIn" => format!(
            "Swap {} {} for at least {} {} through {}",
            s(&m["token_in"]["amount"]),
            s(&m["token_in"]["denom"]),
            s(&m["token_out_min_amount"]),
            s(&m["routes"].as_array().unwrap().last().unwrap()["token_out_denom"]),
            pools_line(&m["routes"])
        ),
        "MsgSwapExactAmountOut" => format!(
            "Swap at most {} {} for exactly {} {} through {}",
            s(&m["token_in_max_amount"]),
            s(&m["routes"][0]["token_in_denom"]),
            s(&m["token_out"]["amount"]),
            s(&m["token_out"]["denom"]),
            pools_line(&m["routes"])
        ),
        "MsgLockTokens" => format!(
            "Lock {} for {} seconds",
            coins_line(&m["coins"]),
            s(&m["duration"]).trim_end_matches('s')
        ),
        "MsgBeginUnlocking" => {
            if m["coins"].as_array().unwrap().is_empty() {
                format!("Begin unlocking all the tokens of lock {}", s(&m["ID"]))
            } else {
                format!(
                    "Begin unlocking {} from lock {}",
                    coins_line(&m["coins"]),
                    s(&m["ID"])
                )
            }
        }
        "MsgSuperfluidUndelegate" => {
            format!("Superfluid-undelegate lock {}", s(&m["lock_id"]))
        }
        "MsgSuperfluidUnbondLock" => format!("Superfluid-unbond lock {}", s(&m["lock_id"])),
        "MsgSuperfluidUndelegateAndUnbondLock" => format!(
            "Superfluid-undelegate lock {} and unbond {} {} from it",
            s(&m["lock_id"]),
            s(&m["coin"]["amount"]),
            s(&m["coin"]["denom"])
        ),
        "MsgMultiSend" => format!(
            "Send {} in one multi-send paid by {}",
            m["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| format!("{} to {}", coins_line(&o["coins"]), s(&o["address"])))
                .collect::<Vec<_>>()
                .join("; "),
            m["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| format!("{} ({})", s(&i["address"]), coins_line(&i["coins"])))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        "MsgCancelUnbondingDelegation" => format!(
            "Cancel the unbonding of {} {} from {}, created at height {}",
            s(&m["amount"]["amount"]),
            s(&m["amount"]["denom"]),
            s(&m["validator_address"]),
            s(&m["creation_height"])
        ),
        "MsgSetWithdrawAddress" => format!(
            "Set the address that receives your staking rewards to {}",
            s(&m["withdraw_address"])
        ),
        "MsgWithdrawValidatorCommission" => format!(
            "Withdraw the commission of validator {}",
            s(&m["validator_address"])
        ),
        "MsgFundCommunityPool" => {
            format!("Fund the community pool with {}", coins_line(&m["amount"]))
        }
        "MsgDeposit" => format!(
            "Deposit {} on proposal {}",
            coins_line(&m["amount"]),
            s(&m["proposal_id"])
        ),
        "MsgRevoke" => format!(
            "Revoke the authorization given to {} for {}",
            s(&m["grantee"]),
            s(&m["msg_type_url"])
        ),
        "MsgRevokeAllowance" => {
            format!("Revoke the fee allowance given to {}", s(&m["grantee"]))
        }
        "MsgInstantiateContract" | "MsgInstantiateContract2" => {
            let mut text = format!(
                "Instantiate code {} as a new contract{}",
                s(&m["code_id"]),
                if name == "MsgInstantiateContract2" {
                    " at a salt-derived address"
                } else {
                    ""
                }
            );
            match s(&m["admin"]).as_str() {
                "" => text.push_str(" with no admin"),
                admin => text.push_str(&format!(" with admin {admin}")),
            }
            if !m["funds"].as_array().unwrap().is_empty() {
                text.push_str(&format!(", sending {}", coins_line(&m["funds"])));
            }
            text
        }
        "MsgMigrateContract" => format!(
            "Migrate contract {} to code {}",
            s(&m["contract"]),
            s(&m["code_id"])
        ),
        "MsgUpdateAdmin" => format!(
            "Make {} the admin of contract {}",
            s(&m["new_admin"]),
            s(&m["contract"])
        ),
        other => panic!("no expected summary for {other}"),
    }
}

/// The LCD fields holding addresses, in the order `addresses()` lists them, and the one that is
/// the payload's `recipient`.
fn address_keys(name: &str) -> (&'static [&'static str], Option<&'static str>) {
    match name {
        "MsgTransferPositions" => (&["sender", "new_owner"], Some("new_owner")),
        "MsgLockTokens" | "MsgBeginUnlocking" => (&["owner"], None),
        "MsgCancelUnbondingDelegation" => (&["delegator_address", "validator_address"], None),
        "MsgSetWithdrawAddress" => (
            &["delegator_address", "withdraw_address"],
            Some("withdraw_address"),
        ),
        "MsgWithdrawValidatorCommission" => (&["validator_address"], None),
        "MsgFundCommunityPool" | "MsgDeposit" => (&["depositor"], None),
        "MsgRevoke" | "MsgRevokeAllowance" => (&["granter", "grantee"], None),
        "MsgInstantiateContract" | "MsgInstantiateContract2" => {
            (&["sender", "admin"], Some("admin"))
        }
        "MsgMigrateContract" => (&["sender", "contract"], None),
        "MsgUpdateAdmin" => (&["sender", "new_admin", "contract"], Some("new_admin")),
        _ => (&["sender"], None),
    }
}

#[test]
fn dapp_messages_decode_to_what_the_lcd_shows_for_real_transactions() {
    use zunia_cosmos::describe::{message_detail, recipient};
    use zunia_cosmos::{decode_direct_sign_doc, DecodedMsg};

    let b64 = base64::engine::general_purpose::STANDARD;
    let doc = dapp_cases();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 50, "the fixture lost cases");
    let mut types = std::collections::BTreeSet::new();
    for case in cases {
        let type_url = s(&case["typeUrl"]);
        let hash = s(&case["hash"]);
        let name = type_url.rsplit('.').next().unwrap().to_owned();
        let lcd = &case["lcd"];
        let index = case["msgIndex"].as_u64().unwrap() as usize;
        let raw = b64.decode(s(&case["tx"])).unwrap();
        // The raw bytes hash to the transaction the LCD reported.
        assert_eq!(
            hex::encode_upper(Sha256::digest(&raw)),
            hash,
            "{name} {hash}: the fixture's bytes are not that transaction"
        );
        assert_eq!(s(&lcd["@type"]), type_url, "{name} {hash}");

        let decoded = decode_direct_sign_doc(&sign_doc_of(&raw, &s(&case["chainId"]))).unwrap();
        assert_eq!(decoded.type_urls[index], type_url, "{name} {hash}");
        let msg = &decoded.msgs[index];
        assert!(!msg.is_unknown(), "{name} {hash} decoded as unknown");

        assert_eq!(
            msg.summary(),
            expected_summary(&type_url, lcd),
            "{name} {hash}: summary"
        );

        // Every address the LCD names, and no other.
        let (keys, recipient_key) = address_keys(&name);
        let expected: Vec<String> = if name == "MsgMultiSend" {
            lcd["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .chain(lcd["outputs"].as_array().unwrap())
                .map(|e| s(&e["address"]))
                .collect()
        } else {
            keys.iter()
                .map(|key| s(&lcd[*key]))
                .filter(|address| !address.is_empty())
                .collect()
        };
        assert_eq!(msg.addresses(), expected, "{name} {hash}: addresses");

        let want_recipient = if name == "MsgMultiSend" {
            let outputs: std::collections::BTreeSet<String> = lcd["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| s(&e["address"]))
                .filter(|a| {
                    lcd["inputs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|i| s(&i["address"]) != *a)
                })
                .collect();
            (outputs.len() == 1).then(|| outputs.into_iter().next().unwrap())
        } else {
            recipient_key
                .map(|key| s(&lcd[key]))
                .filter(|address| !address.is_empty())
        };
        assert_eq!(
            recipient(msg).map(str::to_owned),
            want_recipient,
            "{name} {hash}: recipient"
        );

        // Fields the sentence does not carry.
        let detail = message_detail(msg);
        match name.as_str() {
            "MsgInstantiateContract" | "MsgInstantiateContract2" => {
                let detail = detail.unwrap();
                assert_eq!(detail["kind"], "instantiate-contract");
                assert_eq!(detail["codeId"], lcd["code_id"]);
                assert_eq!(detail["label"], lcd["label"]);
                assert_eq!(detail["msg"], lcd["msg"]);
                assert_eq!(
                    detail["funds"].as_array().unwrap().len(),
                    lcd["funds"].as_array().unwrap().len()
                );
                if s(&lcd["admin"]).is_empty() {
                    assert!(detail["admin"].is_null());
                } else {
                    assert_eq!(detail["admin"], lcd["admin"]);
                }
                if name == "MsgInstantiateContract2" {
                    assert_eq!(
                        detail["salt"].as_str().unwrap(),
                        hex::encode(b64.decode(s(&lcd["salt"])).unwrap())
                    );
                    assert_eq!(detail["fixMsg"], lcd["fix_msg"]);
                } else {
                    assert!(detail.get("salt").is_none());
                }
            }
            "MsgMigrateContract" => {
                let detail = detail.unwrap();
                assert_eq!(detail["kind"], "migrate-contract");
                assert_eq!(detail["contract"], lcd["contract"]);
                assert_eq!(detail["codeId"], lcd["code_id"]);
                assert_eq!(detail["msg"], lcd["msg"]);
            }
            "MsgMultiSend" => {
                let detail = detail.unwrap();
                assert_eq!(detail["kind"], "multi-send");
                for side in ["inputs", "outputs"] {
                    assert_eq!(detail[side], lcd[side], "{name} {hash}: {side}");
                }
            }
            _ => assert!(detail.is_none(), "{name} {hash}: unexpected detail"),
        }

        // The legacy gamm swaps share the poolmanager variants.
        if name.starts_with("MsgSwap") {
            assert!(matches!(
                msg,
                DecodedMsg::SwapExactAmountIn { .. } | DecodedMsg::SwapExactAmountOut { .. }
            ));
        } else {
            assert!(matches!(msg, DecodedMsg::Dapp(_)), "{name} {hash}");
        }
        types.insert(type_url);
    }
    assert_eq!(types.len(), 30, "types covered: {types:?}");
}
