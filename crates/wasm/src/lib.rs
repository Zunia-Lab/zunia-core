//! Browser-facing WASM API for the Zunia wallet kernel.
//!
//! Loaded only in the extension background worker (never a content script or injected page).
//! Callers pass opaque JSON and hex strings; private key bytes never cross this boundary as a
//! return value except during the one-shot onboarding reveal, which the UI then discards.
//!
//! Network I/O stays in JavaScript per ADR-0004. This crate only derives, encodes, signs, and
//! decrypts.

#![deny(clippy::arithmetic_side_effects)]

use wasm_bindgen::prelude::*;

use zunia_cosmos::{
    decode_direct_sign_doc, Coin, Fee, Msg, SignMode, SignerData, UnsignedTx,
};
use zunia_evm::{
    personal_sign_hex, personal_sign_payload_is_safe, sign_typed_data_hex, AccessListItem, Address,
    TypedData, TxKind, UnsignedTx as EvmTx, U256,
};
use zunia_kernel::{
    Account, AddressScheme, Curve, DerivationPath, KdfParams, KeyringEnvelope, WordCount,
    ZuniaMnemonic, KERNEL_VERSION,
};
use zunia_registry::ChainInfo;

fn err(e: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn kernel_version() -> String {
    KERNEL_VERSION.to_owned()
}

#[wasm_bindgen]
pub fn generate_mnemonic(words: u32) -> Result<String, JsValue> {
    let count = match words {
        12 => WordCount::Twelve,
        15 => WordCount::Fifteen,
        18 => WordCount::Eighteen,
        21 => WordCount::TwentyOne,
        24 => WordCount::TwentyFour,
        _ => return Err(err("word count must be 12, 15, 18, 21, or 24")),
    };
    Ok(ZuniaMnemonic::generate(count)
        .map_err(err)?
        .phrase()
        .expose()
        .to_owned())
}

#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> Result<bool, JsValue> {
    Ok(ZuniaMnemonic::parse(phrase).is_ok())
}

/// Seals the mnemonic phrase into a versioned keyring envelope under `password`.
#[wasm_bindgen]
pub fn seal_keyring(
    phrase: &str,
    password: &str,
    metadata_json: &str,
) -> Result<String, JsValue> {
    let mnemonic = ZuniaMnemonic::parse(phrase).map_err(err)?;
    let metadata: serde_json::Value =
        serde_json::from_str(metadata_json).map_err(|e| err(format!("metadata: {e}")))?;
    // Production KDF. Tests use `low_memory`; the extension never should.
    let envelope = KeyringEnvelope::seal(
        mnemonic.phrase().expose().as_bytes(),
        password,
        KdfParams::default(),
        metadata,
    )
    .map_err(err)?;
    envelope.to_json().map_err(err)
}

/// Opens a sealed envelope and returns the mnemonic phrase.
#[wasm_bindgen]
pub fn open_keyring(envelope_json: &str, password: &str) -> Result<String, JsValue> {
    let envelope = KeyringEnvelope::from_json(envelope_json).map_err(err)?;
    let plaintext = envelope.open(password).map_err(err)?;
    let phrase = core::str::from_utf8(plaintext.expose()).map_err(err)?;
    // Re-parse so a corrupted ciphertext cannot smuggle non-mnemonic bytes into the session.
    let mnemonic = ZuniaMnemonic::parse(phrase).map_err(err)?;
    Ok(mnemonic.phrase().expose().to_owned())
}

#[wasm_bindgen]
pub fn rotate_keyring_password(
    envelope_json: &str,
    old_password: &str,
    new_password: &str,
) -> Result<String, JsValue> {
    let envelope = KeyringEnvelope::from_json(envelope_json).map_err(err)?;
    let rotated = envelope
        .change_password(old_password, new_password, KdfParams::default())
        .map_err(err)?;
    rotated.to_json().map_err(err)
}

fn derive_account(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
) -> Result<Account, JsValue> {
    let mnemonic = ZuniaMnemonic::parse(phrase).map_err(err)?;
    let seed = mnemonic.to_seed(passphrase);
    let chain = ChainInfo::from_json(chain_json).map_err(err)?;
    let scheme = chain.address_scheme();
    let path = DerivationPath::bip44(chain.bip44.coin_type, 0, account_index);
    Account::derive(
        seed.expose(),
        Curve::Secp256k1,
        path,
        scheme,
        &chain.bech32.account,
    )
    .map_err(err)
}

#[wasm_bindgen]
pub fn derive_address(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
) -> Result<JsValue, JsValue> {
    let account = derive_account(phrase, passphrase, chain_json, account_index)?;
    let mut out = serde_json::Map::new();
    out.insert("address".into(), account.address().map_err(err)?.into());
    out.insert(
        "publicKeyHex".into(),
        hex::encode(account.public_key().map_err(err)?).into(),
    );
    out.insert("path".into(), account.path().to_string().into());
    if let Ok(eth) = account.eth_address() {
        out.insert("ethAddress".into(), eth.into());
    }
    Ok(serde_wasm_bindgen::to_value(&out).map_err(err)?)
}

#[wasm_bindgen]
pub fn sign_cosmos(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
    sign_bytes_hex: &str,
) -> Result<String, JsValue> {
    let account = derive_account(phrase, passphrase, chain_json, account_index)?;
    let bytes = hex::decode(sign_bytes_hex.trim_start_matches("0x")).map_err(err)?;
    let signature = account.sign_cosmos(&bytes).map_err(err)?;
    Ok(hex::encode(signature.as_bytes()))
}

#[wasm_bindgen]
pub fn decode_direct_tx(sign_doc_hex: &str) -> Result<JsValue, JsValue> {
    let bytes = hex::decode(sign_doc_hex.trim_start_matches("0x")).map_err(err)?;
    let decoded = decode_direct_sign_doc(&bytes).map_err(err)?;
    let payload = serde_json::json!({
        "chainId": decoded.chain_id,
        "memo": decoded.memo,
        "hasUnknownMsgs": decoded.has_unknown_msgs,
        "safeWithoutBlindSigning": decoded.is_safe_to_sign_without_blind_signing(),
        "summaries": decoded.summaries(),
        "addresses": decoded.msgs.iter().flat_map(|m| m.addresses()).collect::<Vec<_>>(),
    });
    Ok(serde_wasm_bindgen::to_value(&payload).map_err(err)?)
}

#[wasm_bindgen]
pub fn build_bank_send_direct(
    chain_id: &str,
    from: &str,
    to: &str,
    amount: &str,
    denom: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    fee_amount: &str,
    fee_denom: &str,
    gas_limit: u64,
    public_key_hex: &str,
    eth_key_type: bool,
) -> Result<String, JsValue> {
    let coin = Coin::new(denom, amount).map_err(err)?;
    let fee_coin = Coin::new(fee_denom, fee_amount).map_err(err)?;
    let pubkey = hex::decode(public_key_hex.trim_start_matches("0x")).map_err(err)?;
    let tx = UnsignedTx::new(
        vec![Msg::Send {
            from_address: from.to_owned(),
            to_address: to.to_owned(),
            amount: vec![coin],
        }],
        Fee::new(vec![fee_coin], gas_limit).map_err(err)?,
        memo,
    )
    .map_err(err)?;
    let signer = SignerData {
        chain_id: chain_id.to_owned(),
        account_number,
        sequence,
        public_key: pubkey,
        eth_key_type,
    };
    Ok(hex::encode(
        tx.sign_bytes(&signer, SignMode::Direct).map_err(err)?,
    ))
}

#[wasm_bindgen]
pub fn personal_sign(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
    message: &str,
) -> Result<String, JsValue> {
    if !personal_sign_payload_is_safe(message.as_bytes()) {
        return Err(err(
            "personal_sign refused: message is not safely renderable text",
        ));
    }
    let key = eth_key(phrase, passphrase, account_index)?;
    personal_sign_hex(&key, message.as_bytes()).map_err(err)
}

#[wasm_bindgen]
pub fn sign_typed_data(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
    typed_data_json: &str,
) -> Result<String, JsValue> {
    let typed = TypedData::from_json(typed_data_json).map_err(err)?;
    let key = eth_key(phrase, passphrase, account_index)?;
    sign_typed_data_hex(&key, &typed).map_err(err)
}

/// Signs an Ethereum transaction described by JSON.
///
/// Shape: `{ type, chainId, nonce, gasLimit, to?, value, data, gasPrice?, maxFeePerGas?,
/// maxPriorityFeePerGas?, accessList? }` with decimal string quantities.
#[wasm_bindgen]
pub fn sign_evm_tx(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
    tx_json: &str,
) -> Result<JsValue, JsValue> {
    let value: serde_json::Value = serde_json::from_str(tx_json).map_err(err)?;
    let unsigned = evm_tx_from_json(&value)?;
    let key = eth_key(phrase, passphrase, account_index)?;
    let signed = unsigned.sign(&key).map_err(err)?;
    let out = serde_json::json!({
        "raw": format!("0x{}", hex::encode(&signed.raw)),
        "hash": format!("0x{}", hex::encode(signed.hash)),
        "v": signed.v.to_string(),
        "r": format!("0x{}", hex::encode(signed.r)),
        "s": format!("0x{}", hex::encode(signed.s)),
    });
    Ok(serde_wasm_bindgen::to_value(&out).map_err(err)?)
}

#[wasm_bindgen]
pub fn validate_bech32_address(address: &str, expected_prefix: &str) -> Result<bool, JsValue> {
    Ok(zunia_kernel::validate_address(address, expected_prefix).is_ok())
}

#[wasm_bindgen]
pub fn parse_chain(chain_json: &str) -> Result<JsValue, JsValue> {
    let chain = ChainInfo::from_json(chain_json).map_err(err)?;
    let fee = chain.primary_fee_currency();
    let out = serde_json::json!({
        "chainId": chain.chain_id,
        "chainName": chain.chain_name,
        "prefix": chain.bech32.account,
        "coinType": chain.bip44.coin_type,
        "ethermint": chain.address_scheme() == AddressScheme::Ethermint,
        "feeDenom": fee.minimal_denom,
        "decimals": fee.decimals,
        "rpc": chain.rpc,
        "rest": chain.rest,
    });
    Ok(serde_wasm_bindgen::to_value(&out).map_err(err)?)
}

fn eth_key(
    phrase: &str,
    passphrase: &str,
    account_index: u32,
) -> Result<zunia_kernel::ExtendedKey, JsValue> {
    let mnemonic = ZuniaMnemonic::parse(phrase).map_err(err)?;
    let seed = mnemonic.to_seed(passphrase);
    zunia_kernel::ExtendedKey::from_seed_and_path(
        Curve::Secp256k1,
        seed.expose(),
        &DerivationPath::bip44(60, 0, account_index),
    )
    .map_err(err)
}

fn qty(value: &serde_json::Value, key: &str) -> Result<U256, JsValue> {
    let text = value
        .get(key)
        .and_then(|v| v.as_str().map(str::to_owned).or_else(|| v.as_u64().map(|n| n.to_string())))
        .ok_or_else(|| err(format!("missing quantity {key}")))?;
    U256::parse_decimal(&text).map_err(err)
}

fn u64_field(value: &serde_json::Value, key: &str) -> Result<u64, JsValue> {
    value
        .get(key)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| err(format!("missing u64 {key}")))
}

fn evm_tx_from_json(value: &serde_json::Value) -> Result<EvmTx, JsValue> {
    let tx_type = value
        .get("type")
        .and_then(|v| v.as_u64())
        .unwrap_or(2);
    let access_list = value
        .get("accessList")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let address = Address::parse(
                        item.get("address")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| err("accessList address"))?,
                    )
                    .map_err(err)?;
                    let storage_keys = item
                        .get("storageKeys")
                        .and_then(|v| v.as_array())
                        .unwrap_or(&Vec::new())
                        .iter()
                        .map(|key| {
                            let bytes = hex::decode(
                                key.as_str()
                                    .unwrap_or_default()
                                    .trim_start_matches("0x"),
                            )
                            .map_err(err)?;
                            <[u8; 32]>::try_from(bytes.as_slice())
                                .map_err(|_| err("storage key must be 32 bytes"))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok::<AccessListItem, JsValue>(AccessListItem {
                        address,
                        storage_keys,
                    })
                })
                .collect::<Result<Vec<_>, JsValue>>()
        })
        .transpose()?
        .unwrap_or_default();

    let kind = match tx_type {
        0 => TxKind::Legacy {
            gas_price: qty(value, "gasPrice")?,
        },
        1 => TxKind::AccessList {
            gas_price: qty(value, "gasPrice")?,
            access_list,
        },
        2 => TxKind::FeeMarket {
            max_priority_fee_per_gas: qty(value, "maxPriorityFeePerGas")?,
            max_fee_per_gas: qty(value, "maxFeePerGas")?,
            access_list,
        },
        other => return Err(err(format!("unsupported tx type {other}"))),
    };

    let to = match value.get("to").and_then(|v| v.as_str()) {
        Some(address) if !address.is_empty() => Some(Address::parse(address).map_err(err)?),
        _ => None,
    };
    let data = value
        .get("data")
        .and_then(|v| v.as_str())
        .map(|hexed| hex::decode(hexed.trim_start_matches("0x")).map_err(err))
        .transpose()?
        .unwrap_or_default();

    Ok(EvmTx {
        chain_id: u64_field(value, "chainId")?,
        nonce: u64_field(value, "nonce")?,
        gas_limit: u64_field(value, "gasLimit")?,
        to,
        value: qty(value, "value")?,
        data,
        kind,
    })
}
