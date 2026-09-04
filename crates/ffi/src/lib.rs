//! Native FFI for the Zunia wallet kernel.
//!
//! Exposes a small C ABI that Flutter (via `dart:ffi` or flutter_rust_bridge) and any other
//! native host can call. Secrets cross the boundary only as caller-owned buffers that the host
//! is responsible for zeroing after use. Prefer the higher-level Dart package in
//! `packages/dart`, which wraps these calls and clears buffers in `finally` blocks.
//!
//! # Ownership
//!
//! Every `*mut c_char` returned from this crate was allocated with [`CString::into_raw`] and
//! must be freed with [`zunia_string_free`]. Forgetting that leaks; calling it twice is UB.

#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use zunia_cosmos::{decode_direct_sign_doc, Coin, Fee, Msg, SignMode, SignerData, UnsignedTx};
use zunia_kernel::{
    Account, Curve, DerivationPath, KdfParams, KeyringEnvelope, WordCount, ZuniaMnemonic,
    KERNEL_VERSION,
};
use zunia_registry::ChainInfo;

fn to_cstring(s: impl Into<String>) -> *mut c_char {
    CString::new(s.into())
        .map(|c| c.into_raw())
        .unwrap_or(ptr::null_mut())
}

fn from_cstr<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    // SAFETY: caller promises a valid NUL-terminated C string for the duration of the call.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| e.to_string())
}

/// Frees a string previously returned by any `zunia_*` function that yields `*mut c_char`.
#[no_mangle]
pub extern "C" fn zunia_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: paired with `CString::into_raw` from this crate.
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn zunia_kernel_version() -> *mut c_char {
    to_cstring(KERNEL_VERSION)
}

#[no_mangle]
pub extern "C" fn zunia_generate_mnemonic(words: u32) -> *mut c_char {
    let count = match words {
        12 => WordCount::Twelve,
        15 => WordCount::Fifteen,
        18 => WordCount::Eighteen,
        21 => WordCount::TwentyOne,
        24 => WordCount::TwentyFour,
        _ => return to_cstring("error: word count must be 12, 15, 18, 21, or 24"),
    };
    match ZuniaMnemonic::generate(count) {
        Ok(m) => to_cstring(m.phrase().expose()),
        Err(e) => to_cstring(format!("error: {e}")),
    }
}

#[no_mangle]
pub extern "C" fn zunia_seal_keyring(
    phrase: *const c_char,
    password: *const c_char,
    metadata_json: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let phrase = from_cstr(phrase)?;
        let password = from_cstr(password)?;
        let metadata_json = from_cstr(metadata_json).unwrap_or("{}");
        let mnemonic = ZuniaMnemonic::parse(phrase).map_err(|e| e.to_string())?;
        let metadata: serde_json::Value =
            serde_json::from_str(metadata_json).map_err(|e| e.to_string())?;
        let envelope = KeyringEnvelope::seal(
            mnemonic.phrase().expose().as_bytes(),
            password,
            KdfParams::default(),
            metadata,
        )
        .map_err(|e| e.to_string())?;
        envelope.to_json().map_err(|e| e.to_string())
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[no_mangle]
pub extern "C" fn zunia_open_keyring(
    envelope_json: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let envelope_json = from_cstr(envelope_json)?;
        let password = from_cstr(password)?;
        let envelope = KeyringEnvelope::from_json(envelope_json).map_err(|e| e.to_string())?;
        let plaintext = envelope.open(password).map_err(|e| e.to_string())?;
        let phrase = core::str::from_utf8(plaintext.expose()).map_err(|e| e.to_string())?;
        let mnemonic = ZuniaMnemonic::parse(phrase).map_err(|e| e.to_string())?;
        Ok(mnemonic.phrase().expose().to_owned())
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[no_mangle]
pub extern "C" fn zunia_derive_address(
    phrase: *const c_char,
    passphrase: *const c_char,
    chain_json: *const c_char,
    account_index: u32,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let phrase = from_cstr(phrase)?;
        let passphrase = from_cstr(passphrase).unwrap_or("");
        let chain_json = from_cstr(chain_json)?;
        let mnemonic = ZuniaMnemonic::parse(phrase).map_err(|e| e.to_string())?;
        let seed = mnemonic.to_seed(passphrase);
        let chain = ChainInfo::from_json(chain_json).map_err(|e| e.to_string())?;
        let path = DerivationPath::bip44(chain.bip44.coin_type, 0, account_index);
        let account = Account::derive(
            seed.expose(),
            Curve::Secp256k1,
            path,
            chain.address_scheme(),
            &chain.bech32.account,
        )
        .map_err(|e| e.to_string())?;
        let mut out = serde_json::Map::new();
        out.insert("address".into(), account.address().map_err(|e| e.to_string())?.into());
        out.insert(
            "publicKeyHex".into(),
            hex::encode(account.public_key().map_err(|e| e.to_string())?).into(),
        );
        out.insert("path".into(), account.path().to_string().into());
        if let Ok(eth) = account.eth_address() {
            out.insert("ethAddress".into(), eth.into());
        }
        Ok(serde_json::to_string(&out).map_err(|e| e.to_string())?)
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[no_mangle]
pub extern "C" fn zunia_sign_cosmos(
    phrase: *const c_char,
    passphrase: *const c_char,
    chain_json: *const c_char,
    account_index: u32,
    sign_bytes_hex: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let phrase = from_cstr(phrase)?;
        let passphrase = from_cstr(passphrase).unwrap_or("");
        let chain_json = from_cstr(chain_json)?;
        let sign_bytes_hex = from_cstr(sign_bytes_hex)?;
        let mnemonic = ZuniaMnemonic::parse(phrase).map_err(|e| e.to_string())?;
        let seed = mnemonic.to_seed(passphrase);
        let chain = ChainInfo::from_json(chain_json).map_err(|e| e.to_string())?;
        let path = DerivationPath::bip44(chain.bip44.coin_type, 0, account_index);
        let account = Account::derive(
            seed.expose(),
            Curve::Secp256k1,
            path,
            chain.address_scheme(),
            &chain.bech32.account,
        )
        .map_err(|e| e.to_string())?;
        let bytes = hex::decode(sign_bytes_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        let signature = account.sign_cosmos(&bytes).map_err(|e| e.to_string())?;
        Ok(hex::encode(signature.as_bytes()))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[no_mangle]
pub extern "C" fn zunia_decode_direct_tx(sign_doc_hex: *const c_char) -> *mut c_char {
    (|| -> Result<String, String> {
        let sign_doc_hex = from_cstr(sign_doc_hex)?;
        let bytes = hex::decode(sign_doc_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        let decoded = decode_direct_sign_doc(&bytes).map_err(|e| e.to_string())?;
        let payload = serde_json::json!({
            "chainId": decoded.chain_id,
            "memo": decoded.memo,
            "hasUnknownMsgs": decoded.has_unknown_msgs,
            "safeWithoutBlindSigning": decoded.is_safe_to_sign_without_blind_signing(),
            "summaries": decoded.summaries(),
        });
        Ok(payload.to_string())
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[no_mangle]
pub extern "C" fn zunia_build_bank_send_direct(
    chain_id: *const c_char,
    from: *const c_char,
    to: *const c_char,
    amount: *const c_char,
    denom: *const c_char,
    memo: *const c_char,
    account_number: u64,
    sequence: u64,
    fee_amount: *const c_char,
    fee_denom: *const c_char,
    gas_limit: u64,
    public_key_hex: *const c_char,
    eth_key_type: u8,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let chain_id = from_cstr(chain_id)?;
        let from = from_cstr(from)?;
        let to = from_cstr(to)?;
        let amount = from_cstr(amount)?;
        let denom = from_cstr(denom)?;
        let memo = from_cstr(memo).unwrap_or("");
        let fee_amount = from_cstr(fee_amount)?;
        let fee_denom = from_cstr(fee_denom)?;
        let public_key_hex = from_cstr(public_key_hex)?;
        let coin = Coin::new(denom, amount).map_err(|e| e.to_string())?;
        let fee_coin = Coin::new(fee_denom, fee_amount).map_err(|e| e.to_string())?;
        let pubkey = hex::decode(public_key_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        let tx = UnsignedTx::new(
            vec![Msg::Send {
                from_address: from.to_owned(),
                to_address: to.to_owned(),
                amount: vec![coin],
            }],
            Fee::new(vec![fee_coin], gas_limit).map_err(|e| e.to_string())?,
            memo,
        )
        .map_err(|e| e.to_string())?;
        let signer = SignerData {
            chain_id: chain_id.to_owned(),
            account_number,
            sequence,
            public_key: pubkey,
            eth_key_type: eth_key_type != 0,
        };
        Ok(hex::encode(
            tx.sign_bytes(&signer, SignMode::Direct)
                .map_err(|e| e.to_string())?,
        ))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn generate_and_free_round_trips() {
        let ptr = zunia_generate_mnemonic(12);
        assert!(!ptr.is_null());
        let phrase = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
        assert!(!phrase.starts_with("error:"));
        zunia_string_free(ptr);
    }

    #[test]
    fn null_free_is_safe() {
        zunia_string_free(ptr::null_mut());
    }

    #[test]
    fn version_is_non_empty() {
        let ptr = zunia_kernel_version();
        let version = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(!version.is_empty());
        zunia_string_free(ptr);
    }
}
