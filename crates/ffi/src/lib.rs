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
//!
//! # The error encoding
//!
//! There is exactly one error convention here and every function uses it: on failure the
//! returned string is the ASCII prefix `error: ` followed by the message. It is unambiguous
//! because no success value can begin that way; every one of them is lowercase hex, a JSON
//! object, a BIP-39 phrase, or a version string. A null return means the string could not be
//! allocated at all, and a caller must treat that as a failure rather than as an empty result.
//!
//! A second convention is not an option. An out-parameter status code that a Dart wrapper
//! forgets to read, or an empty string used as a sentinel, is how "the transaction could not be
//! built" turns into a broadcast of whatever the caller had in that buffer, so anything added
//! here keeps to this one.
//!
//! # Null arguments
//!
//! Every pointer is checked before it is read. A null for a required argument is an error; a
//! null for an optional one (`memo`, `passphrase`) means the empty string. Nothing in this
//! crate dereferences an unchecked pointer, so a null argument returns a message rather than
//! taking the host process down.
//!
//! # The transaction surface
//!
//! [`zunia_build_sign_bytes`], [`zunia_assemble_tx_raw`], [`zunia_build_simulate_tx`] and
//! [`zunia_preview_tx`] hold no key material: they turn the `{ typeUrl, value }` payload the
//! client already has into bytes, and back. Only [`zunia_sign_tx`] touches a mnemonic, and it
//! is the same derive-sign-assemble sequence the caller could run itself, kept in one place so
//! the intermediate seed and key are dropped (and zeroized) before the function returns.

#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use zunia_cosmos::{
    decode_direct_sign_doc, fee_from_json, msgs_from_json, msgs_to_json, sign_mode_from_str, Coin,
    Fee, Msg, SignMode, SignerData, SigningPreview, UnsignedTx,
};
use zunia_kernel::{
    Account, Curve, DerivationPath, KdfParams, KeyringEnvelope, WordCount, ZuniaMnemonic,
    KERNEL_VERSION,
};
use zunia_registry::ChainInfo;

/// The placeholder signature a simulation carries.
///
/// `POST /cosmos/tx/v1beta1/simulate` runs the ante handler with signature verification
/// disabled, but the transaction still has to decode and still has to carry one signature per
/// signer: an empty `signatures` list makes the signature count disagree with the signer count
/// and the node answers with a decode error instead of a gas estimate.
const SIMULATION_SIGNATURE: [u8; 64] = [0u8; 64];

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

/// An argument whose absence is meaningful rather than an error: an empty memo, an empty
/// BIP-39 passphrase.
///
/// Null means "not provided". Non-null still has to be valid UTF-8, because quietly replacing
/// an undecodable memo with the empty string would change the document the user is shown
/// relative to the one they sign.
fn optional_cstr<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Ok("");
    }
    from_cstr(ptr)
}

/// Frees a string previously returned by any `zunia_*` function that yields `*mut c_char`.
// The lint wants this marked `unsafe` because it hands a caller-supplied pointer to
// `CString::from_raw`. Every entry point in this crate carries the same pointer contract, which
// the module documentation states once; marking this one `unsafe` while the rest stay safe
// would imply the others take pointers they do not trust, which is the opposite of true. The C
// signature is identical either way.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
        let metadata_json = if metadata_json.is_null() {
            "{}"
        } else {
            from_cstr(metadata_json)?
        };
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

/// Derives one account and returns it alongside the chain it was derived for.
///
/// The chain descriptor is returned too because signing needs more from it than the derivation
/// did: the bech32 prefix every address in the transaction is checked against, and whether the
/// chain advertises `ethsecp256k1` public keys. Reading those from a second parse of the same
/// JSON would let the two drift.
///
/// The seed and the extended key live only for the duration of the caller's closure and zeroize
/// on drop, which is the whole reason this stays a helper rather than returning key bytes.
fn derive_account(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
) -> Result<(Account, ChainInfo), String> {
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
    Ok((account, chain))
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
        let passphrase = optional_cstr(passphrase)?;
        let chain_json = from_cstr(chain_json)?;
        let (account, _chain) = derive_account(phrase, passphrase, chain_json, account_index)?;
        let mut out = serde_json::Map::new();
        out.insert(
            "address".into(),
            account.address().map_err(|e| e.to_string())?.into(),
        );
        out.insert(
            "publicKeyHex".into(),
            hex::encode(account.public_key().map_err(|e| e.to_string())?).into(),
        );
        out.insert("path".into(), account.path().to_string().into());
        if let Ok(eth) = account.eth_address() {
            out.insert("ethAddress".into(), eth.into());
        }
        serde_json::to_string(&out).map_err(|e| e.to_string())
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
        let passphrase = optional_cstr(passphrase)?;
        let chain_json = from_cstr(chain_json)?;
        let sign_bytes_hex = from_cstr(sign_bytes_hex)?;
        let (account, _chain) = derive_account(phrase, passphrase, chain_json, account_index)?;
        let bytes =
            hex::decode(sign_bytes_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
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
        let bytes =
            hex::decode(sign_doc_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
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

/// Builds the sign bytes for a single bank send.
///
/// Deprecated: superseded by [`zunia_build_sign_bytes`], which takes the same
/// `[{ typeUrl, value }]` payload the client already holds and covers every message type
/// instead of one. Kept because callers built against it still link to it. There is no reason
/// to call it in new code, and it cannot express staking, governance, IBC or a contract call.
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
        let memo = optional_cstr(memo)?;
        let fee_amount = from_cstr(fee_amount)?;
        let fee_denom = from_cstr(fee_denom)?;
        let public_key_hex = from_cstr(public_key_hex)?;
        let coin = Coin::new(denom, amount).map_err(|e| e.to_string())?;
        let fee_coin = Coin::new(fee_denom, fee_amount).map_err(|e| e.to_string())?;
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
        let signer = signer_data(
            chain_id,
            account_number,
            sequence,
            public_key_hex,
            eth_key_type != 0,
        )?;
        Ok(hex::encode(
            tx.sign_bytes(&signer, SignMode::Direct)
                .map_err(|e| e.to_string())?,
        ))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

/* -------------------------------------------------------------------------- *
 * The generic transaction surface
 * -------------------------------------------------------------------------- */

/// Parses the three strings that describe a transaction into an [`UnsignedTx`].
///
/// All of the parsing lives in `zunia_cosmos::json`, deliberately: this crate must not grow a
/// second reading of the wire format, because two readings drift and the drift is only visible
/// as a signature that verifies against nothing.
fn unsigned_tx(msgs_json: &str, fee_json: &str, memo: &str) -> Result<UnsignedTx, String> {
    let msgs = msgs_from_json(msgs_json).map_err(|e| e.to_string())?;
    let fee = fee_from_json(fee_json).map_err(|e| e.to_string())?;
    UnsignedTx::new(msgs, fee, memo).map_err(|e| e.to_string())
}

fn signer_data(
    chain_id: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
) -> Result<SignerData, String> {
    let public_key =
        hex::decode(public_key_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    Ok(SignerData {
        chain_id: chain_id.to_owned(),
        account_number,
        sequence,
        public_key,
        eth_key_type,
    })
}

/// The wire spelling of a sign mode, the same one [`sign_mode_from_str`] accepts.
fn mode_name(mode: SignMode) -> &'static str {
    match mode {
        SignMode::Direct => "direct",
        SignMode::LegacyAminoJson => "amino",
    }
}

/// Renders a [`SigningPreview`] for the approval screen.
///
/// `gasLimit` is a string for the same reason every other integer on this wire is: it is a
/// `uint64`, and a host that reads JSON numbers as doubles loses the top bits silently. The
/// echoed `msgs` are what the bridge actually parsed, not what the caller sent, so a field this
/// build ignored is visible in the prompt rather than assumed.
fn preview_json(tx: &UnsignedTx, preview: &SigningPreview) -> String {
    serde_json::json!({
        "chainId": preview.chain_id,
        "mode": mode_name(preview.mode),
        "summaries": preview.summaries,
        "msgs": msgs_to_json(&tx.msgs),
        "fee": preview.fee,
        "gasLimit": preview.gas_limit.to_string(),
        "memo": preview.memo,
        "spendsFunds": preview.spends_funds,
        "counterparties": preview.counterparties,
        "signBytesHash": preview.sign_bytes_hash,
    })
    .to_string()
}

/// The bytes the kernel must sign, hex encoded.
///
/// Pure: no key material crosses this call, and nothing is signed. `msgs_json` is the
/// `[{ "typeUrl": ..., "value": { ... } }]` array the client already holds, `fee_json` is
/// `{ "amount": [ { "denom", "amount" } ], "gas_limit": "200000" }`, and `mode` is `"direct"`
/// or `"amino"`.
///
/// The mode is required rather than defaulted. Direct and Amino are two different documents,
/// not two encodings of one, so signing the wrong one produces a signature that verifies
/// against nothing and surfaces on chain as an opaque "unauthorized".
#[no_mangle]
pub extern "C" fn zunia_build_sign_bytes(
    chain_id: *const c_char,
    msgs_json: *const c_char,
    fee_json: *const c_char,
    memo: *const c_char,
    account_number: u64,
    sequence: u64,
    public_key_hex: *const c_char,
    eth_key_type: u8,
    mode: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let chain_id = from_cstr(chain_id)?;
        let msgs_json = from_cstr(msgs_json)?;
        let fee_json = from_cstr(fee_json)?;
        let memo = optional_cstr(memo)?;
        let public_key_hex = from_cstr(public_key_hex)?;
        let mode = sign_mode_from_str(from_cstr(mode)?).map_err(|e| e.to_string())?;

        let tx = unsigned_tx(msgs_json, fee_json, memo)?;
        let signer = signer_data(
            chain_id,
            account_number,
            sequence,
            public_key_hex,
            eth_key_type != 0,
        )?;
        Ok(hex::encode(
            tx.sign_bytes(&signer, mode).map_err(|e| e.to_string())?,
        ))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

/// The broadcastable `TxRaw`, hex encoded, given a signature over
/// [`zunia_build_sign_bytes`]' output.
///
/// Pure. Every argument except `signature_hex` must be byte-for-byte what was passed to
/// [`zunia_build_sign_bytes`], the sign mode included: the `auth_info` bytes inside a `TxRaw`
/// carry the mode, and a Direct signature attached to Amino `auth_info` verifies against
/// nothing.
#[no_mangle]
pub extern "C" fn zunia_assemble_tx_raw(
    chain_id: *const c_char,
    msgs_json: *const c_char,
    fee_json: *const c_char,
    memo: *const c_char,
    account_number: u64,
    sequence: u64,
    public_key_hex: *const c_char,
    eth_key_type: u8,
    mode: *const c_char,
    signature_hex: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let chain_id = from_cstr(chain_id)?;
        let msgs_json = from_cstr(msgs_json)?;
        let fee_json = from_cstr(fee_json)?;
        let memo = optional_cstr(memo)?;
        let public_key_hex = from_cstr(public_key_hex)?;
        let mode = sign_mode_from_str(from_cstr(mode)?).map_err(|e| e.to_string())?;
        let signature = hex::decode(from_cstr(signature_hex)?.trim_start_matches("0x"))
            .map_err(|e| e.to_string())?;
        // Named here rather than left to `into_tx_raw`, whose error for this says "sign
        // document is invalid". A truncated or 65-byte recoverable signature is the likely
        // mistake, and the caller cannot act on a message that does not mention the signature.
        if signature.len() != 64 {
            return Err(format!(
                "signature must be 64 bytes (r||s, no recovery id), got {}",
                signature.len()
            ));
        }

        let tx = unsigned_tx(msgs_json, fee_json, memo)?;
        let signer = signer_data(
            chain_id,
            account_number,
            sequence,
            public_key_hex,
            eth_key_type != 0,
        )?;
        Ok(hex::encode(
            tx.into_tx_raw(&signer, mode, &signature)
                .map_err(|e| e.to_string())?,
        ))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

/// A `TxRaw` carrying a 64-byte zero signature, for `POST /cosmos/tx/v1beta1/simulate`.
///
/// Pure, and never broadcastable: the zero signature verifies against nothing, which is the
/// point. Simulation runs the ante handler with signature verification disabled to return a gas
/// estimate, but the transaction must still decode and must still carry one signature per
/// signer.
///
/// Always Direct. The mode is not a parameter because it does not change the estimate, and
/// offering it would invite a caller to simulate in one mode and sign in another.
#[no_mangle]
pub extern "C" fn zunia_build_simulate_tx(
    chain_id: *const c_char,
    msgs_json: *const c_char,
    fee_json: *const c_char,
    memo: *const c_char,
    account_number: u64,
    sequence: u64,
    public_key_hex: *const c_char,
    eth_key_type: u8,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let chain_id = from_cstr(chain_id)?;
        let msgs_json = from_cstr(msgs_json)?;
        let fee_json = from_cstr(fee_json)?;
        let memo = optional_cstr(memo)?;
        let public_key_hex = from_cstr(public_key_hex)?;

        let tx = unsigned_tx(msgs_json, fee_json, memo)?;
        let signer = signer_data(
            chain_id,
            account_number,
            sequence,
            public_key_hex,
            eth_key_type != 0,
        )?;
        Ok(hex::encode(
            tx.into_tx_raw(&signer, SignMode::Direct, &SIMULATION_SIGNATURE)
                .map_err(|e| e.to_string())?,
        ))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

/// Derives, signs and assembles in one call, returning the broadcastable `TxRaw` as hex.
///
/// The convenience path for a host that holds the mnemonic anyway. The seed and the derived key
/// exist only inside this call and zeroize on drop, exactly as in [`zunia_sign_cosmos`]; the
/// public key and the `ethsecp256k1` flag are read from the chain descriptor rather than taken
/// from the caller, so they cannot disagree with the key that actually signs.
///
/// Two checks happen here that the pure functions cannot make, because this is the only entry
/// point that receives the chain descriptor:
///
/// - `chain_id` must equal the descriptor's `chainId`. A mismatch means the wallet derived a
///   key for one chain and is about to sign a document naming another, and the resulting
///   signature is valid on the chain the user did not choose.
/// - every address in the transaction must carry the chain's bech32 prefix, with the ICS-20
///   receiver exempt because it is on the counterparty chain by definition. Catching a
///   wrong-prefix recipient after signing means catching it after the funds are gone.
#[no_mangle]
pub extern "C" fn zunia_sign_tx(
    phrase: *const c_char,
    passphrase: *const c_char,
    chain_json: *const c_char,
    account_index: u32,
    chain_id: *const c_char,
    msgs_json: *const c_char,
    fee_json: *const c_char,
    memo: *const c_char,
    account_number: u64,
    sequence: u64,
    mode: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let phrase = from_cstr(phrase)?;
        let passphrase = optional_cstr(passphrase)?;
        let chain_json = from_cstr(chain_json)?;
        let chain_id = from_cstr(chain_id)?;
        let msgs_json = from_cstr(msgs_json)?;
        let fee_json = from_cstr(fee_json)?;
        let memo = optional_cstr(memo)?;
        let mode = sign_mode_from_str(from_cstr(mode)?).map_err(|e| e.to_string())?;

        let tx = unsigned_tx(msgs_json, fee_json, memo)?;
        let (account, chain) = derive_account(phrase, passphrase, chain_json, account_index)?;
        if chain_id != chain.chain_id {
            return Err(format!(
                "chain id {chain_id:?} does not match the chain descriptor {:?}",
                chain.chain_id
            ));
        }
        tx.validate(&chain.bech32.account)
            .map_err(|e| e.to_string())?;

        let signer = SignerData {
            chain_id: chain_id.to_owned(),
            account_number,
            sequence,
            public_key: account.public_key().map_err(|e| e.to_string())?,
            // `eth-key-sign`, not `eth-address-gen`: the two flags are independent in the
            // registry and this one is what decides the public key type URL inside auth_info.
            eth_key_type: chain.uses_eth_key_sign(),
        };

        let sign_bytes = tx.sign_bytes(&signer, mode).map_err(|e| e.to_string())?;
        let signature = account
            .sign_cosmos(&sign_bytes)
            .map_err(|e| e.to_string())?;
        Ok(hex::encode(
            tx.into_tx_raw(&signer, mode, signature.as_bytes())
                .map_err(|e| e.to_string())?,
        ))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

/// What the approval screen shows, as JSON, computed from the same [`UnsignedTx`] that
/// [`zunia_build_sign_bytes`] would encode.
///
/// Pure: nothing is signed and no key material is involved. The point of computing the prompt
/// from the transaction rather than from the caller's own copy of it is that the two cannot
/// drift; `signBytesHash` is SHA-256 of the exact bytes [`zunia_build_sign_bytes`] returns for
/// the same arguments, so a host can prove the screen and the broadcast describe one document.
///
/// Shape: `{ chainId, mode, summaries, msgs, fee, gasLimit, memo, spendsFunds, counterparties,
/// signBytesHash }`.
#[no_mangle]
pub extern "C" fn zunia_preview_tx(
    chain_id: *const c_char,
    msgs_json: *const c_char,
    fee_json: *const c_char,
    memo: *const c_char,
    account_number: u64,
    sequence: u64,
    public_key_hex: *const c_char,
    eth_key_type: u8,
    mode: *const c_char,
) -> *mut c_char {
    (|| -> Result<String, String> {
        let chain_id = from_cstr(chain_id)?;
        let msgs_json = from_cstr(msgs_json)?;
        let fee_json = from_cstr(fee_json)?;
        let memo = optional_cstr(memo)?;
        let public_key_hex = from_cstr(public_key_hex)?;
        let mode = sign_mode_from_str(from_cstr(mode)?).map_err(|e| e.to_string())?;

        let tx = unsigned_tx(msgs_json, fee_json, memo)?;
        let signer = signer_data(
            chain_id,
            account_number,
            sequence,
            public_key_hex,
            eth_key_type != 0,
        )?;
        let preview = tx.preview(&signer, mode).map_err(|e| e.to_string())?;
        Ok(preview_json(&tx, &preview))
    })()
    .map(to_cstring)
    .unwrap_or_else(|e| to_cstring(format!("error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    /// The mnemonic the CosmJS vector generator used, so a key derived here is the key those
    /// vectors were signed with.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon about";

    /// A minimal Cosmos Hub descriptor: coin type 118, prefix `cosmos`, no Ethermint features.
    /// Deriving account 0 from [`PHRASE`] against it reproduces the vectors'
    /// `m/44'/118'/0'/0/0` key, which is what lets the signing tests compare against CosmJS.
    const CHAIN_JSON: &str = r#"{
        "chainId": "cosmoshub-4",
        "chainName": "Cosmos Hub",
        "rpc": "https://rpc.cosmos.network",
        "rest": "https://rest.cosmos.network",
        "bip44": { "coinType": 118 },
        "bech32Config": {
            "bech32PrefixAccAddr": "cosmos",
            "bech32PrefixValAddr": "cosmosvaloper"
        },
        "feeCurrencies": [
            { "coinDenom": "ATOM", "coinMinimalDenom": "uatom", "coinDecimals": 6 }
        ]
    }"#;

    const RECIPIENT: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";

    fn vectors() -> Value {
        let path: PathBuf =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/cosmos-signing.json");
        let text = std::fs::read_to_string(path).expect(
            "tests/vectors/cosmos-signing.json is missing; run \
             `cd tests/vectors/generate && pnpm install && pnpm generate`",
        );
        serde_json::from_str(&text).expect("vector file is not valid JSON")
    }

    fn case<'a>(vectors: &'a Value, name: &str) -> &'a Value {
        vectors["cases"]
            .as_array()
            .expect("cases is an array")
            .iter()
            .find(|found| found["name"] == json!(name))
            .unwrap_or_else(|| panic!("vector {name} is missing"))
    }

    fn text(value: &Value) -> &str {
        value
            .as_str()
            .unwrap_or_else(|| panic!("expected a string, got {value}"))
    }

    fn c(s: &str) -> CString {
        CString::new(s).expect("test inputs carry no interior NUL")
    }

    /// Reads a returned string and frees it, which is also what keeps the ownership rule
    /// exercised: every call in this module hands its pointer straight back.
    fn read(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null(), "the crate returned a null string");
        // SAFETY: the pointer came from `to_cstring` in this crate, so it is a valid
        // NUL-terminated allocation and nothing else holds a copy of it.
        let value = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("returned strings are UTF-8")
            .to_owned();
        zunia_string_free(ptr);
        value
    }

    fn ok(ptr: *mut c_char) -> String {
        let value = read(ptr);
        assert!(!value.starts_with("error:"), "unexpected failure: {value}");
        value
    }

    #[track_caller]
    fn assert_error(value: &str, needle: &str) {
        assert!(
            value.starts_with("error: "),
            "expected the error encoding, got {value}"
        );
        assert!(
            value.contains(needle),
            "expected an error mentioning {needle:?}, got {value}"
        );
    }

    /// The fee the vectors were generated with, in the wire shape the bindings accept.
    fn fee_json(vectors: &Value) -> String {
        json!({
            "amount": vectors["signer"]["fee"]["amount"],
            "gas_limit": vectors["signer"]["fee"]["gas"],
        })
        .to_string()
    }

    /// The proto-JSON envelope a client sends for each vector.
    ///
    /// Hand written rather than produced by `msgs_to_json`: feeding this crate's own rendering
    /// back into it proves only self-consistency, and a bridge that drops a field is
    /// self-consistent too. These are the shapes `@zunialab/interchain` emits.
    fn envelope(name: &str, vectors: &Value) -> String {
        let from = text(&vectors["key"]["addresses"]["cosmos"]);
        let safro = text(&vectors["key"]["addresses"]["addr_safro"]);
        let value = match name {
            "msg_send" => json!({
                "from_address": from,
                "to_address": RECIPIENT,
                "amount": [{ "denom": "uatom", "amount": "1000000" }],
            }),
            "msg_send_with_memo" => json!({
                "from_address": from,
                "to_address": RECIPIENT,
                "amount": [{ "denom": "uatom", "amount": "1" }],
            }),
            "msg_delegate" => json!({
                "delegator_address": from,
                "validator_address": text(&vectors["key"]["addresses"]["cosmosvaloper"]),
                "amount": { "denom": "uatom", "amount": "5000000" },
            }),
            "msg_withdraw_delegator_reward" => json!({
                "delegator_address": from,
                "validator_address": text(&vectors["key"]["addresses"]["cosmosvaloper"]),
            }),
            "msg_vote" => json!({
                // The short spelling on purpose: the bridge is permissive on input and
                // canonical on output, so the Amino document below must still carry
                // "VOTE_OPTION_NO_WITH_VETO".
                "proposal_id": "848",
                "voter": from,
                "option": "no_with_veto",
            }),
            "msg_transfer_with_timeout" => json!({
                "source_port": "transfer",
                "source_channel": "channel-141",
                "token": { "denom": "uatom", "amount": "1000000" },
                "sender": from,
                "receiver": safro,
                "timeout_height": { "revision_number": "1", "revision_height": "20000000" },
                "timeout_timestamp": "1700000000000000000",
                "memo": "forward",
            }),
            "msg_execute_contract" => json!({
                "sender": from,
                "contract": RECIPIENT,
                // base64 of {"swap":{"offer":"100"}}. The bridge decodes on the way in; if it
                // did not, every swap and every NFT transfer would sign an invalid call.
                "msg": "eyJzd2FwIjp7Im9mZmVyIjoiMTAwIn19",
                "funds": [{ "denom": "uatom", "amount": "100" }],
            }),
            other => panic!("no envelope for vector {other}"),
        };
        json!([{ "typeUrl": text(&case(vectors, name)["type_url"]), "value": value }]).to_string()
    }

    fn sign_bytes(vectors: &Value, msgs_json: &str, memo: &str, mode: &str) -> String {
        let chain_id = c(text(&vectors["signer"]["chain_id"]));
        let msgs = c(msgs_json);
        let fee = c(&fee_json(vectors));
        let memo = c(memo);
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));
        let mode = c(mode);
        read(zunia_build_sign_bytes(
            chain_id.as_ptr(),
            msgs.as_ptr(),
            fee.as_ptr(),
            memo.as_ptr(),
            vectors["signer"]["account_number"].as_u64().unwrap(),
            vectors["signer"]["sequence"].as_u64().unwrap(),
            pubkey.as_ptr(),
            0,
            mode.as_ptr(),
        ))
    }

    fn tx_raw(vectors: &Value, msgs_json: &str, memo: &str, mode: &str, signature: &str) -> String {
        let chain_id = c(text(&vectors["signer"]["chain_id"]));
        let msgs = c(msgs_json);
        let fee = c(&fee_json(vectors));
        let memo = c(memo);
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));
        let mode = c(mode);
        let signature = c(signature);
        read(zunia_assemble_tx_raw(
            chain_id.as_ptr(),
            msgs.as_ptr(),
            fee.as_ptr(),
            memo.as_ptr(),
            vectors["signer"]["account_number"].as_u64().unwrap(),
            vectors["signer"]["sequence"].as_u64().unwrap(),
            pubkey.as_ptr(),
            0,
            mode.as_ptr(),
            signature.as_ptr(),
        ))
    }

    fn simulate(vectors: &Value, msgs_json: &str) -> String {
        let chain_id = c(text(&vectors["signer"]["chain_id"]));
        let msgs = c(msgs_json);
        let fee = c(&fee_json(vectors));
        let memo = c("");
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));
        read(zunia_build_simulate_tx(
            chain_id.as_ptr(),
            msgs.as_ptr(),
            fee.as_ptr(),
            memo.as_ptr(),
            vectors["signer"]["account_number"].as_u64().unwrap(),
            vectors["signer"]["sequence"].as_u64().unwrap(),
            pubkey.as_ptr(),
            0,
        ))
    }

    fn preview(vectors: &Value, msgs_json: &str, memo: &str, mode: &str) -> String {
        let chain_id = c(text(&vectors["signer"]["chain_id"]));
        let msgs = c(msgs_json);
        let fee = c(&fee_json(vectors));
        let memo = c(memo);
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));
        let mode = c(mode);
        read(zunia_preview_tx(
            chain_id.as_ptr(),
            msgs.as_ptr(),
            fee.as_ptr(),
            memo.as_ptr(),
            vectors["signer"]["account_number"].as_u64().unwrap(),
            vectors["signer"]["sequence"].as_u64().unwrap(),
            pubkey.as_ptr(),
            0,
            mode.as_ptr(),
        ))
    }

    fn signed(vectors: &Value, chain_id: &str, msgs_json: &str, memo: &str, mode: &str) -> String {
        let phrase = c(PHRASE);
        let passphrase = c("");
        let chain_json = c(CHAIN_JSON);
        let chain_id = c(chain_id);
        let msgs = c(msgs_json);
        let fee = c(&fee_json(vectors));
        let memo = c(memo);
        let mode = c(mode);
        read(zunia_sign_tx(
            phrase.as_ptr(),
            passphrase.as_ptr(),
            chain_json.as_ptr(),
            0,
            chain_id.as_ptr(),
            msgs.as_ptr(),
            fee.as_ptr(),
            memo.as_ptr(),
            vectors["signer"]["account_number"].as_u64().unwrap(),
            vectors["signer"]["sequence"].as_u64().unwrap(),
            mode.as_ptr(),
        ))
    }

    #[test]
    fn generate_and_free_round_trips() {
        let phrase = ok(zunia_generate_mnemonic(12));
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn null_free_is_safe() {
        zunia_string_free(ptr::null_mut());
    }

    #[test]
    fn version_is_non_empty() {
        assert!(!ok(zunia_kernel_version()).is_empty());
    }

    /// The assertion this binding exists for: a message parsed from the JSON a client actually
    /// sends must produce the sign bytes CosmJS produces, in both modes.
    ///
    /// A round trip through this crate would pass just as happily with a dropped IBC timeout, a
    /// vote-option spelling that never reached the document, or a contract payload that was
    /// never base64-decoded. Only equality with the reference catches those, and the on-chain
    /// symptom of missing one is an opaque "unauthorized" after the user has approved.
    #[test]
    fn sign_bytes_match_the_cosmjs_vectors() {
        let vectors = vectors();
        for name in [
            "msg_send",
            "msg_send_with_memo",
            "msg_delegate",
            "msg_withdraw_delegator_reward",
            "msg_vote",
            "msg_transfer_with_timeout",
            "msg_execute_contract",
        ] {
            let found = case(&vectors, name);
            let msgs = envelope(name, &vectors);
            let memo = text(&found["memo"]).to_owned();
            for mode in ["direct", "amino"] {
                assert_eq!(
                    sign_bytes(&vectors, &msgs, &memo, mode),
                    text(&found[mode]["sign_bytes_hex"]),
                    "{name} in {mode} mode does not match the reference bytes"
                );
            }
        }
    }

    #[test]
    fn a_memo_reaches_the_signed_document() {
        // The one vector that carries a memo. A binding that drops it fails here rather than
        // at broadcast, where the chain reports a signature mismatch and names nothing.
        let vectors = vectors();
        let found = case(&vectors, "msg_send_with_memo");
        assert!(!text(&found["memo"]).is_empty());
        assert_ne!(
            sign_bytes(
                &vectors,
                &envelope("msg_send_with_memo", &vectors),
                text(&found["memo"]),
                "direct"
            ),
            sign_bytes(
                &vectors,
                &envelope("msg_send_with_memo", &vectors),
                "",
                "direct"
            )
        );
    }

    #[test]
    fn tx_raw_wraps_the_reference_body_and_auth_info() {
        let vectors = vectors();
        let found = case(&vectors, "msg_send");
        let signature = "ab".repeat(64);
        let raw = tx_raw(
            &vectors,
            &envelope("msg_send", &vectors),
            "",
            "direct",
            &signature,
        );

        assert!(
            raw.contains(text(&found["direct"]["body_bytes_hex"])),
            "the broadcast body must be the body CosmJS produces"
        );
        assert!(
            raw.contains(text(&found["direct"]["auth_info_bytes_hex"])),
            "the broadcast auth_info must be the auth_info that was signed over"
        );
        // Field 3, length 0x40: the signature is last and framed as a single 64-byte entry.
        assert!(raw.ends_with(&format!("1a40{signature}")));
    }

    #[test]
    fn tx_raw_carries_the_mode_it_was_signed_in() {
        // auth_info encodes the sign mode, so a Direct signature attached to Amino auth_info
        // verifies against nothing. The two assemblies must therefore differ.
        let vectors = vectors();
        let msgs = envelope("msg_send", &vectors);
        let signature = "ab".repeat(64);
        assert_ne!(
            tx_raw(&vectors, &msgs, "", "direct", &signature),
            tx_raw(&vectors, &msgs, "", "amino", &signature)
        );
    }

    #[test]
    fn tx_raw_names_a_signature_of_the_wrong_length() {
        // 65 bytes: an Ethereum-style signature with the recovery id still attached. Worth
        // naming, because "sign document is invalid" sends the caller looking at the messages.
        let vectors = vectors();
        let msgs = envelope("msg_send", &vectors);
        assert_error(
            &tx_raw(&vectors, &msgs, "", "direct", &"11".repeat(65)),
            "signature must be 64 bytes",
        );
        assert_error(
            &tx_raw(&vectors, &msgs, "", "direct", ""),
            "signature must be 64 bytes",
        );
    }

    #[test]
    fn simulate_tx_carries_a_zero_signature() {
        let vectors = vectors();
        let found = case(&vectors, "msg_send");
        let raw = simulate(&vectors, &envelope("msg_send", &vectors));

        assert!(raw.contains(text(&found["direct"]["body_bytes_hex"])));
        assert!(raw.ends_with(&format!("1a40{}", "00".repeat(64))));
    }

    /// `sign_tx` must be exactly derive, sign the bytes, assemble, with nothing else in the
    /// middle. Cosmos signing is deterministic (RFC 6979), so the signature it embeds has to
    /// equal the one `zunia_sign_cosmos` produces over `zunia_build_sign_bytes`' output. If the
    /// convenience path ever signs a document a caller cannot preview, this is where it shows.
    #[test]
    fn sign_tx_is_the_three_step_path_in_one_call() {
        let vectors = vectors();
        let msgs = envelope("msg_send", &vectors);

        for mode in ["direct", "amino"] {
            let bytes = sign_bytes(&vectors, &msgs, "", mode);
            let phrase = c(PHRASE);
            let passphrase = c("");
            let chain_json = c(CHAIN_JSON);
            let bytes_ptr = c(&bytes);
            let signature = ok(zunia_sign_cosmos(
                phrase.as_ptr(),
                passphrase.as_ptr(),
                chain_json.as_ptr(),
                0,
                bytes_ptr.as_ptr(),
            ));
            assert_eq!(signature.len(), 128, "64 bytes of r||s, hex encoded");

            let raw = signed(&vectors, "cosmoshub-4", &msgs, "", mode);
            assert!(!raw.starts_with("error:"), "sign_tx failed: {raw}");
            assert_eq!(
                raw,
                tx_raw(&vectors, &msgs, "", mode, &signature),
                "sign_tx in {mode} mode must assemble what the pure path assembles"
            );
        }
    }

    #[test]
    fn sign_tx_refuses_a_chain_id_the_descriptor_does_not_name() {
        // Deriving a key for one chain and signing a document naming another produces a
        // signature that is valid on the chain the user did not choose.
        let vectors = vectors();
        assert_error(
            &signed(
                &vectors,
                "osmosis-1",
                &envelope("msg_send", &vectors),
                "",
                "direct",
            ),
            "does not match the chain descriptor",
        );
    }

    #[test]
    fn sign_tx_refuses_a_recipient_from_another_chain() {
        // The same 20 bytes under an osmo prefix. Caught before signing, because afterwards
        // the funds are gone.
        let vectors = vectors();
        let msgs = json!([{
            "typeUrl": "/cosmos.bank.v1beta1.MsgSend",
            "value": {
                "from_address": text(&vectors["key"]["addresses"]["cosmos"]),
                "to_address": text(&vectors["key"]["addresses"]["osmo"]),
                "amount": [{ "denom": "uatom", "amount": "1" }],
            }
        }])
        .to_string();
        assert_error(
            &signed(&vectors, "cosmoshub-4", &msgs, "", "direct"),
            "address is invalid for this chain",
        );
        // The pure path has no chain descriptor to check against, so it still builds. That
        // asymmetry is deliberate and documented on `zunia_sign_tx`.
        assert!(!sign_bytes(&vectors, &msgs, "", "direct").starts_with("error:"));
    }

    #[test]
    fn preview_describes_the_bytes_that_will_be_signed() {
        let vectors = vectors();
        let msgs = envelope("msg_send", &vectors);
        let rendered: Value =
            serde_json::from_str(&preview(&vectors, &msgs, "", "direct")).unwrap();

        assert_eq!(rendered["chainId"], json!("cosmoshub-4"));
        assert_eq!(rendered["mode"], json!("direct"));
        assert_eq!(rendered["gasLimit"], json!("200000"));
        assert_eq!(rendered["spendsFunds"], json!(true));
        assert_eq!(rendered["memo"], json!(""));
        assert_eq!(
            rendered["fee"],
            json!([{ "denom": "uatom", "amount": "5000" }])
        );
        assert_eq!(rendered["summaries"].as_array().unwrap().len(), 1);
        assert!(text(&rendered["summaries"][0]).starts_with("Send 1000000 uatom"));
        assert_eq!(rendered["counterparties"].as_array().unwrap().len(), 2);
        assert_eq!(
            rendered["msgs"][0]["typeUrl"],
            json!("/cosmos.bank.v1beta1.MsgSend")
        );

        // The prompt and the broadcast must describe one document, which is what the hash is
        // for: it is over the exact bytes `zunia_build_sign_bytes` returns for these arguments.
        let bytes = hex::decode(sign_bytes(&vectors, &msgs, "", "direct")).unwrap();
        assert_eq!(
            text(&rendered["signBytesHash"]),
            hex::encode(Sha256::digest(&bytes))
        );

        // And it must be mode-specific, or the screen could describe the other document.
        let amino: Value = serde_json::from_str(&preview(&vectors, &msgs, "", "amino")).unwrap();
        assert_eq!(amino["mode"], json!("amino"));
        assert_ne!(amino["signBytesHash"], rendered["signBytesHash"]);
    }

    #[test]
    fn preview_reports_a_vote_as_spending_nothing() {
        let vectors = vectors();
        let rendered: Value = serde_json::from_str(&preview(
            &vectors,
            &envelope("msg_vote", &vectors),
            "",
            "direct",
        ))
        .unwrap();
        assert_eq!(rendered["spendsFunds"], json!(false));
        assert!(text(&rendered["summaries"][0]).contains("proposal 848"));
        // Permissive in, canonical out: the short spelling the envelope used is not what the
        // preview shows.
        assert_eq!(
            rendered["msgs"][0]["value"]["option"],
            json!("VOTE_OPTION_NO_WITH_VETO")
        );
    }

    #[test]
    fn an_unknown_message_type_is_refused_by_name() {
        // Never guessed at. A wallet that signs a payload it cannot describe is a blind signer,
        // and the error has to name the type or nobody can add support for it.
        let vectors = vectors();
        let msgs = json!([{ "typeUrl": "/cosmos.authz.v1beta1.MsgExec", "value": {} }]).to_string();
        assert_error(
            &sign_bytes(&vectors, &msgs, "", "direct"),
            "/cosmos.authz.v1beta1.MsgExec",
        );
    }

    #[test]
    fn an_ibc_transfer_with_no_timeout_is_refused() {
        // Escrowed on the source chain and never refundable if no relayer picks it up.
        let vectors = vectors();
        let msgs = json!([{
            "typeUrl": "/ibc.applications.transfer.v1.MsgTransfer",
            "value": {
                "source_port": "transfer",
                "source_channel": "channel-141",
                "token": { "denom": "uatom", "amount": "1000000" },
                "sender": text(&vectors["key"]["addresses"]["cosmos"]),
                "receiver": text(&vectors["key"]["addresses"]["addr_safro"]),
                "timeout_height": { "revision_number": "0", "revision_height": "0" },
                "timeout_timestamp": "0",
                "memo": "",
            }
        }])
        .to_string();
        assert_error(
            &sign_bytes(&vectors, &msgs, "", "direct"),
            "sign document is invalid",
        );
    }

    #[test]
    fn an_unknown_sign_mode_is_refused_rather_than_defaulted() {
        let vectors = vectors();
        let msgs = envelope("msg_send", &vectors);
        assert_error(&sign_bytes(&vectors, &msgs, "", ""), "sign document");
        assert_error(&sign_bytes(&vectors, &msgs, "", "DIRECT2"), "sign document");
        // Case and surrounding space are accepted, because callers differ on both.
        assert!(!sign_bytes(&vectors, &msgs, "", " Direct ").starts_with("error:"));
    }

    #[test]
    fn a_missing_gas_limit_is_refused_before_signing() {
        // The chain's answer for this arrives after the user has signed and says "out of gas",
        // which names the wrong problem.
        let vectors = vectors();
        let chain_id = c("cosmoshub-4");
        let msgs = c(&envelope("msg_send", &vectors));
        let fee = c(r#"{"amount":[]}"#);
        let memo = c("");
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));
        let mode = c("direct");
        assert_error(
            &read(zunia_build_sign_bytes(
                chain_id.as_ptr(),
                msgs.as_ptr(),
                fee.as_ptr(),
                memo.as_ptr(),
                12345,
                7,
                pubkey.as_ptr(),
                0,
                mode.as_ptr(),
            )),
            "fee or gas limit is invalid",
        );
    }

    /// Every required pointer must be checked. A host that forgets an argument gets a message,
    /// not a crash inside the wallet process.
    #[test]
    fn null_arguments_are_reported_rather_than_dereferenced() {
        let vectors = vectors();
        let chain_id = c("cosmoshub-4");
        let msgs = c(&envelope("msg_send", &vectors));
        let fee = c(&fee_json(&vectors));
        let memo = c("");
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));
        let mode = c("direct");
        let null = ptr::null();

        for (label, args) in [
            (
                "chain_id",
                [
                    null,
                    msgs.as_ptr(),
                    fee.as_ptr(),
                    pubkey.as_ptr(),
                    mode.as_ptr(),
                ],
            ),
            (
                "msgs",
                [
                    chain_id.as_ptr(),
                    null,
                    fee.as_ptr(),
                    pubkey.as_ptr(),
                    mode.as_ptr(),
                ],
            ),
            (
                "fee",
                [
                    chain_id.as_ptr(),
                    msgs.as_ptr(),
                    null,
                    pubkey.as_ptr(),
                    mode.as_ptr(),
                ],
            ),
            (
                "pubkey",
                [
                    chain_id.as_ptr(),
                    msgs.as_ptr(),
                    fee.as_ptr(),
                    null,
                    mode.as_ptr(),
                ],
            ),
            (
                "mode",
                [
                    chain_id.as_ptr(),
                    msgs.as_ptr(),
                    fee.as_ptr(),
                    pubkey.as_ptr(),
                    null,
                ],
            ),
        ] {
            let value = read(zunia_build_sign_bytes(
                args[0],
                args[1],
                args[2],
                memo.as_ptr(),
                12345,
                7,
                args[3],
                0,
                args[4],
            ));
            assert_error(&value, "null pointer");
            assert!(value.contains("null pointer"), "{label} was not checked");
        }

        // The optional ones mean "empty", not "error", which is how the Dart wrapper spells an
        // absent memo.
        assert_eq!(
            read(zunia_build_sign_bytes(
                chain_id.as_ptr(),
                msgs.as_ptr(),
                fee.as_ptr(),
                ptr::null(),
                12345,
                7,
                pubkey.as_ptr(),
                0,
                mode.as_ptr(),
            )),
            sign_bytes(&vectors, &envelope("msg_send", &vectors), "", "direct")
        );

        // And the same holds on every other entry point in the surface.
        assert_error(
            &read(zunia_preview_tx(
                ptr::null(),
                msgs.as_ptr(),
                fee.as_ptr(),
                memo.as_ptr(),
                0,
                0,
                pubkey.as_ptr(),
                0,
                mode.as_ptr(),
            )),
            "null pointer",
        );
        assert_error(
            &read(zunia_assemble_tx_raw(
                chain_id.as_ptr(),
                msgs.as_ptr(),
                fee.as_ptr(),
                memo.as_ptr(),
                0,
                0,
                pubkey.as_ptr(),
                0,
                mode.as_ptr(),
                ptr::null(),
            )),
            "null pointer",
        );
        assert_error(
            &read(zunia_build_simulate_tx(
                chain_id.as_ptr(),
                msgs.as_ptr(),
                fee.as_ptr(),
                memo.as_ptr(),
                0,
                0,
                ptr::null(),
                0,
            )),
            "null pointer",
        );
        assert_error(
            &read(zunia_sign_tx(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                chain_id.as_ptr(),
                msgs.as_ptr(),
                fee.as_ptr(),
                memo.as_ptr(),
                0,
                0,
                mode.as_ptr(),
            )),
            "null pointer",
        );
    }

    #[test]
    fn the_deprecated_bank_send_still_agrees_with_the_generic_path() {
        // Kept working on purpose: callers already link to it. It must not drift from the
        // surface that replaces it.
        let vectors = vectors();
        let chain_id = c("cosmoshub-4");
        let from = c(text(&vectors["key"]["addresses"]["cosmos"]));
        let to = c(RECIPIENT);
        let amount = c("1000000");
        let denom = c("uatom");
        let memo = c("");
        let fee_amount = c("5000");
        let fee_denom = c("uatom");
        let pubkey = c(text(&vectors["key"]["pubkey_compressed_hex"]));

        assert_eq!(
            ok(zunia_build_bank_send_direct(
                chain_id.as_ptr(),
                from.as_ptr(),
                to.as_ptr(),
                amount.as_ptr(),
                denom.as_ptr(),
                memo.as_ptr(),
                12345,
                7,
                fee_amount.as_ptr(),
                fee_denom.as_ptr(),
                200_000,
                pubkey.as_ptr(),
                0,
            )),
            sign_bytes(&vectors, &envelope("msg_send", &vectors), "", "direct")
        );
    }
}
