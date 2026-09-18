//! Browser-facing WASM API for the Zunia wallet kernel.
//!
//! Loaded only in the extension background worker (never a content script or injected page).
//! Callers pass opaque JSON and hex strings; private key bytes never cross this boundary as a
//! return value except during the one-shot onboarding reveal, which the UI then discards.
//!
//! Network I/O stays in JavaScript per ADR-0004. This crate only derives, encodes, signs, and
//! decrypts.
//!
//! # The Cosmos surface
//!
//! [`build_sign_bytes`], [`assemble_tx_raw`], [`build_simulate_tx`], [`sign_tx`] and
//! [`preview_tx`] cover the whole message set rather than one hardcoded transfer. Messages
//! arrive as the `[{ typeUrl, value }]` proto-JSON that `@zunialab/interchain` already emits,
//! are parsed by `zunia_cosmos::json`, and are encoded by the golden-vector-tested encoders in
//! `zunia_cosmos`. Nothing about the wire format is decided in this file: a bug here has to
//! surface as a refusal, never as different bytes.
//!
//! # Two layers, on purpose
//!
//! Every export is a thin wrapper over a private function that returns a typed `BindingError`.
//! The split is not decoration. Constructing a `JsValue` outside a JavaScript runtime aborts
//! the process, so a test that drove an exported function into its error path would kill the
//! test runner rather than fail an assertion. The inner functions are plain Rust, which is
//! what the tests at the bottom of this file exercise against the golden vectors.

#![deny(clippy::arithmetic_side_effects)]
// The exported functions take flat argument lists by necessity: wasm-bindgen passes primitives
// and strings, and handing it a struct would mean a hand-maintained wrapper type on the
// JavaScript side of the boundary for every payload. The typed structures live one layer down,
// in zunia-cosmos.
#![allow(clippy::too_many_arguments)]

use wasm_bindgen::prelude::*;

use zunia_cosmos::{
    decode_direct_sign_doc, fee_from_json, msgs_from_json, sign_mode_from_str, Coin, CosmosError,
    Fee, Msg, SignMode, SignerData, SigningPreview, UnsignedTx,
};
use zunia_evm::{
    personal_sign_hex, personal_sign_payload_is_safe, sign_typed_data_hex, AccessListItem, Address,
    TxKind, TypedData, UnsignedTx as EvmTx, U256,
};
use zunia_kernel::{
    Account, AddressScheme, Curve, DerivationPath, KdfParams, KernelError, KeyringEnvelope,
    WordCount, ZuniaMnemonic, KERNEL_VERSION,
};
use zunia_registry::{ChainInfo, RegistryError};

/// Wraps a failure as a JavaScript `Error`.
///
/// A thrown string is not an `Error`: it has no `.message`, no stack, and `instanceof Error`
/// is false for it, so the extension's error handling takes the wrong branch and an integrator
/// sees a bare sentence with nothing to attach a breakpoint to.
fn err(e: impl core::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
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
pub fn seal_keyring(phrase: &str, password: &str, metadata_json: &str) -> Result<String, JsValue> {
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
) -> BindingResult<Account> {
    let chain = ChainInfo::from_json(chain_json)?;
    derive_for_chain(phrase, passphrase, &chain, account_index)
}

/// Derives the signing account for an already-parsed chain.
///
/// The parsed mnemonic and the seed are locals, and both zeroize when this function returns;
/// the [`Account`] that comes back holds its extended key in the kernel's `SecretBytes`, which
/// does the same when the caller drops it. Nothing key-shaped is returned, logged, or placed
/// into an error, which is why `BindingError` carries no free-form string from the caller's
/// phrase.
fn derive_for_chain(
    phrase: &str,
    passphrase: &str,
    chain: &ChainInfo,
    account_index: u32,
) -> BindingResult<Account> {
    let mnemonic = ZuniaMnemonic::parse(phrase)?;
    let seed = mnemonic.to_seed(passphrase);
    let path = DerivationPath::bip44(chain.bip44.coin_type, 0, account_index);
    Ok(Account::derive(
        seed.expose(),
        Curve::Secp256k1,
        path,
        chain.address_scheme(),
        &chain.bech32.account,
    )?)
}

#[wasm_bindgen]
pub fn derive_address(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
) -> Result<JsValue, JsValue> {
    let account = derive_account(phrase, passphrase, chain_json, account_index).map_err(err)?;
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
    serde_wasm_bindgen::to_value(&out).map_err(err)
}

#[wasm_bindgen]
pub fn sign_cosmos(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
    sign_bytes_hex: &str,
) -> Result<String, JsValue> {
    let account = derive_account(phrase, passphrase, chain_json, account_index).map_err(err)?;
    let bytes = decode_hex("sign bytes", sign_bytes_hex).map_err(err)?;
    let signature = account.sign_cosmos(&bytes).map_err(err)?;
    Ok(hex::encode(signature.as_bytes()))
}

#[wasm_bindgen]
pub fn decode_direct_tx(sign_doc_hex: &str) -> Result<JsValue, JsValue> {
    let bytes = decode_hex("sign document", sign_doc_hex).map_err(err)?;
    let decoded = decode_direct_sign_doc(&bytes).map_err(err)?;
    let payload = serde_json::json!({
        "chainId": decoded.chain_id,
        "memo": decoded.memo,
        "hasUnknownMsgs": decoded.has_unknown_msgs,
        "safeWithoutBlindSigning": decoded.is_safe_to_sign_without_blind_signing(),
        "summaries": decoded.summaries(),
        "addresses": decoded.msgs.iter().flat_map(|m| m.addresses()).collect::<Vec<_>>(),
    });
    serde_wasm_bindgen::to_value(&payload).map_err(err)
}

/// Direct sign bytes for a single bank send.
///
/// Superseded by [`build_sign_bytes`], which takes the whole message set and both sign modes.
/// Kept because callers still reference it; new code should build a
/// `[{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { … } }]` payload and go through the
/// general path, which is the only one that can express staking, governance, IBC and contract
/// calls.
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

/* -------------------------------------------------------------------------- *
 * Cosmos: the general signing surface
 * -------------------------------------------------------------------------- */

/// Compressed secp256k1. Every Cosmos `SignerInfo` carries 33 bytes, Ethermint chains
/// included: they change the key's type URL, not its length.
const PUBLIC_KEY_LEN: usize = 33;

/// A Cosmos signature is `r || s`. There is no recovery byte inside a transaction, so a
/// 65-byte Ethereum-style signature is a caller error rather than something to truncate.
const SIGNATURE_LEN: usize = 64;

/// The placeholder signature a simulate request carries.
///
/// `POST /cosmos/tx/v1beta1/simulate` does not verify signatures, but it does decode the
/// transaction and pair every `SignerInfo` with a signature, so a `TxRaw` carrying none is
/// rejected before any gas is estimated.
const SIMULATION_SIGNATURE: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];

/// Why a call into the Cosmos surface failed, named by the argument that was wrong.
///
/// The layer underneath is typed but deliberately context-free: [`CosmosError::Decode`] cannot
/// say whether the message list or the fee was malformed, and a hex error cannot say which of
/// two hex arguments produced it. An integrator holding nine string arguments and the message
/// "could not decode payload" has no way to find the one that is wrong, so every variant here
/// names its argument. None of them carries key material: the mnemonic never reaches a
/// message, and `KernelError` is documented to hold no secrets either.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BindingError {
    /// A hex argument was not hexadecimal, or had an odd number of digits.
    NotHex(&'static str),
    /// A hex argument decoded to the wrong number of bytes.
    Length {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The sign mode was neither `direct` nor `amino`.
    Mode(String),
    /// The chain document and the chain id being signed for name different chains.
    ChainMismatch { document: String, requested: String },
    /// The transaction layer refused the payload: an unknown message type, a bad amount, a
    /// missing gas limit, an IBC transfer with no timeout.
    Cosmos(CosmosError),
    /// The kernel refused a mnemonic, a derivation or a signature.
    Kernel(KernelError),
    /// The chain registry document did not parse.
    Registry(RegistryError),
}

impl core::fmt::Display for BindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotHex(field) => write!(f, "{field} is not valid hex"),
            Self::Length {
                field,
                expected,
                actual,
            } => write!(f, "{field} must be {expected} bytes, got {actual}"),
            Self::Mode(mode) => {
                write!(f, "sign mode must be \"direct\" or \"amino\", got {mode:?}")
            }
            Self::ChainMismatch {
                document,
                requested,
            } => write!(
                f,
                "chain mismatch: the chain document is for {document:?} but the transaction \
                 signs for {requested:?}"
            ),
            Self::Cosmos(inner) => write!(f, "{inner}"),
            Self::Kernel(inner) => write!(f, "kernel: {inner}"),
            Self::Registry(inner) => write!(f, "chain: {inner}"),
        }
    }
}

impl core::error::Error for BindingError {}

impl From<CosmosError> for BindingError {
    fn from(value: CosmosError) -> Self {
        Self::Cosmos(value)
    }
}

impl From<KernelError> for BindingError {
    fn from(value: KernelError) -> Self {
        Self::Kernel(value)
    }
}

impl From<RegistryError> for BindingError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

type BindingResult<T> = core::result::Result<T, BindingError>;

fn decode_hex(field: &'static str, value: &str) -> BindingResult<Vec<u8>> {
    hex::decode(value.trim().trim_start_matches("0x")).map_err(|_| BindingError::NotHex(field))
}

fn decode_hex_exact(field: &'static str, value: &str, expected: usize) -> BindingResult<Vec<u8>> {
    let bytes = decode_hex(field, value)?;
    if bytes.len() != expected {
        return Err(BindingError::Length {
            field,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Parses the sign mode, relabelling the bridge's error so it names this argument.
///
/// `sign_mode_from_str` reports a bad mode as "sign document is invalid", which is true and
/// useless: the sign document has not been built yet.
fn parse_mode(mode: &str) -> BindingResult<SignMode> {
    sign_mode_from_str(mode).map_err(|_| BindingError::Mode(mode.to_owned()))
}

/// The wire spelling of a sign mode, the inverse of `sign_mode_from_str`.
fn mode_name(mode: SignMode) -> &'static str {
    match mode {
        SignMode::Direct => "direct",
        SignMode::LegacyAminoJson => "amino",
    }
}

/// Turns the binding's flat arguments into the two typed values `zunia_cosmos` signs over.
///
/// The public key is required to be 33 bytes here rather than at broadcast: an empty or
/// truncated key still encodes into a `SignerInfo`, and the chain's complaint about it arrives
/// as "unauthorized" long after the user approved a prompt that looked correct.
fn signing_request(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
) -> BindingResult<(UnsignedTx, SignerData)> {
    let msgs = msgs_from_json(msgs_json)?;
    let fee = fee_from_json(fee_json)?;
    let tx = UnsignedTx::new(msgs, fee, memo)?;
    let signer = SignerData {
        chain_id: chain_id.to_owned(),
        account_number,
        sequence,
        public_key: decode_hex_exact("public key", public_key_hex, PUBLIC_KEY_LEN)?,
        eth_key_type,
    };
    Ok((tx, signer))
}

/// The bytes the kernel must sign, hex encoded.
///
/// Pure: no key material is read and nothing is signed. `msgs_json` is the
/// `[{ typeUrl, value }]` array `@zunialab/interchain` emits, `fee_json` is
/// `{ amount: [{ denom, amount }], gas_limit }`, and `mode` is `"direct"` or `"amino"`.
///
/// The mode is not defaulted. Direct and Amino are two different documents rather than two
/// encodings of one, a Ledger signer requires Amino while a modern dApp expects Direct, and a
/// signature made over the wrong document verifies against nothing: on chain that surfaces as
/// an opaque "unauthorized" after the user has already approved.
#[wasm_bindgen]
pub fn build_sign_bytes(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
    mode: &str,
) -> Result<String, JsValue> {
    sign_bytes_hex(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
        mode,
    )
    .map_err(err)
}

fn sign_bytes_hex(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
    mode: &str,
) -> BindingResult<String> {
    let mode = parse_mode(mode)?;
    let (tx, signer) = signing_request(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
    )?;
    Ok(hex::encode(tx.sign_bytes(&signer, mode)?))
}

/// The broadcastable `TxRaw`, hex encoded, given a signature over [`build_sign_bytes`].
///
/// Every argument except `signature_hex` must be byte-for-byte what was passed to
/// [`build_sign_bytes`], `mode` included: the sign mode is encoded inside `auth_info`, so
/// attaching a Direct signature to Amino auth info produces a transaction whose signature
/// verifies against nothing. The signature is `r || s` with no recovery byte, which is why a
/// 65-byte Ethereum-style signature is refused rather than trimmed.
#[wasm_bindgen]
pub fn assemble_tx_raw(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
    mode: &str,
    signature_hex: &str,
) -> Result<String, JsValue> {
    tx_raw_hex(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
        mode,
        signature_hex,
    )
    .map_err(err)
}

fn tx_raw_hex(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
    mode: &str,
    signature_hex: &str,
) -> BindingResult<String> {
    let mode = parse_mode(mode)?;
    let signature = decode_hex_exact("signature", signature_hex, SIGNATURE_LEN)?;
    let (tx, signer) = signing_request(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
    )?;
    Ok(hex::encode(tx.into_tx_raw(&signer, mode, &signature)?))
}

/// A `TxRaw` for `POST /cosmos/tx/v1beta1/simulate`, hex encoded.
///
/// Carries the real public key, the real sequence and a 64-byte zero signature. Simulation
/// does not verify signatures, but it does decode the transaction and it does run the ante
/// handler's sequence check, so a placeholder key or a zero sequence returns a gas estimate for
/// a transaction the user is not about to send.
///
/// Always Direct: the sign mode only reaches the chain through `auth_info`, nothing verifies it
/// here, and the estimate does not depend on it.
#[wasm_bindgen]
pub fn build_simulate_tx(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
) -> Result<String, JsValue> {
    simulate_tx_hex(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
    )
    .map_err(err)
}

fn simulate_tx_hex(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
) -> BindingResult<String> {
    let (tx, signer) = signing_request(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
    )?;
    Ok(hex::encode(tx.into_tx_raw(
        &signer,
        SignMode::Direct,
        &SIMULATION_SIGNATURE,
    )?))
}

/// Derives, signs and assembles in one call. Returns the broadcastable `TxRaw`, hex encoded.
///
/// The public key and the `ethsecp256k1` key type are read from `chain_json` rather than taken
/// as arguments, so they cannot disagree with the account that actually signs.
///
/// Three refusals happen before anything is signed: the chain document must name the chain id
/// being signed for, every address must carry that chain's bech32 prefix, and the messages
/// must parse. Each of those is a transaction that would be broadcast and rejected, after the
/// user approved it, for a reason the chain reports as "unauthorized".
///
/// Key material lives for the length of this call and no longer. The mnemonic, the seed and the
/// derived extended key all zeroize on drop, none of them is returned, and no error message
/// carries any of them.
#[wasm_bindgen]
pub fn sign_tx(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    mode: &str,
) -> Result<String, JsValue> {
    signed_tx_hex(
        phrase,
        passphrase,
        chain_json,
        account_index,
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        mode,
    )
    .map_err(err)
}

fn signed_tx_hex(
    phrase: &str,
    passphrase: &str,
    chain_json: &str,
    account_index: u32,
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    mode: &str,
) -> BindingResult<String> {
    let mode = parse_mode(mode)?;
    let chain = ChainInfo::from_json(chain_json)?;
    if chain.chain_id != chain_id {
        return Err(BindingError::ChainMismatch {
            document: chain.chain_id,
            requested: chain_id.to_owned(),
        });
    }

    let tx = UnsignedTx::new(msgs_from_json(msgs_json)?, fee_from_json(fee_json)?, memo)?;
    // The prefix check is only possible here, where the chain is known. It is what stops a
    // transaction built for one chain from being signed against another chain's account.
    tx.validate(&chain.bech32.account)?;

    let account = derive_for_chain(phrase, passphrase, &chain, account_index)?;
    let signer = SignerData {
        chain_id: chain_id.to_owned(),
        account_number,
        sequence,
        public_key: account.public_key()?,
        // `eth-key-sign`, not `eth-address-gen`: the first decides which public key type the
        // transaction advertises, the second only decides how the address is derived, and a
        // chain can carry one without the other.
        eth_key_type: chain.uses_eth_key_sign(),
    };
    Ok(hex::encode(zunia_cosmos::sign_tx(
        &account, &tx, &signer, mode,
    )?))
}

/// What the approval screen shows, as a JSON string. Signs nothing.
///
/// Shape:
///
/// ```json
/// {
///   "chainId": "cosmoshub-4",
///   "mode": "direct",
///   "messages": [{ "typeUrl": "…", "summary": "Send 1000000 uatom to cosmos1…",
///                  "spendsFunds": true }],
///   "summaries": ["Send 1000000 uatom to cosmos1…"],
///   "fee": [{ "denom": "uatom", "amount": "5000" }],
///   "gasLimit": "200000",
///   "memo": "",
///   "spendsFunds": true,
///   "counterparties": ["cosmos1…"],
///   "signBytesHash": "…"
/// }
/// ```
///
/// `signBytesHash` is SHA-256 of the bytes [`build_sign_bytes`] returns for the same
/// arguments, so a prompt and a broadcast transaction can be compared after the fact. Every
/// summary is derived from the same parsed message the sign bytes are built from, which is what
/// keeps the screen from describing something other than what gets signed.
///
/// A JSON string rather than a JavaScript object: `serde_wasm_bindgen` renders a
/// `serde_json` object as a JS `Map`, not a plain object, and an approval screen reaching for
/// `preview.memo` would silently read `undefined`. `JSON.parse` gives the caller the same shape
/// the FFI binding returns.
#[wasm_bindgen]
pub fn preview_tx(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
    mode: &str,
) -> Result<String, JsValue> {
    preview_json(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
        mode,
    )
    .map_err(err)
}

fn preview_json(
    chain_id: &str,
    msgs_json: &str,
    fee_json: &str,
    memo: &str,
    account_number: u64,
    sequence: u64,
    public_key_hex: &str,
    eth_key_type: bool,
    mode: &str,
) -> BindingResult<String> {
    let mode = parse_mode(mode)?;
    let (tx, signer) = signing_request(
        chain_id,
        msgs_json,
        fee_json,
        memo,
        account_number,
        sequence,
        public_key_hex,
        eth_key_type,
    )?;
    let preview = tx.preview(&signer, mode)?;
    Ok(render_preview(&tx, &preview).to_string())
}

/// Renders a [`SigningPreview`] for the UI.
///
/// `gasLimit` is a string for the same reason every other `uint64` on this boundary is: a
/// JavaScript number above 2^53 has already lost precision, and a gas limit that is off by one
/// is a transaction the fee no longer covers.
fn render_preview(tx: &UnsignedTx, preview: &SigningPreview) -> serde_json::Value {
    let messages: Vec<serde_json::Value> = tx
        .msgs
        .iter()
        .zip(preview.summaries.iter())
        .map(|(msg, summary)| {
            serde_json::json!({
                "typeUrl": msg.type_url(),
                "summary": summary,
                "spendsFunds": msg.spends_funds(),
            })
        })
        .collect();

    serde_json::json!({
        "chainId": preview.chain_id,
        "mode": mode_name(preview.mode),
        "messages": messages,
        "summaries": preview.summaries,
        "fee": preview.fee.iter().map(coin_json).collect::<Vec<_>>(),
        "gasLimit": preview.gas_limit.to_string(),
        "memo": preview.memo,
        "spendsFunds": preview.spends_funds,
        "counterparties": preview.counterparties,
        "signBytesHash": preview.sign_bytes_hash,
    })
}

fn coin_json(coin: &Coin) -> serde_json::Value {
    serde_json::json!({ "denom": coin.denom, "amount": coin.amount })
}

/* -------------------------------------------------------------------------- *
 * EVM
 * -------------------------------------------------------------------------- */

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
    serde_wasm_bindgen::to_value(&out).map_err(err)
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
    serde_wasm_bindgen::to_value(&out).map_err(err)
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
        .and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
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
    let tx_type = value.get("type").and_then(|v| v.as_u64()).unwrap_or(2);
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
                                key.as_str().unwrap_or_default().trim_start_matches("0x"),
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

#[cfg(test)]
mod tests {
    //! Anchored to `tests/vectors/cosmos-signing.json`, the CosmJS reference.
    //!
    //! The exported `#[wasm_bindgen]` functions are plain Rust off the wasm target, but they
    //! return `JsValue` on failure and constructing one outside a JavaScript runtime aborts
    //! the process, so these tests drive the inner functions. That is the whole of the
    //! difference: the wrappers add `map_err(err)` and nothing else.
    //!
    //! Message payloads are hand-written proto-JSON rather than produced by
    //! `zunia_cosmos::json::msgs_to_json`, because that is the situation in production: the
    //! payload comes from `@zunialab/interchain`. Reconstructing it with the same code that
    //! parses it would prove only that the bridge is self-consistent.

    use super::*;
    use std::path::{Path, PathBuf};

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    /// The recipient the vector generator used. Not in the vector file's address table, which
    /// only holds addresses derived from the test key.
    const TO: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";

    /// The fee the generator used, in the shape a client sends it.
    const FEE: &str = r#"{"amount":[{"denom":"uatom","amount":"5000"}],"gas_limit":"200000"}"#;

    /// The one vector the JSON bridge deliberately refuses to rebuild: an IBC transfer with
    /// neither timeout can leave the tokens escrowed forever. See `zunia_cosmos::json`.
    const NO_TIMEOUT: &str = "msg_transfer_no_timeout";

    /// A chain document matching the key and addresses in the vector file: coin type 118,
    /// `cosmos` prefix, plain secp256k1.
    const COSMOS_HUB: &str = r#"{
        "chainId": "cosmoshub-4",
        "chainName": "Cosmos Hub",
        "rpc": "https://rpc.cosmos.example",
        "rest": "https://api.cosmos.example",
        "bip44": { "coinType": 118 },
        "bech32Config": {
            "bech32PrefixAccAddr": "cosmos",
            "bech32PrefixValAddr": "cosmosvaloper",
            "bech32PrefixConsAddr": "cosmosvalcons"
        },
        "currencies": [{ "coinDenom": "ATOM", "coinMinimalDenom": "uatom", "coinDecimals": 6 }],
        "feeCurrencies": [{ "coinDenom": "ATOM", "coinMinimalDenom": "uatom", "coinDecimals": 6 }],
        "stakeCurrency": { "coinDenom": "ATOM", "coinMinimalDenom": "uatom", "coinDecimals": 6 }
    }"#;

    fn vectors_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/cosmos-signing.json")
    }

    fn load() -> Value {
        let text = std::fs::read_to_string(vectors_path()).expect(
            "tests/vectors/cosmos-signing.json is missing; run \
             `cd tests/vectors/generate && pnpm install && pnpm generate`",
        );
        serde_json::from_str(&text).expect("vector file is not valid JSON")
    }

    fn str_at(value: &Value, path: &[&str]) -> String {
        let mut cursor = value;
        for key in path {
            cursor = &cursor[*key];
        }
        cursor
            .as_str()
            .unwrap_or_else(|| panic!("expected a string at {path:?}, got {cursor}"))
            .to_owned()
    }

    /// The `value` half of the envelope for one vector, written the way a client writes it.
    ///
    /// Deliberately duplicates the generator's inputs: a change to the generator that nobody
    /// mirrors here shows up as a failing byte comparison rather than passing silently.
    fn value_for(name: &str, addresses: &Value) -> Value {
        let from = str_at(addresses, &["cosmos"]);
        let valoper = str_at(addresses, &["cosmosvaloper"]);
        let safro = str_at(addresses, &["addr_safro"]);

        match name {
            "msg_send" => json!({
                "from_address": from,
                "to_address": TO,
                "amount": [{ "denom": "uatom", "amount": "1000000" }],
            }),
            "msg_send_with_memo" => json!({
                "from_address": from,
                "to_address": TO,
                "amount": [{ "denom": "uatom", "amount": "1" }],
            }),
            "msg_delegate" => json!({
                "delegator_address": from,
                "validator_address": valoper,
                "amount": { "denom": "uatom", "amount": "5000000" },
            }),
            "msg_undelegate" => json!({
                "delegator_address": from,
                "validator_address": valoper,
                "amount": { "denom": "uatom", "amount": "1000000" },
            }),
            "msg_begin_redelegate" => json!({
                "delegator_address": from,
                "validator_src_address": valoper,
                "validator_dst_address": valoper,
                "amount": { "denom": "uatom", "amount": "1000000" },
            }),
            "msg_withdraw_delegator_reward" => json!({
                "delegator_address": from,
                "validator_address": valoper,
            }),
            // The short vote spelling on purpose: dApps send all three forms, and the golden
            // bytes prove the permissive input still reaches the canonical enum value.
            "msg_vote" => json!({
                "proposal_id": "848",
                "voter": from,
                "option": "no_with_veto",
            }),
            "msg_transfer_no_timeout" => json!({
                "source_port": "transfer",
                "source_channel": "channel-141",
                "token": { "denom": "uatom", "amount": "1000000" },
                "sender": from,
                "receiver": safro,
                "timeout_height": { "revision_number": "0", "revision_height": "0" },
                "timeout_timestamp": "0",
                "memo": "",
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
            // Base64 of {"swap":{"offer":"100"}}, which is how interchain sends a contract
            // call. The bridge decodes it; the golden bytes prove the direction is right.
            "msg_execute_contract" => json!({
                "sender": from,
                "contract": TO,
                "msg": "eyJzd2FwIjp7Im9mZmVyIjoiMTAwIn19",
                "funds": [{ "denom": "uatom", "amount": "100" }],
            }),
            other => panic!(
                "vector \"{other}\" has no proto-JSON counterpart; add it to value_for or \
                 remove it from the generator"
            ),
        }
    }

    fn envelope_for(case: &Value, addresses: &Value) -> String {
        json!([{
            "typeUrl": str_at(case, &["type_url"]),
            "value": value_for(&str_at(case, &["name"]), addresses),
        }])
        .to_string()
    }

    struct Signer {
        chain_id: String,
        account_number: u64,
        sequence: u64,
        public_key_hex: String,
    }

    fn signer_from(vectors: &Value) -> Signer {
        Signer {
            chain_id: str_at(vectors, &["signer", "chain_id"]),
            account_number: vectors["signer"]["account_number"].as_u64().unwrap(),
            sequence: vectors["signer"]["sequence"].as_u64().unwrap(),
            public_key_hex: str_at(vectors, &["key", "pubkey_compressed_hex"]),
        }
    }

    fn case_named(vectors: &Value, name: &str) -> Value {
        vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == json!(name))
            .unwrap_or_else(|| panic!("vector {name} is missing"))
            .clone()
    }

    /// `body_bytes`, `auth_info_bytes` and the single signature out of a `TxRaw`.
    fn tx_raw_parts(raw_hex: &str) -> (String, String, Vec<u8>) {
        let raw = hex::decode(raw_hex).unwrap();
        let fields = zunia_cosmos::proto::decode_fields(&raw).unwrap();
        assert_eq!(fields.len(), 3, "TxRaw is body, auth_info and signatures");
        (
            hex::encode(
                zunia_cosmos::proto::find_field(&fields, 1)
                    .unwrap()
                    .as_bytes()
                    .unwrap(),
            ),
            hex::encode(
                zunia_cosmos::proto::find_field(&fields, 2)
                    .unwrap()
                    .as_bytes()
                    .unwrap(),
            ),
            zunia_cosmos::proto::find_field(&fields, 3)
                .unwrap()
                .as_bytes()
                .unwrap()
                .to_vec(),
        )
    }

    #[test]
    fn sign_bytes_match_cosmjs_for_every_message_type_in_both_modes() {
        // The assertion the whole binding exists for. If a message type, a vote option, an IBC
        // timeout or a base64 contract payload were mis-parsed on the way through, these bytes
        // diverge and every signature the extension produces verifies against nothing.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let mut checked = 0usize;

        for case in vectors["cases"].as_array().unwrap() {
            let name = str_at(case, &["name"]);
            if name == NO_TIMEOUT {
                continue;
            }
            let msgs = envelope_for(case, addresses);
            let memo = str_at(case, &["memo"]);

            for (mode, key) in [("direct", "direct"), ("amino", "amino")] {
                assert_eq!(
                    sign_bytes_hex(
                        &signer.chain_id,
                        &msgs,
                        FEE,
                        &memo,
                        signer.account_number,
                        signer.sequence,
                        &signer.public_key_hex,
                        false,
                        mode,
                    )
                    .unwrap(),
                    str_at(case, &[key, "sign_bytes_hex"]),
                    "{name}: {mode} sign bytes diverged from CosmJS"
                );
            }
            checked = checked.saturating_add(1);
        }

        assert!(
            checked >= 9,
            "expected the whole vector set minus {NO_TIMEOUT}, checked {checked}"
        );
    }

    #[test]
    fn sign_mode_is_case_insensitive_and_nothing_else_is_accepted() {
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let case = case_named(&vectors, "msg_send");
        let msgs = envelope_for(&case, addresses);

        let build = |mode: &str| {
            sign_bytes_hex(
                &signer.chain_id,
                &msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                mode,
            )
        };

        assert_eq!(
            build("DIRECT").unwrap(),
            str_at(&case, &["direct", "sign_bytes_hex"])
        );
        assert_eq!(
            build(" amino ").unwrap(),
            str_at(&case, &["amino", "sign_bytes_hex"])
        );
        // Not defaulted to Direct: a caller that meant Amino must not silently get the other
        // document.
        assert_eq!(build("").unwrap_err(), BindingError::Mode(String::new()));
        assert_eq!(
            build("SIGN_MODE_DIRECT").unwrap_err(),
            BindingError::Mode("SIGN_MODE_DIRECT".to_owned())
        );
    }

    #[test]
    fn the_no_timeout_transfer_is_refused_before_signing() {
        // The encoder can still produce this message, and golden_vectors.rs pins its bytes,
        // because a wallet must be able to display one that arrives from a dApp. The building
        // door is closed: an ICS-20 packet with no timeout of either kind never expires, so
        // the escrowed tokens are unrecoverable if no relayer delivers it.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let case = case_named(&vectors, NO_TIMEOUT);

        assert_eq!(
            sign_bytes_hex(
                &signer.chain_id,
                &envelope_for(&case, addresses),
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                "direct",
            )
            .unwrap_err(),
            BindingError::Cosmos(CosmosError::SignDoc)
        );
    }

    #[test]
    fn assembled_tx_raw_carries_the_golden_body_auth_info_and_the_signature_given() {
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let case = case_named(&vectors, "msg_send");
        let msgs = envelope_for(&case, addresses);
        let signature = [7u8; SIGNATURE_LEN];

        let raw = tx_raw_hex(
            &signer.chain_id,
            &msgs,
            FEE,
            "",
            signer.account_number,
            signer.sequence,
            &signer.public_key_hex,
            false,
            "direct",
            &hex::encode(signature),
        )
        .unwrap();

        let (body, auth_info, attached) = tx_raw_parts(&raw);
        assert_eq!(body, str_at(&case, &["direct", "body_bytes_hex"]));
        assert_eq!(
            auth_info,
            str_at(&case, &["direct", "auth_info_bytes_hex"]),
            "the auth_info in the broadcast must be the auth_info that was signed"
        );
        assert_eq!(attached, signature);
    }

    #[test]
    fn amino_and_direct_tx_raw_differ_in_auth_info() {
        // The sign mode is encoded inside auth_info, so assembling with the wrong one produces
        // a transaction whose signature verifies against nothing.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let msgs = envelope_for(&case_named(&vectors, "msg_send"), addresses);

        let assemble = |mode: &str| {
            tx_raw_hex(
                &signer.chain_id,
                &msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                mode,
                &hex::encode([1u8; SIGNATURE_LEN]),
            )
            .unwrap()
        };

        let (direct_body, direct_auth, _) = tx_raw_parts(&assemble("direct"));
        let (amino_body, amino_auth, _) = tx_raw_parts(&assemble("amino"));
        assert_eq!(direct_body, amino_body, "the body does not depend on mode");
        assert_ne!(direct_auth, amino_auth);
    }

    #[test]
    fn simulate_tx_carries_the_real_signer_and_a_zero_signature() {
        // The simulate endpoint does not verify the signature but does decode the transaction
        // and check the sequence, so the auth_info has to be the real one.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let case = case_named(&vectors, "msg_send");

        let raw = simulate_tx_hex(
            &signer.chain_id,
            &envelope_for(&case, addresses),
            FEE,
            "",
            signer.account_number,
            signer.sequence,
            &signer.public_key_hex,
            false,
        )
        .unwrap();

        let (body, auth_info, signature) = tx_raw_parts(&raw);
        assert_eq!(body, str_at(&case, &["direct", "body_bytes_hex"]));
        assert_eq!(auth_info, str_at(&case, &["direct", "auth_info_bytes_hex"]));
        assert_eq!(signature, vec![0u8; SIGNATURE_LEN]);
    }

    #[test]
    fn preview_describes_the_bytes_that_will_be_signed() {
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let case = case_named(&vectors, "msg_send");
        let msgs = envelope_for(&case, addresses);

        let rendered = preview_json(
            &signer.chain_id,
            &msgs,
            FEE,
            "note",
            signer.account_number,
            signer.sequence,
            &signer.public_key_hex,
            false,
            "direct",
        )
        .unwrap();
        let preview: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(preview["chainId"], json!("cosmoshub-4"));
        assert_eq!(preview["mode"], json!("direct"));
        assert_eq!(preview["memo"], json!("note"));
        assert_eq!(preview["gasLimit"], json!("200000"));
        assert_eq!(preview["spendsFunds"], json!(true));
        assert_eq!(
            preview["fee"],
            json!([{ "denom": "uatom", "amount": "5000" }])
        );
        assert_eq!(preview["messages"].as_array().unwrap().len(), 1);
        assert_eq!(
            preview["messages"][0]["typeUrl"],
            json!("/cosmos.bank.v1beta1.MsgSend")
        );
        assert!(preview["messages"][0]["summary"]
            .as_str()
            .unwrap()
            .starts_with("Send 1000000 uatom"));
        assert_eq!(preview["summaries"][0], preview["messages"][0]["summary"]);
        assert!(preview["counterparties"]
            .as_array()
            .unwrap()
            .contains(&json!(TO)));

        // The hash is of the bytes the caller will actually sign, which is the only thing that
        // makes a prompt comparable to a broadcast transaction after the fact.
        let sign_bytes = sign_bytes_hex(
            &signer.chain_id,
            &msgs,
            FEE,
            "note",
            signer.account_number,
            signer.sequence,
            &signer.public_key_hex,
            false,
            "direct",
        )
        .unwrap();
        assert_eq!(
            preview["signBytesHash"],
            json!(hex::encode(Sha256::digest(
                hex::decode(&sign_bytes).unwrap()
            )))
        );
    }

    #[test]
    fn preview_mode_names_round_trip_through_the_bridge() {
        // The name the preview shows must be the name build_sign_bytes accepts, or an approval
        // screen and the signature it authorises can describe different documents.
        for mode in ["direct", "amino"] {
            assert_eq!(mode_name(parse_mode(mode).unwrap()), mode);
        }
    }

    #[test]
    fn preview_of_a_vote_spends_nothing() {
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);

        let rendered = preview_json(
            &signer.chain_id,
            &envelope_for(&case_named(&vectors, "msg_vote"), addresses),
            FEE,
            "",
            signer.account_number,
            signer.sequence,
            &signer.public_key_hex,
            false,
            "amino",
        )
        .unwrap();
        let preview: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(preview["mode"], json!("amino"));
        assert_eq!(preview["spendsFunds"], json!(false));
        assert_eq!(preview["messages"][0]["spendsFunds"], json!(false));
        assert!(preview["summaries"][0]
            .as_str()
            .unwrap()
            .contains("proposal 848"));
    }

    #[test]
    fn sign_tx_produces_a_transaction_whose_signature_verifies_against_the_golden_bytes() {
        // End to end: derive, sign, assemble. The body and auth_info must be the CosmJS bytes,
        // and the signature must verify against the CosmJS sign bytes. Anything less would
        // pass while producing an "unauthorized" on chain.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let phrase = str_at(&vectors, &["key", "mnemonic"]);

        for name in ["msg_send", "msg_delegate", "msg_execute_contract"] {
            let case = case_named(&vectors, name);
            let msgs = envelope_for(&case, addresses);
            let memo = str_at(&case, &["memo"]);

            for (mode, key) in [("direct", "direct"), ("amino", "amino")] {
                let raw = signed_tx_hex(
                    &phrase,
                    "",
                    COSMOS_HUB,
                    0,
                    &signer.chain_id,
                    &msgs,
                    FEE,
                    &memo,
                    signer.account_number,
                    signer.sequence,
                    mode,
                )
                .unwrap();

                let (body, auth_info, signature) = tx_raw_parts(&raw);
                assert_eq!(body, str_at(&case, &["direct", "body_bytes_hex"]));
                if mode == "direct" {
                    assert_eq!(auth_info, str_at(&case, &["direct", "auth_info_bytes_hex"]));
                }
                assert_eq!(signature.len(), SIGNATURE_LEN);

                let sign_bytes = hex::decode(str_at(&case, &[key, "sign_bytes_hex"])).unwrap();
                let digest: [u8; 32] = Sha256::digest(&sign_bytes).into();
                assert!(
                    zunia_kernel::verify_digest_secp256k1(
                        &hex::decode(&signer.public_key_hex).unwrap(),
                        &digest,
                        &signature,
                    )
                    .unwrap(),
                    "{name}/{mode}: the signature does not verify against the CosmJS sign bytes"
                );
            }
        }
    }

    #[test]
    fn sign_tx_derives_the_account_the_vectors_describe() {
        // If the derivation drifted, the transaction would be signed by a key that does not
        // own the addresses inside it, which the chain reports only as "unauthorized".
        let vectors = load();
        let phrase = str_at(&vectors, &["key", "mnemonic"]);
        let account = derive_account(&phrase, "", COSMOS_HUB, 0).unwrap();

        assert_eq!(
            account.address().unwrap(),
            str_at(&vectors, &["key", "addresses", "cosmos"])
        );
        assert_eq!(
            hex::encode(account.public_key().unwrap()),
            str_at(&vectors, &["key", "pubkey_compressed_hex"])
        );
    }

    #[test]
    fn sign_tx_refuses_a_chain_document_for_a_different_chain() {
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let phrase = str_at(&vectors, &["key", "mnemonic"]);

        let failure = signed_tx_hex(
            &phrase,
            "",
            COSMOS_HUB,
            0,
            "cosmoshub-3",
            &envelope_for(&case_named(&vectors, "msg_send"), addresses),
            FEE,
            "",
            signer.account_number,
            signer.sequence,
            "direct",
        )
        .unwrap_err();

        assert_eq!(
            failure,
            BindingError::ChainMismatch {
                document: "cosmoshub-4".to_owned(),
                requested: "cosmoshub-3".to_owned(),
            }
        );
    }

    #[test]
    fn sign_tx_refuses_addresses_from_another_chain() {
        // A send to an osmo address on the Hub is a transaction the chain will reject after
        // the user has approved it, so it is refused before the key is even derived.
        let vectors = load();
        let signer = signer_from(&vectors);
        let phrase = str_at(&vectors, &["key", "mnemonic"]);
        let msgs = json!([{
            "typeUrl": "/cosmos.bank.v1beta1.MsgSend",
            "value": {
                "from_address": str_at(&vectors, &["key", "addresses", "cosmos"]),
                "to_address": str_at(&vectors, &["key", "addresses", "osmo"]),
                "amount": [{ "denom": "uatom", "amount": "1" }],
            },
        }])
        .to_string();

        assert_eq!(
            signed_tx_hex(
                &phrase,
                "",
                COSMOS_HUB,
                0,
                &signer.chain_id,
                &msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                "direct",
            )
            .unwrap_err(),
            BindingError::Cosmos(CosmosError::Address)
        );
    }

    #[test]
    fn sign_tx_never_puts_the_mnemonic_in_an_error() {
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let phrase = "abandon abandon abandon";

        let message = signed_tx_hex(
            phrase,
            "",
            COSMOS_HUB,
            0,
            &signer.chain_id,
            &envelope_for(&case_named(&vectors, "msg_send"), addresses),
            FEE,
            "",
            signer.account_number,
            signer.sequence,
            "direct",
        )
        .unwrap_err()
        .to_string();

        assert!(!message.contains("abandon"), "{message}");
        assert!(message.starts_with("kernel: "), "{message}");
    }

    #[test]
    fn errors_name_the_argument_that_was_wrong() {
        // The property an integrator depends on: nine string arguments, and the message says
        // which one to look at.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let msgs = envelope_for(&case_named(&vectors, "msg_send"), addresses);

        let sign_bytes = |msgs: &str, fee: &str, pubkey: &str| {
            sign_bytes_hex(
                &signer.chain_id,
                msgs,
                fee,
                "",
                signer.account_number,
                signer.sequence,
                pubkey,
                false,
                "direct",
            )
        };

        let unknown =
            json!([{ "typeUrl": "/cosmos.nonsense.v1.MsgThing", "value": {} }]).to_string();
        assert_eq!(
            sign_bytes(&unknown, FEE, &signer.public_key_hex)
                .unwrap_err()
                .to_string(),
            "cannot decode message type /cosmos.nonsense.v1.MsgThing"
        );

        assert_eq!(
            sign_bytes(&msgs, r#"{"amount":[]}"#, &signer.public_key_hex)
                .unwrap_err()
                .to_string(),
            "fee or gas limit is invalid"
        );

        assert_eq!(
            sign_bytes(&msgs, FEE, "zz").unwrap_err().to_string(),
            "public key is not valid hex"
        );
        assert_eq!(
            sign_bytes(&msgs, FEE, "00ff").unwrap_err().to_string(),
            "public key must be 33 bytes, got 2"
        );

        // A bad signature must be distinguishable from all of the above, and from a bad
        // sign document, which is what into_tx_raw alone would have reported.
        let assemble = |signature: &str| {
            tx_raw_hex(
                &signer.chain_id,
                &msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                "direct",
                signature,
            )
            .unwrap_err()
            .to_string()
        };
        assert_eq!(assemble("not-a-signature"), "signature is not valid hex");
        assert_eq!(
            assemble(&hex::encode([0u8; 65])),
            "signature must be 64 bytes, got 65"
        );

        assert_eq!(
            preview_json(
                &signer.chain_id,
                &msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                "quick",
            )
            .unwrap_err()
            .to_string(),
            "sign mode must be \"direct\" or \"amino\", got \"quick\""
        );
    }

    #[test]
    fn an_empty_or_oversized_message_list_is_refused() {
        let vectors = load();
        let signer = signer_from(&vectors);
        let build = |msgs: &str| {
            sign_bytes_hex(
                &signer.chain_id,
                msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                "direct",
            )
            .unwrap_err()
        };

        // A transaction with no messages pays a fee to do nothing.
        assert_eq!(build("[]"), BindingError::Cosmos(CosmosError::SignDoc));
        assert_eq!(build("{}"), BindingError::Cosmos(CosmosError::Decode));
        assert_eq!(build("not json"), BindingError::Cosmos(CosmosError::Decode));
    }

    #[test]
    fn the_deprecated_bank_send_export_agrees_with_the_general_path() {
        // build_bank_send_direct stays supported, so it must not drift from the path that
        // replaces it. Its Ok branch builds no JsValue, so it is callable in a native test.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let case = case_named(&vectors, "msg_send");
        let from = str_at(addresses, &["cosmos"]);

        let legacy = build_bank_send_direct(
            &signer.chain_id,
            &from,
            TO,
            "1000000",
            "uatom",
            "",
            signer.account_number,
            signer.sequence,
            "5000",
            "uatom",
            200_000,
            &signer.public_key_hex,
            false,
        )
        .unwrap();

        assert_eq!(legacy, str_at(&case, &["direct", "sign_bytes_hex"]));
        assert_eq!(
            legacy,
            sign_bytes_hex(
                &signer.chain_id,
                &envelope_for(&case, addresses),
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                false,
                "direct",
            )
            .unwrap()
        );
    }

    #[test]
    fn ethermint_signers_change_the_bytes() {
        // eth_key_type reaches the sign document through the public key's type URL. If the
        // flag were dropped, an Injective transaction would be signed as plain secp256k1 and
        // rejected on chain.
        let vectors = load();
        let addresses = &vectors["key"]["addresses"];
        let signer = signer_from(&vectors);
        let msgs = envelope_for(&case_named(&vectors, "msg_send"), addresses);

        let build = |eth: bool| {
            sign_bytes_hex(
                &signer.chain_id,
                &msgs,
                FEE,
                "",
                signer.account_number,
                signer.sequence,
                &signer.public_key_hex,
                eth,
                "direct",
            )
            .unwrap()
        };
        assert_ne!(build(true), build(false));
    }
}
