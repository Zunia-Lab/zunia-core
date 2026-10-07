//! Property assertions for the parsers that read hostile input.
//!
//! Each function takes arbitrary bytes, feeds them to a parser, and asserts what must hold if
//! the parser accepted them. Rejection is always a valid outcome; the assertions constrain
//! success. Every function is total: no input should make it panic, and a panic is the bug the
//! caller is looking for.
//!
//! # Why this is a separate crate
//!
//! The same assertions are used two ways. `fuzz/` calls them from libFuzzer targets, which
//! needs a nightly toolchain and a long time budget. `tests/corpus_replay.rs` calls them over
//! the committed corpus on stable in ordinary CI, which is fast and catches regressions on
//! crashes that were already found once.
//!
//! Keeping them here rather than duplicating them means a property cannot drift between the two
//! callers, and keeps fuzzing scaffolding out of the crates that actually ship.
//!
//! Not published: this is test infrastructure.

use zunia_cosmos::proto::{decode_fields, find_all, find_field, Field};
use zunia_cosmos::{decode_direct_sign_doc, DecodedMsg, DecodedTx};
use zunia_kernel::{
    convert_prefix, decode_bech32, validate_address, validate_eth_address, AddressScheme,
    KeyringEnvelope,
};
use zunia_registry::ChainInfo;

/// Properties of the `SIGN_MODE_DIRECT` decoder.
///
/// The bytes come from a website via `signDirect`, and the result is what the signing prompt
/// renders. The decoder is allowed to fail, and allowed to report a message as unknown. It is
/// not allowed to crash, and it is not allowed to describe a message it did not understand,
/// because the user approves based on what the prompt says.
pub fn check_tx_decoder(data: &[u8]) {
    let Ok(decoded) = decode_direct_sign_doc(data) else {
        return;
    };

    // The prompt has no fallback rendering, so a message with no summary would appear as blank
    // space above an approve button.
    let summaries = decoded.summaries();
    assert_eq!(
        summaries.len(),
        decoded.msgs.len(),
        "every message must produce exactly one summary"
    );
    for summary in &summaries {
        assert!(!summary.is_empty(), "a decoded message produced no summary");
    }

    // `has_unknown_msgs` drives the blind-signing warning. If it were false while an unknown
    // message was present, the prompt would confidently describe a transaction nobody read.
    let any_unknown = decoded.msgs.iter().any(|m| m.is_unknown());
    assert_eq!(
        decoded.has_unknown_msgs, any_unknown,
        "the unknown-message flag disagrees with the decoded messages"
    );
    assert_eq!(
        decoded.is_safe_to_sign_without_blind_signing(),
        !any_unknown,
        "the blind-signing gate disagrees with the unknown-message flag"
    );

    if decoded.msgs.is_empty() {
        assert!(
            !decoded.is_safe_to_sign_without_blind_signing(),
            "a transaction with no messages must not be presented as safe to sign"
        );
    }

    // The prompt highlights first-time recipients by string comparison and the user compares the
    // rendered address by eye against one from elsewhere. Both break if the string contains
    // anything that does not render as itself: a NUL truncates it, a bidirectional override
    // reorders it, whitespace hides a difference. Every Cosmos address format in use is printable
    // ASCII, so nothing legitimate is excluded by requiring exactly that.
    for msg in &decoded.msgs {
        for address in msg.addresses() {
            assert!(!address.is_empty(), "an empty address reached the UI");
            for byte in address.bytes() {
                assert!(
                    (0x21..=0x7e).contains(&byte),
                    "an address containing byte {byte:#04x} reached the UI: {address:?}"
                );
            }
        }
    }

    // A contract call is described by its action, the top-level key of its message, which the
    // prompt quotes and nothing on chain checks. A key that does not render as itself rewrites
    // the sentence around it: a bidirectional override reorders the contract and the coins, a
    // line separator breaks the sentence in two, and a quote ends the action early and passes
    // the rest off as the wallet's words. So an understood contract call names an action of
    // printable ASCII with no space and no quote.
    for msg in &decoded.msgs {
        if let DecodedMsg::ExecuteContract { action, .. } = msg {
            let action = action
                .as_deref()
                .expect("an understood contract call reached the UI without an action");
            assert!(
                !action.is_empty()
                    && action
                        .bytes()
                        .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'"'),
                "a contract action that does not render as itself reached the UI: {action:?}"
            );
        }
    }

    // The chain reads the last occurrence of a singular protobuf field. A decoder that read the
    // first could show one recipient, fee or message type while the chain executed another, so
    // a document the decoder accepted has no singular field written twice in its envelope, and a
    // message it calls understood has none in its own fields or its coins.
    assert_no_repeated_singular_fields(data, &decoded);
}

/// Whether any field number in `singular` occurs more than once in `fields`.
fn repeats_any(fields: &[Field], singular: &[u32]) -> bool {
    singular
        .iter()
        .any(|tag| fields.iter().filter(|field| field.tag == *tag).count() > 1)
}

/// The singular fields of each message the decoder can describe, by proto field number.
///
/// Written out from the protos rather than taken from the decoder, so that this property checks
/// the decoder instead of restating it. Repeated fields (a send's coins, a contract call's funds,
/// a swap's routes) are not listed.
fn message_singular_fields(type_url: &str) -> &'static [u32] {
    match type_url {
        "/cosmos.bank.v1beta1.MsgSend"
        | "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward" => &[1, 2],
        "/cosmos.staking.v1beta1.MsgDelegate"
        | "/cosmos.staking.v1beta1.MsgUndelegate"
        | "/cosmwasm.wasm.v1.MsgExecuteContract" => &[1, 2, 3],
        "/cosmos.staking.v1beta1.MsgBeginRedelegate" => &[1, 2, 3, 4],
        // gov v1 adds metadata at 4; v1beta1 has no field 4 at all.
        "/cosmos.gov.v1beta1.MsgVote" | "/cosmos.gov.v1.MsgVote" => &[1, 2, 3, 4],
        "/ibc.applications.transfer.v1.MsgTransfer" => &[1, 2, 3, 4, 5, 6, 7, 8],
        "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn"
        | "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn" => &[1, 3, 4],
        _ => &[],
    }
}

/// The fields of each message that hold a `cosmos.base.v1beta1.Coin`, singular or repeated.
fn message_coin_fields(type_url: &str) -> &'static [u32] {
    match type_url {
        "/cosmos.bank.v1beta1.MsgSend"
        | "/cosmos.staking.v1beta1.MsgDelegate"
        | "/cosmos.staking.v1beta1.MsgUndelegate"
        | "/ibc.applications.transfer.v1.MsgTransfer"
        | "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn" => &[3],
        "/cosmos.staking.v1beta1.MsgBeginRedelegate" => &[4],
        "/cosmwasm.wasm.v1.MsgExecuteContract" => &[5],
        _ => &[],
    }
}

fn assert_no_repeated_singular_fields(data: &[u8], decoded: &DecodedTx) {
    let parse = |bytes: &[u8], what: &str| -> Vec<Field> {
        decode_fields(bytes)
            .unwrap_or_else(|_| panic!("the decoder accepted a {what} that does not parse"))
    };
    let embedded = |fields: &[Field], tag: u32| -> Vec<Vec<u8>> {
        find_all(fields, tag)
            .into_iter()
            .filter_map(|value| value.as_bytes().ok().map(<[u8]>::to_vec))
            .collect()
    };

    // SignDoc, TxBody, AuthInfo, every SignerInfo, the Fee and its coins, every Any.
    let doc = parse(data, "SignDoc");
    assert!(
        !repeats_any(&doc, &[1, 2, 3, 4]),
        "accepted a SignDoc with a singular field written twice"
    );
    let (Some(body), Some(auth_info)) = (embedded(&doc, 1).pop(), embedded(&doc, 2).pop()) else {
        panic!("the decoder accepted a SignDoc without a body or an auth info");
    };
    let body = parse(&body, "TxBody");
    assert!(
        !repeats_any(&body, &[2, 3, 4, 5]),
        "accepted a TxBody with a singular field written twice"
    );
    let auth_info = parse(&auth_info, "AuthInfo");
    assert!(
        !repeats_any(&auth_info, &[2, 3]),
        "accepted an AuthInfo with a singular field written twice"
    );
    for signer_info in embedded(&auth_info, 1) {
        assert!(
            !repeats_any(&parse(&signer_info, "SignerInfo"), &[1, 2, 3]),
            "accepted a SignerInfo with a singular field written twice"
        );
    }
    for fee in embedded(&auth_info, 2) {
        let fee = parse(&fee, "Fee");
        assert!(
            !repeats_any(&fee, &[2, 3, 4]),
            "accepted a Fee with a singular field written twice"
        );
        for coin in embedded(&fee, 1) {
            assert!(
                !repeats_any(&parse(&coin, "fee coin"), &[1, 2]),
                "accepted a fee coin with two denoms or two amounts"
            );
        }
    }

    let anys = embedded(&body, 1);
    assert_eq!(
        anys.len(),
        decoded.msgs.len(),
        "every Any in the body must become exactly one decoded message"
    );
    for (any, msg) in anys.iter().zip(&decoded.msgs) {
        let any = parse(any, "Any");
        assert!(
            !repeats_any(&any, &[1, 2]),
            "accepted an Any with two type URLs or two values"
        );
        if msg.is_unknown() {
            continue;
        }
        // Each field occurs at most once now, so the first occurrence is the only one.
        let type_url = find_field(&any, 1)
            .and_then(|value| value.as_string().ok())
            .unwrap_or_default();
        let value = find_field(&any, 2)
            .and_then(|value| value.as_bytes().ok())
            .unwrap_or_default();
        let fields = parse(value, "message body");
        assert!(
            !repeats_any(&fields, message_singular_fields(&type_url)),
            "described {type_url} as understood although one of its singular fields is written \
             twice"
        );
        for &tag in message_coin_fields(&type_url) {
            for coin in embedded(&fields, tag) {
                assert!(
                    !repeats_any(&parse(&coin, "coin"), &[1, 2]),
                    "described {type_url} as understood although a coin in it has two denoms or \
                     two amounts"
                );
            }
        }
    }
}

/// Properties of the chain registry parser.
///
/// Descriptors are community-submitted and reach users through the registry mirror. Anything
/// `from_json` accepts has passed `validate`, which means the signing path will treat it as
/// usable, so it must actually be usable: derivable address, payable fee, contactable endpoint.
pub fn check_registry_parser(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(chain) = ChainInfo::from_json(text) else {
        return;
    };

    assert!(
        !chain.chain_id.trim().is_empty(),
        "accepted a descriptor with an empty chain id"
    );
    assert!(
        !chain.bech32.account.is_empty(),
        "accepted a descriptor with no account prefix"
    );

    // A prefix that is not a valid human-readable part makes every address on the chain
    // unrenderable, and mixed case silently fails prefix comparison against the registry.
    assert!(
        chain
            .bech32
            .account
            .bytes()
            .all(|b| (33..=126).contains(&b) && !b.is_ascii_uppercase()),
        "accepted a prefix that is not a valid bech32 HRP: {:?}",
        chain.bech32.account
    );

    // No payable fee currency means the user can build transactions that can never broadcast.
    let fee = chain.primary_fee_currency();
    assert!(
        !fee.minimal_denom.is_empty(),
        "accepted a fee currency with no denomination"
    );

    // The scheme must come from the feature flag, not from the coin type. Several chains use
    // coin type 60 for Ledger compatibility while keeping Cosmos addresses, and treating those
    // as Ethermint derives an address that belongs to nobody.
    let scheme = chain.address_scheme();
    assert_eq!(
        scheme == AddressScheme::Ethermint,
        chain.has_feature("eth-address-gen"),
        "the address scheme was decided by something other than eth-address-gen"
    );

    for endpoint in [&chain.rpc, &chain.rest] {
        assert!(
            endpoint.starts_with("https://")
                || endpoint.starts_with("http://localhost")
                || endpoint.starts_with("http://127.0.0.1")
                || endpoint.starts_with("http://0.0.0.0"),
            "accepted a non-https endpoint, which leaks every address the user queries: \
             {endpoint:?}"
        );
    }

    // Decimal lookup formats every amount the user sees, so it has to be total.
    let _ = chain.decimals_for_denom(&fee.minimal_denom);
    let _ = chain.decimals_for_denom("");
    let _ = chain.decimals_for_denom("\u{0}not-a-denom");
}

/// Properties of address decoding, validation and prefix conversion.
///
/// Addresses arrive by paste, by QR scan, and from dApp requests. The property that matters is
/// round-tripping: if decode and re-encode disagree, the wallet can display one address while
/// sending to another.
pub fn check_address_parser(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(account) = validate_eth_address(text) {
        let canonical = account.to_eth_hex();
        assert!(canonical.starts_with("0x"));
        let reparsed = validate_eth_address(&canonical)
            .expect("the canonical EIP-55 form of an accepted address must itself be accepted");
        assert_eq!(
            reparsed.as_bytes(),
            account.as_bytes(),
            "hex address did not round-trip"
        );
    }

    let Ok(decoded) = decode_bech32(text) else {
        return;
    };

    // Prefixes are compared against the registry by equality, so a non-lowercase result would
    // silently fail to match the chain it belongs to.
    assert_eq!(
        decoded.prefix,
        decoded.prefix.to_lowercase(),
        "decode produced a prefix that is not lowercase"
    );
    assert!(!decoded.prefix.is_empty());

    // Re-encoding need not reproduce the input string, since bech32 permits uppercase input,
    // but it must reproduce the account.
    let re_encoded = decoded
        .account
        .to_bech32(&decoded.prefix)
        .expect("an accepted address must be re-encodable under its own prefix");
    let round_tripped = decode_bech32(&re_encoded).expect("a re-encoded address must decode again");
    assert_eq!(
        round_tripped.account.as_bytes(),
        decoded.account.as_bytes(),
        "bech32 round trip changed the account"
    );
    assert_eq!(round_tripped.prefix, decoded.prefix);

    // Sending to a valid address on the wrong chain is unrecoverable, so prefix checking has to
    // be exact rather than advisory.
    validate_address(&re_encoded, &decoded.prefix)
        .expect("an address must validate against its own prefix");
    let other = if decoded.prefix == "cosmos" {
        "osmo"
    } else {
        "cosmos"
    };
    assert!(
        validate_address(&re_encoded, other).is_err(),
        "an address validated against a prefix that is not its own"
    );

    if let Ok(converted) = convert_prefix(&re_encoded, "osmo") {
        let converted = decode_bech32(&converted).expect("a converted address must decode");
        assert_eq!(converted.prefix, "osmo");
        assert_eq!(
            converted.account.as_bytes(),
            decoded.account.as_bytes(),
            "prefix conversion changed the account"
        );
    }
}

/// Properties of keyring envelope deserialisation.
///
/// The envelope is read from `chrome.storage.local` or the mobile document directory, both
/// writable by anything with local access. A malformed envelope must produce an error the UI
/// can show, never a panic that stops the wallet starting, and never a successful open.
///
/// Does not attempt a successful decryption: reaching one by mutation is vanishingly unlikely
/// and Argon2id makes each attempt slow enough to ruin throughput. The success path is covered
/// by the pinned fixture in `crates/kernel/tests/keyring_envelope.rs`.
pub fn check_keyring_envelope(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(envelope) = KeyringEnvelope::from_json(text) else {
        return;
    };

    assert!(!envelope.kdf.is_empty());
    assert!(!envelope.aead.is_empty());

    // The envelope is rewritten on every metadata change, so an asymmetry between write and
    // read would corrupt a working wallet.
    if let Ok(json) = envelope.to_json() {
        let reparsed = KeyringEnvelope::from_json(&json)
            .expect("an envelope this build produced must be one it can read");
        assert_eq!(reparsed.version, envelope.version);
        assert_eq!(reparsed.kdf, envelope.kdf);
        assert_eq!(reparsed.aead, envelope.aead);
        assert_eq!(reparsed.params, envelope.params);
        assert_eq!(reparsed.salt, envelope.salt);
        assert_eq!(reparsed.nonce, envelope.nonce);
        assert_eq!(reparsed.ciphertext, envelope.ciphertext);
        assert_eq!(reparsed.metadata, envelope.metadata);
    }

    // Only attempted for cheap parameters, so neither the fuzzer nor CI spends its budget
    // inside Argon2id.
    if envelope.params.memory_kib <= 19_456 && envelope.params.iterations <= 3 {
        assert!(
            envelope.open("\u{0}not-the-password").is_err(),
            "an envelope opened with a password that cannot be correct"
        );
    }
}

/// Properties of the EIP-712 typed-data parser.
///
/// The document comes straight from a website via `eth_signTypedData_v4` and the wallet is about
/// to hash it and sign. The only thing standing between a user and an arbitrary signature is that
/// the prompt shows the same structure that gets hashed, so anything the parser accepts must be
/// something it can encode, and encoding must be deterministic. Accepting a document whose
/// signing hash cannot be computed would leave the prompt with something to display and nothing
/// to sign, or worse, display one thing and sign another after a retry.
pub fn check_eip712_parser(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(typed) = zunia_evm::TypedData::from_json(text) else {
        return;
    };

    // A document that parses but cannot be hashed is the worst outcome: the prompt renders it and
    // the signature never comes. Rejecting at parse time is fine; rejecting later is not.
    let hash = typed
        .signing_hash()
        .expect("a document that parsed must be hashable");

    assert_eq!(
        hash,
        typed.signing_hash().expect("hashing must be repeatable"),
        "the signing hash is not deterministic"
    );

    // The domain separator and the struct hash both feed the digest, so both must be reachable.
    let _ = typed
        .domain_separator()
        .expect("a parsed document must have a domain separator");
    let encoded = typed
        .encode_type(&typed.primary_type)
        .expect("a parsed document must have an encodable primary type");

    // The type string is what a careful user reads to decide whether the payload is a permit or a
    // transfer. Control characters would let a document hide the difference.
    assert!(
        !encoded.contains('\0'),
        "an encoded type containing a NUL byte reached the UI: {encoded:?}"
    );
    assert!(
        encoded.starts_with(&typed.primary_type),
        "the encoded type does not begin with the primary type it claims to describe"
    );

    assert!(
        !typed.primary_type.is_empty(),
        "accepted a document with an empty primary type"
    );
}

/// Properties of the Solana message parser.
///
/// A dApp can hand over a serialised message and ask for a signature. Privileges in a Solana
/// message are positional, so a parser that accepted an inconsistent header would let the prompt
/// attribute "read-only" to an account the transaction can drain.
#[cfg(feature = "solana")]
pub fn check_svm_message_parser(data: &[u8]) {
    let Ok(message) = zunia_svm::Message::parse(data) else {
        return;
    };

    // Serialising what we parsed must give back what we were given. Otherwise the bytes the user
    // approved and the bytes we sign are different documents.
    let re_serialised = message
        .serialize()
        .expect("a parsed message must be serialisable");
    assert_eq!(
        re_serialised, data,
        "a parsed message did not re-serialise to its input"
    );

    // Validation ran during parse, so these must already hold.
    assert!(
        message.header.num_required_signatures >= 1,
        "accepted a message nobody can sign"
    );
    assert!(
        usize::from(message.header.num_required_signatures) <= message.account_keys.len(),
        "accepted a message claiming more signers than it has accounts"
    );

    // The fee payer is index 0 and pays, so it must be both a signer and writable. If it were
    // not, the prompt would show a fee coming out of an account that cannot be debited.
    assert!(message.is_signer(0), "the fee payer does not sign");
    assert!(message.is_writable(0), "the fee payer is not writable");

    for instruction in &message.instructions {
        assert!(
            usize::from(instruction.program_id_index) < message.account_keys.len(),
            "an instruction names a program outside the account table"
        );
        for index in &instruction.accounts {
            assert!(
                usize::from(*index) < message.account_keys.len(),
                "an instruction names an account outside the table"
            );
        }
    }

    // The summary is what the prompt renders, so it must be total and must not overstate.
    let summary = zunia_svm::summarize(&message);
    assert_eq!(
        summary.instructions.len(),
        message.instructions.len(),
        "the summary dropped or invented an instruction"
    );
    assert_eq!(
        summary.fee_payer,
        *message
            .fee_payer()
            .expect("a validated message has a fee payer"),
        "the summary named the wrong fee payer"
    );

    // Any account the summary calls writable must be writable per the header, or the prompt
    // understates what the transaction can touch.
    for account in &summary.writable_accounts {
        let index = message
            .account_keys
            .iter()
            .position(|key| key == account)
            .expect("the summary invented an account");
        assert!(
            message.is_writable(index),
            "the summary called a read-only account writable"
        );
    }

    // A decoded transfer must be backed by a system-program instruction, never inferred.
    for entry in &summary.instructions {
        if let zunia_svm::InstructionSummary::Transfer { .. } = entry {
            assert!(
                message
                    .account_keys
                    .contains(&zunia_svm::Pubkey::SYSTEM_PROGRAM),
                "a transfer was decoded from a message that never names the system program"
            );
        }
    }
}
