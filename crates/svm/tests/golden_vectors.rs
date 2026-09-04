//! Asserts Solana derivation, message serialisation and signing against `@solana/web3.js`.
//!
//! Regenerate with `pnpm generate:svm` in `tests/vectors/generate`.
//!
//! The compiler is tested by round trip rather than by restating each case's intent twice. Every
//! vector's message bytes are parsed, decompiled back into instructions naming accounts by
//! address, and recompiled. If our account ordering, header derivation, deduplication or
//! privilege union differed from web3.js in any way, the recompiled bytes would not match the
//! bytes web3.js produced. That is a stronger check than comparing a hand-restated intent,
//! because it exercises the compiler against input we did not choose the shape of.
//!
//! One divergence is expected and handled rather than hidden: web3.js orders accounts within a
//! privilege class by base58 string, while solana-sdk and this crate order by raw key bytes. The
//! generator flags cases where the two disagree, and byte equality is asserted only where they
//! agree. See the note in the vector file.

#![cfg(feature = "solana")]

use serde_json::Value;
use zunia_kernel::{Curve, DerivationPath, ExtendedKey, ZuniaMnemonic};
use zunia_svm::{
    message::{AccountMeta, Instruction, Message},
    summary::{summarize, InstructionSummary},
    system, Pubkey, Transaction,
};

fn vectors() -> Value {
    let raw = include_str!("../../../tests/vectors/svm-signing.json");
    serde_json::from_str(raw).expect("svm-signing.json is not valid JSON")
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
        .to_string()
}

fn key_at(mnemonic: &str, path: &str) -> ExtendedKey {
    let seed = ZuniaMnemonic::parse(mnemonic).unwrap().to_seed("");
    let path = DerivationPath::parse(path).expect("vector path does not parse");
    ExtendedKey::from_seed_and_path(Curve::Ed25519, seed.expose(), &path).unwrap()
}

#[test]
fn derivation_matches_the_solana_ecosystem() {
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let accounts = vectors["accounts"].as_array().unwrap();
    assert!(!accounts.is_empty());

    for account in accounts {
        let path = text(account, "path");
        let key = key_at(&mnemonic, &path);

        // The private scalar, not just the address. Two implementations can agree on an address
        // while disagreeing on the key only if one of them is doing something very strange, but
        // when derivation does break this says whether it broke before or after the public key.
        assert_eq!(
            hex::encode(key.private_key().expose()),
            text(account, "privateKey"),
            "SLIP-0010 private key diverged at {path}"
        );
        assert_eq!(
            hex::encode(key.public_key_bytes().unwrap()),
            text(account, "publicKey"),
            "public key diverged at {path}"
        );

        let address = Pubkey::from_public_key(&key.public_key_bytes().unwrap()).unwrap();
        assert_eq!(
            address.to_base58(),
            text(account, "address"),
            "address diverged at {path}"
        );
    }
}

/// Turns a compiled message back into instructions that name accounts by address.
///
/// The privileges come from the message's own positional layout, which is the only place they
/// exist. This is also exactly what an approval prompt has to do with a message handed to it by
/// a dApp, so a bug here would be a bug in the prompt.
fn decompile(message: &Message) -> Vec<Instruction> {
    message
        .instructions
        .iter()
        .map(|compiled| Instruction {
            program_id: message.account_keys[usize::from(compiled.program_id_index)],
            accounts: compiled
                .accounts
                .iter()
                .map(|index| {
                    let position = usize::from(*index);
                    AccountMeta {
                        pubkey: message.account_keys[position],
                        is_signer: message.is_signer(position),
                        is_writable: message.is_writable(position),
                    }
                })
                .collect(),
            data: compiled.data.clone(),
        })
        .collect()
}

#[test]
fn compilation_reproduces_the_web3js_message_bytes() {
    let vectors = vectors();
    let cases = vectors["transactions"].as_array().unwrap();
    assert!(cases.len() >= 9, "expected the full transaction matrix");

    let mut compared = 0;
    for case in cases {
        let name = text(case, "name");
        let expected_bytes = hex::decode(text(case, "messageBytes")).unwrap();

        // First: our parser accepts what web3.js produced, and re-serialising is a fixed point.
        let parsed = Message::parse(&expected_bytes)
            .unwrap_or_else(|e| panic!("{name} failed to parse: {e}"));
        assert_eq!(
            parsed.serialize().unwrap(),
            expected_bytes,
            "re-serialising a parsed message changed it for {name}"
        );

        // The header and account table, checked field by field so a mismatch names itself.
        let header = &case["header"];
        assert_eq!(
            u64::from(parsed.header.num_required_signatures),
            header["numRequiredSignatures"].as_u64().unwrap(),
            "signer count diverged for {name}"
        );
        assert_eq!(
            u64::from(parsed.header.num_readonly_signed_accounts),
            header["numReadonlySignedAccounts"].as_u64().unwrap(),
            "read-only signer count diverged for {name}"
        );
        assert_eq!(
            u64::from(parsed.header.num_readonly_unsigned_accounts),
            header["numReadonlyUnsignedAccounts"].as_u64().unwrap(),
            "read-only non-signer count diverged for {name}"
        );
        assert_eq!(
            parsed
                .account_keys
                .iter()
                .map(Pubkey::to_base58)
                .collect::<Vec<_>>(),
            case["accountKeys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            "account table diverged for {name}"
        );

        // Then: recompiling from the decompiled intent lands on the same bytes, which is what
        // proves our ordering and header derivation agree with web3.js rather than merely that
        // our parser is self-consistent.
        if case["orderingsAgree"].as_bool().unwrap_or(false) {
            let recompiled = Message::compile(
                *parsed.fee_payer().unwrap(),
                &decompile(&parsed),
                parsed.recent_blockhash,
            )
            .unwrap_or_else(|e| panic!("{name} failed to recompile: {e}"));

            assert_eq!(
                recompiled.serialize().unwrap(),
                expected_bytes,
                "recompiled message diverged for {name}"
            );
            compared += 1;
        }
    }

    assert!(
        compared >= 9,
        "only {compared} cases had comparable ordering, so the compiler is barely covered"
    );
}

#[test]
fn signatures_match_web3js() {
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");

    for case in vectors["transactions"].as_array().unwrap() {
        let name = text(case, "name");
        let message = Message::parse(&hex::decode(text(case, "messageBytes")).unwrap()).unwrap();
        let mut tx = Transaction::new_unsigned(message);

        for path in case["signerPaths"].as_array().unwrap() {
            let key = key_at(&mnemonic, path.as_str().unwrap());
            tx.sign(&key)
                .unwrap_or_else(|e| panic!("{name} failed to sign with {path}: {e}"));
        }

        assert!(tx.is_fully_signed(), "{name} left a signature slot empty");
        assert!(tx.verify().unwrap(), "{name} does not verify");

        let expected: Vec<Option<String>> = case["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["signature"].as_str().map(str::to_string))
            .collect();
        let produced: Vec<Option<String>> = tx
            .signatures
            .iter()
            .map(|signature| Some(hex::encode(signature)))
            .collect();
        assert_eq!(produced, expected, "signatures diverged for {name}");

        // The wire format and the id a block explorer would show.
        if case["orderingsAgree"].as_bool().unwrap_or(false) {
            assert_eq!(
                hex::encode(tx.serialize().unwrap()),
                text(case, "wire"),
                "wire format diverged for {name}"
            );
        }
        assert_eq!(tx.id().unwrap(), text(case, "id"), "id diverged for {name}");
    }
}

#[test]
fn transfers_built_from_intent_match_web3js() {
    // The round-trip test above proves the compiler is consistent with web3.js given web3.js's
    // own output. This one starts from intent, the way the send screen will, and confirms the
    // high-level builder produces the same thing.
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let accounts = vectors["accounts"].as_array().unwrap();
    let payer_key = key_at(&mnemonic, &text(&accounts[0], "path"));
    let payer = Pubkey::from_public_key(&payer_key.public_key_bytes().unwrap()).unwrap();
    let recipient = Pubkey::parse(&text(&accounts[1], "address")).unwrap();
    let blockhash = {
        let bytes = bs58::decode(text(&vectors["transactions"][0], "recentBlockhash"))
            .into_vec()
            .unwrap();
        <[u8; 32]>::try_from(bytes.as_slice()).unwrap()
    };

    let cases = [
        ("single_transfer", 1_000_000_000u64),
        ("transfer_one_lamport", 1),
        ("transfer_zero_lamports", 0),
    ];

    for (name, lamports) in cases {
        let vector = vectors["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| text(case, "name") == name)
            .unwrap_or_else(|| panic!("vector {name} is missing"));

        let message = Message::compile(
            payer,
            &[system::transfer(payer, recipient, lamports)],
            blockhash,
        )
        .unwrap();

        assert_eq!(
            hex::encode(message.serialize().unwrap()),
            text(vector, "messageBytes"),
            "message built from intent diverged for {name}"
        );

        let mut tx = Transaction::new_unsigned(message);
        tx.sign(&payer_key).unwrap();
        assert_eq!(
            hex::encode(tx.serialize().unwrap()),
            text(vector, "wire"),
            "signed transaction built from intent diverged for {name}"
        );
    }
}

#[test]
fn the_summary_tells_the_truth_about_every_vector() {
    // The whole point of the summary is that the prompt never overstates what it understands.
    // These expectations are written per case rather than derived, because deriving them from
    // the same code under test would prove nothing.
    let vectors = vectors();

    for case in vectors["transactions"].as_array().unwrap() {
        let name = text(case, "name");
        let message = Message::parse(&hex::decode(text(case, "messageBytes")).unwrap()).unwrap();
        let summary = summarize(&message);

        let (should_be_readable, transfer_count) = match name.as_str() {
            "single_transfer" | "transfer_one_lamport" | "transfer_zero_lamports" => (true, 1),
            "two_transfers" => (true, 2),
            "multi_signer" => (true, 1),
            // A memo is not decoded, so these must not claim to be readable.
            "opaque_program" | "empty_instruction_data" | "large_instruction_data" => (false, 0),
            "transfer_plus_memo" => (false, 1),
            other => panic!("vector {other} has no stated expectation; add one"),
        };

        assert_eq!(
            summary.is_fully_understood(),
            should_be_readable,
            "readability misreported for {name}"
        );
        assert_eq!(
            summary
                .instructions
                .iter()
                .filter(|i| matches!(i, InstructionSummary::Transfer { .. }))
                .count(),
            transfer_count,
            "decoded transfer count wrong for {name}"
        );
        assert_eq!(
            summary.fee_payer.to_base58(),
            text(case, "feePayer"),
            "fee payer wrong for {name}"
        );

        // Every account the summary calls writable must really be writable per the header.
        for account in &summary.writable_accounts {
            let index = message
                .account_keys
                .iter()
                .position(|k| k == account)
                .unwrap();
            assert!(
                message.is_writable(index),
                "{name} reported a read-only account as writable"
            );
        }
    }
}

#[test]
fn the_decoded_amounts_match_what_the_generator_asked_for() {
    // Pins the amounts end to end: the generator built a transfer of a stated size, and the
    // summary has to recover that number from the bytes rather than from a label.
    let vectors = vectors();
    let expected = [
        ("single_transfer", 1_000_000_000u64),
        ("transfer_one_lamport", 1),
        ("transfer_zero_lamports", 0),
        ("two_transfers", 350),
        ("multi_signer", 42),
        ("transfer_plus_memo", 5_000_000),
    ];

    for (name, total) in expected {
        let case = vectors["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| text(case, "name") == name)
            .unwrap();
        let message = Message::parse(&hex::decode(text(case, "messageBytes")).unwrap()).unwrap();
        let summary = summarize(&message);

        let moved: u64 = summary
            .instructions
            .iter()
            .filter_map(|i| match i {
                InstructionSummary::Transfer { lamports, .. } => Some(*lamports),
                _ => None,
            })
            .sum();
        assert_eq!(moved, total, "decoded amount wrong for {name}");
    }
}

#[test]
fn a_tampered_message_produces_a_different_signature() {
    // Confirms the vectors are sensitive to what they claim to cover.
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let case = &vectors["transactions"][0];
    let key = key_at(&mnemonic, case["signerPaths"][0].as_str().unwrap());

    let message = Message::parse(&hex::decode(text(case, "messageBytes")).unwrap()).unwrap();
    let mut tampered = message.clone();
    tampered.instructions[0].data =
        system::transfer(*message.fee_payer().unwrap(), message.account_keys[1], 999).data;

    let mut original = Transaction::new_unsigned(message);
    original.sign(&key).unwrap();
    let mut modified = Transaction::new_unsigned(tampered);
    modified.sign(&key).unwrap();

    assert_ne!(
        original.signatures, modified.signatures,
        "changing the amount did not change the signature"
    );
}

#[test]
fn every_vector_section_is_asserted() {
    let vectors = vectors();
    let asserted = ["accounts", "transactions"];
    for key in vectors.as_object().unwrap().keys() {
        if matches!(
            key.as_str(),
            "description" | "generator" | "mnemonic" | "note"
        ) {
            continue;
        }
        assert!(
            asserted.contains(&key.as_str()),
            "vector section {key} is generated but never asserted"
        );
    }
}
