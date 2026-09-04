//! Asserts that a wallet sealed by an earlier build still opens.
//!
//! `tests/vectors/keyring-envelope.json` was produced by `examples/seal_fixture.rs` and is
//! committed. The unit tests in `src/keyring.rs` cover behaviour by sealing and opening within
//! the same build, which cannot detect the failure that matters most here: a change to the
//! envelope format, the associated-data construction, or the KDF inputs that leaves every
//! existing user unable to open the wallet they already have.
//!
//! Recovering from that in the field means asking users for their recovery phrase, and the ones
//! who did not write it down lose everything. So if this test fails, the change needs a
//! migration path and a bump to [`ENVELOPE_VERSION`], not a regenerated fixture.

use std::path::{Path, PathBuf};

use serde_json::Value;
use zunia_kernel::{KdfParams, KernelError, KeyringEnvelope, ZuniaMnemonic, ENVELOPE_VERSION};

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/keyring-envelope.json")
}

struct Fixture {
    password: String,
    mnemonic: String,
    expected_seed: Vec<u8>,
    envelope_json: String,
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(fixture_path()).expect(
        "tests/vectors/keyring-envelope.json is missing; it is committed, so this means the \
         checkout is incomplete rather than that it needs regenerating",
    );
    let value: Value = serde_json::from_str(&text).expect("fixture is not valid JSON");

    Fixture {
        password: value["password"].as_str().unwrap().to_owned(),
        mnemonic: value["mnemonic"].as_str().unwrap().to_owned(),
        expected_seed: hex::decode(value["expected_seed_hex"].as_str().unwrap()).unwrap(),
        envelope_json: serde_json::to_string(&value["envelope"]).unwrap(),
    }
}

#[test]
fn a_wallet_sealed_by_an_earlier_build_still_opens() {
    let fixture = fixture();
    let envelope = KeyringEnvelope::from_json(&fixture.envelope_json)
        .expect("the pinned envelope no longer deserialises: the format changed");

    let opened = envelope.open(&fixture.password).unwrap_or_else(|e| {
        panic!(
            "the pinned envelope no longer opens ({e}). Every existing wallet is now \
             unopenable. Add a migration and bump ENVELOPE_VERSION rather than regenerating \
             the fixture."
        )
    });

    assert_eq!(
        opened.expose(),
        &fixture.expected_seed[..],
        "the envelope opened but yielded different bytes, which is worse than failing to open: \
         the wallet would silently derive the wrong accounts"
    );

    // And the recovered seed must be the one the recovery phrase produces, so a user restoring
    // from the phrase lands on the same accounts as a user unlocking with the password.
    let from_phrase = ZuniaMnemonic::parse(&fixture.mnemonic).unwrap().to_seed("");
    assert_eq!(
        from_phrase.expose(),
        &fixture.expected_seed[..],
        "unlocking and restoring disagree, so the two paths lead to different wallets"
    );
}

#[test]
fn the_pinned_envelope_is_still_the_current_version() {
    // Not a correctness requirement, but a prompt: if the version has moved on, this file
    // should gain a fixture for the new version while keeping this one, so both paths stay
    // covered.
    let fixture = fixture();
    let envelope = KeyringEnvelope::from_json(&fixture.envelope_json).unwrap();
    assert!(
        envelope.version <= ENVELOPE_VERSION,
        "the fixture claims a version this build does not know about"
    );
    assert_eq!(
        envelope.version, ENVELOPE_VERSION,
        "ENVELOPE_VERSION has moved past the pinned fixture; add a fixture for version {} and \
         keep this one so older wallets stay covered",
        ENVELOPE_VERSION
    );
}

#[test]
fn the_pinned_envelope_rejects_a_wrong_password() {
    // Guards against the opposite failure: an open path so permissive that anything unlocks.
    let fixture = fixture();
    let envelope = KeyringEnvelope::from_json(&fixture.envelope_json).unwrap();

    for wrong in ["", "pinned-fixture-passwor", "Pinned-Fixture-Password", "x"] {
        assert_eq!(
            envelope.open(wrong).unwrap_err(),
            KernelError::Decrypt,
            "{wrong:?} must not open the pinned envelope"
        );
    }
}

#[test]
fn the_pinned_envelope_is_tamper_evident() {
    let fixture = fixture();
    let base = KeyringEnvelope::from_json(&fixture.envelope_json).unwrap();

    let mut flipped = base.clone();
    flipped.ciphertext[0] ^= 0x80;
    assert_eq!(
        flipped.open(&fixture.password).unwrap_err(),
        KernelError::Decrypt
    );

    let mut relabelled = base.clone();
    relabelled.metadata["accounts"][0]["path"] = Value::from("m/44'/118'/0'/0/99");
    assert_eq!(
        relabelled.open(&fixture.password).unwrap_err(),
        KernelError::Decrypt,
        "rewriting a stored derivation path must invalidate the tag, otherwise an attacker can \
         make the wallet display an address they control"
    );

    let mut weakened = base;
    weakened.params.memory_kib = 1024;
    weakened.params.iterations = 1;
    assert_eq!(
        weakened.open(&fixture.password).unwrap_err(),
        KernelError::KdfParams,
        "a downgraded KDF must be refused before it is used, not merely fail the tag"
    );
}

#[test]
fn the_pinned_envelope_can_be_upgraded_in_place() {
    // A wallet sealed with low-memory parameters on a cheap device must be strengthenable on
    // next unlock without the user doing anything, and must still open afterwards.
    let fixture = fixture();
    let envelope = KeyringEnvelope::from_json(&fixture.envelope_json).unwrap();
    assert!(
        envelope.params.needs_upgrade(),
        "the fixture is meant to use reduced parameters so this path is exercised"
    );

    let upgraded = envelope.upgrade(&fixture.password).unwrap();
    assert_eq!(upgraded.params, KdfParams::default());
    assert!(!upgraded.params.needs_upgrade());
    assert_eq!(
        upgraded.open(&fixture.password).unwrap().expose(),
        &fixture.expected_seed[..]
    );
    assert_eq!(
        upgraded.metadata, envelope.metadata,
        "an upgrade must not disturb the account list"
    );

    // The old envelope must keep working, since the upgrade is written separately and the
    // write can fail.
    assert!(envelope.open(&fixture.password).is_ok());
}

#[test]
fn the_fixture_contains_no_plaintext_secret() {
    // The fixture is committed, so it is worth proving the file itself leaks nothing beyond the
    // published test values it deliberately includes.
    let text = std::fs::read_to_string(fixture_path()).unwrap();
    let fixture = fixture();

    let envelope_only: Value = serde_json::from_str(&fixture.envelope_json).unwrap();
    let envelope_text = serde_json::to_string(&envelope_only).unwrap();

    assert!(
        !envelope_text.contains(&hex::encode(&fixture.expected_seed)),
        "the seed appears in the envelope in the clear"
    );
    let ciphertext = hex::decode(envelope_only["ciphertext"].as_str().unwrap()).unwrap();
    assert!(
        !ciphertext
            .windows(fixture.expected_seed.len())
            .any(|window| window == &fixture.expected_seed[..]),
        "the seed appears in the ciphertext, so it was not encrypted"
    );
    assert!(
        text.contains("password") && text.contains("mnemonic"),
        "the fixture is expected to publish its own test password and phrase"
    );
}
