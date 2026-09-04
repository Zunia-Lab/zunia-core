//! Emits the pinned keyring envelope fixture.
//!
//! Run once to create `tests/vectors/keyring-envelope.json`, then commit the output. The
//! fixture is a wallet sealed by a known-good build; `tests/keyring_envelope.rs` asserts that
//! every later build can still open it.
//!
//! Regenerating is almost always the wrong move. If the pinned test fails, the format changed
//! and every existing user's wallet just became unopenable. The fix is a migration path, not a
//! new fixture. Regenerate only when deliberately adding a new envelope version, and keep the
//! old fixture alongside the new one.
//!
//!   cargo run -p zunia-kernel --example seal_fixture
//!
//! The password and seed are published test values. Nothing here guards anything.

use zunia_kernel::{KdfParams, KeyringEnvelope, ZuniaMnemonic};

const PASSWORD: &str = "pinned-fixture-password";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn main() {
    let mnemonic = ZuniaMnemonic::parse(MNEMONIC).expect("the test mnemonic must parse");
    let seed = mnemonic.to_seed("");

    let metadata = serde_json::json!({
        "accounts": [
            { "label": "Main", "path": "m/44'/118'/0'/0/0", "scheme": "cosmos" },
            { "label": "Injective", "path": "m/44'/60'/0'/0/0", "scheme": "ethermint" }
        ],
        "chains": ["safrochain-1", "cosmoshub-4", "injective-1"],
        "createdWith": env!("CARGO_PKG_VERSION")
    });

    // Low-memory parameters, so the pinned test stays fast and also exercises the
    // needs-upgrade path that a real wallet sealed on a cheap device would hit.
    let envelope =
        KeyringEnvelope::seal(seed.expose(), PASSWORD, KdfParams::low_memory(), metadata)
            .expect("sealing must succeed");

    let fixture = serde_json::json!({
        "_comment": concat!(
            "A keyring envelope sealed by a known-good build. Asserted by ",
            "crates/kernel/tests/keyring_envelope.rs. If that test fails, the envelope format ",
            "changed and existing wallets can no longer be opened: write a migration, do not ",
            "regenerate this file."
        ),
        "password": PASSWORD,
        "mnemonic": MNEMONIC,
        "expected_seed_hex": hex::encode(seed.expose()),
        "envelope": serde_json::from_str::<serde_json::Value>(&envelope.to_json().unwrap())
            .unwrap(),
    });

    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
