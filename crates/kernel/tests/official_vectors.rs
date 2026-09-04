//! Runs the official BIP-39, BIP-32 and SLIP-0010 test vectors against the kernel.
//!
//! `tests/vectors/bip-derivation.json` is fetched from the normative upstreams by
//! `tests/vectors/generate/bip-vectors.py` and committed, so this runs offline.
//!
//! Every account in every Zunia wallet is reachable only through these algorithms. A wrong
//! derivation is not a bug that shows up as an error: it silently produces a valid-looking
//! wallet at the wrong address, and the user's funds are at a key nobody can find. There is no
//! recovery from shipping that, so the vectors are asserted in full rather than sampled.

use std::path::{Path, PathBuf};

use serde_json::Value;
use zunia_kernel::{Curve, DerivationPath, ExtendedKey, WordCount, ZuniaMnemonic};

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/bip-derivation.json")
}

fn load() -> Value {
    let text = std::fs::read_to_string(vectors_path()).expect(
        "tests/vectors/bip-derivation.json is missing; run \
         `python3 tests/vectors/generate/bip-vectors.py`",
    );
    serde_json::from_str(&text).expect("vector file is not valid JSON")
}

fn hex_at(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing {key} in {value}")),
    )
    .unwrap_or_else(|_| panic!("{key} is not hex in {value}"))
}

#[test]
fn bip39_entropy_to_mnemonic_matches_the_reference() {
    let vectors = load();
    let cases = vectors["bip39"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24, "expected the full English vector set");

    for case in cases {
        let entropy = hex_at(case, "entropy_hex");
        let expected = case["mnemonic"].as_str().unwrap();

        let mnemonic = ZuniaMnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.phrase().expose(),
            expected,
            "entropy {} produced the wrong phrase",
            hex::encode(&entropy)
        );

        // And the entropy must survive the round trip, since restore-from-phrase depends on it.
        let reparsed = ZuniaMnemonic::parse(expected).unwrap();
        assert_eq!(
            reparsed.entropy().expose(),
            &entropy[..],
            "phrase did not decode back to its entropy"
        );
        assert_eq!(
            reparsed.word_count(),
            expected.split_whitespace().count(),
            "word count disagreed with the phrase"
        );
        assert!(
            WordCount::from_words(reparsed.word_count()).is_ok(),
            "reference vector has a word count the kernel rejects"
        );
    }
}

#[test]
fn bip39_seed_derivation_matches_the_reference() {
    let vectors = load();
    let passphrase = vectors["bip39"]["passphrase"].as_str().unwrap();

    for case in vectors["bip39"]["cases"].as_array().unwrap() {
        let mnemonic = ZuniaMnemonic::parse(case["mnemonic"].as_str().unwrap()).unwrap();
        let seed = mnemonic.to_seed(passphrase);
        assert_eq!(
            hex::encode(seed.expose()),
            case["seed_hex"].as_str().unwrap(),
            "PBKDF2 seed diverged for {:?}",
            case["mnemonic"].as_str().unwrap()
        );
    }
}

#[test]
fn bip39_passphrase_changes_the_seed() {
    // Guards against the passphrase being accepted and then dropped, which would silently
    // hand every 25th-word user the same wallet as a no-passphrase user.
    let vectors = load();
    let case = &vectors["bip39"]["cases"][0];
    let mnemonic = ZuniaMnemonic::parse(case["mnemonic"].as_str().unwrap()).unwrap();

    let with = mnemonic.to_seed(vectors["bip39"]["passphrase"].as_str().unwrap());
    let without = mnemonic.to_seed("");
    assert_ne!(with.expose(), without.expose());
    assert_eq!(with.expose().len(), 64);
    assert_eq!(without.expose().len(), 64);
}

#[test]
fn bip32_derivation_matches_the_official_vectors() {
    let vectors = load();
    let sets = vectors["bip32"].as_array().unwrap();
    assert_eq!(sets.len(), 4, "expected all four seed-based BIP-32 vectors");

    let mut checked = 0;
    for set in sets {
        let name = set["name"].as_str().unwrap();
        let seed = hex_at(set, "seed_hex");

        for chain in set["chains"].as_array().unwrap() {
            let path_str = chain["path"].as_str().unwrap();
            let path = DerivationPath::parse(path_str)
                .unwrap_or_else(|e| panic!("{name}: cannot parse path {path_str}: {e}"));

            let key = ExtendedKey::from_seed_and_path(Curve::Secp256k1, &seed, &path)
                .unwrap_or_else(|e| panic!("{name} {path_str}: derivation failed: {e}"));

            assert_eq!(
                hex::encode(key.private_key().expose()),
                chain["private_key_hex"].as_str().unwrap(),
                "{name} {path_str}: private key diverged"
            );
            assert_eq!(
                hex::encode(key.chain_code().expose()),
                chain["chain_code_hex"].as_str().unwrap(),
                "{name} {path_str}: chain code diverged"
            );
            assert_eq!(
                hex::encode(key.public_key_bytes().unwrap()),
                chain["public_key_hex"].as_str().unwrap(),
                "{name} {path_str}: compressed public key diverged"
            );
            assert_eq!(
                path.depth(),
                chain["depth"].as_u64().unwrap() as usize,
                "{name} {path_str}: the vector's depth disagrees with the parsed path, so the \
                 path parser dropped or invented a level"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 17, "expected every derived key to be checked");
}

#[test]
fn bip32_vector_3_covers_leading_zero_retention() {
    // Vector 3 exists specifically because an implementation that trims leading zeros from
    // the private key derives a different child. Named here so a future reader knows why the
    // seed looks arbitrary and does not "simplify" the vector set.
    let vectors = load();
    let set = vectors["bip32"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "bip32_vector_3")
        .expect("BIP-32 vector 3 is missing");

    let seed = hex_at(set, "seed_hex");
    let path = DerivationPath::parse("m/0'").unwrap();
    let key = ExtendedKey::from_seed_and_path(Curve::Secp256k1, &seed, &path).unwrap();
    let expected = set["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["path"] == "m/0'")
        .unwrap();
    assert_eq!(
        hex::encode(key.private_key().expose()),
        expected["private_key_hex"].as_str().unwrap()
    );
}

#[test]
fn slip10_ed25519_derivation_matches_the_official_vectors() {
    let vectors = load();
    let sets = vectors["slip10_ed25519"].as_array().unwrap();
    assert_eq!(sets.len(), 2);

    let mut checked = 0;
    for set in sets {
        let name = set["name"].as_str().unwrap();
        let seed = hex_at(set, "seed_hex");

        for chain in set["chains"].as_array().unwrap() {
            let path_str = chain["path"].as_str().unwrap();
            let path = DerivationPath::parse(path_str).unwrap();
            let key = ExtendedKey::from_seed_and_path(Curve::Ed25519, &seed, &path)
                .unwrap_or_else(|e| panic!("{name} {path_str}: derivation failed: {e}"));

            assert_eq!(
                hex::encode(key.private_key().expose()),
                chain["private_key_hex"].as_str().unwrap(),
                "{name} {path_str}: private key diverged"
            );
            assert_eq!(
                hex::encode(key.chain_code().expose()),
                chain["chain_code_hex"].as_str().unwrap(),
                "{name} {path_str}: chain code diverged"
            );
            assert_eq!(
                hex::encode(key.public_key_bytes().unwrap()),
                chain["public_key_hex"].as_str().unwrap(),
                "{name} {path_str}: public key diverged"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 12);
}

#[test]
fn ed25519_refuses_unhardened_derivation() {
    // SLIP-0010 has no public parent to private child derivation for ed25519, so an
    // unhardened index is not representable. Accepting it silently would put keys somewhere
    // no other wallet could reproduce, so it must be an error rather than a coercion.
    let vectors = load();
    let seed = hex_at(&vectors["slip10_ed25519"][0], "seed_hex");
    let path = DerivationPath::parse("m/0'/1").unwrap();

    let error = ExtendedKey::from_seed_and_path(Curve::Ed25519, &seed, &path)
        .expect_err("unhardened ed25519 derivation must be rejected, not silently hardened");
    let message = error.to_string();
    assert!(
        message.to_lowercase().contains("harden"),
        "the error should say why: {message}"
    );
}

#[test]
fn bip44_paths_from_the_registry_derive_distinct_keys() {
    // The registry drives coin types, so a bug that collapsed distinct coin types into one
    // path would give the same key to two chains. Cheap to rule out.
    let vectors = load();
    let seed = hex_at(&vectors["bip32"][0], "seed_hex");

    let mut seen = std::collections::HashSet::new();
    for coin_type in [118u32, 60, 529, 330, 0] {
        for index in 0..3u32 {
            let path = DerivationPath::bip44(coin_type, 0, index);
            assert_eq!(path.depth(), 5, "a BIP-44 path has five levels");
            assert_eq!(path.address_index(), Some(index));
            assert_eq!(path.account(), Some(0));

            let key = ExtendedKey::from_seed_and_path(Curve::Secp256k1, &seed, &path).unwrap();
            assert!(
                seen.insert(hex::encode(key.private_key().expose())),
                "coin type {coin_type} index {index} collided with an earlier path"
            );
        }
    }
    assert_eq!(seen.len(), 15);
}
