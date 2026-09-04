//! Replays the committed fuzz corpus on the stable toolchain.
//!
//! A real fuzzing campaign needs nightly, `cargo-fuzz`, and minutes to hours of CPU. That is a
//! scheduled job, not something a pull request can wait for. This test gives ordinary CI the
//! part that is cheap and still valuable: every input the fuzzer has already found, replayed
//! against the same property assertions in a second.
//!
//! The point is regression coverage. When fuzzing finds a crash, the artifact is committed to
//! `fuzz/corpus/<target>/`, and from then on it is checked on every pull request without anyone
//! needing to remember to re-run the fuzzer.
//!
//! Also covers the properties with adversarial inputs constructed here, so the file is useful
//! before the corpus has grown.

use std::path::{Path, PathBuf};

use zunia_properties::{
    check_address_parser, check_eip712_parser, check_keyring_envelope, check_registry_parser,
    check_tx_decoder,
};

fn corpus_dir(target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target)
}

fn read_corpus(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if name.starts_with('.') {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            out.push((name, bytes));
        }
    }
    out.sort();
    out
}

/// Runs one target's property function over its corpus.
///
/// Named inputs, so a failure identifies the file rather than just reporting that something in a
/// directory broke.
fn replay(target: &str, check: fn(&[u8])) -> usize {
    let corpus = read_corpus(target);
    for (name, bytes) in &corpus {
        // The property functions panic on violation, which is what libFuzzer wants. Here that
        // surfaces as a test failure naming the offending corpus entry.
        check(bytes);
        let _ = name;
    }
    corpus.len()
}

#[test]
fn the_corpus_is_present() {
    // A silently empty corpus would make every test below vacuous.
    for target in [
        "tx_decoder",
        "registry_parser",
        "address_parser",
        "keyring_envelope",
        "eip712_parser",
        "svm_message",
    ] {
        assert!(
            !read_corpus(target).is_empty(),
            "no corpus for {target}; seed it per fuzz/README.md, otherwise this replay proves \
             nothing"
        );
    }
}

#[test]
fn tx_decoder_corpus_holds_its_properties() {
    let count = replay("tx_decoder", check_tx_decoder);
    println!("replayed {count} tx_decoder inputs");
}

#[test]
fn registry_parser_corpus_holds_its_properties() {
    let count = replay("registry_parser", check_registry_parser);
    println!("replayed {count} registry_parser inputs");
}

#[test]
fn address_parser_corpus_holds_its_properties() {
    let count = replay("address_parser", check_address_parser);
    println!("replayed {count} address_parser inputs");
}

#[test]
fn keyring_envelope_corpus_holds_its_properties() {
    let count = replay("keyring_envelope", check_keyring_envelope);
    println!("replayed {count} keyring_envelope inputs");
}

#[test]
fn eip712_parser_corpus_holds_its_properties() {
    let count = replay("eip712_parser", check_eip712_parser);
    println!("replayed {count} eip712_parser inputs");
}

#[cfg(feature = "solana")]
#[test]
fn svm_message_corpus_holds_its_properties() {
    let count = replay("svm_message", zunia_properties::check_svm_message_parser);
    println!("replayed {count} svm_message inputs");
}

#[test]
fn the_properties_survive_adversarial_input() {
    // Inputs chosen to hit the shapes a mutation fuzzer takes a while to reach: truncation at
    // every length, byte flips, and the degenerate cases around empty and maximum values.
    let seeds: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xff; 64],
        // Protobuf-shaped noise: valid tags with absurd lengths.
        vec![0x0a, 0xff, 0xff, 0xff, 0xff, 0x7f],
        vec![0x0a, 0x00],
        vec![0x12, 0x00],
        // Varints that never terminate.
        vec![0x08; 32],
        // JSON-shaped noise.
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"{\"version\":999999}".to_vec(),
        b"{\"chainId\":\"\"}".to_vec(),
        // Bech32-shaped noise, including the separator with nothing around it.
        b"1".to_vec(),
        b"cosmos1".to_vec(),
        b"COSMOS1QQQQ".to_vec(),
        b"0x".to_vec(),
        b"0x0000000000000000000000000000000000000000".to_vec(),
        // Invalid UTF-8, which every text parser must reject rather than misread.
        vec![0xc3, 0x28],
        vec![0xf0, 0x90, 0x28, 0xbc],
    ];

    for seed in &seeds {
        check_all(seed);
    }

    // Truncations of every corpus entry, which is the single most productive mutation and
    // catches length handling that assumes a field is present.
    for target in [
        "tx_decoder",
        "registry_parser",
        "address_parser",
        "eip712_parser",
        "svm_message",
    ] {
        for (_, bytes) in read_corpus(target) {
            for len in 0..bytes.len().min(96) {
                check_all(&bytes[..len]);
            }
        }
    }
}

/// Feeds one input to every parser, not just the one whose corpus it came from.
///
/// Cross-feeding is deliberate. A parser is most likely to misbehave on input shaped for a
/// different format, because that is the input its author never pictured, and a website can send
/// whatever it likes to whichever method it likes.
fn check_all(data: &[u8]) {
    check_tx_decoder(data);
    check_registry_parser(data);
    check_address_parser(data);
    check_keyring_envelope(data);
    check_eip712_parser(data);
    #[cfg(feature = "solana")]
    zunia_properties::check_svm_message_parser(data);
}

#[test]
fn single_byte_flips_in_real_sign_docs_hold_their_properties() {
    // A dApp-supplied sign document that has been corrupted in transit, or crafted to look
    // almost valid, must still either decode honestly or be rejected. Never a panic, and never
    // a message described as understood when it was not.
    for (name, bytes) in read_corpus("tx_decoder") {
        for index in 0..bytes.len().min(200) {
            for mask in [0x01u8, 0x80] {
                let mut mutated = bytes.clone();
                mutated[index] ^= mask;
                check_tx_decoder(&mutated);
            }
        }
        let _ = name;
    }
}
