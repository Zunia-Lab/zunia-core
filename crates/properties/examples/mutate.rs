//! A stable-toolchain mutation sweep over the corpus.
//!
//! Not a replacement for `cargo-fuzz`: there is no coverage feedback, so it will never find the
//! deep paths libFuzzer reaches. What it does give is a way to hunt for shallow parser bugs
//! without a nightly toolchain, on a machine or in a job that does not have one, and to hammer a
//! specific target hard right after writing it. Everything it finds is reported with the exact
//! bytes so it can go straight into a regression test and the corpus.
//!
//! ```text
//! cargo run --release -p zunia-properties --features solana --example mutate
//! cargo run --release -p zunia-properties --example mutate -- eip712_parser 2000000
//! ```
//!
//! Deterministic: the same arguments produce the same mutations, so a finding is reproducible
//! and a clean run means something.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

type Check = fn(&[u8]);

fn targets() -> BTreeMap<&'static str, Check> {
    let mut map: BTreeMap<&'static str, Check> = BTreeMap::new();
    map.insert("tx_decoder", zunia_properties::check_tx_decoder);
    map.insert("registry_parser", zunia_properties::check_registry_parser);
    map.insert("address_parser", zunia_properties::check_address_parser);
    map.insert("keyring_envelope", zunia_properties::check_keyring_envelope);
    map.insert("eip712_parser", zunia_properties::check_eip712_parser);
    #[cfg(feature = "solana")]
    map.insert("svm_message", zunia_properties::check_svm_message_parser);
    map
}

/// xorshift64*, so a run is reproducible from its seed without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

/// Applies one of the mutations that actually find parser bugs.
///
/// Truncation and length-field corruption dominate, because almost every parser bug is a length
/// that was trusted. Splicing two corpus entries is included because it produces inputs that are
/// structurally plausible but semantically wrong, which is where inconsistent-header bugs live.
fn mutate(rng: &mut Rng, input: &[u8], donor: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    match rng.below(8) {
        0 => {
            // Truncate.
            let len = rng.below(out.len().saturating_add(1));
            out.truncate(len);
        }
        1 => {
            // Flip one bit.
            if !out.is_empty() {
                let index = rng.below(out.len());
                out[index] ^= 1u8 << rng.below(8);
            }
        }
        2 => {
            // Replace one byte with an interesting value.
            if !out.is_empty() {
                let index = rng.below(out.len());
                let interesting = [0x00u8, 0x01, 0x7f, 0x80, 0xff, 0xfe, 0x22, 0x5c];
                out[index] = interesting[rng.below(interesting.len())];
            }
        }
        3 => {
            // Insert a run of bytes.
            let index = rng.below(out.len().saturating_add(1));
            let count = 1 + rng.below(8);
            let byte = (rng.next() & 0xff) as u8;
            for _ in 0..count {
                out.insert(index.min(out.len()), byte);
            }
        }
        4 => {
            // Delete a run of bytes, which shifts every field after it.
            if !out.is_empty() {
                let index = rng.below(out.len());
                let count = 1 + rng.below(8);
                let end = index.saturating_add(count).min(out.len());
                out.drain(index..end);
            }
        }
        5 => {
            // Splice in part of another entry.
            if !donor.is_empty() && !out.is_empty() {
                let at = rng.below(out.len());
                let take = 1 + rng.below(donor.len().min(64));
                let from = rng.below(donor.len());
                let slice: Vec<u8> = donor
                    .iter()
                    .cycle()
                    .skip(from)
                    .take(take)
                    .copied()
                    .collect();
                out.splice(at..at, slice);
            }
        }
        6 => {
            // Corrupt the first few bytes, which is where headers and length prefixes live.
            for index in 0..out.len().min(4) {
                if rng.below(2) == 0 {
                    out[index] = (rng.next() & 0xff) as u8;
                }
            }
        }
        _ => {
            // Repeat the input, which turns a "trailing bytes" bug into a visible one.
            let copy = out.clone();
            out.extend_from_slice(&copy);
        }
    }
    out
}

fn read_corpus(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `""` and `all` both mean every target, so a CI invocation can pass a positional iteration
    // count without naming one.
    let requested = args
        .first()
        .filter(|name| !name.is_empty() && *name != "all")
        .cloned();
    let iterations: u64 = args
        .get(1)
        .or_else(|| requested.is_none().then(|| args.first()).flatten())
        .and_then(|n| n.parse().ok())
        .unwrap_or(200_000);

    // Panics are the finding, so the default hook's backtrace spam is noise until then.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut failures = 0usize;

    for (target, check) in targets() {
        if let Some(only) = &requested {
            if only != target {
                continue;
            }
        }

        // A corpus of every target's entries, not just this one's. A parser is most likely to
        // break on input shaped for a different format.
        let mut seeds = read_corpus(target);
        for other in targets().keys() {
            if *other != target {
                seeds.extend(read_corpus(other).into_iter().take(4));
            }
        }
        if seeds.is_empty() {
            println!("{target}: no corpus, skipped");
            continue;
        }

        // Seeded from the target name so each target gets a different but fixed stream.
        let seed = target.bytes().fold(0x9e37_79b9_7f4a_7c15u64, |acc, b| {
            acc.rotate_left(7) ^ u64::from(b)
        });
        let mut rng = Rng(seed | 1);
        let mut found = 0usize;

        for _ in 0..iterations {
            let base = &seeds[rng.below(seeds.len())];
            let donor = &seeds[rng.below(seeds.len())];
            let mut candidate = mutate(&mut rng, base, donor);
            // Occasionally stack a second mutation, which reaches shapes one pass cannot.
            if rng.below(3) == 0 {
                candidate = mutate(&mut rng, &candidate, donor);
            }

            let probe = candidate.clone();
            if catch_unwind(AssertUnwindSafe(|| check(&probe))).is_err() {
                found += 1;
                failures += 1;
                println!("{target}: property violated");
                println!("  hex: {}", hex::encode(&candidate));
                if let Ok(text) = core::str::from_utf8(&candidate) {
                    println!("  utf8: {text:?}");
                }
                if found >= 3 {
                    println!("  (stopping this target after 3 findings)");
                    break;
                }
            }
        }

        if found == 0 {
            println!("{target}: {iterations} mutations, no violations");
        }
    }

    std::panic::set_hook(previous);

    if failures > 0 {
        println!(
            "\n{failures} violation(s). Commit each input to fuzz/corpus/<target>/ and turn it \
             into a unit test in the crate it came from."
        );
        std::process::exit(1);
    }
}
