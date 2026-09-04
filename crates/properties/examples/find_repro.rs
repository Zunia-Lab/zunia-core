//! Locates the corpus entry and byte flip that violates a `tx_decoder` property.
//!
//! Scratch tool. Run it when `corpus_replay` fails and you need the exact bytes to turn into a
//! regression test:
//!
//!   cargo run -p zunia-properties --example find_repro

use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/tx_decoder");

    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let bytes = std::fs::read(entry.path()).unwrap();
        let name = entry.file_name().to_string_lossy().to_string();

        for index in 0..bytes.len().min(200) {
            for mask in [0x01u8, 0x80] {
                let mut mutated = bytes.clone();
                mutated[index] ^= mask;

                let probe = mutated.clone();
                let violated = std::panic::catch_unwind(move || {
                    zunia_properties::check_tx_decoder(&probe);
                })
                .is_err();

                if violated {
                    println!("{name}: byte {index} flipped with {mask:#04x}");
                    println!("hex: {}", hex::encode(&mutated));
                    if let Ok(decoded) = zunia_cosmos::decode_direct_sign_doc(&mutated) {
                        println!("chain_id={:?} memo={:?}", decoded.chain_id, decoded.memo);
                        for msg in &decoded.msgs {
                            println!(
                                "  unknown={} summary={:?} addresses={:?}",
                                msg.is_unknown(),
                                msg.summary(),
                                msg.addresses()
                            );
                        }
                    }
                    return;
                }
            }
        }
    }
    println!("no violation found");
}
