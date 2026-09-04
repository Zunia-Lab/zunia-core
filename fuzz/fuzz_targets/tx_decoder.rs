//! Fuzzes the `SIGN_MODE_DIRECT` decoder.
//!
//! The highest-value target here. The bytes come straight from a website via `signDirect`, and
//! the decoder output is what the signing prompt renders. A panic aborts the extension's WASM
//! instance, so a site could kill the wallet on demand; a confident wrong decode is worse still,
//! because the user approves a transaction based on a description of something else.
//!
//! The assertions live in `zunia-properties` so that ordinary CI can replay the committed
//! corpus against them on stable, without needing nightly or a fuzzing time budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zunia_properties::check_tx_decoder;

fuzz_target!(|data: &[u8]| {
    check_tx_decoder(data);
});
