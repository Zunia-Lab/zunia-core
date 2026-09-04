//! Fuzzes address decoding, validation and prefix conversion.
//!
//! Addresses arrive by paste, by QR scan, and from dApp requests, so this parser sees hostile
//! input routinely. The property that matters is round-tripping: if decode and re-encode
//! disagree, the wallet can display one address while sending to another.
//!
//! Assertions live in `zunia-properties`; see that crate for what is being claimed and why.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zunia_properties::check_address_parser;

fuzz_target!(|data: &[u8]| {
    check_address_parser(data);
});
