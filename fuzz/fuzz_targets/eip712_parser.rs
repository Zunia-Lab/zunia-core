//! Fuzzes the EIP-712 typed-data parser.
//!
//! Ranks with the Cosmos direct decoder as the most exposed parser in the wallet. A website calls
//! `eth_signTypedData_v4` with a JSON document it controls entirely, and the wallet parses it,
//! renders it, then hashes and signs it. Two failure modes matter. A panic aborts the WASM
//! instance, so any site could disable the wallet. A document that parses but whose structure is
//! not what the prompt displayed is worse: EIP-712 signatures authorise token allowances and
//! order fills, so a mismatch between what is shown and what is hashed is a drain.
//!
//! The recursive type graph is the part most likely to break: types referencing each other,
//! arrays of arrays, and array lengths large enough to matter.
//!
//! The assertions live in `zunia-properties` so ordinary CI can replay the corpus on stable.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zunia_properties::check_eip712_parser;

fuzz_target!(|data: &[u8]| {
    check_eip712_parser(data);
});
