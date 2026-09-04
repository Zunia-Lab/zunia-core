//! Fuzzes the chain registry parser.
//!
//! Descriptors are community-submitted JSON delivered through the registry mirror, so one bad
//! descriptor takes out chain loading for every user at once, and one that parses into nonsense
//! derives addresses on a scheme the user did not choose.
//!
//! Assertions live in `zunia-properties`; see that crate for what is being claimed and why.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zunia_properties::check_registry_parser;

fuzz_target!(|data: &[u8]| {
    check_registry_parser(data);
});
