//! Fuzzes the Solana message parser.
//!
//! Solana encodes signing privileges positionally: the first `num_required_signatures` accounts
//! sign, and read-only accounts sit at the end of each class. Nothing in the bytes says which
//! account is which beyond those three header counters, so a parser that accepts an inconsistent
//! header hands the prompt a message whose privileges it will describe incorrectly. Labelling a
//! writable account read-only is the difference between "approve a memo" and "approve a drain".
//!
//! The compact-u16 length prefixes are the other half: they appear before the account table, the
//! instruction list, each instruction's account list, and each instruction's data, so a
//! mis-parsed length shifts every field after it.
//!
//! The assertions live in `zunia-properties` so ordinary CI can replay the corpus on stable.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zunia_properties::check_svm_message_parser;

fuzz_target!(|data: &[u8]| {
    check_svm_message_parser(data);
});
