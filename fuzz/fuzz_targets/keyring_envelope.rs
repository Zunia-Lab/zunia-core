//! Fuzzes keyring envelope deserialisation and the reject path.
//!
//! The envelope is read from `chrome.storage.local` or the mobile document directory, both
//! writable by anything with local access. A malformed envelope must yield an error the UI can
//! show, never a panic that stops the wallet starting, and never a successful open.
//!
//! Assertions live in `zunia-properties`; see that crate for what is being claimed and why.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zunia_properties::check_keyring_envelope;

fuzz_target!(|data: &[u8]| {
    check_keyring_envelope(data);
});
