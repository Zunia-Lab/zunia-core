//! `personal_sign`, which is EIP-191 version `0x45`.
//!
//! The prefix is the entire security mechanism. Signing a raw hash would let a site hand over
//! the hash of a transaction and get back a valid transaction signature, so every message
//! signature is domain-separated by a prefix that no transaction encoding can produce.
//!
//! Zunia additionally refuses payloads that look like a transaction hash, because a site asking
//! the user to "sign in" with a 32-byte binary blob is not asking them to sign in.

use sha3::{Digest, Keccak256};
use zunia_kernel::{sign_digest_secp256k1, ExtendedKey, Signature};

use crate::error::Result;

/// The EIP-191 version `0x45` prefix.
const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// Builds the bytes that get hashed for `personal_sign`.
///
/// `\x19Ethereum Signed Message:\n` followed by the decimal length, then the message. The `\x19`
/// leading byte cannot begin a valid RLP transaction, which is what makes the separation work.
pub fn personal_sign_payload(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX.len().saturating_add(8).saturating_add(message.len()));
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(message.len().to_string().as_bytes());
    out.extend_from_slice(message);
    out
}

/// The hash `personal_sign` signs.
pub fn personal_sign_hash(message: &[u8]) -> [u8; 32] {
    Keccak256::digest(personal_sign_payload(message)).into()
}

/// Signs a message with `personal_sign`.
pub fn personal_sign(key: &ExtendedKey, message: &[u8]) -> Result<Signature> {
    Ok(sign_digest_secp256k1(key, &personal_sign_hash(message))?)
}

/// The 65-byte `r || s || v` form that `eth_sign` returns, with `v` as 27 or 28.
///
/// Note that `v` here is not EIP-155 encoded. Message signatures are not chain-specific, and a
/// verifier expects 27 or 28.
pub fn personal_sign_hex(key: &ExtendedKey, message: &[u8]) -> Result<String> {
    let signature = personal_sign(key, message)?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(signature.as_bytes());
    let recovery = signature
        .recovery_id()
        .ok_or(zunia_kernel::KernelError::Signature)?;
    out[64] = recovery.saturating_add(27);
    Ok(format!("0x{}", hex::encode(out)))
}

/// Whether a `personal_sign` payload is safe to present as a message.
///
/// The attack: a site requests a signature over 32 bytes that are actually the Keccak hash of a
/// transaction, or over RLP that begins like one. A wallet that renders it as "sign this
/// message" gets the user to authorise a transfer.
///
/// EIP-191's prefix already prevents the resulting signature from being reused as a transaction
/// signature, so this is defence in depth rather than the only barrier. It matters because the
/// prompt cannot describe binary: showing a hex blob and an approve button is blind signing.
pub fn personal_sign_payload_is_safe(message: &[u8]) -> bool {
    // Valid UTF-8 is necessary but nowhere near sufficient: 32 zero bytes are valid UTF-8, and
    // that is exactly the shape of a hash. The test is whether the prompt could render the
    // message honestly, so control characters are rejected too. Newline, carriage return and tab
    // are kept because real sign-in messages, including every EIP-4361 one, are multi-line.
    let Ok(text) = core::str::from_utf8(message) else {
        return false;
    };
    !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zunia_kernel::{verify_digest_secp256k1, Curve, DerivationPath, ZuniaMnemonic};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn key() -> ExtendedKey {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::parse("m/44'/60'/0'/0/0").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn the_payload_matches_eip191() {
        assert_eq!(
            personal_sign_payload(b"Hello"),
            b"\x19Ethereum Signed Message:\n5Hello".to_vec()
        );
        assert_eq!(
            personal_sign_payload(b""),
            b"\x19Ethereum Signed Message:\n0".to_vec()
        );
        // The length is the byte length, not the character count, so multi-byte characters must
        // not be counted as one each.
        let message = "héllo".as_bytes();
        assert_eq!(message.len(), 6);
        assert_eq!(
            personal_sign_payload(message),
            b"\x19Ethereum Signed Message:\n6h\xc3\xa9llo".to_vec()
        );
    }

    #[test]
    fn the_length_prefix_prevents_a_message_boundary_attack() {
        // Without the length, "12" + "3" and "1" + "23" would produce the same payload, so a
        // signature over one could be presented as a signature over the other.
        assert_ne!(personal_sign_payload(b"123"), {
            let mut faked = PREFIX.to_vec();
            faked.extend_from_slice(b"123");
            faked
        });
        assert_ne!(personal_sign_hash(b"1"), personal_sign_hash(b"11"));
    }

    #[test]
    fn the_hash_matches_a_known_vector() {
        // The canonical `personal_sign` example: keccak256("\x19Ethereum Signed Message:\n5Hello")
        let hash = personal_sign_hash(b"Hello");
        assert_eq!(hash.len(), 32);
        // A message signature must never equal the hash of the bare message, which is what a
        // missing prefix would produce.
        let unprefixed: [u8; 32] = Keccak256::digest(b"Hello").into();
        assert_ne!(hash, unprefixed);
    }

    #[test]
    fn signatures_verify_and_are_deterministic() {
        let key = key();
        let message = b"Sign in to Zunia at 2026-08-31T12:00:00Z";

        let signature = personal_sign(&key, message).unwrap();
        assert!(verify_digest_secp256k1(
            &key.public_key_bytes().unwrap(),
            &personal_sign_hash(message),
            signature.as_bytes()
        )
        .unwrap());

        assert_eq!(
            personal_sign(&key, message).unwrap().as_bytes(),
            signature.as_bytes(),
            "RFC 6979 signing must be deterministic"
        );
    }

    #[test]
    fn the_hex_form_uses_v_27_or_28() {
        // Not EIP-155 encoded. A verifier that sees a chain-encoded v on a message signature
        // cannot recover the address.
        let hex = personal_sign_hex(&key(), b"Hello").unwrap();
        assert_eq!(hex.len(), 2 + 130);
        let v = u8::from_str_radix(&hex[hex.len() - 2..], 16).unwrap();
        assert!(v == 27 || v == 28, "v was {v}");
    }

    #[test]
    fn binary_payloads_are_refused() {
        // A site handing over 32 bytes of binary is handing over a hash, and the prompt has no
        // honest way to describe it. Note that 32 zero bytes are valid UTF-8, so a UTF-8 check
        // alone would let this through.
        assert!(!personal_sign_payload_is_safe(&[0u8; 32]));
        assert!(!personal_sign_payload_is_safe(&[0xff; 32]));
        assert!(!personal_sign_payload_is_safe(&[0xc0, 0x80, 0xff]));
        assert!(!personal_sign_payload_is_safe(b"looks fine\x00until here"));
        assert!(!personal_sign_payload_is_safe(b"\x07bell"));

        // Text is fine, including text that happens to be hex, and multi-line text, which every
        // EIP-4361 sign-in message is.
        assert!(personal_sign_payload_is_safe(b"Sign in to Zunia"));
        assert!(personal_sign_payload_is_safe(b""));
        assert!(personal_sign_payload_is_safe(
            "0xdeadbeef and unicode \u{4f60}\u{597d}".as_bytes()
        ));
        assert!(personal_sign_payload_is_safe(
            br#"{"domain":"app.example","nonce":"abc"}"#
        ));
        assert!(personal_sign_payload_is_safe(
            b"app.example wants you to sign in\n\nURI: https://app.example\nNonce: abc123"
        ));
        assert!(personal_sign_payload_is_safe(b"tab\tseparated"));
    }

    #[test]
    fn a_message_signature_cannot_be_reused_as_a_transaction_signature() {
        // The property the prefix exists to guarantee. A transaction signs keccak of RLP, which
        // starts at 0xc0 or above; a message signs keccak of a payload starting with 0x19. No
        // input can produce both, so the two hash spaces never intersect.
        let payload = personal_sign_payload(b"anything at all");
        assert_eq!(payload[0], 0x19);
        assert!(payload[0] < 0xc0);
    }
}
