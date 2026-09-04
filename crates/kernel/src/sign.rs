use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::derive::{Curve, ExtendedKey};
use crate::error::{KernelError, Result};

/// A 64-byte signature, plus a recovery id when the curve provides one.
///
/// Cosmos wire format is raw `r || s` with low-s normalisation and no recovery byte. Ethereum
/// needs the recovery id, so it is carried separately rather than appended, which keeps the
/// Cosmos path from accidentally shipping 65 bytes where a chain expects 64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; 64],
    recovery_id: Option<u8>,
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn recovery_id(&self) -> Option<u8> {
        self.recovery_id
    }

    /// 65-byte Ethereum form, `r || s || v` where v is 27 or 28.
    pub fn to_eth_rsv(&self) -> Result<[u8; 65]> {
        let recovery = self.recovery_id.ok_or(KernelError::Signature)?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&self.bytes);
        out[64] = recovery + 27;
        Ok(out)
    }

    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.bytes)
    }
}

/// Signs an already-hashed 32-byte digest with secp256k1.
///
/// The caller hashes, because Cosmos signs `sha256(sign_bytes)` while Ethereum signs
/// `keccak256(rlp)`, and hiding that inside the signer invites signing the wrong preimage.
///
/// Signatures are low-s normalised. Without it, roughly half of all signatures are rejected by
/// Cosmos SDK chains, which enforce the canonical form, and the failure is intermittent, so it
/// looks like a network problem rather than a signing bug.
pub fn sign_digest_secp256k1(key: &ExtendedKey, digest: &[u8; 32]) -> Result<Signature> {
    if key.curve() != Curve::Secp256k1 {
        return Err(KernelError::InvalidKey);
    }
    let signing =
        SigningKey::from_slice(key.private_key().expose()).map_err(|_| KernelError::InvalidKey)?;

    let (signature, recovery): (K256Signature, RecoveryId) = signing
        .sign_prehash(digest)
        .map_err(|_| KernelError::Signature)?;

    // RustCrypto returns a normalised signature, but assert rather than assume: a future
    // version that changed this default would silently break broadcast on every chain.
    let normalised = signature.normalize_s().unwrap_or(signature);
    debug_assert!(
        normalised.normalize_s().is_none(),
        "signature must be low-s"
    );

    let bytes: [u8; 64] = normalised.to_bytes().into();
    Ok(Signature {
        bytes,
        recovery_id: Some(recovery.to_byte()),
    })
}

/// Hashes with SHA-256 then signs. The Cosmos signing path.
pub fn sign_cosmos(key: &ExtendedKey, sign_bytes: &[u8]) -> Result<Signature> {
    let digest: [u8; 32] = Sha256::digest(sign_bytes).into();
    sign_digest_secp256k1(key, &digest)
}

/// Signs a message with ed25519. Used by Solana, which signs the message directly.
pub fn sign_ed25519(key: &ExtendedKey, message: &[u8]) -> Result<Signature> {
    use ed25519_dalek::{Signer, SigningKey as EdSigningKey};

    if key.curve() != Curve::Ed25519 {
        return Err(KernelError::InvalidKey);
    }
    let bytes: [u8; 32] = key.private_key().as_array()?;
    let signing = EdSigningKey::from_bytes(&bytes);
    Ok(Signature {
        bytes: signing.sign(message).to_bytes(),
        recovery_id: None,
    })
}

/// Verifies a secp256k1 signature over a digest.
///
/// Used by the test vectors and by `verifyArbitrary` in the provider API, where a dApp asks
/// the wallet to confirm a signature it was given.
pub fn verify_digest_secp256k1(
    public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<bool> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    let verifying =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| KernelError::InvalidKey)?;
    let signature = K256Signature::from_slice(signature).map_err(|_| KernelError::Signature)?;

    // Reject a high-s signature outright rather than accepting both forms. Accepting both
    // makes signatures malleable, which turns a transaction hash into something an attacker
    // can change without invalidating the signature.
    if signature.normalize_s().is_some() {
        return Ok(false);
    }

    Ok(verifying.verify_prehash(digest, &signature).is_ok())
}

/// Verifies an ed25519 signature.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey as EdVerifyingKey};

    let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| KernelError::InvalidKey)?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| KernelError::Signature)?;
    let verifying = EdVerifyingKey::from_bytes(&key_bytes).map_err(|_| KernelError::InvalidKey)?;
    Ok(verifying
        .verify(message, &EdSignature::from_bytes(&sig_bytes))
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{DerivationPath, ExtendedKey};
    use crate::mnemonic::ZuniaMnemonic;

    const TREZOR_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn secp_key() -> ExtendedKey {
        let seed = ZuniaMnemonic::parse(TREZOR_12).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::bip44(118, 0, 0),
        )
        .unwrap()
    }

    fn ed_key() -> ExtendedKey {
        let seed = ZuniaMnemonic::parse(TREZOR_12).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Ed25519,
            seed.expose(),
            &DerivationPath::slip10_ed25519(501, 0),
        )
        .unwrap()
    }

    #[test]
    fn cosmos_signature_round_trips() {
        let key = secp_key();
        let message = b"zunia sign bytes";
        let signature = sign_cosmos(&key, message).unwrap();
        let digest: [u8; 32] = Sha256::digest(message).into();

        assert_eq!(signature.as_bytes().len(), 64);
        assert!(verify_digest_secp256k1(
            &key.public_key_bytes().unwrap(),
            &digest,
            signature.as_bytes()
        )
        .unwrap());
    }

    #[test]
    fn signature_is_deterministic() {
        // RFC 6979 deterministic nonces mean the same key and message always produce the same
        // signature. A change here would indicate the nonce source changed, which is a
        // catastrophic class of bug worth catching in CI.
        let key = secp_key();
        let a = sign_cosmos(&key, b"same message").unwrap();
        let b = sign_cosmos(&key, b"same message").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn signature_is_low_s() {
        let key = secp_key();
        // Many messages, because high-s only shows up about half the time before
        // normalisation.
        for i in 0..64u32 {
            let signature = sign_cosmos(&key, &i.to_be_bytes()).unwrap();
            let parsed = K256Signature::from_slice(signature.as_bytes()).unwrap();
            assert!(
                parsed.normalize_s().is_none(),
                "signature {i} was not low-s normalised"
            );
        }
    }

    #[test]
    fn rejects_tampered_message() {
        let key = secp_key();
        let signature = sign_cosmos(&key, b"original").unwrap();
        let other: [u8; 32] = Sha256::digest(b"tampered").into();
        assert!(!verify_digest_secp256k1(
            &key.public_key_bytes().unwrap(),
            &other,
            signature.as_bytes()
        )
        .unwrap());
    }

    #[test]
    fn rejects_wrong_public_key() {
        let key = secp_key();
        let other = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            ZuniaMnemonic::parse(TREZOR_12)
                .unwrap()
                .to_seed("")
                .expose(),
            &DerivationPath::bip44(118, 0, 1),
        )
        .unwrap();
        let signature = sign_cosmos(&key, b"message").unwrap();
        let digest: [u8; 32] = Sha256::digest(b"message").into();
        assert!(!verify_digest_secp256k1(
            &other.public_key_bytes().unwrap(),
            &digest,
            signature.as_bytes()
        )
        .unwrap());
    }

    #[test]
    fn eth_rsv_appends_recovery_byte() {
        let key = secp_key();
        let signature = sign_cosmos(&key, b"message").unwrap();
        let rsv = signature.to_eth_rsv().unwrap();
        assert_eq!(rsv.len(), 65);
        assert!(rsv[64] == 27 || rsv[64] == 28);
        assert_eq!(&rsv[..64], signature.as_bytes());
    }

    #[test]
    fn ed25519_signature_round_trips() {
        let key = ed_key();
        let signature = sign_ed25519(&key, b"solana message").unwrap();
        assert!(signature.recovery_id().is_none());
        assert!(verify_ed25519(
            &key.public_key_bytes().unwrap(),
            b"solana message",
            signature.as_bytes()
        )
        .unwrap());
        assert!(!verify_ed25519(
            &key.public_key_bytes().unwrap(),
            b"different message",
            signature.as_bytes()
        )
        .unwrap());
    }

    #[test]
    fn ed25519_has_no_eth_form() {
        let key = ed_key();
        let signature = sign_ed25519(&key, b"message").unwrap();
        assert!(signature.to_eth_rsv().is_err());
    }

    #[test]
    fn curve_mismatch_is_rejected() {
        assert_eq!(
            sign_cosmos(&ed_key(), b"message").unwrap_err(),
            KernelError::InvalidKey
        );
        assert_eq!(
            sign_ed25519(&secp_key(), b"message").unwrap_err(),
            KernelError::InvalidKey
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let digest = [0u8; 32];
        assert!(verify_digest_secp256k1(&[0u8; 33], &digest, &[0u8; 64]).is_err());
        assert!(verify_ed25519(&[0u8; 31], b"m", &[0u8; 64]).is_err());
        assert!(verify_ed25519(&[0u8; 32], b"m", &[0u8; 63]).is_err());
    }

    #[test]
    fn base64_encoding_is_standard() {
        let key = secp_key();
        let signature = sign_cosmos(&key, b"message").unwrap();
        let encoded = signature.to_base64();
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(decoded, signature.to_vec());
    }
}
