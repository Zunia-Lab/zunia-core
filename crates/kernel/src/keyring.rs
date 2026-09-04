use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{KernelError, Result};
use crate::secret::{fill_random, SecretBytes};

/// Envelope format version.
///
/// Stored with the ciphertext so KDF parameters can be strengthened later without orphaning
/// existing wallets: on unlock we read the version and parameters from the envelope, decrypt
/// with them, and re-encrypt with current defaults. A format that hardcodes its parameters can
/// never be upgraded, which is why this field exists from day one.
pub const ENVELOPE_VERSION: u16 = 1;

/// Argon2id defaults.
///
/// 64 MiB and three passes is the OWASP recommendation and takes roughly 100 ms on a modern
/// phone. It is deliberately not tuned to the slowest supported device: the cost of unlocking
/// is paid once per session, and the cost of a weak KDF is paid by every user whose encrypted
/// blob is stolen.
///
/// PBKDF2-SHA256 is not offered at any iteration count. It is trivially parallelised on a GPU,
/// which is exactly the attack this envelope must resist.
pub const DEFAULT_MEMORY_KIB: u32 = 65_536;
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 1;

/// Floors below which we refuse to operate. An envelope claiming weaker parameters is rejected
/// rather than honoured, so a tampered file cannot downgrade the KDF and make a brute force
/// cheap.
const MIN_MEMORY_KIB: u32 = 19_456;
const MIN_ITERATIONS: u32 = 2;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MAX_ITERATIONS: u32 = 16;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// KDF parameters as stored in the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    #[serde(rename = "m")]
    pub memory_kib: u32,
    #[serde(rename = "t")]
    pub iterations: u32,
    #[serde(rename = "p")]
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl KdfParams {
    fn validate(&self) -> Result<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            || self.parallelism == 0
            || self.parallelism > 16
        {
            return Err(KernelError::KdfParams);
        }
        Ok(())
    }

    /// Reduced parameters for a low-memory device.
    ///
    /// Still above the floor. Exposed so a caller can make the tradeoff explicitly rather than
    /// discovering an allocation failure at unlock time on a cheap Android device.
    pub fn low_memory() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 3,
            parallelism: 1,
        }
    }

    /// True if these parameters are weaker than current defaults, meaning the envelope should
    /// be re-encrypted after a successful unlock.
    pub fn needs_upgrade(&self) -> bool {
        self.memory_kib < DEFAULT_MEMORY_KIB || self.iterations < DEFAULT_ITERATIONS
    }
}

/// The encrypted keyring as persisted to disk, `chrome.storage.local`, or the mobile
/// document directory.
///
/// Contains no plaintext secret. Safe to back up, safe to sync, and useless without the
/// password. The `metadata` field is authenticated as AEAD associated data, so an attacker
/// cannot swap the account list or the chain set without invalidating the tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringEnvelope {
    pub version: u16,
    pub kdf: String,
    pub params: KdfParams,
    pub aead: String,
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
    /// Non-secret, authenticated metadata: account labels, derivation paths, enabled chains.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text).map_err(serde::de::Error::custom)
    }
}

impl KeyringEnvelope {
    /// Encrypts `plaintext` under `password`.
    ///
    /// `plaintext` is normally the BIP-39 seed or the serialised keyring. `metadata` is bound
    /// into the AEAD tag, so it is tamper evident but readable without the password, which is
    /// what lets the UI list accounts on a locked wallet.
    pub fn seal(
        plaintext: &[u8],
        password: &str,
        params: KdfParams,
        metadata: serde_json::Value,
    ) -> Result<Self> {
        params.validate()?;

        let mut salt = vec![0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let mut nonce_bytes = vec![0u8; NONCE_LEN];
        fill_random(&mut nonce_bytes)?;

        let key = derive_key(password, &salt, &params)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| KernelError::InvalidKey)?;

        let associated = associated_data(ENVELOPE_VERSION, &params, &metadata)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &associated,
                },
            )
            .map_err(|_| KernelError::Decrypt)?;

        Ok(Self {
            version: ENVELOPE_VERSION,
            kdf: "argon2id".to_owned(),
            params,
            aead: "xchacha20poly1305".to_owned(),
            salt,
            nonce: nonce_bytes,
            ciphertext,
            metadata,
        })
    }

    /// Decrypts with `password`.
    ///
    /// Returns [`KernelError::Decrypt`] for a wrong password and for a tampered envelope
    /// alike. Distinguishing them would hand an attacker an oracle, and there is nothing the
    /// user can do differently in either case.
    pub fn open(&self, password: &str) -> Result<SecretBytes> {
        if self.version > ENVELOPE_VERSION {
            return Err(KernelError::EnvelopeVersion(self.version));
        }
        if self.kdf != "argon2id" || self.aead != "xchacha20poly1305" {
            return Err(KernelError::EnvelopeFormat);
        }
        if self.salt.len() != SALT_LEN || self.nonce.len() != NONCE_LEN {
            return Err(KernelError::EnvelopeFormat);
        }
        self.params.validate()?;

        let key = derive_key(password, &self.salt, &self.params)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| KernelError::InvalidKey)?;

        let associated = associated_data(self.version, &self.params, &self.metadata)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &associated,
                },
            )
            .map_err(|_| KernelError::Decrypt)?;

        Ok(SecretBytes::new(plaintext))
    }

    /// Re-encrypts under a new password, keeping the metadata.
    pub fn change_password(
        &self,
        current: &str,
        new_password: &str,
        params: KdfParams,
    ) -> Result<Self> {
        let plaintext = self.open(current)?;
        Self::seal(
            plaintext.expose(),
            new_password,
            params,
            self.metadata.clone(),
        )
    }

    /// Re-encrypts with current default parameters, for use after unlocking an envelope whose
    /// [`KdfParams::needs_upgrade`] returns true.
    pub fn upgrade(&self, password: &str) -> Result<Self> {
        let plaintext = self.open(password)?;
        Self::seal(
            plaintext.expose(),
            password,
            KdfParams::default(),
            self.metadata.clone(),
        )
    }

    /// Replaces the authenticated metadata. Requires the password because the metadata is
    /// bound into the AEAD tag.
    pub fn with_metadata(&self, password: &str, metadata: serde_json::Value) -> Result<Self> {
        let plaintext = self.open(password)?;
        Self::seal(plaintext.expose(), password, self.params, metadata)
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| KernelError::EnvelopeFormat)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|_| KernelError::EnvelopeFormat)
    }
}

/// Argon2id key derivation.
fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<SecretBytes> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| KernelError::KdfParams)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| KernelError::KdfParams)?;
    Ok(SecretBytes::from_slice(&key))
}

/// Builds the AEAD associated data.
///
/// Binding the version and parameters means an attacker cannot rewrite them to something
/// weaker and have the tag still verify. Binding the metadata means the account list cannot be
/// swapped, which would otherwise let an attacker change a stored derivation path so the
/// wallet derives, and displays, an address they control.
fn associated_data(
    version: u16,
    params: &KdfParams,
    metadata: &serde_json::Value,
) -> Result<Vec<u8>> {
    let canonical = serde_json::json!({
        "v": version,
        "kdf": "argon2id",
        "params": params,
        "aead": "xchacha20poly1305",
        "meta": metadata,
    });
    serde_json::to_vec(&canonical).map_err(|_| KernelError::EnvelopeFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test parameters. The real defaults allocate 64 MiB per call, which makes a test suite
    /// with dozens of seal and open round trips unpleasantly slow. Correctness does not depend
    /// on the cost parameters, and `defaults_are_at_least_owasp_minimums` covers the values
    /// that actually ship.
    fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    fn meta() -> serde_json::Value {
        serde_json::json!({
            "accounts": [{ "label": "Main", "path": "m/44'/118'/0'/0/0" }],
            "chains": ["safrochain-1", "cosmoshub-4"]
        })
    }

    #[test]
    fn seals_and_opens() {
        let seed = [7u8; 64];
        let envelope =
            KeyringEnvelope::seal(&seed, "correct horse", fast_params(), meta()).unwrap();
        let opened = envelope.open("correct horse").unwrap();
        assert_eq!(opened.expose(), &seed);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let envelope = KeyringEnvelope::seal(&[1u8; 32], "right", fast_params(), meta()).unwrap();
        assert_eq!(
            envelope.open("wrong").unwrap_err(),
            KernelError::Decrypt,
            "must not distinguish a wrong password from a tampered envelope"
        );
        assert_eq!(envelope.open("").unwrap_err(), KernelError::Decrypt);
    }

    #[test]
    fn ciphertext_contains_no_plaintext() {
        let seed = b"this is the secret seed material";
        let envelope = KeyringEnvelope::seal(seed, "pw", fast_params(), meta()).unwrap();
        assert!(!envelope
            .ciphertext
            .windows(seed.len())
            .any(|window| window == seed));
        let json = envelope.to_json().unwrap();
        assert!(!json.contains("secret seed"));
    }

    #[test]
    fn two_seals_of_the_same_input_differ() {
        // Random salt and nonce per seal, so identical inputs must not produce identical
        // output. If they did, an attacker could tell two users share a password.
        let a = KeyringEnvelope::seal(&[0u8; 32], "pw", fast_params(), meta()).unwrap();
        let b = KeyringEnvelope::seal(&[0u8; 32], "pw", fast_params(), meta()).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut envelope = KeyringEnvelope::seal(&[3u8; 32], "pw", fast_params(), meta()).unwrap();
        envelope.ciphertext[0] ^= 0x01;
        assert_eq!(envelope.open("pw").unwrap_err(), KernelError::Decrypt);
    }

    #[test]
    fn tampered_metadata_is_rejected() {
        // The attack this prevents: rewrite the stored derivation path so the wallet derives
        // and displays an address the attacker controls, while the ciphertext stays valid.
        let mut envelope = KeyringEnvelope::seal(&[4u8; 32], "pw", fast_params(), meta()).unwrap();
        envelope.metadata = serde_json::json!({
            "accounts": [{ "label": "Main", "path": "m/44'/118'/0'/0/99" }]
        });
        assert_eq!(envelope.open("pw").unwrap_err(), KernelError::Decrypt);
    }

    #[test]
    fn downgraded_kdf_params_are_rejected() {
        // Without validation plus authentication, an attacker rewrites the parameters to
        // something trivially brute forceable and the envelope still opens.
        let mut envelope = KeyringEnvelope::seal(&[5u8; 32], "pw", fast_params(), meta()).unwrap();
        envelope.params.memory_kib = 8;
        envelope.params.iterations = 1;
        assert_eq!(envelope.open("pw").unwrap_err(), KernelError::KdfParams);
    }

    #[test]
    fn params_within_range_but_altered_are_rejected() {
        // Legal-looking parameters, but not the ones used to seal, so the AEAD tag fails.
        let mut envelope = KeyringEnvelope::seal(&[6u8; 32], "pw", fast_params(), meta()).unwrap();
        envelope.params.iterations += 1;
        assert_eq!(envelope.open("pw").unwrap_err(), KernelError::Decrypt);
    }

    #[test]
    fn future_version_is_refused() {
        let mut envelope = KeyringEnvelope::seal(&[7u8; 32], "pw", fast_params(), meta()).unwrap();
        envelope.version = ENVELOPE_VERSION + 1;
        assert_eq!(
            envelope.open("pw").unwrap_err(),
            KernelError::EnvelopeVersion(ENVELOPE_VERSION + 1)
        );
    }

    #[test]
    fn unknown_primitives_are_refused() {
        let mut envelope = KeyringEnvelope::seal(&[8u8; 32], "pw", fast_params(), meta()).unwrap();
        let good = envelope.clone();
        envelope.kdf = "pbkdf2".to_owned();
        assert_eq!(
            envelope.open("pw").unwrap_err(),
            KernelError::EnvelopeFormat
        );
        envelope = good;
        envelope.aead = "aes-256-cbc".to_owned();
        assert_eq!(
            envelope.open("pw").unwrap_err(),
            KernelError::EnvelopeFormat
        );
    }

    #[test]
    fn truncated_salt_or_nonce_is_refused() {
        let base = KeyringEnvelope::seal(&[9u8; 32], "pw", fast_params(), meta()).unwrap();
        let mut short_salt = base.clone();
        short_salt.salt.truncate(8);
        assert_eq!(
            short_salt.open("pw").unwrap_err(),
            KernelError::EnvelopeFormat
        );
        let mut short_nonce = base;
        short_nonce.nonce.truncate(12);
        assert_eq!(
            short_nonce.open("pw").unwrap_err(),
            KernelError::EnvelopeFormat
        );
    }

    #[test]
    fn json_round_trips() {
        let envelope = KeyringEnvelope::seal(&[10u8; 64], "pw", fast_params(), meta()).unwrap();
        let restored = KeyringEnvelope::from_json(&envelope.to_json().unwrap()).unwrap();
        assert_eq!(restored.open("pw").unwrap().expose(), &[10u8; 64]);
        assert_eq!(restored.metadata, meta());
    }

    #[test]
    fn malformed_json_is_refused() {
        assert!(KeyringEnvelope::from_json("{").is_err());
        assert!(KeyringEnvelope::from_json("{\"version\":1}").is_err());
    }

    #[test]
    fn password_change_preserves_the_secret() {
        let seed = [11u8; 64];
        let envelope = KeyringEnvelope::seal(&seed, "old", fast_params(), meta()).unwrap();
        let rotated = envelope
            .change_password("old", "new", fast_params())
            .unwrap();
        assert_eq!(rotated.open("new").unwrap().expose(), &seed);
        assert!(rotated.open("old").is_err());
        assert!(envelope
            .change_password("wrong", "new", fast_params())
            .is_err());
    }

    #[test]
    fn upgrade_strengthens_parameters() {
        let weak = KdfParams::low_memory();
        assert!(weak.needs_upgrade());
        let envelope = KeyringEnvelope::seal(&[12u8; 32], "pw", weak, meta()).unwrap();
        let upgraded = envelope.upgrade("pw").unwrap();
        assert_eq!(upgraded.params, KdfParams::default());
        assert!(!upgraded.params.needs_upgrade());
        assert_eq!(upgraded.open("pw").unwrap().expose(), &[12u8; 32]);
    }

    #[test]
    fn metadata_can_be_replaced_with_the_password() {
        let envelope = KeyringEnvelope::seal(&[13u8; 32], "pw", fast_params(), meta()).unwrap();
        let updated = envelope
            .with_metadata("pw", serde_json::json!({ "accounts": [] }))
            .unwrap();
        assert_eq!(updated.metadata, serde_json::json!({ "accounts": [] }));
        assert_eq!(updated.open("pw").unwrap().expose(), &[13u8; 32]);
        assert!(envelope
            .with_metadata("wrong", serde_json::json!({}))
            .is_err());
    }

    #[test]
    fn defaults_are_at_least_owasp_minimums() {
        let defaults = KdfParams::default();
        defaults.validate().unwrap();
        assert!(defaults.memory_kib >= 19_456);
        assert!(defaults.iterations >= 2);
        assert!(!defaults.needs_upgrade());
        KdfParams::low_memory().validate().unwrap();
    }

    #[test]
    fn absurd_parameters_are_refused_at_seal_time() {
        for bad in [
            KdfParams {
                memory_kib: 1,
                iterations: 3,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: 65_536,
                iterations: 0,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 0,
            },
            KdfParams {
                memory_kib: MAX_MEMORY_KIB + 1,
                iterations: 3,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: 65_536,
                iterations: MAX_ITERATIONS + 1,
                parallelism: 1,
            },
        ] {
            assert_eq!(
                KeyringEnvelope::seal(&[0u8; 32], "pw", bad, meta()).unwrap_err(),
                KernelError::KdfParams,
                "should refuse {bad:?}"
            );
        }
    }

    #[test]
    fn real_defaults_work_end_to_end() {
        // One slow test proving the shipped parameters are usable, since every other test in
        // this module deliberately uses reduced cost.
        let envelope =
            KeyringEnvelope::seal(&[14u8; 64], "pw", KdfParams::default(), meta()).unwrap();
        assert_eq!(envelope.open("pw").unwrap().expose(), &[14u8; 64]);
    }
}
