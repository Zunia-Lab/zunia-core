//! Zunia wallet kernel.
//!
//! The only place in the product where private key material exists in plaintext. The
//! JavaScript and Dart layers above hold opaque handles and never see key bytes, per
//! [ADR-0002](../../../docs/adr/0002-wallet-kernel-language.md).
//!
//! Custody is self-custody only, per
//! [ADR-0003](../../../docs/adr/0003-custody-model.md). There is deliberately no API here for
//! key escrow, key sharing, MPC shares, or exporting a seed to a server, and adding one
//! requires revising that ADR first.
//!
//! # What this crate guarantees
//!
//! - Entropy comes from the platform CSPRNG and nothing else. There is no seeded or
//!   user-supplied randomness API.
//! - Every type holding secret bytes redacts its `Debug`, refuses `Serialize`, and zeroizes on
//!   drop.
//! - Signatures are low-s normalised, so a chain will not intermittently reject them.
//! - Addresses are derived under the scheme the chain actually uses, Cosmos or Ethermint, and
//!   validated against the expected bech32 prefix before use.
//! - The keyring envelope authenticates its own KDF parameters and metadata, so neither can be
//!   downgraded or swapped.
//!
//! # What it does not do
//!
//! Zeroization is best effort in a garbage-collected or moving-allocator world. A value may
//! have been copied before it reached a `Zeroizing` wrapper, and in WASM the linear memory is
//! visible to the host page. The extension mitigates this by keeping the kernel in the
//! background context only, never in a content script. This limitation is documented rather
//! than hidden.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, clippy::all)]

pub mod address;
pub mod derive;
pub mod error;
pub mod keyring;
pub mod mnemonic;
pub mod secret;
pub mod sign;

pub use address::{
    convert_prefix, decode_bech32, solana_address, validate_address, validate_eth_address,
    AccountId, AddressScheme, DecodedAddress,
};
pub use derive::{Curve, DerivationPath, ExtendedKey, HARDENED};
pub use error::{KernelError, Result};
pub use keyring::{KdfParams, KeyringEnvelope, ENVELOPE_VERSION};
pub use mnemonic::{is_wordlist_word, wordlist_suggestions, WordCount, ZuniaMnemonic};
pub use secret::{SecretBytes, SecretString};
pub use sign::{
    sign_cosmos, sign_digest_secp256k1, sign_ed25519, verify_digest_secp256k1, verify_ed25519,
    Signature,
};

/// Kernel version, surfaced to the UI so a support request can identify the build.
pub const KERNEL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A derived account, ready to display and to sign with.
///
/// Holds the extended key, so it is secret. The public parts are exposed through methods
/// rather than fields so a caller cannot serialise the whole struct by accident.
pub struct Account {
    key: ExtendedKey,
    path: DerivationPath,
    scheme: AddressScheme,
    prefix: String,
}

impl Account {
    /// Derives an account from a BIP-39 seed.
    ///
    /// `curve`, `scheme`, `prefix` and the coin type inside `path` all come from the chain
    /// registry. Nothing here is hardcoded per chain, which is what allows Terra's coin type
    /// 330 and Injective's Ethermint addressing to work without a code change.
    pub fn derive(
        seed: &[u8],
        curve: Curve,
        path: DerivationPath,
        scheme: AddressScheme,
        prefix: &str,
    ) -> Result<Self> {
        let key = ExtendedKey::from_seed_and_path(curve, seed, &path)?;
        Ok(Self {
            key,
            path,
            scheme,
            prefix: prefix.to_lowercase(),
        })
    }

    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        self.key.public_key_bytes()
    }

    pub fn account_id(&self) -> Result<AccountId> {
        AccountId::from_public_key(self.scheme, &self.key.public_key_bytes()?)
    }

    /// The bech32 address for this chain.
    pub fn address(&self) -> Result<String> {
        self.account_id()?.to_bech32(&self.prefix)
    }

    /// The EIP-55 hex address. Only meaningful on an Ethermint or EVM chain.
    pub fn eth_address(&self) -> Result<String> {
        if self.scheme != AddressScheme::Ethermint {
            return Err(KernelError::InvalidAddress);
        }
        Ok(self.account_id()?.to_eth_hex())
    }

    /// Signs Cosmos sign bytes: SHA-256 then secp256k1, low-s normalised.
    pub fn sign_cosmos(&self, sign_bytes: &[u8]) -> Result<Signature> {
        sign::sign_cosmos(&self.key, sign_bytes)
    }

    pub fn key(&self) -> &ExtendedKey {
        &self.key
    }
}

impl core::fmt::Debug for Account {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The address is public information, so it is safe to show and useful when debugging.
        // The key is not.
        write!(
            f,
            "Account({}, {}, {:?}, key redacted)",
            self.path,
            self.address().unwrap_or_else(|_| "<invalid>".into()),
            self.scheme
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREZOR_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn seed() -> SecretBytes {
        ZuniaMnemonic::parse(TREZOR_12).unwrap().to_seed("")
    }

    #[test]
    fn derives_a_cosmos_account_end_to_end() {
        let account = Account::derive(
            seed().expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "cosmos",
        )
        .unwrap();

        assert_eq!(
            account.address().unwrap(),
            "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4"
        );
        assert_eq!(account.public_key().unwrap().len(), 33);
        assert!(account.eth_address().is_err(), "not an Ethermint chain");
    }

    #[test]
    fn derives_an_ethermint_account_end_to_end() {
        let account = Account::derive(
            seed().expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(60, 0, 0),
            AddressScheme::Ethermint,
            "inj",
        )
        .unwrap();
        assert!(account.address().unwrap().starts_with("inj1"));
        assert_eq!(
            account.eth_address().unwrap(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn account_signs_and_verifies() {
        let account = Account::derive(
            seed().expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "safro",
        )
        .unwrap();
        let signature = account.sign_cosmos(b"sign doc bytes").unwrap();
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(b"sign doc bytes").into();
        assert!(verify_digest_secp256k1(
            &account.public_key().unwrap(),
            &digest,
            signature.as_bytes()
        )
        .unwrap());
    }

    #[test]
    fn different_indices_give_different_accounts() {
        let a = Account::derive(
            seed().expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "cosmos",
        )
        .unwrap();
        let b = Account::derive(
            seed().expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 1),
            AddressScheme::Cosmos,
            "cosmos",
        )
        .unwrap();
        assert_ne!(a.address().unwrap(), b.address().unwrap());
    }

    #[test]
    fn debug_shows_address_but_never_the_key() {
        let account = Account::derive(
            seed().expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "cosmos",
        )
        .unwrap();
        let rendered = format!("{account:?}");
        assert!(rendered.contains("cosmos1"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn full_wallet_lifecycle() {
        // Create, back up, verify the backup, encrypt, forget, restore, derive the same
        // address. This is the flow onboarding actually performs.
        let mnemonic = ZuniaMnemonic::generate(WordCount::TwentyFour).unwrap();

        let positions = mnemonic.verification_positions(4).unwrap();
        let words = mnemonic.words();
        let answers: Vec<(usize, String)> = positions
            .iter()
            .map(|i| (*i, words[*i].expose().to_owned()))
            .collect();
        assert!(mnemonic.verify_positions(&answers));

        let seed = mnemonic.to_seed("");
        let original = Account::derive(
            seed.expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "safro",
        )
        .unwrap()
        .address()
        .unwrap();

        let envelope = KeyringEnvelope::seal(
            mnemonic.phrase().expose().as_bytes(),
            "user password",
            KdfParams::low_memory(),
            serde_json::json!({ "accounts": [{ "path": "m/44'/118'/0'/0/0" }] }),
        )
        .unwrap();
        let json = envelope.to_json().unwrap();

        // Everything is dropped and only the encrypted JSON survives, which is the state on
        // disk between sessions.
        let restored = KeyringEnvelope::from_json(&json).unwrap();
        let phrase = restored.open("user password").unwrap();
        let recovered =
            ZuniaMnemonic::parse(core::str::from_utf8(phrase.expose()).unwrap()).unwrap();
        let recovered_address = Account::derive(
            recovered.to_seed("").expose(),
            Curve::Secp256k1,
            DerivationPath::bip44(118, 0, 0),
            AddressScheme::Cosmos,
            "safro",
        )
        .unwrap()
        .address()
        .unwrap();

        assert_eq!(original, recovered_address);
    }
}
