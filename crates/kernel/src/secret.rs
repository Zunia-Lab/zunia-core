use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{KernelError, Result};

/// Owned secret bytes that are wiped when dropped and never printed.
///
/// The `Debug` implementation prints only the length. This is not cosmetic: a `Debug` on a
/// secret is how key material ends up in a log line, a panic message or a crash report, which
/// is the exact leak `PRE-DEVELOPMENT.md` §3.2 forbids.
///
/// Zeroization is best effort in the same sense it is everywhere: the compiler may have copied
/// the value before we got here, and a `Vec` reallocation leaves the old buffer untouched.
/// `SecretBytes::with_capacity` exists so callers can avoid the reallocation case.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Allocates up front so pushes cannot reallocate and leave a copy of the secret behind.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(bytes.len());
        buf.extend_from_slice(bytes);
        Self(buf)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, byte: u8) {
        self.0.push(byte);
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    /// Fixed-size view, for callers that need a `[u8; N]` such as a curve scalar.
    pub fn as_array<const N: usize>(&self) -> Result<[u8; N]> {
        if self.0.len() != N {
            return Err(KernelError::InvalidKey);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.0);
        Ok(out)
    }

    /// Constant-time equality. Never compare secrets with `==` on slices.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.ct_eq(&other.0).into()
    }

    /// Wipes the contents immediately rather than waiting for drop. Useful when a secret is
    /// held in a long-lived struct that outlives its usefulness, such as a session cache
    /// being locked.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes, redacted)", self.0.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Opt out of accidental serialisation. A secret that can be serialised will eventually be
/// serialised into somewhere it should not be.
impl serde::Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, _: S) -> core::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "SecretBytes must not be serialised",
        ))
    }
}

/// Owned secret string, for a mnemonic or a passphrase.
///
/// Same rules as [`SecretBytes`]: redacted formatting, wiped on drop, refuses serialisation.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({} bytes, redacted)", self.0.len())
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl serde::Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, _: S) -> core::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "SecretString must not be serialised",
        ))
    }
}

/// Fills a buffer from the platform CSPRNG.
///
/// The only randomness entry point in the kernel. There is no fallback: if the platform RNG
/// fails we return an error rather than degrade, per `mnemonic_security.yaml`
/// (`source: platform_csprng_only`, `forbid_math_random: true`).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    use rand_core::{OsRng, RngCore};
    OsRng.try_fill_bytes(buf).map_err(|_| KernelError::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_contents() {
        let secret = SecretBytes::from_slice(b"correct horse battery staple");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("horse"));

        let text = SecretString::from("abandon abandon about");
        assert!(!format!("{text:?}").contains("abandon"));
        assert_eq!(format!("{text}"), "[redacted]");
    }

    #[test]
    fn serialisation_is_refused() {
        let secret = SecretBytes::from_slice(b"key");
        assert!(serde_json::to_string(&secret).is_err());
        let text = SecretString::from("mnemonic");
        assert!(serde_json::to_string(&text).is_err());
    }

    #[test]
    fn constant_time_eq_matches_value_equality() {
        let a = SecretBytes::from_slice(b"aaaa");
        let b = SecretBytes::from_slice(b"aaaa");
        let c = SecretBytes::from_slice(b"aaab");
        let d = SecretBytes::from_slice(b"aaa");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d));
    }

    #[test]
    fn wipe_clears_contents() {
        let mut secret = SecretBytes::from_slice(b"sensitive");
        secret.wipe();
        assert!(secret.is_empty());
    }

    #[test]
    fn as_array_enforces_length() {
        let secret = SecretBytes::from_slice(&[1u8; 32]);
        assert!(secret.as_array::<32>().is_ok());
        assert_eq!(
            secret.as_array::<31>().unwrap_err(),
            KernelError::InvalidKey
        );
    }

    #[test]
    fn random_fills_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b, "two draws must not be identical");
    }
}
