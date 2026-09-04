use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::error::{KernelError, Result};
use crate::secret::{fill_random, SecretBytes, SecretString};

/// Supported mnemonic strengths.
///
/// 12 words is the floor. 24 is offered as an advanced option, per `PRE-DEVELOPMENT.md` §3.1.
/// The intermediate lengths exist because imported wallets use them, not because we generate
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    TwentyFour,
}

impl WordCount {
    pub fn words(self) -> usize {
        match self {
            Self::Twelve => 12,
            Self::Fifteen => 15,
            Self::Eighteen => 18,
            Self::TwentyOne => 21,
            Self::TwentyFour => 24,
        }
    }

    pub fn entropy_bytes(self) -> usize {
        // BIP-39: ENT = words * 11 - words / 3, in bits. Reduces to these five cases.
        match self {
            Self::Twelve => 16,
            Self::Fifteen => 20,
            Self::Eighteen => 24,
            Self::TwentyOne => 28,
            Self::TwentyFour => 32,
        }
    }

    pub fn from_words(words: usize) -> Result<Self> {
        match words {
            12 => Ok(Self::Twelve),
            15 => Ok(Self::Fifteen),
            18 => Ok(Self::Eighteen),
            21 => Ok(Self::TwentyOne),
            24 => Ok(Self::TwentyFour),
            other => Err(KernelError::MnemonicLength(other)),
        }
    }
}

/// A validated BIP-39 mnemonic.
///
/// Construction always validates the checksum, so a `ZuniaMnemonic` in hand means the phrase
/// is well formed. The phrase itself is only reachable through [`Self::phrase`], which returns
/// a [`SecretString`], so it cannot be logged by accident.
pub struct ZuniaMnemonic {
    inner: Mnemonic,
}

impl ZuniaMnemonic {
    /// Generates a new mnemonic from the platform CSPRNG.
    ///
    /// Entropy comes from [`fill_random`] and nowhere else. There is deliberately no API that
    /// accepts user-supplied "randomness", because dice rolls typed into a text field are the
    /// classic way to generate a weak wallet.
    pub fn generate(count: WordCount) -> Result<Self> {
        let mut entropy = Zeroizing::new(vec![0u8; count.entropy_bytes()]);
        fill_random(&mut entropy)?;
        let inner =
            Mnemonic::from_entropy_in(Language::English, &entropy).map_err(map_bip39_error)?;
        Ok(Self { inner })
    }

    /// Rebuilds a mnemonic from raw entropy. Used by the test vectors and by import from a
    /// backup that stored entropy rather than words.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        match entropy.len() {
            16 | 20 | 24 | 28 | 32 => {}
            other => return Err(KernelError::EntropyLength(other)),
        }
        let inner =
            Mnemonic::from_entropy_in(Language::English, entropy).map_err(map_bip39_error)?;
        Ok(Self { inner })
    }

    /// Parses and validates a phrase.
    ///
    /// Normalises whitespace and case first, because users paste phrases with newlines, double
    /// spaces and capitals, and rejecting those as "invalid mnemonic" is a support burden with
    /// no security benefit. The checksum is still enforced.
    pub fn parse(phrase: &str) -> Result<Self> {
        let normalised = Zeroizing::new(normalise_phrase(phrase));
        let word_count = normalised.split(' ').filter(|w| !w.is_empty()).count();
        WordCount::from_words(word_count)?;
        let inner =
            Mnemonic::parse_in(Language::English, normalised.as_str()).map_err(map_bip39_error)?;
        Ok(Self { inner })
    }

    /// The phrase, wrapped so it cannot be printed or serialised.
    pub fn phrase(&self) -> SecretString {
        SecretString::new(self.inner.to_string())
    }

    /// The individual words, for rendering a `MnemonicGrid` in the UI.
    ///
    /// The caller is responsible for the display rules in `mnemonic_security.yaml`: blur by
    /// default, hold to reveal, auto-hide, no screenshots.
    pub fn words(&self) -> Vec<SecretString> {
        self.inner
            .words()
            .map(|w| SecretString::new(w.to_owned()))
            .collect()
    }

    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// Raw entropy behind the phrase.
    pub fn entropy(&self) -> SecretBytes {
        let (bytes, len) = self.inner.to_entropy_array();
        SecretBytes::from_slice(&bytes[..len])
    }

    /// Derives the 64-byte BIP-39 seed.
    ///
    /// `passphrase` is the optional BIP-39 "25th word". An empty passphrase and no passphrase
    /// are the same thing by specification. A non-empty passphrase produces a completely
    /// different wallet and is unrecoverable if forgotten, so the UI must warn loudly before
    /// accepting one.
    pub fn to_seed(&self, passphrase: &str) -> SecretBytes {
        SecretBytes::from_slice(&self.inner.to_seed(passphrase))
    }

    /// Positions to ask the user to retype during backup verification.
    ///
    /// Returns `count` distinct zero-based indices drawn from the platform CSPRNG. Typed entry
    /// is required rather than multiple choice, per `mnemonic_security.yaml`
    /// (`random_word_positions: 4`), because tapping the right chip out of three proves far
    /// less than writing the word.
    pub fn verification_positions(&self, count: usize) -> Result<Vec<usize>> {
        let total = self.word_count();
        let wanted = count.min(total);
        let mut chosen: Vec<usize> = Vec::with_capacity(wanted);

        // Rejection sampling on a byte, discarding values in the biased tail so every
        // position is equally likely.
        let limit = (256 / total) * total;
        let mut guard = 0usize;
        while chosen.len() < wanted {
            guard += 1;
            if guard > 10_000 {
                return Err(KernelError::Random);
            }
            let mut byte = [0u8; 1];
            fill_random(&mut byte)?;
            if (byte[0] as usize) >= limit {
                continue;
            }
            let index = byte[0] as usize % total;
            if !chosen.contains(&index) {
                chosen.push(index);
            }
        }

        chosen.sort_unstable();
        Ok(chosen)
    }

    /// Checks a user's retyped words against the phrase in constant time.
    ///
    /// Returns true only if every requested position matches. Comparison is constant time so
    /// the check cannot be turned into a per-character oracle, and the words are compared
    /// after the same normalisation used at parse time so trailing whitespace is not a
    /// failure.
    pub fn verify_positions(&self, answers: &[(usize, String)]) -> bool {
        use subtle::ConstantTimeEq;

        if answers.is_empty() {
            return false;
        }

        let words: Vec<&'static str> = self.inner.words().collect();
        let mut all_match = subtle::Choice::from(1u8);

        for (index, answer) in answers {
            let Some(expected) = words.get(*index) else {
                return false;
            };
            let given = Zeroizing::new(answer.trim().to_lowercase());
            let matches = if given.len() == expected.len() {
                given.as_bytes().ct_eq(expected.as_bytes())
            } else {
                subtle::Choice::from(0u8)
            };
            all_match &= matches;
        }

        all_match.into()
    }
}

impl core::fmt::Debug for ZuniaMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ZuniaMnemonic({} words, redacted)", self.word_count())
    }
}

/// Suggestions for a mnemonic input field.
///
/// Autocomplete against the official wordlist prevents transcription errors, which are a much
/// more common cause of failed imports than a genuinely wrong phrase. Returns at most `limit`
/// words. An empty prefix returns nothing, so the full list is never dumped into the DOM.
pub fn wordlist_suggestions(prefix: &str, limit: usize) -> Vec<&'static str> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        return Vec::new();
    }
    Language::English
        .word_list()
        .iter()
        .filter(|word| word.starts_with(&prefix))
        .take(limit)
        .copied()
        .collect()
}

/// True if the word is in the official English wordlist.
pub fn is_wordlist_word(word: &str) -> bool {
    let word = word.trim().to_lowercase();
    Language::English.word_list().contains(&word.as_str())
}

/// Lowercases, collapses all whitespace to single spaces, and trims.
fn normalise_phrase(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(|word| word.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn map_bip39_error(error: bip39::Error) -> KernelError {
    match error {
        bip39::Error::BadWordCount(n) => KernelError::MnemonicLength(n),
        bip39::Error::UnknownWord(_) => KernelError::MnemonicWord,
        bip39::Error::InvalidChecksum => KernelError::MnemonicChecksum,
        bip39::Error::BadEntropyBitCount(bits) => KernelError::EntropyLength(bits / 8),
        // Ambiguous or unexpected language only arises with multi-language parsing, which we
        // do not use. Treat as an unknown word rather than inventing a variant.
        _ => KernelError::MnemonicWord,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREZOR_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn generates_requested_length() {
        for count in [
            WordCount::Twelve,
            WordCount::Fifteen,
            WordCount::Eighteen,
            WordCount::TwentyOne,
            WordCount::TwentyFour,
        ] {
            let mnemonic = ZuniaMnemonic::generate(count).unwrap();
            assert_eq!(mnemonic.word_count(), count.words());
        }
    }

    #[test]
    fn two_generated_mnemonics_differ() {
        let a = ZuniaMnemonic::generate(WordCount::Twelve).unwrap();
        let b = ZuniaMnemonic::generate(WordCount::Twelve).unwrap();
        assert_ne!(a.phrase().expose(), b.phrase().expose());
    }

    #[test]
    fn parses_official_vector() {
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        assert_eq!(hex::encode(mnemonic.entropy().expose()), "0".repeat(32));
    }

    #[test]
    fn normalises_messy_input() {
        let messy = "  ABANDON\tabandon\nabandon  abandon abandon abandon \
                     abandon abandon abandon abandon abandon ABOUT ";
        let mnemonic = ZuniaMnemonic::parse(messy).unwrap();
        assert_eq!(mnemonic.phrase().expose(), TREZOR_12);
    }

    #[test]
    fn rejects_bad_checksum() {
        // Valid words, last word swapped so the checksum fails.
        let bad = TREZOR_12.replace("about", "abandon");
        assert_eq!(
            ZuniaMnemonic::parse(&bad).unwrap_err(),
            KernelError::MnemonicChecksum
        );
    }

    #[test]
    fn rejects_unknown_word() {
        let bad = TREZOR_12.replace("about", "zzzzzz");
        assert_eq!(
            ZuniaMnemonic::parse(&bad).unwrap_err(),
            KernelError::MnemonicWord
        );
    }

    #[test]
    fn rejects_wrong_word_count() {
        assert_eq!(
            ZuniaMnemonic::parse("abandon abandon about").unwrap_err(),
            KernelError::MnemonicLength(3)
        );
    }

    #[test]
    fn rejects_bad_entropy_length() {
        assert_eq!(
            ZuniaMnemonic::from_entropy(&[0u8; 17]).unwrap_err(),
            KernelError::EntropyLength(17)
        );
    }

    #[test]
    fn passphrase_changes_the_seed() {
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        let plain = mnemonic.to_seed("");
        let with_passphrase = mnemonic.to_seed("TREZOR");
        assert_ne!(plain.expose(), with_passphrase.expose());
        assert_eq!(plain.len(), 64);
    }

    #[test]
    fn seed_matches_official_vector() {
        // BIP-39 English test vector 1, passphrase "TREZOR".
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        assert_eq!(
            hex::encode(mnemonic.to_seed("TREZOR").expose()),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn verification_positions_are_distinct_and_in_range() {
        let mnemonic = ZuniaMnemonic::generate(WordCount::TwentyFour).unwrap();
        let positions = mnemonic.verification_positions(4).unwrap();
        assert_eq!(positions.len(), 4);
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "sorted, distinct"
        );
        assert!(positions.iter().all(|p| *p < 24));
    }

    #[test]
    fn verification_positions_clamp_to_word_count() {
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        assert_eq!(mnemonic.verification_positions(50).unwrap().len(), 12);
    }

    #[test]
    fn verifies_correct_answers() {
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        assert!(mnemonic.verify_positions(&[(0, "abandon".into()), (11, "about".into()),]));
        // Whitespace and case are forgiven, the word is not.
        assert!(mnemonic.verify_positions(&[(11, "  ABOUT ".into())]));
    }

    #[test]
    fn rejects_wrong_answers() {
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        assert!(!mnemonic.verify_positions(&[(0, "about".into())]));
        assert!(!mnemonic.verify_positions(&[(0, "abandon".into()), (11, "abandon".into())]));
        assert!(
            !mnemonic.verify_positions(&[(99, "abandon".into())]),
            "out of range"
        );
        assert!(!mnemonic.verify_positions(&[]), "empty proves nothing");
    }

    #[test]
    fn suggestions_filter_by_prefix() {
        let suggestions = wordlist_suggestions("aban", 10);
        assert_eq!(suggestions, vec!["abandon"]);
        assert!(
            wordlist_suggestions("", 10).is_empty(),
            "no prefix, no dump"
        );
        assert!(wordlist_suggestions("zzzz", 10).is_empty());
        assert_eq!(wordlist_suggestions("a", 5).len(), 5, "respects the limit");
    }

    #[test]
    fn wordlist_membership() {
        assert!(is_wordlist_word("abandon"));
        assert!(is_wordlist_word(" ZOO "));
        assert!(!is_wordlist_word("zzzzzz"));
    }

    #[test]
    fn debug_does_not_leak_the_phrase() {
        let mnemonic = ZuniaMnemonic::parse(TREZOR_12).unwrap();
        let rendered = format!("{mnemonic:?}");
        assert!(!rendered.contains("abandon"));
        assert!(rendered.contains("redacted"));
    }
}
