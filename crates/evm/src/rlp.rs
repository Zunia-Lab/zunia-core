//! RLP encoding.
//!
//! Only the encoder is implemented. Zunia builds transactions and hands them to a node; it never
//! needs to decode RLP, and an unused decoder is attack surface with no user.
//!
//! # The rule that matters
//!
//! RLP has exactly one canonical form for any value, and Ethereum's signature covers the encoded
//! bytes. Two rules produce almost all real bugs:
//!
//!   * A quantity is encoded with no leading zero bytes, and zero is the empty string, not
//!     `0x00`. Encoding zero as a single zero byte produces a different hash and therefore a
//!     signature the network rejects.
//!   * A single byte below 0x80 is its own encoding, with no length prefix.
//!
//! Both are enforced here rather than left to callers.

/// Buffer for building an RLP payload.
#[derive(Debug, Default, Clone)]
pub struct RlpStream {
    out: Vec<u8>,
}

impl RlpStream {
    pub fn new() -> Self {
        Self { out: Vec::new() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Appends a byte string.
    pub fn append_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            // A single low byte is its own encoding. Prefixing it would change the hash.
            self.out.push(bytes[0]);
        } else {
            self.append_header(0x80, bytes.len());
            self.out.extend_from_slice(bytes);
        }
        self
    }

    /// Appends an already-encoded list payload.
    pub fn append_list_payload(&mut self, payload: &[u8]) -> &mut Self {
        self.append_header(0xc0, payload.len());
        self.out.extend_from_slice(payload);
        self
    }

    /// Appends a nested list built from its own stream.
    pub fn append_list(&mut self, list: &RlpStream) -> &mut Self {
        self.append_list_payload(list.as_bytes())
    }

    /// Appends a quantity, stripped of leading zero bytes.
    ///
    /// Zero encodes as the empty string, which is what `nonce: 0` and `value: 0` must produce.
    pub fn append_quantity(&mut self, value: &[u8]) -> &mut Self {
        let trimmed = strip_leading_zeros(value);
        self.append_bytes(trimmed)
    }

    pub fn append_u64(&mut self, value: u64) -> &mut Self {
        self.append_quantity(&value.to_be_bytes())
    }

    /// Appends a 256-bit quantity given as big-endian bytes.
    pub fn append_u256(&mut self, value: &[u8; 32]) -> &mut Self {
        self.append_quantity(value)
    }

    /// Appends the empty string, which is how RLP represents an absent `to` field, meaning
    /// contract creation.
    pub fn append_empty(&mut self) -> &mut Self {
        self.out.push(0x80);
        self
    }

    fn append_header(&mut self, base: u8, len: usize) {
        // `base` is 0x80 or 0xc0 and the branch bounds the addend, so neither sum can wrap.
        // Written saturating rather than plain because the bound lives in the caller's choice of
        // `base`, and a wrapped header byte would be a silently different transaction.
        if len < 56 {
            self.out.push(base.saturating_add(len as u8));
        } else {
            let be = (len as u64).to_be_bytes();
            let len_bytes = strip_leading_zeros(&be);
            self.out.push(
                base.saturating_add(55)
                    .saturating_add(len_bytes.len() as u8),
            );
            self.out.extend_from_slice(len_bytes);
        }
    }
}

/// Drops leading zero bytes, leaving an empty slice for zero.
pub fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Left-pads big-endian bytes into a 32-byte word, for EIP-712 encoding and for callers holding
/// quantities in narrower types.
pub fn to_word(bytes: &[u8]) -> Option<[u8; 32]> {
    let start = 32usize.checked_sub(bytes.len())?;
    let mut word = [0u8; 32];
    word.get_mut(start..)?.copy_from_slice(bytes);
    Some(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_specification_examples() {
        // From the Ethereum yellow paper and the RLP specification page.
        let mut stream = RlpStream::new();
        stream.append_bytes(b"dog");
        assert_eq!(stream.into_bytes(), vec![0x83, b'd', b'o', b'g']);

        let mut inner = RlpStream::new();
        inner.append_bytes(b"cat").append_bytes(b"dog");
        let mut stream = RlpStream::new();
        stream.append_list(&inner);
        assert_eq!(
            stream.into_bytes(),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );

        let mut stream = RlpStream::new();
        stream.append_bytes(b"");
        assert_eq!(stream.into_bytes(), vec![0x80]);

        let mut stream = RlpStream::new();
        stream.append_list(&RlpStream::new());
        assert_eq!(stream.into_bytes(), vec![0xc0]);
    }

    #[test]
    fn a_single_low_byte_is_its_own_encoding() {
        for byte in 0x00u8..0x80 {
            let mut stream = RlpStream::new();
            stream.append_bytes(&[byte]);
            assert_eq!(stream.into_bytes(), vec![byte], "byte {byte:#04x}");
        }
    }

    #[test]
    fn a_single_high_byte_gets_a_prefix() {
        for byte in 0x80u8..=0xff {
            let mut stream = RlpStream::new();
            stream.append_bytes(&[byte]);
            assert_eq!(stream.into_bytes(), vec![0x81, byte], "byte {byte:#04x}");
        }
    }

    #[test]
    fn zero_is_the_empty_string_not_a_zero_byte() {
        // The single most common RLP bug. `nonce: 0` encoding as 0x00 instead of 0x80 changes
        // the transaction hash, so the signature is over different bytes and the network
        // rejects it with no useful diagnostic.
        let mut stream = RlpStream::new();
        stream.append_u64(0);
        assert_eq!(stream.into_bytes(), vec![0x80]);

        let mut stream = RlpStream::new();
        stream.append_quantity(&[0, 0, 0, 0]);
        assert_eq!(stream.into_bytes(), vec![0x80]);

        // And one is a bare byte, not a prefixed one.
        let mut stream = RlpStream::new();
        stream.append_u64(1);
        assert_eq!(stream.into_bytes(), vec![0x01]);
    }

    #[test]
    fn quantities_drop_leading_zeros() {
        let mut stream = RlpStream::new();
        stream.append_quantity(&[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(stream.into_bytes(), vec![0x82, 0x01, 0x00]);

        let mut stream = RlpStream::new();
        stream.append_u64(0x0f_ff_ff);
        assert_eq!(stream.into_bytes(), vec![0x83, 0x0f, 0xff, 0xff]);
    }

    #[test]
    fn long_strings_use_the_length_of_length_form() {
        let payload = vec![0xaau8; 56];
        let mut stream = RlpStream::new();
        stream.append_bytes(&payload);
        let encoded = stream.into_bytes();
        assert_eq!(encoded[0], 0xb8, "56 bytes crosses into the long form");
        assert_eq!(encoded[1], 56);
        assert_eq!(encoded.len(), 58);

        let payload = vec![0xaau8; 1024];
        let mut stream = RlpStream::new();
        stream.append_bytes(&payload);
        let encoded = stream.into_bytes();
        assert_eq!(encoded[0], 0xb9, "1024 needs two length bytes");
        assert_eq!(&encoded[1..3], &[0x04, 0x00]);
        assert_eq!(encoded.len(), 1027);

        // 55 bytes is still the short form, so the boundary is exact.
        let payload = vec![0xaau8; 55];
        let mut stream = RlpStream::new();
        stream.append_bytes(&payload);
        assert_eq!(stream.as_bytes()[0], 0x80 + 55);
    }

    #[test]
    fn long_lists_use_the_length_of_length_form() {
        let mut inner = RlpStream::new();
        for _ in 0..20 {
            inner.append_bytes(&[0xff; 4]);
        }
        assert_eq!(inner.as_bytes().len(), 100);

        let mut stream = RlpStream::new();
        stream.append_list(&inner);
        let encoded = stream.into_bytes();
        assert_eq!(encoded[0], 0xf8);
        assert_eq!(encoded[1], 100);
    }

    #[test]
    fn word_padding_rejects_oversize_input() {
        assert_eq!(to_word(&[1]).unwrap()[31], 1);
        assert_eq!(to_word(&[1]).unwrap()[0], 0);
        assert!(to_word(&[0u8; 32]).is_some());
        assert!(to_word(&[0u8; 33]).is_none());
    }
}
