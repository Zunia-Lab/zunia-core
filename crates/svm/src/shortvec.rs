//! Solana's compact-u16 length prefix, called ShortVec on the wire.
//!
//! It is a LEB128 varint capped at u16: seven bits per byte, high bit set to continue. One to
//! three bytes. Solana rejects non-minimal encodings, so a 3-byte encoding of a small value is a
//! different transaction, not the same one spelled differently.

use crate::error::{Result, SvmError};

/// Appends a compact-u16 length prefix.
pub fn encode(out: &mut Vec<u8>, value: u16) {
    let mut rest = value;
    loop {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest == 0 {
            out.push(byte);
            return;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Appends a compact-u16 prefix for a collection length, rejecting anything past u16.
pub fn encode_len(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let short = u16::try_from(len).map_err(|_| SvmError::TooManyAccounts(len))?;
    encode(out, short);
    Ok(())
}

/// Reads a compact-u16, returning the value and the number of bytes consumed.
///
/// Rejects non-minimal encodings, because a decoder that accepts them would hash a transaction
/// differently from the one the validator sees.
pub fn decode(bytes: &[u8]) -> Option<(u16, usize)> {
    let mut value: u32 = 0;
    for (i, &byte) in bytes.iter().enumerate().take(3) {
        let chunk = u32::from(byte & 0x7f);
        // `take(3)` bounds the shift to 0, 7 or 14, so it can never reach the width of u32.
        let shift = (i as u32).saturating_mul(7);
        value |= chunk << shift;
        if byte & 0x80 == 0 {
            // The final byte carrying zero means the whole trailing group contributed nothing,
            // so a shorter encoding existed and this one is not canonical. Only the final byte
            // is checked: an intermediate zero group is legitimate, which is exactly how 0x4000
            // encodes as 80 80 01.
            if i > 0 && chunk == 0 {
                return None;
            }
            let value = u16::try_from(value).ok()?;
            return Some((value, i.checked_add(1)?));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: u16) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, value);
        assert_eq!(decode(&out), Some((value, out.len())), "value {value}");
        out
    }

    #[test]
    fn small_values_are_one_byte() {
        assert_eq!(round_trip(0), vec![0x00]);
        assert_eq!(round_trip(1), vec![0x01]);
        assert_eq!(round_trip(127), vec![0x7f]);
    }

    #[test]
    fn the_boundaries_match_the_reference_encoding() {
        // These are the values solana-sdk's own short_vec tests pin.
        assert_eq!(round_trip(128), vec![0x80, 0x01]);
        assert_eq!(round_trip(255), vec![0xff, 0x01]);
        assert_eq!(round_trip(0x4000 - 1), vec![0xff, 0x7f]);
        assert_eq!(round_trip(0x4000), vec![0x80, 0x80, 0x01]);
        assert_eq!(round_trip(u16::MAX), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    fn every_value_round_trips() {
        for value in 0..=u16::MAX {
            round_trip(value);
        }
    }

    #[test]
    fn non_minimal_encodings_are_rejected() {
        // 0x80 0x00 would decode to 0 but 0x00 was available, so it is not canonical.
        assert_eq!(decode(&[0x80, 0x00]), None);
        assert_eq!(decode(&[0x80, 0x80, 0x00]), None);
        // 0x01 0x00 is the same: two bytes spelling a value that fits in one.
        assert_eq!(decode(&[0x81, 0x00]), None);
        // But an intermediate zero group is fine when a later byte carries bits.
        assert_eq!(decode(&[0x80, 0x80, 0x01]), Some((0x4000, 3)));
        // Truncated input.
        assert_eq!(decode(&[0x80]), None);
        assert_eq!(decode(&[]), None);
        // Four continuation bytes cannot be a u16.
        assert_eq!(decode(&[0x80, 0x80, 0x80, 0x01]), None);
        // Overflow past u16 in the third byte.
        assert_eq!(decode(&[0xff, 0xff, 0x04]), None);
    }

    #[test]
    fn lengths_past_u16_are_refused() {
        let mut out = Vec::new();
        assert!(encode_len(&mut out, 65_535).is_ok());
        assert!(encode_len(&mut out, 65_536).is_err());
    }
}
