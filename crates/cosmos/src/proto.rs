//! A minimal protobuf writer and reader for the Cosmos transaction types.
//!
//! # Why hand rolled
//!
//! Cosmos `SIGN_MODE_DIRECT` signs the serialised protobuf bytes, so the exact encoding is
//! part of the signature. Three properties matter more than convenience:
//!
//! 1. **No `protoc` in the build.** A code generator in the crypto path is another thing to
//!    pin, audit and reproduce across five target platforms.
//! 2. **Byte-level control.** Cosmos requires canonical encoding: fields in tag order, no
//!    default values emitted, no unknown fields. A general purpose library will happily
//!    produce valid protobuf that a chain rejects, or worse, accepts with different bytes than
//!    the ones the user was shown.
//! 3. **A small, reviewable surface.** The message set a wallet needs is fixed and short.
//!
//! The tradeoff is that correctness rests on tests rather than on a generated schema. Every
//! encoder here is asserted byte for byte against golden vectors produced with CosmJS, per
//! [ADR-0004](../../../docs/adr/0004-cosmos-client-libs.md). A golden mismatch is a release
//! blocker, because the failure mode is a silently invalid signature.

use crate::error::{CosmosError, Result};

/// Protobuf wire types. Only the two Cosmos transaction encoding uses are represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint = 0,
    LengthDelimited = 2,
}

/// Builds a protobuf message.
///
/// Callers must write fields in ascending tag order. Protobuf does not require it, but Cosmos
/// canonical encoding does, and a decoder comparing bytes will reject anything else.
#[derive(Debug, Default, Clone)]
pub struct ProtoWriter {
    buf: Vec<u8>,
    last_tag: u32,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn write_tag(&mut self, tag: u32, wire: WireType) {
        debug_assert!(
            tag >= self.last_tag,
            "fields must be written in ascending tag order for canonical encoding, \
             got {tag} after {}",
            self.last_tag
        );
        self.last_tag = tag;
        write_varint(&mut self.buf, u64::from(tag << 3 | wire as u32));
    }

    /// Writes a `uint64`. Skips the field entirely when the value is zero, which is what
    /// proto3 default-value omission requires and what the Cosmos SDK expects.
    pub fn uint64(&mut self, tag: u32, value: u64) -> &mut Self {
        if value != 0 {
            self.write_tag(tag, WireType::Varint);
            write_varint(&mut self.buf, value);
        }
        self
    }

    /// Writes an `int32` or an enum. Skips zero, so `SIGN_MODE_UNSPECIFIED` and the default
    /// enum variant are omitted rather than encoded.
    pub fn int32(&mut self, tag: u32, value: i32) -> &mut Self {
        if value != 0 {
            self.write_tag(tag, WireType::Varint);
            write_varint(&mut self.buf, value as u64);
        }
        self
    }

    pub fn bool(&mut self, tag: u32, value: bool) -> &mut Self {
        if value {
            self.write_tag(tag, WireType::Varint);
            write_varint(&mut self.buf, 1);
        }
        self
    }

    /// Writes a `string`. Skips an empty string.
    pub fn string(&mut self, tag: u32, value: &str) -> &mut Self {
        if !value.is_empty() {
            self.write_tag(tag, WireType::LengthDelimited);
            write_varint(&mut self.buf, value.len() as u64);
            self.buf.extend_from_slice(value.as_bytes());
        }
        self
    }

    /// Writes `bytes`. Skips an empty slice.
    pub fn bytes(&mut self, tag: u32, value: &[u8]) -> &mut Self {
        if !value.is_empty() {
            self.write_tag(tag, WireType::LengthDelimited);
            write_varint(&mut self.buf, value.len() as u64);
            self.buf.extend_from_slice(value);
        }
        self
    }

    /// Writes an embedded message. Skips it when the encoding is empty, matching proto3.
    pub fn message(&mut self, tag: u32, value: &[u8]) -> &mut Self {
        self.bytes(tag, value)
    }

    /// Writes a repeated embedded message, once per element.
    ///
    /// Repeated fields legitimately break ascending tag order, since the same tag appears
    /// several times, so the order check is relaxed for the duration.
    pub fn repeated_message(&mut self, tag: u32, values: &[Vec<u8>]) -> &mut Self {
        for value in values {
            self.write_tag(tag, WireType::LengthDelimited);
            write_varint(&mut self.buf, value.len() as u64);
            self.buf.extend_from_slice(value);
            self.last_tag = tag;
        }
        self
    }

    /// Writes a repeated string.
    pub fn repeated_string(&mut self, tag: u32, values: &[String]) -> &mut Self {
        for value in values {
            self.write_tag(tag, WireType::LengthDelimited);
            write_varint(&mut self.buf, value.len() as u64);
            self.buf.extend_from_slice(value.as_bytes());
            self.last_tag = tag;
        }
        self
    }

    /// Writes a message even when its encoding is empty.
    ///
    /// Needed for `ModeInfo.Single`, where the whole point of the field is its presence: an
    /// omitted `ModeInfo` means no signer mode at all, while a present but empty one means
    /// single-signer with the default mode.
    pub fn message_always(&mut self, tag: u32, value: &[u8]) -> &mut Self {
        self.write_tag(tag, WireType::LengthDelimited);
        write_varint(&mut self.buf, value.len() as u64);
        self.buf.extend_from_slice(value);
        self
    }
}

fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

/// A protobuf field as read off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub tag: u32,
    pub value: FieldValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Varint(u64),
    Bytes(Vec<u8>),
}

impl FieldValue {
    pub fn as_varint(&self) -> Result<u64> {
        match self {
            Self::Varint(v) => Ok(*v),
            Self::Bytes(_) => Err(CosmosError::Decode),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(b) => Ok(b),
            Self::Varint(_) => Err(CosmosError::Decode),
        }
    }

    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.as_bytes()?.to_vec()).map_err(|_| CosmosError::Decode)
    }
}

/// Reads a protobuf message into a flat field list.
///
/// Used to decode a transaction the wallet did not build, which is the dangerous case: a dApp
/// hands over `SIGN_MODE_DIRECT` bytes and the user must be shown what they actually contain.
/// Anything this cannot decode is surfaced as undecodable rather than signed, per the blind
/// signing rule in `PRE-DEVELOPMENT.md` §4.
pub fn decode_fields(mut input: &[u8]) -> Result<Vec<Field>> {
    let mut fields = Vec::new();

    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;

        let tag = u32::try_from(key >> 3).map_err(|_| CosmosError::Decode)?;
        if tag == 0 {
            // Tag 0 is invalid protobuf and is how a malformed or adversarial payload most
            // often shows up.
            return Err(CosmosError::Decode);
        }

        match key & 0x07 {
            0 => {
                let (value, rest) = read_varint(input)?;
                input = rest;
                fields.push(Field {
                    tag,
                    value: FieldValue::Varint(value),
                });
            }
            2 => {
                let (len, rest) = read_varint(input)?;
                let len = usize::try_from(len).map_err(|_| CosmosError::Decode)?;
                if rest.len() < len {
                    return Err(CosmosError::Decode);
                }
                fields.push(Field {
                    tag,
                    value: FieldValue::Bytes(rest[..len].to_vec()),
                });
                input = &rest[len..];
            }
            // 64-bit (1), 32-bit (5) and the deprecated group types (3, 4) do not appear in
            // Cosmos transaction messages. Refusing them is safer than skipping them, because
            // a skipped field is a field the user was not shown.
            _ => return Err(CosmosError::Decode),
        }
    }

    Ok(fields)
}

fn read_varint(input: &[u8]) -> Result<(u64, &[u8])> {
    let mut value: u64 = 0;
    for (i, byte) in input.iter().enumerate() {
        if i >= 10 {
            // A varint longer than 10 bytes cannot fit in u64.
            return Err(CosmosError::Decode);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, &input[i + 1..]));
        }
    }
    Err(CosmosError::Decode)
}

/// Finds the first field with `tag`.
pub fn find_field(fields: &[Field], tag: u32) -> Option<&FieldValue> {
    fields.iter().find(|f| f.tag == tag).map(|f| &f.value)
}

/// Collects every field with `tag`, for repeated fields.
pub fn find_all(fields: &[Field], tag: u32) -> Vec<&FieldValue> {
    fields
        .iter()
        .filter(|f| f.tag == tag)
        .map(|f| &f.value)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_match_the_specification() {
        // Canonical examples from the protobuf encoding documentation.
        let mut buf = Vec::new();
        write_varint(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);

        buf.clear();
        write_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xac, 0x02]);

        buf.clear();
        write_varint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_varint(&mut buf, u64::MAX);
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn varint_round_trips_at_boundaries() {
        for value in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            300,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, value);
            let (decoded, rest) = read_varint(&buf).unwrap();
            assert_eq!(decoded, value, "round trip failed for {value}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn omits_proto3_default_values() {
        // This is the property that makes or breaks Direct signing. The Cosmos SDK encodes
        // with default-value omission, so emitting `account_number: 0` produces different
        // bytes than the chain computes, and the signature verifies against nothing.
        let mut writer = ProtoWriter::new();
        writer
            .uint64(1, 0)
            .string(2, "")
            .bytes(3, &[])
            .bool(4, false)
            .int32(5, 0);
        assert!(writer.is_empty(), "defaults must produce no bytes at all");
    }

    #[test]
    fn encodes_scalar_fields() {
        let mut writer = ProtoWriter::new();
        writer.string(1, "hello").uint64(2, 300);
        // field 1, wire type 2 -> 0x0a; len 5; "hello"
        // field 2, wire type 0 -> 0x10; varint 300 -> 0xac 0x02
        assert_eq!(
            writer.as_bytes(),
            &[0x0a, 0x05, b'h', b'e', b'l', b'l', b'o', 0x10, 0xac, 0x02]
        );
    }

    #[test]
    fn empty_message_is_omitted_but_message_always_is_not() {
        let mut omitted = ProtoWriter::new();
        omitted.message(1, &[]);
        assert!(omitted.is_empty());

        let mut kept = ProtoWriter::new();
        kept.message_always(1, &[]);
        assert_eq!(kept.as_bytes(), &[0x0a, 0x00]);
    }

    #[test]
    fn repeated_fields_emit_once_per_element() {
        let mut writer = ProtoWriter::new();
        writer.repeated_message(1, &[vec![0xaa], vec![0xbb, 0xcc]]);
        assert_eq!(
            writer.as_bytes(),
            &[0x0a, 0x01, 0xaa, 0x0a, 0x02, 0xbb, 0xcc]
        );

        let mut strings = ProtoWriter::new();
        strings.repeated_string(2, &["a".to_owned(), "bc".to_owned()]);
        assert_eq!(
            strings.as_bytes(),
            &[0x12, 0x01, b'a', 0x12, 0x02, b'b', b'c']
        );
    }

    #[test]
    fn decodes_what_it_encodes() {
        let mut writer = ProtoWriter::new();
        writer
            .string(1, "cosmoshub-4")
            .uint64(2, 42)
            .bytes(3, &[1, 2, 3]);

        let fields = decode_fields(writer.as_bytes()).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(
            find_field(&fields, 1).unwrap().as_string().unwrap(),
            "cosmoshub-4"
        );
        assert_eq!(find_field(&fields, 2).unwrap().as_varint().unwrap(), 42);
        assert_eq!(
            find_field(&fields, 3).unwrap().as_bytes().unwrap(),
            &[1, 2, 3]
        );
        assert!(find_field(&fields, 9).is_none());
    }

    #[test]
    fn decodes_repeated_fields() {
        let mut writer = ProtoWriter::new();
        writer.repeated_string(1, &["a".to_owned(), "b".to_owned()]);
        let fields = decode_fields(writer.as_bytes()).unwrap();
        let all = find_all(&fields, 1);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].as_string().unwrap(), "a");
        assert_eq!(all[1].as_string().unwrap(), "b");
    }

    #[test]
    fn rejects_malformed_input() {
        // Truncated length-delimited field: claims 10 bytes, supplies 2.
        assert!(decode_fields(&[0x0a, 0x0a, 0x01, 0x02]).is_err());
        // Truncated varint: continuation bit set with nothing following.
        assert!(decode_fields(&[0x08, 0x80]).is_err());
        // Tag zero.
        assert!(decode_fields(&[0x00, 0x01]).is_err());
        // 64-bit wire type, which Cosmos messages never use.
        assert!(decode_fields(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Deprecated group start.
        assert!(decode_fields(&[0x0b]).is_err());
        // Varint longer than 10 bytes.
        assert!(decode_fields(&[
            0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
        ])
        .is_err());
    }

    #[test]
    fn empty_input_decodes_to_nothing() {
        assert!(decode_fields(&[]).unwrap().is_empty());
    }

    #[test]
    fn type_confusion_is_an_error_not_a_coercion() {
        let mut writer = ProtoWriter::new();
        writer.uint64(1, 5).string(2, "text");
        let fields = decode_fields(writer.as_bytes()).unwrap();
        assert!(find_field(&fields, 1).unwrap().as_bytes().is_err());
        assert!(find_field(&fields, 2).unwrap().as_varint().is_err());
    }
}
