//! EIP-712 typed structured data.
//!
//! EIP-712 exists so a wallet can show a user what they are signing instead of a hash. That only
//! works if the hashing is exact: the signature covers `0x1901 || domainSeparator || hashStruct`,
//! and any disagreement with the verifying contract produces a signature that contract rejects.
//!
//! The parts that are easy to get wrong, and are handled explicitly here:
//!
//!   * `encodeType` must list dependent structs in alphabetical order after the primary type,
//!     with no duplicates. A different order is a different type hash.
//!   * Dynamic types (`string`, `bytes`) hash to `keccak256(contents)`; static types are padded
//!     to 32 bytes. Treating a `string` as static silently truncates it.
//!   * Arrays hash to `keccak256` of the concatenated encoded elements.
//!   * Omitted optional domain fields must be omitted from `encodeType` too, not encoded as
//!     zero, or the domain separator will not match the contract's.
//!
//! This module rejects anything it cannot encode faithfully. A best-effort hash would produce a
//! signature the user believes covers what the prompt showed, which is worse than an error.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use zunia_kernel::{sign_digest_secp256k1, ExtendedKey, Signature};

use crate::error::{EvmError, Result};

/// One member of a struct type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// A typed-data document, as it arrives from `eth_signTypedData_v4`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
    pub types: BTreeMap<String, Vec<Field>>,
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    pub domain: Value,
    pub message: Value,
}

impl TypedData {
    /// Parses a document and refuses anything that cannot be signed.
    ///
    /// The validation is not cosmetic. The approval prompt renders the parsed document, and only
    /// then, after the user has approved, does the wallet hash it. If a document could parse but
    /// fail to hash, the prompt would have shown the user a payload the wallet was never able to
    /// sign, which at best is a dead end after an approval and at worst renders fields that bear
    /// no relation to what a retry would produce. Rejecting up front means anything the user is
    /// ever shown is something the wallet can sign exactly as displayed.
    ///
    /// Computing the hash is how that is checked, rather than a separate list of rules that could
    /// drift from the encoder: if the digest can be produced, every type resolved and every value
    /// encoded. The cost is one extra Keccak pass over a small document.
    ///
    /// Found by the mutation sweep in `crates/properties/examples/mutate.rs`, which produced
    /// documents with an undefined `primaryType`, a field typed `256`, and a `bytes32` holding
    /// 57 hex characters. All three parsed and none could be hashed.
    pub fn from_json(json: &str) -> Result<Self> {
        let parsed: Self =
            serde_json::from_str(json).map_err(|e| EvmError::TypedData(e.to_string()))?;
        parsed.signing_hash()?;
        Ok(parsed)
    }

    /// Parses without checking that the document can be hashed.
    ///
    /// Only for tests that need to construct a deliberately broken document. Production callers
    /// want `from_json`.
    #[cfg(test)]
    fn from_json_unchecked(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| EvmError::TypedData(e.to_string()))
    }

    /// The full `0x1901`-prefixed digest that gets signed.
    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        let domain_separator = self.hash_struct("EIP712Domain", &self.domain)?;
        let message_hash = self.hash_struct(&self.primary_type, &self.message)?;

        let mut input = Vec::with_capacity(66);
        input.extend_from_slice(&[0x19, 0x01]);
        input.extend_from_slice(&domain_separator);
        input.extend_from_slice(&message_hash);
        Ok(Keccak256::digest(input).into())
    }

    /// The domain separator alone, which the UI shows so a user can confirm the target contract.
    pub fn domain_separator(&self) -> Result<[u8; 32]> {
        self.hash_struct("EIP712Domain", &self.domain)
    }

    /// `encodeType`, for example `Mail(Person from,Person to,string contents)Person(...)`.
    pub fn encode_type(&self, type_name: &str) -> Result<String> {
        let mut dependencies = BTreeSet::new();
        self.collect_dependencies(type_name, &mut dependencies)?;
        // The primary type leads, then the rest alphabetically. BTreeSet gives the ordering;
        // removing the primary type first stops it appearing twice.
        dependencies.remove(type_name);

        let mut encoded = self.encode_one_type(type_name)?;
        for dependency in &dependencies {
            encoded.push_str(&self.encode_one_type(dependency)?);
        }
        Ok(encoded)
    }

    /// `typeHash`, the Keccak-256 of `encodeType`.
    pub fn type_hash(&self, type_name: &str) -> Result<[u8; 32]> {
        Ok(Keccak256::digest(self.encode_type(type_name)?.as_bytes()).into())
    }

    /// `hashStruct`, meaning `keccak256(typeHash || encodeData)`.
    pub fn hash_struct(&self, type_name: &str, value: &Value) -> Result<[u8; 32]> {
        let mut encoded = self.type_hash(type_name)?.to_vec();
        encoded.extend_from_slice(&self.encode_data(type_name, value)?);
        Ok(Keccak256::digest(encoded).into())
    }

    fn encode_one_type(&self, type_name: &str) -> Result<String> {
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| EvmError::TypedData(format!("type {type_name:?} is not defined")))?;

        let members: Vec<String> = fields
            .iter()
            .map(|field| format!("{} {}", field.kind, field.name))
            .collect();
        Ok(format!("{type_name}({})", members.join(",")))
    }

    /// Walks the type graph. Cycles terminate because a type already in the set is not revisited.
    fn collect_dependencies(&self, type_name: &str, found: &mut BTreeSet<String>) -> Result<()> {
        if !found.insert(type_name.to_owned()) {
            return Ok(());
        }
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| EvmError::TypedData(format!("type {type_name:?} is not defined")))?;

        for field in fields {
            let base = base_type(&field.kind);
            if self.types.contains_key(base) {
                self.collect_dependencies(base, found)?;
            }
        }
        Ok(())
    }

    /// `encodeData`: each member encoded to exactly 32 bytes, concatenated.
    ///
    /// Public so the golden-vector test can compare this step against ethers directly. When a
    /// signing hash diverges, the encoded data says which member is wrong; the hash alone does
    /// not.
    pub fn encode_data(&self, type_name: &str, value: &Value) -> Result<Vec<u8>> {
        let fields = self
            .types
            .get(type_name)
            .ok_or_else(|| EvmError::TypedData(format!("type {type_name:?} is not defined")))?;

        let mut out = Vec::with_capacity(fields.len().saturating_mul(32));
        for field in fields {
            let member = value.get(&field.name).unwrap_or(&Value::Null);
            out.extend_from_slice(&self.encode_value(&field.kind, member, &field.name)?);
        }
        Ok(out)
    }

    fn encode_value(&self, kind: &str, value: &Value, field_name: &str) -> Result<[u8; 32]> {
        let fail = |reason: &str| {
            EvmError::TypedData(format!("field {field_name:?} of type {kind:?}: {reason}"))
        };

        // Arrays: keccak of the concatenated encodings of the elements.
        if let Some(element_type) = array_element_type(kind) {
            let items = value.as_array().ok_or_else(|| fail("expected an array"))?;
            if let Some(expected) = fixed_array_length(kind) {
                if items.len() != expected {
                    return Err(fail(&format!(
                        "expected {expected} elements, got {}",
                        items.len()
                    )));
                }
            }
            // Saturating because `items` came from a website: on wasm32 a `usize` multiply is
            // 32-bit, and a capacity hint is never worth a panic.
            let mut concatenated = Vec::with_capacity(items.len().saturating_mul(32));
            for item in items {
                concatenated.extend_from_slice(&self.encode_value(
                    element_type,
                    item,
                    field_name,
                )?);
            }
            return Ok(Keccak256::digest(concatenated).into());
        }

        // Nested structs: hashStruct.
        if self.types.contains_key(kind) {
            if value.is_null() {
                return Err(fail("a struct member must be present"));
            }
            return self.hash_struct(kind, value);
        }

        match kind {
            // Dynamic types hash their contents. Padding them instead would truncate anything
            // over 32 bytes, so a long `contents` string would sign as its first 32 bytes.
            "string" => {
                let text = value.as_str().ok_or_else(|| fail("expected a string"))?;
                Ok(Keccak256::digest(text.as_bytes()).into())
            }
            "bytes" => {
                let bytes = decode_hex(value).ok_or_else(|| fail("expected hex bytes"))?;
                Ok(Keccak256::digest(bytes).into())
            }
            "address" => {
                let text = value.as_str().ok_or_else(|| fail("expected an address"))?;
                let account = zunia_kernel::validate_eth_address(text)
                    .map_err(|_| fail("not a valid address"))?;
                let mut word = [0u8; 32];
                word[12..].copy_from_slice(account.as_bytes());
                Ok(word)
            }
            "bool" => {
                let flag = value.as_bool().ok_or_else(|| fail("expected a bool"))?;
                let mut word = [0u8; 32];
                word[31] = u8::from(flag);
                Ok(word)
            }
            _ => {
                if let Some(size) = fixed_bytes_size(kind) {
                    let bytes = decode_hex(value).ok_or_else(|| fail("expected hex bytes"))?;
                    if bytes.len() != size {
                        return Err(fail(&format!("expected {size} bytes, got {}", bytes.len())));
                    }
                    // bytesN is left aligned, unlike every numeric type.
                    let mut word = [0u8; 32];
                    word[..size].copy_from_slice(&bytes);
                    return Ok(word);
                }
                if is_integer_type(kind) {
                    return encode_integer(value, kind.starts_with("int")).ok_or_else(|| {
                        fail("expected an integer, as a number or a decimal or hex string")
                    });
                }
                Err(fail("unsupported type"))
            }
        }
    }
}

/// Signs a typed-data document.
pub fn sign_typed_data(key: &ExtendedKey, data: &TypedData) -> Result<Signature> {
    Ok(sign_digest_secp256k1(key, &data.signing_hash()?)?)
}

/// The 65-byte `r || s || v` hex form, with `v` as 27 or 28.
pub fn sign_typed_data_hex(key: &ExtendedKey, data: &TypedData) -> Result<String> {
    let signature = sign_typed_data(key, data)?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(signature.as_bytes());
    let recovery = signature
        .recovery_id()
        .ok_or(zunia_kernel::KernelError::Signature)?;
    out[64] = recovery.saturating_add(27);
    Ok(format!("0x{}", hex::encode(out)))
}

/// Strips array suffixes to find the underlying type name.
fn base_type(kind: &str) -> &str {
    match kind.find('[') {
        Some(index) => &kind[..index],
        None => kind,
    }
}

/// For `Person[3]` returns `Person`; for a non-array returns `None`.
fn array_element_type(kind: &str) -> Option<&str> {
    if !kind.ends_with(']') {
        return None;
    }
    let open = kind.rfind('[')?;
    Some(&kind[..open])
}

/// For `uint256[3]` returns 3; for `uint256[]` returns `None`.
fn fixed_array_length(kind: &str) -> Option<usize> {
    let open = kind.rfind('[')?;
    // Sliced with `get` rather than indexed: `kind` comes from a website's `types` map, and a
    // type spelled `uint256[` would panic on a range that runs backwards.
    let inner = kind.get(open.checked_add(1)?..kind.len().checked_sub(1)?)?;
    if inner.is_empty() {
        None
    } else {
        inner.parse().ok()
    }
}

/// For `bytes32` returns 32. Excludes bare `bytes`, which is dynamic.
fn fixed_bytes_size(kind: &str) -> Option<usize> {
    let digits = kind.strip_prefix("bytes")?;
    if digits.is_empty() {
        return None;
    }
    let size: usize = digits.parse().ok()?;
    (1..=32).contains(&size).then_some(size)
}

fn is_integer_type(kind: &str) -> bool {
    let digits = match kind
        .strip_prefix("uint")
        .or_else(|| kind.strip_prefix("int"))
    {
        Some(digits) => digits,
        None => return false,
    };
    if digits.is_empty() {
        // Bare `int` and `uint` are aliases for the 256-bit versions in Solidity, but EIP-712
        // requires the canonical spelling, and accepting the alias would produce a type hash the
        // contract does not agree with.
        return false;
    }
    match digits.parse::<usize>() {
        Ok(bits) => bits % 8 == 0 && (8..=256).contains(&bits),
        Err(_) => false,
    }
}

/// Encodes an integer into a 32-byte word.
///
/// Accepts a JSON number, a decimal string, or a hex string, because all three appear in real
/// dApp requests. Negative values are two's complement, and only for signed types.
fn encode_integer(value: &Value, signed: bool) -> Option<[u8; 32]> {
    let mut word = [0u8; 32];

    if let Some(number) = value.as_u64() {
        word[24..].copy_from_slice(&number.to_be_bytes());
        return Some(word);
    }
    if let Some(number) = value.as_i64() {
        if number < 0 {
            if !signed {
                return None;
            }
            // Sign extension across the whole word.
            word = [0xff; 32];
            word[24..].copy_from_slice(&number.to_be_bytes());
            return Some(word);
        }
        word[24..].copy_from_slice(&number.to_be_bytes());
        return Some(word);
    }

    let text = value.as_str()?.trim();
    if let Some(hex_digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        let padded = if hex_digits.len() % 2 == 1 {
            format!("0{hex_digits}")
        } else {
            hex_digits.to_owned()
        };
        let bytes = hex::decode(padded).ok()?;
        let start = 32usize.checked_sub(bytes.len())?;
        word.get_mut(start..)?.copy_from_slice(&bytes);
        return Some(word);
    }

    let (text, negative) = match text.strip_prefix('-') {
        Some(rest) if signed => (rest, true),
        Some(_) => return None,
        None => (text, false),
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    for digit in text.bytes().map(|b| u32::from(b.wrapping_sub(b'0'))) {
        let mut carry = digit;
        for byte in word.iter_mut().rev() {
            // Bounded by construction: a byte times ten plus a carry below 256 is under 2^16,
            // so the checked form can only be `Some`. Written checked anyway because the bound
            // is an argument rather than a guarantee the compiler enforces.
            let product = u32::from(*byte)
                .checked_mul(10)
                .and_then(|scaled| scaled.checked_add(carry))?;
            *byte = (product & 0xff) as u8;
            carry = product >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    if negative {
        // Two's complement: invert and add one.
        for byte in word.iter_mut() {
            *byte = !*byte;
        }
        for byte in word.iter_mut().rev() {
            match byte.checked_add(1) {
                Some(next) => {
                    *byte = next;
                    break;
                }
                None => *byte = 0,
            }
        }
    }
    Some(word)
}

fn decode_hex(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str()?;
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty() {
        return Some(Vec::new());
    }
    hex::decode(digits).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zunia_kernel::{verify_digest_secp256k1, Curve, DerivationPath, ZuniaMnemonic};

    /// The worked example from the EIP-712 specification.
    const MAIL: &str = r#"{
      "types": {
        "EIP712Domain": [
          { "name": "name", "type": "string" },
          { "name": "version", "type": "string" },
          { "name": "chainId", "type": "uint256" },
          { "name": "verifyingContract", "type": "address" }
        ],
        "Person": [
          { "name": "name", "type": "string" },
          { "name": "wallet", "type": "address" }
        ],
        "Mail": [
          { "name": "from", "type": "Person" },
          { "name": "to", "type": "Person" },
          { "name": "contents", "type": "string" }
        ]
      },
      "primaryType": "Mail",
      "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      },
      "message": {
        "from": { "name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
        "to": { "name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
        "contents": "Hello, Bob!"
      }
    }"#;

    fn key() -> ExtendedKey {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = ZuniaMnemonic::parse(mnemonic).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::parse("m/44'/60'/0'/0/0").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn encode_type_matches_the_specification() {
        let data = TypedData::from_json(MAIL).unwrap();
        // Straight from EIP-712: the primary type first, dependencies alphabetically after.
        assert_eq!(
            data.encode_type("Mail").unwrap(),
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
        assert_eq!(
            data.encode_type("Person").unwrap(),
            "Person(string name,address wallet)"
        );
        assert_eq!(
            data.encode_type("EIP712Domain").unwrap(),
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    }

    #[test]
    fn the_hashes_match_the_specification_vectors() {
        let data = TypedData::from_json(MAIL).unwrap();

        // Every one of these is published in EIP-712.
        assert_eq!(
            hex::encode(data.type_hash("Mail").unwrap()),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
        );
        assert_eq!(
            hex::encode(data.domain_separator().unwrap()),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );
        assert_eq!(
            hex::encode(data.hash_struct("Mail", &data.message).unwrap()),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );
        assert_eq!(
            hex::encode(data.signing_hash().unwrap()),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn the_0x1901_prefix_is_present() {
        // Without it, a typed-data signature could collide with another signing scheme.
        let data = TypedData::from_json(MAIL).unwrap();
        let domain = data.domain_separator().unwrap();
        let message = data.hash_struct("Mail", &data.message).unwrap();

        let mut expected = vec![0x19, 0x01];
        expected.extend_from_slice(&domain);
        expected.extend_from_slice(&message);
        let expected: [u8; 32] = Keccak256::digest(expected).into();
        assert_eq!(data.signing_hash().unwrap(), expected);
    }

    #[test]
    fn a_long_string_is_hashed_not_truncated() {
        // Padding a dynamic type to 32 bytes would sign only its first 32 bytes, so a user could
        // approve "Transfer 1 token" and actually sign a much longer message.
        let long = "x".repeat(100);
        let short = "x".repeat(32);
        let data = TypedData::from_json(MAIL).unwrap();

        let a = data
            .encode_value("string", &Value::from(long.clone()), "contents")
            .unwrap();
        let b = data
            .encode_value("string", &Value::from(short), "contents")
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(a, <[u8; 32]>::from(Keccak256::digest(long.as_bytes())));
    }

    #[test]
    fn integers_accept_the_forms_dapps_actually_send() {
        let data = TypedData::from_json(MAIL).unwrap();
        let one = data
            .encode_value("uint256", &Value::from(1u64), "x")
            .unwrap();
        assert_eq!(one[31], 1);

        for form in [Value::from("1"), Value::from("0x1"), Value::from("0x01")] {
            assert_eq!(
                data.encode_value("uint256", &form, "x").unwrap(),
                one,
                "form {form:?} disagreed"
            );
        }

        // Values beyond u64, which is the normal case for a token amount.
        let big = data
            .encode_value("uint256", &Value::from("18446744073709551616"), "x")
            .unwrap();
        assert_eq!(big[23], 1);
        assert_eq!(big[24..], [0u8; 8]);

        // The maximum, and one past it.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(
            data.encode_value("uint256", &Value::from(max), "x")
                .unwrap(),
            [0xff; 32]
        );
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(data
            .encode_value("uint256", &Value::from(over), "x")
            .is_err());
    }

    #[test]
    fn a_negative_value_is_refused_for_an_unsigned_type() {
        // Encoding -1 as an unsigned maximum would turn "refund 1 token" into "transfer
        // everything", which is exactly the confusion this rejects.
        let data = TypedData::from_json(MAIL).unwrap();
        assert!(data
            .encode_value("uint256", &Value::from(-1i64), "x")
            .is_err());
        assert!(data
            .encode_value("uint256", &Value::from("-1"), "x")
            .is_err());

        let signed = data
            .encode_value("int256", &Value::from(-1i64), "x")
            .unwrap();
        assert_eq!(signed, [0xff; 32]);
        let signed = data
            .encode_value("int256", &Value::from("-1"), "x")
            .unwrap();
        assert_eq!(signed, [0xff; 32]);
    }

    #[test]
    fn bytes32_is_left_aligned_and_integers_are_right_aligned() {
        // The one place EIP-712 alignment differs by type. Getting it backwards produces a hash
        // that no contract agrees with.
        let data = TypedData::from_json(MAIL).unwrap();
        let word = data
            .encode_value("bytes4", &Value::from("0xdeadbeef"), "x")
            .unwrap();
        assert_eq!(&word[..4], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&word[4..], &[0u8; 28]);

        let word = data
            .encode_value("uint32", &Value::from(0xdeadbeefu64), "x")
            .unwrap();
        assert_eq!(&word[28..], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&word[..28], &[0u8; 28]);
    }

    #[test]
    fn addresses_are_validated_not_merely_padded() {
        let data = TypedData::from_json(MAIL).unwrap();
        let word = data
            .encode_value(
                "address",
                &Value::from("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"),
                "wallet",
            )
            .unwrap();
        assert_eq!(&word[..12], &[0u8; 12]);

        // A bad checksum must fail rather than being padded into a different address.
        assert!(data
            .encode_value(
                "address",
                &Value::from("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD827"),
                "wallet"
            )
            .is_err());
        assert!(data
            .encode_value("address", &Value::from("0x1234"), "wallet")
            .is_err());
    }

    #[test]
    fn arrays_hash_their_concatenated_elements() {
        let json = r#"{
          "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }],
            "Order": [
              { "name": "amounts", "type": "uint256[]" },
              { "name": "pair", "type": "bytes32[2]" }
            ]
          },
          "primaryType": "Order",
          "domain": { "name": "Test" },
          "message": {
            "amounts": ["1", "2", "3"],
            "pair": ["0x1111111111111111111111111111111111111111111111111111111111111111",
                     "0x2222222222222222222222222222222222222222222222222222222222222222"]
          }
        }"#;
        let data = TypedData::from_json(json).unwrap();
        assert!(data.signing_hash().is_ok());

        // A fixed-length array with the wrong count must fail, not be padded or truncated.
        let mut broken = data.clone();
        broken.message["pair"] = serde_json::json!([
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        ]);
        assert!(broken.signing_hash().is_err());

        // Order matters, since the elements are concatenated before hashing.
        let mut reordered = data.clone();
        reordered.message["amounts"] = serde_json::json!(["3", "2", "1"]);
        assert_ne!(
            reordered.signing_hash().unwrap(),
            data.signing_hash().unwrap()
        );
    }

    #[test]
    fn an_undefined_type_is_an_error_not_a_guess() {
        let json = r#"{
          "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }],
            "Thing": [{ "name": "nested", "type": "Missing" }]
          },
          "primaryType": "Thing",
          "domain": { "name": "Test" },
          "message": { "nested": { "a": 1 } }
        }"#;
        // "Missing" is not in `types`, so it is an unsupported primitive rather than something to
        // silently hash as. Rejected at parse time, so the prompt never renders it.
        assert!(TypedData::from_json(json).is_err());

        let data = TypedData::from_json_unchecked(json).unwrap();
        assert!(data.signing_hash().is_err());
    }

    #[test]
    fn a_recursive_type_terminates() {
        // A malicious document with a cycle must not hang the extension worker.
        let json = r#"{
          "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }],
            "Node": [
              { "name": "value", "type": "uint256" },
              { "name": "next", "type": "Node" }
            ]
          },
          "primaryType": "Node",
          "domain": { "name": "Test" },
          "message": { "value": 1, "next": { "value": 2 } }
        }"#;
        // The value recursion has no base case, so the document cannot be hashed and is rejected.
        assert!(TypedData::from_json(json).is_err());

        // Parsed unchecked, `encode_type` must still terminate rather than recurse forever: a
        // hang in the extension's worker is a denial of service any site could trigger.
        let data = TypedData::from_json_unchecked(json).unwrap();
        assert_eq!(
            data.encode_type("Node").unwrap(),
            "Node(uint256 value,Node next)"
        );
        assert!(data.signing_hash().is_err());
    }

    #[test]
    fn a_missing_struct_member_is_an_error() {
        let mut data = TypedData::from_json(MAIL).unwrap();
        data.message = serde_json::json!({ "contents": "Hello, Bob!" });
        assert!(data.signing_hash().is_err());
    }

    #[test]
    fn unsupported_type_spellings_are_refused() {
        let data = TypedData::from_json(MAIL).unwrap();
        // Solidity accepts `uint` as an alias for `uint256`, but EIP-712 requires the canonical
        // spelling. Accepting the alias would produce a type hash the contract disagrees with,
        // so the signature would be rejected on chain with nothing to point at.
        assert!(data.encode_value("uint", &Value::from(1u64), "x").is_err());
        assert!(data.encode_value("int", &Value::from(1u64), "x").is_err());
        assert!(data
            .encode_value("uint257", &Value::from(1u64), "x")
            .is_err());
        assert!(data.encode_value("uint7", &Value::from(1u64), "x").is_err());
        assert!(data
            .encode_value("bytes33", &Value::from("0x00"), "x")
            .is_err());
        assert!(data
            .encode_value("fixed128x18", &Value::from(1u64), "x")
            .is_err());
    }

    #[test]
    fn documents_that_cannot_be_hashed_are_refused_at_parse_time() {
        // All three were produced by the mutation sweep in
        // `crates/properties/examples/mutate.rs`. Each parsed cleanly as JSON and each was
        // impossible to hash, which meant the approval prompt could render a payload the wallet
        // would then fail to sign. Committed to `fuzz/corpus/eip712_parser/` as well.
        let cases = [
            (
                "primary type is not in the types map",
                r#"{
                  "types": {
                    "EIP712Domain": [{ "name": "name", "type": "string" }],
                    "Permitt": [{ "name": "owner", "type": "address" }]
                  },
                  "primaryType": "Permit",
                  "domain": { "name": "USD Coin" },
                  "message": { "owner": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" }
                }"#,
            ),
            (
                "a field typed 256, which is not an EIP-712 type",
                r#"{
                  "types": {
                    "EIP712Domain": [{ "name": "name", "type": "string" }],
                    "Ping": [{ "name": "nonce", "type": "256" }]
                  },
                  "primaryType": "Ping",
                  "domain": { "name": "Zunia" },
                  "message": { "nonce": "1" }
                }"#,
            ),
            (
                "a bytes32 holding 57 hex characters",
                r#"{
                  "types": {
                    "EIP712Domain": [
                      { "name": "name", "type": "string" },
                      { "name": "salt", "type": "bytes32" }
                    ],
                    "Ping": [{ "name": "nonce", "type": "uint256" }]
                  },
                  "primaryType": "Ping",
                  "domain": {
                    "name": "Zunia",
                    "salt": "0x000000000000000000000000000000000000000000000000000000042"
                  },
                  "message": { "nonce": "1" }
                }"#,
            ),
        ];

        for (why, json) in cases {
            assert!(
                TypedData::from_json(json).is_err(),
                "accepted a document that cannot be hashed: {why}"
            );
        }
    }

    #[test]
    fn a_valid_document_still_parses_after_the_hashability_check() {
        // The check must not be so strict that it rejects real payloads. The spec's own Mail
        // example and a permit both have to survive it.
        assert!(TypedData::from_json(MAIL).is_ok());
        assert!(TypedData::from_json(
            r#"{
              "types": {
                "EIP712Domain": [
                  { "name": "name", "type": "string" },
                  { "name": "version", "type": "string" },
                  { "name": "chainId", "type": "uint256" },
                  { "name": "verifyingContract", "type": "address" }
                ],
                "Permit": [
                  { "name": "owner", "type": "address" },
                  { "name": "spender", "type": "address" },
                  { "name": "value", "type": "uint256" },
                  { "name": "nonce", "type": "uint256" },
                  { "name": "deadline", "type": "uint256" }
                ]
              },
              "primaryType": "Permit",
              "domain": {
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
              },
              "message": {
                "owner": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
                "spender": "0x1111111254EEB25477B68fb85Ed929f73A960582",
                "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "nonce": "0",
                "deadline": "1893456000"
              }
            }"#
        )
        .is_ok());
    }

    #[test]
    fn signatures_verify_and_use_v_27_or_28() {
        let key = key();
        let data = TypedData::from_json(MAIL).unwrap();

        let signature = sign_typed_data(&key, &data).unwrap();
        assert!(verify_digest_secp256k1(
            &key.public_key_bytes().unwrap(),
            &data.signing_hash().unwrap(),
            signature.as_bytes()
        )
        .unwrap());

        let hex = sign_typed_data_hex(&key, &data).unwrap();
        let v = u8::from_str_radix(&hex[hex.len() - 2..], 16).unwrap();
        assert!(v == 27 || v == 28, "v was {v}");
    }

    #[test]
    fn changing_the_domain_changes_the_signature() {
        // The domain separator is what stops a signature for one contract being replayed against
        // another, so every field of it must reach the hash.
        let base = TypedData::from_json(MAIL).unwrap();
        let baseline = base.signing_hash().unwrap();

        for (field, replacement) in [
            ("chainId", serde_json::json!(137)),
            ("name", serde_json::json!("Other Mail")),
            ("version", serde_json::json!("2")),
            (
                "verifyingContract",
                serde_json::json!("0x0000000000000000000000000000000000000001"),
            ),
        ] {
            let mut variant = base.clone();
            variant.domain[field] = replacement;
            assert_ne!(
                variant.signing_hash().unwrap(),
                baseline,
                "changing domain.{field} did not change the signing hash"
            );
        }
    }
}
