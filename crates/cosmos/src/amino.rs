//! Amino JSON canonicalisation.
//!
//! `SIGN_MODE_LEGACY_AMINO_JSON` signs the UTF-8 bytes of a JSON document, so the signature is
//! over a *string*, not over a structure. Two documents that are semantically identical but
//! differ by one byte produce different signatures, and the chain only accepts one of them.
//! That makes this file the highest-risk code in the kernel: a mistake here does not throw, it
//! produces a signature that verifies against nothing, and the user sees "insufficient fee" or
//! "unauthorized" with no indication that the encoding was wrong.
//!
//! The rules, all of which are load bearing:
//!
//! 1. **Object keys sorted lexicographically by byte, at every depth.** The Cosmos SDK calls
//!    `sortJSON` before signing.
//! 2. **Compact.** No whitespace between tokens.
//! 3. **Integers as strings.** `sequence`, `account_number`, `gas` and every amount are quoted
//!    decimal strings, because JavaScript cannot represent a 64-bit integer exactly and the
//!    wire format compensates.
//! 4. **Empty values omitted.** The SDK's struct tags carry `omitempty`, so an empty memo, an
//!    empty coin list and a zero timeout are absent rather than present-and-empty. `"memo":""`
//!    is a different document from no `memo` key at all.
//!
//! # HTML escaping
//!
//! Go's `encoding/json`, which builds the document the chain verifies (legacy amino's
//! `MustSortJSON` and x/tx's aminojson encoder alike), escapes `<`, `>` and `&` as `\u003c`,
//! `\u003e` and `\u0026`, and U+2028 and U+2029 as `\u2028` and `\u2029`. CosmJS's
//! `serializeSignDoc` applies the first three (`escapeCharacters`) and Keplr does the same. A memo
//! or a contract message carrying one of them, signed unescaped, verifies against nothing.
//!
//! Asserted in [`tests::html_characters_are_escaped_like_the_chain`].

use serde_json::{Map, Value};

/// Serialises a JSON value into Amino sign bytes.
///
/// Sorts keys at every depth and emits compact output. Does not strip empty values: message
/// encoders are responsible for not producing them, so that omission is a deliberate decision
/// at the message level rather than a blanket rule applied here that might drop a legitimately
/// empty field.
pub fn to_sign_bytes(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out.into_bytes()
}

/// Same as [`to_sign_bytes`] but returns the string, for display and for tests.
pub fn to_canonical_string(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            // Sort by raw bytes, not by locale or by Unicode collation. `sortJSON` in the SDK
            // is a byte-wise sort, and the two differ for non-ASCII keys.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// Writes a JSON string the way Go's `encoding/json` does.
///
/// The JSON grammar's escapes (quote, backslash, control characters below 0x20, with the short
/// forms for backspace, form feed, newline, carriage return and tab), plus Go's HTML escapes for
/// `<`, `>` and `&` and its escapes for U+2028 and U+2029. All other non-ASCII is emitted
/// literally as UTF-8.
fn write_json_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Builds a JSON object, dropping entries whose value is empty.
///
/// "Empty" means null, an empty string, an empty array, or an empty object, mirroring Go's
/// `omitempty`. Note that it does **not** mean the string `"0"`: `account_number` and
/// `sequence` are legitimately `"0"` for a fresh account and must be present, which is why
/// integers are stringified before they get here.
pub fn object_omit_empty<I>(entries: I) -> Value
where
    I: IntoIterator<Item = (&'static str, Value)>,
{
    let mut map = Map::new();
    for (key, value) in entries {
        if is_empty(&value) {
            continue;
        }
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

/// Builds a JSON object keeping every entry, including empty ones.
pub fn object<I>(entries: I) -> Value
where
    I: IntoIterator<Item = (&'static str, Value)>,
{
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

/// Wraps a message in the Amino `{ "type": ..., "value": ... }` envelope.
pub fn typed(type_name: &str, value: Value) -> Value {
    object([
        ("type", Value::String(type_name.to_owned())),
        ("value", value),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_at_every_depth() {
        let value = json!({
            "z": 1,
            "a": { "d": 4, "b": { "y": 1, "x": 2 } },
            "m": [ { "q": 1, "p": 2 } ]
        });
        assert_eq!(
            to_canonical_string(&value),
            r#"{"a":{"b":{"x":2,"y":1},"d":4},"m":[{"p":2,"q":1}],"z":1}"#
        );
    }

    #[test]
    fn output_is_compact() {
        let value = json!({ "a": 1, "b": [1, 2, 3] });
        let rendered = to_canonical_string(&value);
        assert!(!rendered.contains(' '));
        assert!(!rendered.contains('\n'));
        assert_eq!(rendered, r#"{"a":1,"b":[1,2,3]}"#);
    }

    #[test]
    fn array_order_is_preserved() {
        // Arrays are ordered data. Sorting them would change which validator receives a
        // delegation in a multi-message transaction.
        let value = json!(["c", "a", "b"]);
        assert_eq!(to_canonical_string(&value), r#"["c","a","b"]"#);
    }

    #[test]
    fn keys_sort_by_byte_not_by_collation() {
        // Uppercase sorts before lowercase in byte order, which is what the SDK does.
        let value = json!({ "b": 1, "B": 2, "a": 3, "A": 4 });
        assert_eq!(to_canonical_string(&value), r#"{"A":4,"B":2,"a":3,"b":1}"#);
    }

    #[test]
    fn escapes_only_what_json_requires() {
        let value = json!({ "memo": "line\nbreak \"quoted\" back\\slash\ttab" });
        assert_eq!(
            to_canonical_string(&value),
            r#"{"memo":"line\nbreak \"quoted\" back\\slash\ttab"}"#
        );
    }

    #[test]
    fn escapes_control_characters() {
        let value = json!({ "m": "\u{0001}\u{0008}\u{000c}\u{001f}" });
        assert_eq!(to_canonical_string(&value), r#"{"m":"\u0001\b\f\u001f"}"#);
    }

    #[test]
    fn html_characters_are_escaped_like_the_chain() {
        // Go's encoding/json, which builds the document the chain verifies, writes these three
        // escaped, and CosmJS's serializeSignDoc (escapeCharacters) and Keplr match it. A memo
        // like "rent & food" signed unescaped verifies against nothing.
        let bs = char::from(0x5c_u8);
        let value = json!({ "memo": "a<b>c&d" });
        assert_eq!(
            to_canonical_string(&value),
            format!(r#"{{"memo":"a{bs}u003cb{bs}u003ec{bs}u0026d"}}"#)
        );
    }

    #[test]
    fn line_and_paragraph_separators_are_escaped_like_go() {
        // Go escapes U+2028 and U+2029 in every string it marshals. CosmJS does not, so a memo
        // carrying one fails there too; matching the chain is what counts.
        let bs = char::from(0x5c_u8);
        let (ls, ps) = (
            char::from_u32(0x2028).unwrap(),
            char::from_u32(0x2029).unwrap(),
        );
        let value = json!({ "memo": format!("a{ls}b{ps}c") });
        assert_eq!(
            to_canonical_string(&value),
            format!(r#"{{"memo":"a{bs}u2028b{bs}u2029c"}}"#)
        );
    }

    #[test]
    fn non_ascii_is_emitted_literally() {
        let value = json!({ "memo": "Zunia 안녕 مرحبا 🔐" });
        let rendered = to_canonical_string(&value);
        assert!(rendered.contains("안녕"));
        assert!(rendered.contains('🔐'));
        assert!(!rendered.contains("\\u"));
    }

    #[test]
    fn omit_empty_drops_the_right_things() {
        let value = object_omit_empty([
            ("memo", json!("")),
            ("amount", json!([])),
            ("extra", json!({})),
            ("nothing", Value::Null),
            ("sequence", json!("0")),
            ("count", json!(0)),
            ("flag", json!(false)),
            ("kept", json!("value")),
        ]);
        assert_eq!(
            to_canonical_string(&value),
            r#"{"count":0,"flag":false,"kept":"value","sequence":"0"}"#,
            "\"0\" and false must survive; only null, empty string, empty array and empty \
             object are dropped"
        );
    }

    #[test]
    fn plain_object_keeps_empty_values() {
        let value = object([("memo", json!("")), ("a", json!(1))]);
        assert_eq!(to_canonical_string(&value), r#"{"a":1,"memo":""}"#);
    }

    #[test]
    fn typed_envelope_shape() {
        let value = typed("cosmos-sdk/MsgSend", json!({ "b": 1, "a": 2 }));
        assert_eq!(
            to_canonical_string(&value),
            r#"{"type":"cosmos-sdk/MsgSend","value":{"a":2,"b":1}}"#
        );
    }

    #[test]
    fn sign_bytes_are_utf8_of_the_canonical_string() {
        let value = json!({ "chain_id": "safrochain-1" });
        assert_eq!(
            to_sign_bytes(&value),
            to_canonical_string(&value).into_bytes()
        );
    }

    #[test]
    fn empty_containers_render() {
        assert_eq!(to_canonical_string(&json!({})), "{}");
        assert_eq!(to_canonical_string(&json!([])), "[]");
        assert_eq!(to_canonical_string(&Value::Null), "null");
    }
}
