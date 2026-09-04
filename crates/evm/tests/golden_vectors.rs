//! Asserts the Ethereum encoding and signing paths byte for byte against ethers v6.
//!
//! Regenerate the vectors with `pnpm generate:evm` in `tests/vectors/generate`. A diff there is
//! not a test to update: it means our encoding changed, and every signature the wallet produces
//! for an EVM chain is suspect until the diff is explained.
//!
//! Why ethers rather than a hand-written table: the interesting failures are not in the cases a
//! human thinks to write down. They are zero values that must encode as an empty string rather
//! than a zero byte, chain ids that overflow a 32-bit `v`, and EIP-712 arrays whose elements are
//! hashed before concatenation. ethers has been agreeing with the chains on all of that for
//! years, so disagreement with ethers is our bug until proven otherwise.

use serde_json::Value;
use zunia_evm::{
    eip712::TypedData,
    personal::{personal_sign_hash, personal_sign_hex, personal_sign_payload},
    tx::{AccessListItem, Address, TxKind, UnsignedTx, U256},
};
use zunia_kernel::{Curve, DerivationPath, ExtendedKey, ZuniaMnemonic};

fn vectors() -> Value {
    let raw = include_str!("../../../tests/vectors/evm-signing.json");
    serde_json::from_str(raw).expect("evm-signing.json is not valid JSON")
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
        .to_string()
}

fn quantity(value: &Value, key: &str) -> Option<U256> {
    match value.get(key) {
        Some(Value::String(s)) => Some(U256::parse_decimal(s).expect("bad decimal quantity")),
        _ => None,
    }
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing quantity {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("{key} does not fit in u64"))
}

fn key_at(mnemonic: &str, path: &str) -> ExtendedKey {
    let seed = ZuniaMnemonic::parse(mnemonic).unwrap().to_seed("");
    let path = DerivationPath::parse(path).expect("vector path does not parse");
    ExtendedKey::from_seed_and_path(Curve::Secp256k1, seed.expose(), &path).unwrap()
}

fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text.trim_start_matches("0x")).expect("vector field is not hex")
}

#[test]
fn addresses_match_ethers() {
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let accounts = vectors["accounts"].as_array().unwrap();
    assert!(!accounts.is_empty(), "no accounts in the vector file");

    for account in accounts {
        let path = text(account, "path");
        let key = key_at(&mnemonic, &path);

        // The compressed public key first: if this diverges, the address would too, and knowing
        // which of the two broke saves an hour.
        assert_eq!(
            hex::encode(key.public_key_bytes().unwrap()),
            text(account, "publicKeyCompressed"),
            "public key diverged at {path}"
        );

        let derived = zunia_evm::address_from_public_key(&key.public_key_bytes().unwrap())
            .expect("address derivation failed");

        // Checksummed, because that is the form a user compares against a block explorer.
        assert_eq!(
            derived.to_checksummed(),
            text(account, "address"),
            "address diverged at {path}"
        );
        assert_eq!(
            derived.to_string().to_lowercase(),
            text(account, "addressLowercase")
        );
    }
}

/// Rebuilds one transaction vector as an `UnsignedTx`.
fn unsigned_from(vector: &Value) -> UnsignedTx {
    let tx = &vector["tx"];
    let tx_type = tx["type"].as_u64().expect("missing type");
    let chain_id = tx["chainId"].as_str().unwrap().parse::<u64>().unwrap();

    let to = tx["to"]
        .as_str()
        .map(|address| Address::parse(address).expect("bad recipient"));

    let access_list: Vec<AccessListItem> = tx["accessList"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| AccessListItem {
                    address: Address::parse(item["address"].as_str().unwrap()).unwrap(),
                    storage_keys: item["storageKeys"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|key| {
                            let bytes = hex_bytes(key.as_str().unwrap());
                            <[u8; 32]>::try_from(bytes.as_slice()).expect("storage key size")
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();

    let kind = match tx_type {
        0 => TxKind::Legacy {
            gas_price: quantity(tx, "gasPrice").expect("legacy needs a gas price"),
        },
        1 => TxKind::AccessList {
            gas_price: quantity(tx, "gasPrice").expect("2930 needs a gas price"),
            access_list,
        },
        2 => TxKind::FeeMarket {
            max_priority_fee_per_gas: quantity(tx, "maxPriorityFeePerGas").unwrap(),
            max_fee_per_gas: quantity(tx, "maxFeePerGas").unwrap(),
            access_list,
        },
        other => panic!("unhandled transaction type {other}"),
    };

    UnsignedTx {
        chain_id,
        nonce: u64_field(tx, "nonce"),
        gas_limit: u64_field(tx, "gasLimit"),
        to,
        value: quantity(tx, "value").unwrap(),
        data: hex_bytes(tx["data"].as_str().unwrap()),
        kind,
    }
}

#[test]
fn transaction_sign_payloads_match_ethers() {
    let vectors = vectors();
    let cases = vectors["transactions"].as_array().unwrap();
    assert!(cases.len() >= 8, "expected the full transaction matrix");

    for case in cases {
        let name = text(case, "name");
        let tx = unsigned_from(case);

        // The payload before the hash. An encoding bug shows up here in a form that can be read
        // and diffed, rather than as an opaque 32-byte mismatch.
        assert_eq!(
            hex::encode(tx.sign_payload().expect("payload")),
            text(case, "signPayload"),
            "sign payload diverged for {name}"
        );
        assert_eq!(
            hex::encode(tx.sign_hash().expect("hash")),
            text(case, "signHash"),
            "sign hash diverged for {name}"
        );
    }
}

#[test]
fn transaction_signatures_match_ethers() {
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");

    for case in vectors["transactions"].as_array().unwrap() {
        let name = text(case, "name");
        let key = key_at(&mnemonic, &text(case, "signerPath"));
        let signed = unsigned_from(case).sign(&key).expect("signing failed");

        let expected = &case["signature"];
        assert_eq!(
            hex::encode(signed.r),
            expected["r"].as_str().unwrap(),
            "r diverged for {name}"
        );
        assert_eq!(
            hex::encode(signed.s),
            expected["s"].as_str().unwrap(),
            "s diverged for {name}"
        );
        // `onWireV`, not ethers' normalised `v`: for a legacy transaction the RLP carries the
        // EIP-155 value, and for a typed one it carries the bare y parity.
        assert_eq!(
            signed.v.to_string(),
            expected["onWireV"].as_str().unwrap(),
            "v diverged for {name}"
        );

        // The full serialised transaction, which is what actually goes to the node.
        assert_eq!(
            hex::encode(&signed.raw),
            text(case, "signedSerialized"),
            "serialised transaction diverged for {name}"
        );
        assert_eq!(
            hex::encode(signed.hash),
            text(case, "txHash"),
            "transaction hash diverged for {name}"
        );
    }
}

#[test]
fn personal_sign_matches_ethers() {
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let cases = vectors["messages"].as_array().unwrap();
    assert!(cases.len() >= 8);

    for case in cases {
        let name = text(case, "name");
        let message = text(case, "message");
        let key = key_at(&mnemonic, "m/44'/60'/0'/0/0");

        // Byte length, not character count. The unicode case fails loudly here if we ever count
        // characters, which is a real interop bug in other wallets.
        assert_eq!(
            message.len() as u64,
            case["byteLength"].as_u64().unwrap(),
            "byte length diverged for {name}"
        );
        assert_eq!(
            hex::encode(personal_sign_payload(message.as_bytes())),
            text(case, "payload"),
            "payload diverged for {name}"
        );
        assert_eq!(
            hex::encode(personal_sign_hash(message.as_bytes())),
            text(case, "hash"),
            "hash diverged for {name}"
        );
        // The 65-byte r || s || v form a dApp receives, with v as 27 or 28.
        assert_eq!(
            personal_sign_hex(&key, message.as_bytes()).expect("sign"),
            format!("0x{}", text(case, "signature")),
            "signature diverged for {name}"
        );
    }
}

#[test]
fn typed_data_matches_ethers_at_every_intermediate_step() {
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let key = key_at(&mnemonic, "m/44'/60'/0'/0/0");
    let cases = vectors["typedData"].as_array().unwrap();
    assert!(cases.len() >= 5);

    for case in cases {
        let name = text(case, "name");
        let typed = TypedData::from_json(&case["payload"].to_string())
            .unwrap_or_else(|e| panic!("{name} failed to parse: {e}"));

        // Each intermediate is asserted separately because they fail for different reasons:
        // encodeType catches type-string construction and dependency ordering, typeHash catches
        // the hash of it, domainSeparator catches optional-field omission, hashStruct catches
        // value encoding, and only then does the final digest mean anything.
        assert_eq!(
            typed.encode_type(&typed.primary_type).expect("encode type"),
            text(case, "encodeType"),
            "encodeType diverged for {name}"
        );
        assert_eq!(
            hex::encode(typed.type_hash(&typed.primary_type).expect("type hash")),
            text(case, "typeHash"),
            "typeHash diverged for {name}"
        );
        assert_eq!(
            hex::encode(typed.domain_separator().expect("domain separator")),
            text(case, "domainSeparator"),
            "domainSeparator diverged for {name}"
        );
        assert_eq!(
            hex::encode(
                typed
                    .hash_struct(&typed.primary_type, &typed.message)
                    .expect("hash struct")
            ),
            text(case, "hashStruct"),
            "hashStruct diverged for {name}"
        );
        // ethers' `encodeData` is the specification's `typeHash || encodeData`, so ours has to
        // be prefixed before comparing. Asserting the members separately is what localises a
        // divergence to a single field rather than to the whole struct.
        let mut with_type_hash = typed
            .type_hash(&typed.primary_type)
            .expect("type hash")
            .to_vec();
        with_type_hash.extend_from_slice(
            &typed
                .encode_data(&typed.primary_type, &typed.message)
                .expect("encode data"),
        );
        assert_eq!(
            hex::encode(&with_type_hash),
            text(case, "typeHashAndEncodedData"),
            "encodeData diverged for {name}"
        );
        assert_eq!(
            hex::encode(typed.signing_hash().expect("signing hash")),
            text(case, "signingHash"),
            "signingHash diverged for {name}"
        );
        assert_eq!(
            zunia_evm::eip712::sign_typed_data_hex(&key, &typed).expect("sign"),
            format!("0x{}", text(case, "signature")),
            "signature diverged for {name}"
        );
    }
}

#[test]
fn the_signatures_we_produce_are_low_s() {
    // A high-s signature is the mirror image of a valid one and verifies just as well, but many
    // contracts reject it and some indexers treat the two as different transactions. ethers is
    // always low-s, so agreeing with ethers already proves this; asserting it directly means the
    // property survives a future change to how we call the curve library.
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let key = key_at(&mnemonic, "m/44'/60'/0'/0/0");

    for case in vectors["transactions"].as_array().unwrap() {
        let signed = unsigned_from(case).sign(&key).expect("sign");
        assert!(
            signed.s <= HALF_N,
            "high-s signature for {}",
            text(case, "name")
        );
    }

    for case in vectors["recovery"].as_array().unwrap() {
        assert!(
            case["sIsLow"].as_bool().unwrap(),
            "the generator recorded a high-s signature, which should be impossible"
        );
    }
}

#[test]
fn every_vector_is_exercised_by_a_test() {
    // A vector nobody asserts is worse than no vector: it looks like coverage. This fails if a
    // future generator adds a section the Rust side does not read.
    let vectors = vectors();
    let sections: Vec<&str> = vectors
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|key| !matches!(*key, "description" | "generator" | "mnemonic" | "note"))
        .collect();

    let asserted = [
        "accounts",
        "transactions",
        "messages",
        "typedData",
        "recovery",
    ];
    for section in &sections {
        assert!(
            asserted.contains(section),
            "vector section {section} is generated but never asserted"
        );
    }
    for section in asserted {
        assert!(
            sections.contains(&section),
            "test expects section {section} but the generator no longer emits it"
        );
    }
}

#[test]
fn a_signature_over_a_tampered_transaction_does_not_match_the_vector() {
    // Confirms the vectors are actually sensitive to what they claim to cover. If flipping the
    // recipient still produced the recorded signature, every assertion above would be vacuous.
    let vectors = vectors();
    let mnemonic = text(&vectors, "mnemonic");
    let key = key_at(&mnemonic, "m/44'/60'/0'/0/0");
    let case = &vectors["transactions"][0];

    let mut tx = unsigned_from(case);
    tx.to = Some(Address::parse("0x0000000000000000000000000000000000000dad").unwrap());
    let signed = tx.sign(&key).unwrap();

    assert_ne!(
        hex::encode(signed.r),
        case["signature"]["r"].as_str().unwrap(),
        "changing the recipient did not change the signature"
    );
}
