//! Parses the actual `zunia-chain-registry` checkout, when one is present.
//!
//! Skips rather than fails when the sibling repository is missing, because `zunia-core` is an
//! independent repository per ADR-0005 and CI for this crate must not require another checkout.
//! CI sets `ZUNIA_CHAIN_REGISTRY` in the job that does have both, so the skip cannot hide a
//! regression there.
//!
//! The unit tests in `src/lib.rs` cover behaviour with fixtures. This covers the thing fixtures
//! cannot: that 332 real, community-maintained descriptors actually parse.

use std::path::{Path, PathBuf};

use zunia_kernel::AddressScheme;
use zunia_registry::{ChainInfo, Registry};

fn registry_dir() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("ZUNIA_CHAIN_REGISTRY") {
        let path = PathBuf::from(explicit);
        return path.is_dir().then_some(path);
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../zunia-chain-registry")
        .canonicalize()
        .ok()?;
    sibling.is_dir().then_some(sibling)
}

fn read_all(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((name, text));
        }
    }
    out.sort();
    out
}

#[test]
fn every_cosmos_descriptor_parses() {
    let Some(root) = registry_dir() else {
        eprintln!("skipping: no zunia-chain-registry checkout, set ZUNIA_CHAIN_REGISTRY");
        return;
    };

    let documents = read_all(&root.join("cosmos"));
    assert!(
        documents.len() > 300,
        "expected the full registry, found {} files",
        documents.len()
    );

    let borrowed: Vec<(&str, &str)> = documents
        .iter()
        .map(|(name, json)| (name.as_str(), json.as_str()))
        .collect();
    let (registry, errors) = Registry::from_jsons(borrowed);

    // Failures are printed in full rather than summarised. A descriptor that stops parsing is
    // a chain the user can no longer transact on, so the specific file matters.
    if !errors.is_empty() {
        for (name, error) in &errors {
            eprintln!("  {name}: {error}");
        }
    }

    // Every rejection must be an endpoint or completeness problem, never a parse failure.
    // A `Malformed` here means the registry schema drifted from this crate's model, which
    // would silently disable chains.
    let malformed: Vec<_> = errors
        .iter()
        .filter(|(_, e)| *e == zunia_registry::RegistryError::Malformed)
        .collect();
    assert!(
        malformed.is_empty(),
        "{} descriptors failed to parse, the registry schema has drifted: {:?}",
        malformed.len(),
        malformed
    );

    assert!(
        registry.len() > 250,
        "only {} of {} chains were usable",
        registry.len(),
        documents.len()
    );

    println!(
        "parsed {} of {} cosmos chains, {} rejected on validation",
        registry.len(),
        documents.len(),
        errors.len()
    );
}

#[test]
fn every_bech32_prefix_in_the_registry_is_a_valid_hrp() {
    // A bech32 human-readable part is lowercase printable ASCII. A mixed-case prefix is not a
    // cosmetic issue: some libraries silently lowercase it, so the wallet would show a
    // validator address in a spelling the chain and its explorers reject, and staking to it
    // would fail with nothing to point at. The registry shipped exactly this on
    // lumiwaveprotocol, which is why the check now runs over every descriptor.
    let Some(root) = registry_dir() else {
        eprintln!("skipping: no zunia-chain-registry checkout");
        return;
    };

    let documents = read_all(&root.join("cosmos"));
    assert!(!documents.is_empty(), "no descriptors were read");

    let mut offenders = Vec::new();
    for (name, json) in &documents {
        // Other rejections are covered by `every_cosmos_descriptor_parses`.
        if let Err(zunia_registry::RegistryError::InvalidPrefix(prefix)) =
            ChainInfo::from_json(json)
        {
            offenders.push(format!("{name}: {prefix:?}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} descriptors have a malformed bech32 prefix:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

#[test]
fn safrochain_is_present_and_correct() {
    let Some(root) = registry_dir() else {
        eprintln!("skipping: no zunia-chain-registry checkout");
        return;
    };

    let json = std::fs::read_to_string(root.join("cosmos/safrochain.json"))
        .expect("safrochain.json must exist, it is the flagship chain");
    let chain = ChainInfo::from_json(&json).unwrap();

    assert_eq!(chain.chain_id, "safrochain-1");
    assert_eq!(chain.bip44.coin_type, 118);
    assert_eq!(chain.bech32.account, "addr_safro");
    assert_eq!(chain.address_scheme(), AddressScheme::Cosmos);
    assert!(chain.supports_cosmwasm());
    assert!(!chain.is_testnet());
    assert_eq!(chain.primary_fee_currency().minimal_denom, "usaf");
    assert_eq!(chain.decimals_for_denom("usaf"), 6);
}

#[test]
fn ethermint_chains_are_recognised_across_the_registry() {
    let Some(root) = registry_dir() else {
        eprintln!("skipping: no zunia-chain-registry checkout");
        return;
    };

    let documents = read_all(&root.join("cosmos"));
    let borrowed: Vec<(&str, &str)> = documents
        .iter()
        .map(|(name, json)| (name.as_str(), json.as_str()))
        .collect();
    let (registry, _) = Registry::from_jsons(borrowed);

    let ethermint = registry
        .chains()
        .iter()
        .filter(|c| c.address_scheme() == AddressScheme::Ethermint)
        .count();

    // 68 chains carry `eth-address-gen` at the time of writing. Asserting a floor rather than
    // an exact count keeps the test from breaking every time upstream adds a chain, while
    // still catching a feature-parsing regression that would silently derive Cosmos addresses
    // for all of them.
    assert!(
        ethermint >= 50,
        "only {ethermint} Ethermint chains detected, feature parsing has regressed"
    );

    let injective = registry
        .get("injective-1")
        .expect("injective must be in the registry");
    assert_eq!(injective.address_scheme(), AddressScheme::Ethermint);
    assert!(injective.uses_eth_key_sign());
}
