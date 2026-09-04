//! Chain registry parsing.
//!
//! `zunia-chain-registry` is a fork of the Keplr registry, so the on-disk format is Keplr's
//! `ChainInfo`. This crate turns that JSON into the parameters the kernel needs: coin type,
//! bech32 prefix, curve, and address scheme.
//!
//! Nothing about a chain is hardcoded anywhere else. That is the point. Of the 332 Cosmos
//! chains in the registry, 68 use Ethermint address derivation and several use a non-118 coin
//! type, and every one of those differences is a wrong address if it is guessed instead of
//! read.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::{Deserialize, Serialize};
use zunia_kernel::{AddressScheme, Curve, DerivationPath};

/// Feature flags the registry uses that change cryptographic behaviour.
///
/// The remaining flags in the registry (`cosmwasm`, `secretwasm`, `ibc-v2`, fee-market
/// variants) affect features and fees, not key derivation, and are exposed through
/// [`ChainInfo::has_feature`] rather than given named constants here.
pub mod features {
    /// Addresses are derived with the Ethereum rule, `keccak256(pubkey)[12..]`, then bech32
    /// encoded. Injective, Evmos, Kava and 65 other chains.
    pub const ETH_ADDRESS_GEN: &str = "eth-address-gen";
    /// Signing uses the `ethsecp256k1` public key type rather than Cosmos `secp256k1`.
    pub const ETH_KEY_SIGN: &str = "eth-key-sign";
    /// CosmWasm is enabled, so `MsgExecuteContract` is expected.
    pub const COSMWASM: &str = "cosmwasm";
    /// Secret Network's encrypted CosmWasm variant.
    pub const SECRETWASM: &str = "secretwasm";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip44 {
    #[serde(rename = "coinType")]
    pub coin_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bech32Config {
    #[serde(rename = "bech32PrefixAccAddr")]
    pub account: String,
    #[serde(rename = "bech32PrefixValAddr", default)]
    pub validator: Option<String>,
    #[serde(rename = "bech32PrefixConsAddr", default)]
    pub consensus: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GasPriceStep {
    pub low: f64,
    pub average: f64,
    pub high: f64,
}

/// Which gas price tier the user picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeTier {
    Low,
    Average,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Currency {
    #[serde(rename = "coinDenom")]
    pub denom: String,
    #[serde(rename = "coinMinimalDenom")]
    pub minimal_denom: String,
    #[serde(rename = "coinDecimals")]
    pub decimals: u32,
    #[serde(rename = "coinImageUrl", default)]
    pub image_url: Option<String>,
    #[serde(rename = "gasPriceStep", default)]
    pub gas_price_step: Option<GasPriceStep>,
}

/// A chain as described by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    #[serde(rename = "chainId")]
    pub chain_id: String,
    #[serde(rename = "chainName")]
    pub chain_name: String,
    #[serde(rename = "chainSymbolImageUrl", default)]
    pub image_url: Option<String>,
    pub rpc: String,
    pub rest: String,
    pub bip44: Bip44,
    #[serde(rename = "bech32Config")]
    pub bech32: Bech32Config,
    #[serde(default)]
    pub currencies: Vec<Currency>,
    #[serde(rename = "feeCurrencies", default)]
    pub fee_currencies: Vec<Currency>,
    #[serde(rename = "stakeCurrency", default)]
    pub stake_currency: Option<Currency>,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Why a chain descriptor was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// JSON did not parse, or a required field was missing.
    Malformed,
    /// `chainId` was empty.
    MissingChainId,
    /// `bech32PrefixAccAddr` was empty, so no address could be produced.
    MissingPrefix,
    /// A bech32 prefix is not a valid human-readable part: uppercase, or a character outside
    /// printable ASCII. Carries the offending value so the registry file can be corrected.
    InvalidPrefix(String),
    /// No fee currency, so no transaction could ever be paid for.
    MissingFeeCurrency,
    /// An RPC or REST endpoint was not `https`. Rejected rather than warned about, because a
    /// plaintext endpoint leaks every address the user queries.
    InsecureEndpoint,
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("chain descriptor is malformed"),
            Self::MissingChainId => f.write_str("chain descriptor has no chainId"),
            Self::MissingPrefix => f.write_str("chain descriptor has no bech32 account prefix"),
            Self::InvalidPrefix(prefix) => write!(
                f,
                "bech32 prefix {prefix:?} is not a valid human-readable part; it must be \
                 lowercase printable ASCII"
            ),
            Self::MissingFeeCurrency => f.write_str("chain descriptor has no fee currency"),
            Self::InsecureEndpoint => f.write_str("chain endpoint is not https"),
        }
    }
}

impl core::error::Error for RegistryError {}

impl ChainInfo {
    /// Parses a single registry file.
    pub fn from_json(json: &str) -> Result<Self, RegistryError> {
        let info: Self = serde_json::from_str(json).map_err(|_| RegistryError::Malformed)?;
        info.validate()?;
        Ok(info)
    }

    /// Structural checks that must hold before the chain is usable for signing.
    ///
    /// Enforced here rather than at the call site so a malformed community submission cannot
    /// reach the signing path. A chain with no fee currency, for instance, would let the user
    /// build a transaction that can never be broadcast.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.chain_id.trim().is_empty() {
            return Err(RegistryError::MissingChainId);
        }
        if self.bech32.account.trim().is_empty() {
            return Err(RegistryError::MissingPrefix);
        }
        // A bech32 human-readable part is lowercase by definition, so a mixed-case prefix is
        // not a cosmetic problem. Some libraries silently lowercase it, which means the same
        // chain gets two spellings and the wallet can display a validator address no explorer
        // will accept. Caught here, at parse time, rather than at signing time. The registry
        // has shipped this defect before, on lumiwaveprotocol.
        let optional = [&self.bech32.validator, &self.bech32.consensus];
        for prefix in core::iter::once(&self.bech32.account).chain(optional.into_iter().flatten()) {
            if !is_valid_hrp(prefix) {
                return Err(RegistryError::InvalidPrefix(prefix.clone()));
            }
        }
        if self.fee_currencies.is_empty() {
            return Err(RegistryError::MissingFeeCurrency);
        }
        for endpoint in [&self.rpc, &self.rest] {
            if !endpoint.starts_with("https://") && !is_localhost(endpoint) {
                return Err(RegistryError::InsecureEndpoint);
            }
        }
        Ok(())
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// The address derivation rule for this chain.
    ///
    /// Read from the registry, never inferred from the coin type. Coin type 60 usually means
    /// Ethermint but not always, and the `eth-address-gen` flag is the authoritative signal.
    pub fn address_scheme(&self) -> AddressScheme {
        if self.has_feature(features::ETH_ADDRESS_GEN) {
            AddressScheme::Ethermint
        } else {
            AddressScheme::Cosmos
        }
    }

    /// Cosmos chains are all secp256k1. Kept as a method so an ed25519 Cosmos chain, should one
    /// appear, is a registry change rather than a code change.
    pub fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    /// True if signing must advertise the `ethsecp256k1` public key type.
    pub fn uses_eth_key_sign(&self) -> bool {
        self.has_feature(features::ETH_KEY_SIGN)
    }

    pub fn supports_cosmwasm(&self) -> bool {
        self.has_feature(features::COSMWASM) || self.has_feature(features::SECRETWASM)
    }

    /// The BIP-44 path for an account and address index on this chain.
    pub fn derivation_path(&self, account: u32, index: u32) -> DerivationPath {
        DerivationPath::bip44(self.bip44.coin_type, account, index)
    }

    /// The fee currency, which is not always the staking currency.
    pub fn primary_fee_currency(&self) -> &Currency {
        // `validate` guarantees the vector is non-empty.
        &self.fee_currencies[0]
    }

    /// Gas price for a tier, in the fee currency's minimal denom.
    ///
    /// Returns `None` when the registry omits `gasPriceStep`, which means the chain expects the
    /// client to query the fee market instead of using a static price. Defaulting to zero here
    /// would produce transactions that are silently rejected for insufficient fee.
    pub fn gas_price(&self, tier: FeeTier) -> Option<f64> {
        let step = self.primary_fee_currency().gas_price_step?;
        Some(match tier {
            FeeTier::Low => step.low,
            FeeTier::Average => step.average,
            FeeTier::High => step.high,
        })
    }

    /// Looks up a currency by its minimal denom, for rendering an amount.
    pub fn currency_for_denom(&self, minimal_denom: &str) -> Option<&Currency> {
        self.currencies
            .iter()
            .chain(self.fee_currencies.iter())
            .chain(self.stake_currency.iter())
            .find(|c| c.minimal_denom == minimal_denom)
    }

    /// Decimals for a denom, defaulting to 6.
    ///
    /// Six is the Cosmos convention, but an unknown denom is a display risk: showing a raw
    /// integer as if it were whole tokens overstates a balance by a million. Callers that are
    /// about to show a number to a user should prefer `currency_for_denom` and handle the
    /// unknown case explicitly.
    pub fn decimals_for_denom(&self, minimal_denom: &str) -> u32 {
        self.currency_for_denom(minimal_denom)
            .map(|c| c.decimals)
            .unwrap_or(6)
    }

    /// True if this is a testnet, by the usual chain-id conventions.
    ///
    /// Used to keep testnet assets out of the fiat portfolio total and to label the UI.
    pub fn is_testnet(&self) -> bool {
        let id = self.chain_id.to_lowercase();
        id.contains("test")
            || id.contains("devnet")
            || id.contains("localnet")
            || self.chain_name.to_lowercase().contains("testnet")
    }
}

/// A parsed set of chains, indexed by chain id.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    chains: Vec<ChainInfo>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses many descriptors, skipping and reporting the invalid ones.
    ///
    /// A single bad community submission must not stop the wallet from loading the other 331
    /// chains, so failures are collected rather than propagated.
    pub fn from_jsons<'a>(
        documents: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> (Self, Vec<(String, RegistryError)>) {
        let mut chains = Vec::new();
        let mut errors = Vec::new();
        for (name, json) in documents {
            match ChainInfo::from_json(json) {
                Ok(info) => chains.push(info),
                Err(error) => errors.push((name.to_owned(), error)),
            }
        }
        (Self { chains }, errors)
    }

    pub fn insert(&mut self, info: ChainInfo) -> Result<(), RegistryError> {
        info.validate()?;
        self.chains.retain(|c| c.chain_id != info.chain_id);
        self.chains.push(info);
        Ok(())
    }

    pub fn get(&self, chain_id: &str) -> Option<&ChainInfo> {
        self.chains.iter().find(|c| c.chain_id == chain_id)
    }

    /// Finds the chain that owns a bech32 prefix.
    ///
    /// Used to answer "which chain is this address for" when a user pastes one. Prefixes are
    /// not globally unique in principle, so the first match wins and the UI must still confirm.
    pub fn by_prefix(&self, prefix: &str) -> Option<&ChainInfo> {
        self.chains.iter().find(|c| c.bech32.account == prefix)
    }

    pub fn chains(&self) -> &[ChainInfo] {
        &self.chains
    }

    pub fn len(&self) -> usize {
        self.chains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    pub fn mainnets(&self) -> impl Iterator<Item = &ChainInfo> {
        self.chains.iter().filter(|c| !c.is_testnet())
    }
}

/// Whether a string is a usable bech32 human-readable part.
///
/// BIP-173 allows any printable US-ASCII in the range 33 to 126 and forbids mixed case, so
/// prefixes such as `addr_safro` and `lava@` are legitimate while `lumiValoper` is not. The
/// length ceiling of 83 leaves room for the separator and a 20-byte payload inside the 90
/// character bech32 limit.
fn is_valid_hrp(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= 83
        && prefix
            .bytes()
            .all(|b| (33..=126).contains(&b) && !b.is_ascii_uppercase())
}

fn is_localhost(endpoint: &str) -> bool {
    endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://0.0.0.0")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFROCHAIN: &str = r#"{
        "chainId": "safrochain-1",
        "chainName": "Safrochain",
        "rpc": "https://rpc.safrochain.network",
        "rest": "https://api.safrochain.network",
        "bip44": { "coinType": 118 },
        "bech32Config": {
            "bech32PrefixAccAddr": "addr_safro",
            "bech32PrefixValAddr": "addr_safrovaloper",
            "bech32PrefixConsAddr": "addr_safrovalcons"
        },
        "currencies": [
            { "coinDenom": "SAF", "coinMinimalDenom": "usaf", "coinDecimals": 6 },
            { "coinDenom": "DYMA", "coinMinimalDenom": "factory/addr_safro1z/udyma", "coinDecimals": 6 }
        ],
        "feeCurrencies": [
            {
                "coinDenom": "SAF",
                "coinMinimalDenom": "usaf",
                "coinDecimals": 6,
                "gasPriceStep": { "low": 0.05, "average": 0.075, "high": 0.1 }
            }
        ],
        "stakeCurrency": { "coinDenom": "SAF", "coinMinimalDenom": "usaf", "coinDecimals": 6 },
        "features": ["cosmwasm"]
    }"#;

    const INJECTIVE: &str = r#"{
        "chainId": "injective-1",
        "chainName": "Injective",
        "rpc": "https://rpc.injective.example",
        "rest": "https://api.injective.example",
        "bip44": { "coinType": 60 },
        "bech32Config": { "bech32PrefixAccAddr": "inj" },
        "currencies": [{ "coinDenom": "INJ", "coinMinimalDenom": "inj", "coinDecimals": 18 }],
        "feeCurrencies": [{ "coinDenom": "INJ", "coinMinimalDenom": "inj", "coinDecimals": 18 }],
        "features": ["eth-address-gen", "eth-key-sign", "cosmwasm"]
    }"#;

    #[test]
    fn parses_safrochain() {
        let chain = ChainInfo::from_json(SAFROCHAIN).unwrap();
        assert_eq!(chain.chain_id, "safrochain-1");
        assert_eq!(chain.bip44.coin_type, 118);
        assert_eq!(chain.bech32.account, "addr_safro");
        assert_eq!(chain.address_scheme(), AddressScheme::Cosmos);
        assert!(chain.supports_cosmwasm());
        assert!(!chain.uses_eth_key_sign());
        assert!(!chain.is_testnet());
        assert_eq!(chain.derivation_path(0, 0).to_string(), "m/44'/118'/0'/0/0");
    }

    #[test]
    fn ethermint_chains_are_detected_from_features() {
        let chain = ChainInfo::from_json(INJECTIVE).unwrap();
        assert_eq!(chain.address_scheme(), AddressScheme::Ethermint);
        assert!(chain.uses_eth_key_sign());
        assert_eq!(chain.derivation_path(0, 0).to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn coin_type_60_alone_does_not_imply_ethermint() {
        // Some coin-type-60 chains use the Cosmos address rule. Inferring the scheme from the
        // coin type would derive the wrong address for them.
        let json = INJECTIVE.replace(
            r#""features": ["eth-address-gen", "eth-key-sign", "cosmwasm"]"#,
            r#""features": []"#,
        );
        let chain = ChainInfo::from_json(&json).unwrap();
        assert_eq!(chain.bip44.coin_type, 60);
        assert_eq!(chain.address_scheme(), AddressScheme::Cosmos);
    }

    #[test]
    fn resolves_gas_prices_per_tier() {
        let chain = ChainInfo::from_json(SAFROCHAIN).unwrap();
        assert_eq!(chain.gas_price(FeeTier::Low), Some(0.05));
        assert_eq!(chain.gas_price(FeeTier::Average), Some(0.075));
        assert_eq!(chain.gas_price(FeeTier::High), Some(0.1));
    }

    #[test]
    fn missing_gas_price_step_is_none_not_zero() {
        // Injective omits gasPriceStep, so the client must query the fee market. A zero
        // default would build unbroadcastable transactions.
        let chain = ChainInfo::from_json(INJECTIVE).unwrap();
        assert_eq!(chain.gas_price(FeeTier::Average), None);
    }

    #[test]
    fn resolves_decimals_including_factory_denoms() {
        let chain = ChainInfo::from_json(SAFROCHAIN).unwrap();
        assert_eq!(chain.decimals_for_denom("usaf"), 6);
        assert_eq!(chain.decimals_for_denom("factory/addr_safro1z/udyma"), 6);
        assert_eq!(
            chain.decimals_for_denom("unknown"),
            6,
            "documented fallback"
        );

        let injective = ChainInfo::from_json(INJECTIVE).unwrap();
        assert_eq!(injective.decimals_for_denom("inj"), 18);
    }

    #[test]
    fn rejects_descriptors_that_cannot_sign() {
        let no_prefix = SAFROCHAIN.replace(
            r#""bech32PrefixAccAddr": "addr_safro""#,
            r#""bech32PrefixAccAddr": """#,
        );
        assert_eq!(
            ChainInfo::from_json(&no_prefix).unwrap_err(),
            RegistryError::MissingPrefix
        );

        let no_chain_id = SAFROCHAIN.replace(r#""chainId": "safrochain-1""#, r#""chainId": " ""#);
        assert_eq!(
            ChainInfo::from_json(&no_chain_id).unwrap_err(),
            RegistryError::MissingChainId
        );

        assert_eq!(
            ChainInfo::from_json("{}").unwrap_err(),
            RegistryError::Malformed
        );
        assert_eq!(
            ChainInfo::from_json("not json").unwrap_err(),
            RegistryError::Malformed
        );
    }

    #[test]
    fn rejects_a_chain_with_no_fee_currency() {
        let json = SAFROCHAIN.replace(
            r#""feeCurrencies": [
            {
                "coinDenom": "SAF",
                "coinMinimalDenom": "usaf",
                "coinDecimals": 6,
                "gasPriceStep": { "low": 0.05, "average": 0.075, "high": 0.1 }
            }
        ]"#,
            r#""feeCurrencies": []"#,
        );
        assert_eq!(
            ChainInfo::from_json(&json).unwrap_err(),
            RegistryError::MissingFeeCurrency
        );
    }

    #[test]
    fn rejects_plaintext_endpoints_but_allows_localhost() {
        let insecure =
            SAFROCHAIN.replace("https://rpc.safrochain.network", "http://rpc.evil.example");
        assert_eq!(
            ChainInfo::from_json(&insecure).unwrap_err(),
            RegistryError::InsecureEndpoint
        );

        let local = SAFROCHAIN
            .replace("https://rpc.safrochain.network", "http://localhost:26657")
            .replace("https://api.safrochain.network", "http://127.0.0.1:1317");
        assert!(
            ChainInfo::from_json(&local).is_ok(),
            "local dev nodes must work"
        );
    }

    #[test]
    fn detects_testnets() {
        let testnet = SAFROCHAIN.replace("safrochain-1", "safrochain-testnet-2");
        assert!(ChainInfo::from_json(&testnet).unwrap().is_testnet());
        assert!(!ChainInfo::from_json(SAFROCHAIN).unwrap().is_testnet());
    }

    #[test]
    fn registry_indexes_and_reports_failures() {
        let (registry, errors) = Registry::from_jsons([
            ("safrochain.json", SAFROCHAIN),
            ("injective.json", INJECTIVE),
            ("broken.json", "{ not json"),
        ]);

        assert_eq!(registry.len(), 2);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "broken.json");
        assert_eq!(errors[0].1, RegistryError::Malformed);

        assert_eq!(
            registry.get("safrochain-1").unwrap().chain_name,
            "Safrochain"
        );
        assert_eq!(registry.by_prefix("inj").unwrap().chain_id, "injective-1");
        assert!(registry.get("nope").is_none());
        assert_eq!(registry.mainnets().count(), 2);
    }

    #[test]
    fn insert_replaces_by_chain_id() {
        let mut registry = Registry::new();
        registry
            .insert(ChainInfo::from_json(SAFROCHAIN).unwrap())
            .unwrap();
        let renamed =
            SAFROCHAIN.replace(r#""chainName": "Safrochain""#, r#""chainName": "Safro v2""#);
        registry
            .insert(ChainInfo::from_json(&renamed).unwrap())
            .unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get("safrochain-1").unwrap().chain_name, "Safro v2");
    }
}
