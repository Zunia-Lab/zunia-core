use serde::{Deserialize, Serialize};

use crate::error::{CosmosError, Result};

/// A Cosmos coin: an integer amount plus a denom.
///
/// The amount is kept as a validated decimal string, never a float and never a `u64`. Cosmos
/// amounts are arbitrary precision `sdk.Int`, and an 18-decimal token balance overflows `u64`
/// at roughly 18 tokens. Parsing through `f64` silently loses precision above 2^53, which for
/// an 18-decimal token is about 0.009 tokens: small enough to look right in the UI and wrong
/// enough to fail on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    pub denom: String,
    pub amount: String,
}

impl Coin {
    /// Builds a coin, validating both parts.
    pub fn new(denom: impl Into<String>, amount: impl Into<String>) -> Result<Self> {
        let denom = denom.into();
        let amount = amount.into();
        validate_denom(&denom)?;
        validate_amount(&amount)?;
        Ok(Self { denom, amount })
    }

    /// Convenience for amounts that genuinely fit in a `u128`, such as a computed fee.
    pub fn from_u128(denom: impl Into<String>, amount: u128) -> Result<Self> {
        Self::new(denom, amount.to_string())
    }

    /// The amount as `u128`, for arithmetic that is known to be in range.
    ///
    /// Returns an error rather than saturating on overflow. A saturated fee is a wrong fee.
    pub fn amount_u128(&self) -> Result<u128> {
        self.amount.parse().map_err(|_| CosmosError::Amount)
    }

    /// Formats for display, inserting the decimal point at `decimals`.
    ///
    /// Pure string arithmetic, so precision is preserved regardless of magnitude. Trailing
    /// zeros are trimmed, because `1.000000 ATOM` reads as noise.
    pub fn to_display(&self, decimals: u32) -> String {
        let decimals = decimals as usize;
        if decimals == 0 {
            return self.amount.clone();
        }

        let digits = &self.amount;
        let (whole, fraction) = if digits.len() > decimals {
            let split = digits.len() - decimals;
            (digits[..split].to_owned(), digits[split..].to_owned())
        } else {
            (
                "0".to_owned(),
                format!("{:0>width$}", digits, width = decimals),
            )
        };

        let fraction = fraction.trim_end_matches('0');
        if fraction.is_empty() {
            whole
        } else {
            format!("{whole}.{fraction}")
        }
    }

    /// Parses a human-entered decimal amount into base units.
    ///
    /// The inverse of [`Self::to_display`], and equally string based. Rejects more fractional
    /// digits than the denom supports rather than truncating, because truncating a user's
    /// "1.9999999" into "1.999999" sends a different amount than they typed.
    pub fn from_display(denom: impl Into<String>, input: &str, decimals: u32) -> Result<Self> {
        let input = input.trim().replace(['_', ','], "");
        if input.is_empty() {
            return Err(CosmosError::Amount);
        }

        let (whole, fraction) = match input.split_once('.') {
            Some((w, f)) => (w, f),
            None => (input.as_str(), ""),
        };

        if whole.is_empty() && fraction.is_empty() {
            return Err(CosmosError::Amount);
        }
        if !whole.chars().all(|c| c.is_ascii_digit())
            || !fraction.chars().all(|c| c.is_ascii_digit())
        {
            return Err(CosmosError::Amount);
        }
        if fraction.len() > decimals as usize {
            return Err(CosmosError::Amount);
        }

        let padded = format!("{fraction:0<width$}", width = decimals as usize);
        let combined = format!("{whole}{padded}");
        let trimmed = combined.trim_start_matches('0');
        let normalised = if trimmed.is_empty() { "0" } else { trimmed };

        Self::new(denom, normalised)
    }

    pub fn is_zero(&self) -> bool {
        self.amount.chars().all(|c| c == '0')
    }
}

/// Validates an amount string.
///
/// Must be a non-empty run of ASCII digits with no sign, no exponent, no decimal point and no
/// leading zeros beyond a bare "0". Leading zeros are rejected because `"007"` and `"7"` are
/// the same number but different bytes, and Amino signs the bytes.
pub fn validate_amount(amount: &str) -> Result<()> {
    if amount.is_empty() || !amount.chars().all(|c| c.is_ascii_digit()) {
        return Err(CosmosError::Amount);
    }
    if amount.len() > 1 && amount.starts_with('0') {
        return Err(CosmosError::Amount);
    }
    // sdk.Int is a 256-bit integer, so 78 decimal digits is the ceiling.
    if amount.len() > 78 {
        return Err(CosmosError::Amount);
    }
    Ok(())
}

/// Validates a denom against the Cosmos SDK rules.
///
/// Base rule: 3 to 128 characters, starting with a letter, then letters, digits, and any of
/// `/ : . _ -`. The permissive set is required by real denoms: IBC denoms look like
/// `ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2` and token factory
/// denoms look like `factory/addr_safro1.../udyma`.
pub fn validate_denom(denom: &str) -> Result<()> {
    if denom.len() < 3 || denom.len() > 128 {
        return Err(CosmosError::Denom);
    }
    let mut chars = denom.chars();
    let first = chars.next().ok_or(CosmosError::Denom)?;
    if !first.is_ascii_alphabetic() {
        return Err(CosmosError::Denom);
    }
    for ch in chars {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '/' | ':' | '.' | '_' | '-');
        if !ok {
            return Err(CosmosError::Denom);
        }
    }
    Ok(())
}

/// Computes a fee amount from a gas limit and a gas price.
///
/// Rounds up. Rounding down produces a fee one unit short of what the chain requires, which
/// fails at broadcast with an opaque "insufficient fee" error.
pub fn fee_from_gas(gas_limit: u64, gas_price: f64, denom: &str) -> Result<Coin> {
    if gas_limit == 0 || !gas_price.is_finite() || gas_price < 0.0 {
        return Err(CosmosError::Fee);
    }
    let raw = gas_price * gas_limit as f64;
    let amount = raw.ceil();
    if !amount.is_finite() || amount < 0.0 || amount > u128::MAX as f64 {
        return Err(CosmosError::Fee);
    }
    Coin::from_u128(denom, amount as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_denoms() {
        for denom in [
            "uatom",
            "usaf",
            "inj",
            "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2",
            "factory/addr_safro1zlqc8hf3drqz9ntaklfhddetfay3tt9n9c2tar/udyma",
            "gamm/pool/1",
            "erc20/0x1234",
            "cw20:addr_safro1abc",
        ] {
            validate_denom(denom).unwrap_or_else(|_| panic!("{denom} should be valid"));
        }
    }

    #[test]
    fn rejects_bad_denoms() {
        for denom in [
            "",
            "ab",
            "1uatom",
            "/uatom",
            "uatom!",
            "u atom",
            &"a".repeat(129),
        ] {
            assert!(
                validate_denom(denom).is_err(),
                "{denom:?} should be invalid"
            );
        }
    }

    #[test]
    fn rejects_bad_amounts() {
        for amount in [
            "", "-1", "1.5", "1e10", "abc", "007", "0x10", " 1", "1 ", "+1",
        ] {
            assert!(
                validate_amount(amount).is_err(),
                "{amount:?} should be invalid"
            );
        }
        validate_amount("0").unwrap();
        validate_amount("1").unwrap();
        validate_amount("999999999999999999999999999999").unwrap();
    }

    #[test]
    fn handles_amounts_beyond_u64() {
        // An 18-decimal token balance of 1000 tokens is 1e21, which does not fit in u64.
        let coin = Coin::new("inj", "1000000000000000000000").unwrap();
        assert_eq!(coin.to_display(18), "1000");
        assert_eq!(coin.amount_u128().unwrap(), 1_000_000_000_000_000_000_000);
    }

    #[test]
    fn display_formatting() {
        assert_eq!(
            Coin::new("uatom", "1234567").unwrap().to_display(6),
            "1.234567"
        );
        assert_eq!(Coin::new("uatom", "1000000").unwrap().to_display(6), "1");
        assert_eq!(Coin::new("uatom", "1").unwrap().to_display(6), "0.000001");
        assert_eq!(Coin::new("uatom", "0").unwrap().to_display(6), "0");
        assert_eq!(Coin::new("uatom", "100").unwrap().to_display(6), "0.0001");
        assert_eq!(
            Coin::new("uatom", "1234567").unwrap().to_display(0),
            "1234567"
        );
        // 18 decimals, sub-unit amount.
        assert_eq!(
            Coin::new("inj", "123456789012345678")
                .unwrap()
                .to_display(18),
            "0.123456789012345678"
        );
    }

    #[test]
    fn display_round_trips() {
        for (amount, decimals) in [
            ("1234567", 6u32),
            ("1", 6),
            ("1000000", 6),
            ("123456789012345678901", 18),
            ("0", 6),
        ] {
            let coin = Coin::new("uatom", amount).unwrap();
            let rendered = coin.to_display(decimals);
            let parsed = Coin::from_display("uatom", &rendered, decimals).unwrap();
            assert_eq!(parsed.amount, amount, "round trip failed for {amount}");
        }
    }

    #[test]
    fn parses_user_input() {
        assert_eq!(
            Coin::from_display("uatom", "1.5", 6).unwrap().amount,
            "1500000"
        );
        assert_eq!(
            Coin::from_display("uatom", "1", 6).unwrap().amount,
            "1000000"
        );
        assert_eq!(
            Coin::from_display("uatom", "0.000001", 6).unwrap().amount,
            "1"
        );
        assert_eq!(Coin::from_display("uatom", "0", 6).unwrap().amount, "0");
        assert_eq!(
            Coin::from_display("uatom", ".5", 6).unwrap().amount,
            "500000"
        );
        // Thousands separators and underscores are stripped, since users paste them.
        assert_eq!(
            Coin::from_display("uatom", "1,234.5", 6).unwrap().amount,
            "1234500000"
        );
    }

    #[test]
    fn rejects_more_precision_than_the_denom_supports() {
        // Truncating here would send a different amount than the user typed.
        assert!(Coin::from_display("uatom", "1.9999999", 6).is_err());
        assert!(Coin::from_display("uatom", "1.0000001", 6).is_err());
        assert!(Coin::from_display("uatom", "1.5", 0).is_err());
    }

    #[test]
    fn rejects_malformed_user_input() {
        for input in ["", " ", ".", "-1", "1.2.3", "abc", "1e5", "1..5", "0x10"] {
            assert!(
                Coin::from_display("uatom", input, 6).is_err(),
                "{input:?} should be rejected"
            );
        }
    }

    #[test]
    fn fee_rounds_up() {
        // 200000 gas at 0.025uatom is exactly 5000.
        assert_eq!(
            fee_from_gas(200_000, 0.025, "uatom").unwrap().amount,
            "5000"
        );
        // 200000 at 0.075 is 15000 exactly.
        assert_eq!(
            fee_from_gas(200_000, 0.075, "usaf").unwrap().amount,
            "15000"
        );
        // A fractional result rounds up, never down, or the chain rejects the fee.
        assert_eq!(fee_from_gas(1, 0.025, "uatom").unwrap().amount, "1");
        assert_eq!(fee_from_gas(3, 0.5, "uatom").unwrap().amount, "2");
    }

    #[test]
    fn rejects_nonsense_fees() {
        assert!(fee_from_gas(0, 0.025, "uatom").is_err());
        assert!(fee_from_gas(200_000, -1.0, "uatom").is_err());
        assert!(fee_from_gas(200_000, f64::NAN, "uatom").is_err());
        assert!(fee_from_gas(200_000, f64::INFINITY, "uatom").is_err());
    }

    #[test]
    fn zero_detection() {
        assert!(Coin::new("uatom", "0").unwrap().is_zero());
        assert!(!Coin::new("uatom", "1").unwrap().is_zero());
    }

    #[test]
    fn coin_construction_validates_both_parts() {
        assert!(Coin::new("u", "1").is_err());
        assert!(Coin::new("uatom", "-1").is_err());
        assert!(Coin::new("uatom", "1.5").is_err());
    }
}
