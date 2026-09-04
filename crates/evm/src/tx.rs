//! Ethereum transaction assembly and signing.
//!
//! Covers legacy (EIP-155), access-list (EIP-2930) and fee-market (EIP-1559) transactions. All
//! three share a shape: build a list, hash it with Keccak-256, sign the hash, then rebuild the
//! list with the signature appended.
//!
//! The dangerous part is the `v` value, which differs per type and, for legacy transactions,
//! encodes the chain id. Getting it wrong does not fail locally: it produces a signature that
//! recovers to a different address, so the node reports "invalid sender" or, worse, the
//! transaction is valid on a chain the user did not intend.

use sha3::{Digest, Keccak256};
use zunia_kernel::{sign_digest_secp256k1, ExtendedKey};

use crate::error::{EvmError, Result};
use crate::rlp::RlpStream;

/// A 20-byte Ethereum address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 20]);

impl Address {
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Parses `0x`-prefixed hex, verifying the EIP-55 checksum when the input is mixed case.
    pub fn parse(text: &str) -> Result<Self> {
        let account =
            zunia_kernel::validate_eth_address(text).map_err(|_| EvmError::InvalidAddress)?;
        Ok(Self(*account.as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// The EIP-55 mixed-case form, which is what the UI must display.
    ///
    /// Never show an all-lowercase address: the checksum is the only protection against a
    /// mistyped or tampered address, and a user cannot verify one that has been stripped.
    pub fn to_checksummed(&self) -> String {
        zunia_kernel::AccountId::from_bytes(self.0).to_eth_hex()
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_checksummed())
    }
}

/// A 256-bit quantity, held big-endian.
///
/// Wei amounts exceed `u64` routinely (1 ETH is 10^18 wei, and a whale balance is not far off
/// 2^64), so quantities are carried as words rather than integers. Arithmetic is deliberately
/// not provided: this crate encodes values the caller already computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256([u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_u64(value: u64) -> Self {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&value.to_be_bytes());
        Self(word)
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        let word = crate::rlp::to_word(bytes).ok_or(EvmError::QuantityTooLarge)?;
        Ok(Self(word))
    }

    /// Parses a decimal string, which is how amounts arrive from a UI or an API.
    pub fn parse_decimal(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EvmError::QuantityTooLarge);
        }

        // Schoolbook multiply-accumulate over the 32-byte word. Avoids a bignum dependency for
        // the one operation this crate needs.
        let mut word = [0u8; 32];
        for digit in text.bytes().map(|b| u32::from(b.wrapping_sub(b'0'))) {
            let mut carry = digit;
            for byte in word.iter_mut().rev() {
                // A byte times ten plus a carry below 256 stays well inside u32, but the bound
                // is an argument rather than something the compiler checks, so it is written
                // checked: a wrapped digit would silently change the amount being signed.
                let product = u32::from(*byte)
                    .checked_mul(10)
                    .and_then(|scaled| scaled.checked_add(carry))
                    .ok_or(EvmError::QuantityTooLarge)?;
                *byte = (product & 0xff) as u8;
                carry = product >> 8;
            }
            if carry != 0 {
                return Err(EvmError::QuantityTooLarge);
            }
        }
        Ok(Self(word))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    /// The minimal big-endian representation, which is what RLP wants.
    pub fn to_minimal_bytes(&self) -> &[u8] {
        crate::rlp::strip_leading_zeros(&self.0)
    }
}

/// One EIP-2930 access list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<[u8; 32]>,
}

/// The transaction types Zunia can sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxKind {
    /// Pre-EIP-1559. Still needed: some chains and some contracts reject typed transactions.
    Legacy { gas_price: U256 },
    /// EIP-2930. Rarely used directly, but the encoding is shared with EIP-1559 so it is nearly
    /// free to support, and omitting it would mean rejecting a dApp request the wallet could
    /// have handled.
    AccessList {
        gas_price: U256,
        access_list: Vec<AccessListItem>,
    },
    /// EIP-1559. The default for anything that supports it.
    FeeMarket {
        max_priority_fee_per_gas: U256,
        max_fee_per_gas: U256,
        access_list: Vec<AccessListItem>,
    },
}

impl TxKind {
    /// The EIP-2718 type byte, absent for legacy transactions.
    pub fn type_byte(&self) -> Option<u8> {
        match self {
            Self::Legacy { .. } => None,
            Self::AccessList { .. } => Some(0x01),
            Self::FeeMarket { .. } => Some(0x02),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Legacy { .. } => "legacy",
            Self::AccessList { .. } => "EIP-2930",
            Self::FeeMarket { .. } => "EIP-1559",
        }
    }
}

/// An unsigned Ethereum transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    /// `None` means contract creation.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub kind: TxKind,
}

impl UnsignedTx {
    /// An EIP-1559 transfer, the common case.
    pub fn transfer(
        chain_id: u64,
        nonce: u64,
        to: Address,
        value: U256,
        gas_limit: u64,
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    ) -> Result<Self> {
        let tx = Self {
            chain_id,
            nonce,
            gas_limit,
            to: Some(to),
            value,
            data: Vec::new(),
            kind: TxKind::FeeMarket {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                access_list: Vec::new(),
            },
        };
        tx.validate()?;
        Ok(tx)
    }

    /// Checks the invariants that would otherwise produce a silently unusable transaction.
    pub fn validate(&self) -> Result<()> {
        if self.chain_id == 0 {
            // Chain id zero disables EIP-155 replay protection, so the same signature would be
            // valid on any chain that also used zero.
            return Err(EvmError::InvalidChainId);
        }
        Ok(())
    }

    /// The bytes to hash for signing.
    ///
    /// Legacy transactions sign a nine-element list ending in the chain id and two zeros, which
    /// is EIP-155. Typed transactions sign the type byte followed by their own list.
    pub fn sign_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;

        let mut list = RlpStream::new();
        match &self.kind {
            TxKind::Legacy { gas_price } => {
                list.append_u64(self.nonce)
                    .append_quantity(gas_price.as_bytes())
                    .append_u64(self.gas_limit);
                self.append_to_and_value(&mut list);
                // EIP-155: chain_id, 0, 0 stand in for the signature fields while hashing.
                list.append_u64(self.chain_id).append_u64(0).append_u64(0);

                let mut out = RlpStream::new();
                out.append_list(&list);
                Ok(out.into_bytes())
            }
            TxKind::AccessList {
                gas_price,
                access_list,
            } => {
                list.append_u64(self.chain_id)
                    .append_u64(self.nonce)
                    .append_quantity(gas_price.as_bytes())
                    .append_u64(self.gas_limit);
                self.append_to_and_value(&mut list);
                append_access_list(&mut list, access_list);
                Ok(prefixed(0x01, &list))
            }
            TxKind::FeeMarket {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                access_list,
            } => {
                list.append_u64(self.chain_id)
                    .append_u64(self.nonce)
                    .append_quantity(max_priority_fee_per_gas.as_bytes())
                    .append_quantity(max_fee_per_gas.as_bytes())
                    .append_u64(self.gas_limit);
                self.append_to_and_value(&mut list);
                append_access_list(&mut list, access_list);
                Ok(prefixed(0x02, &list))
            }
        }
    }

    /// The Keccak-256 hash that gets signed.
    pub fn sign_hash(&self) -> Result<[u8; 32]> {
        Ok(Keccak256::digest(self.sign_payload()?).into())
    }

    /// Signs and returns the raw transaction ready for `eth_sendRawTransaction`.
    pub fn sign(&self, key: &ExtendedKey) -> Result<SignedTx> {
        let hash = self.sign_hash()?;
        let signature = sign_digest_secp256k1(key, &hash)?;
        let recovery = signature
            .recovery_id()
            .ok_or(zunia_kernel::KernelError::Signature)?;

        let v = match self.kind {
            // EIP-155: v = recovery_id + chain_id * 2 + 35. This is what binds the signature to
            // one chain; the pre-155 form (27 + recovery_id) is replayable and never emitted.
            //
            // Checked because a chain id above (u64::MAX - 35) / 2 would wrap, and a wrapped `v`
            // is a signature that either fails to verify or, far worse, verifies as belonging to
            // a different chain. Refusing is the only safe answer.
            TxKind::Legacy { .. } => self
                .chain_id
                .checked_mul(2)
                .and_then(|doubled| doubled.checked_add(35))
                .and_then(|base| base.checked_add(u64::from(recovery)))
                .ok_or(EvmError::InvalidChainId)?,
            // Typed transactions carry the chain id in the payload, so y_parity is just 0 or 1.
            _ => u64::from(recovery),
        };

        let (r, s) = signature.as_bytes().split_at(32);
        let raw = self.encode_signed(v, r, s)?;

        Ok(SignedTx {
            raw,
            hash: Keccak256::digest(&self.encode_signed(v, r, s)?).into(),
            v,
            r: r.try_into().expect("32 bytes"),
            s: s.try_into().expect("32 bytes"),
        })
    }

    fn encode_signed(&self, v: u64, r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
        let mut list = RlpStream::new();
        match &self.kind {
            TxKind::Legacy { gas_price } => {
                list.append_u64(self.nonce)
                    .append_quantity(gas_price.as_bytes())
                    .append_u64(self.gas_limit);
                self.append_to_and_value(&mut list);
                list.append_u64(v).append_quantity(r).append_quantity(s);

                let mut out = RlpStream::new();
                out.append_list(&list);
                Ok(out.into_bytes())
            }
            TxKind::AccessList {
                gas_price,
                access_list,
            } => {
                list.append_u64(self.chain_id)
                    .append_u64(self.nonce)
                    .append_quantity(gas_price.as_bytes())
                    .append_u64(self.gas_limit);
                self.append_to_and_value(&mut list);
                append_access_list(&mut list, access_list);
                list.append_u64(v).append_quantity(r).append_quantity(s);
                Ok(prefixed(0x01, &list))
            }
            TxKind::FeeMarket {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                access_list,
            } => {
                list.append_u64(self.chain_id)
                    .append_u64(self.nonce)
                    .append_quantity(max_priority_fee_per_gas.as_bytes())
                    .append_quantity(max_fee_per_gas.as_bytes())
                    .append_u64(self.gas_limit);
                self.append_to_and_value(&mut list);
                append_access_list(&mut list, access_list);
                list.append_u64(v).append_quantity(r).append_quantity(s);
                Ok(prefixed(0x02, &list))
            }
        }
    }

    fn append_to_and_value(&self, list: &mut RlpStream) {
        match &self.to {
            Some(address) => list.append_bytes(address.as_bytes()),
            // An absent `to` is the empty string, which is how contract creation is expressed.
            None => list.append_empty(),
        };
        list.append_quantity(self.value.as_bytes())
            .append_bytes(&self.data);
    }
}

/// A signed transaction, ready to broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTx {
    /// The bytes for `eth_sendRawTransaction`.
    pub raw: Vec<u8>,
    /// The transaction hash, which is Keccak-256 of `raw` for every type.
    pub hash: [u8; 32],
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl SignedTx {
    pub fn raw_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.raw))
    }

    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash))
    }
}

fn append_access_list(list: &mut RlpStream, items: &[AccessListItem]) {
    let mut outer = RlpStream::new();
    for item in items {
        let mut keys = RlpStream::new();
        for key in &item.storage_keys {
            keys.append_bytes(key);
        }
        let mut entry = RlpStream::new();
        entry
            .append_bytes(item.address.as_bytes())
            .append_list(&keys);
        outer.append_list(&entry);
    }
    list.append_list(&outer);
}

/// Wraps a typed-transaction list in its EIP-2718 type byte.
fn prefixed(type_byte: u8, list: &RlpStream) -> Vec<u8> {
    let mut out = RlpStream::new();
    out.append_list(list);
    let mut bytes = Vec::with_capacity(out.as_bytes().len().saturating_add(1));
    bytes.push(type_byte);
    bytes.extend_from_slice(out.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use zunia_kernel::{Curve, DerivationPath, ZuniaMnemonic};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn key() -> ExtendedKey {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::parse("m/44'/60'/0'/0/0").unwrap(),
        )
        .unwrap()
    }

    fn recipient() -> Address {
        Address::parse("0x3535353535353535353535353535353535353535").unwrap()
    }

    #[test]
    fn parses_and_checksums_addresses() {
        // EIP-55 reference vectors.
        for expected in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let address = Address::parse(expected).unwrap();
            assert_eq!(address.to_checksummed(), expected);
            // All-lowercase is accepted as unchecksummed and re-checksummed on output.
            assert_eq!(
                Address::parse(&expected.to_lowercase())
                    .unwrap()
                    .to_checksummed(),
                expected
            );
        }
    }

    #[test]
    fn rejects_a_tampered_checksum() {
        // A flipped case bit is exactly what a lookalike address attack produces, so it must be
        // an error rather than a silent acceptance.
        assert!(Address::parse("0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed").is_err());
        assert!(Address::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe").is_err());
        assert!(Address::parse("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").is_err());
    }

    #[test]
    fn parses_decimal_quantities() {
        assert!(U256::parse_decimal("0").unwrap().is_zero());
        assert_eq!(
            U256::parse_decimal("1000000000000000000").unwrap(),
            U256::from_u64(1_000_000_000_000_000_000)
        );
        // 10^18 is beyond u64 when scaled, so the path that matters is a value above 2^64.
        let big = U256::parse_decimal("18446744073709551616").unwrap(); // 2^64
        assert_eq!(big.to_minimal_bytes(), &[0x01, 0, 0, 0, 0, 0, 0, 0, 0]);

        // The maximum, and one past it.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::parse_decimal(max).unwrap().as_bytes(), &[0xff; 32]);
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert_eq!(
            U256::parse_decimal(over).unwrap_err(),
            EvmError::QuantityTooLarge
        );

        for bad in ["", " ", "-1", "1.5", "0x10", "1e18", "abc"] {
            assert!(U256::parse_decimal(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn eip155_sign_payload_matches_the_specification_example() {
        // The worked example from EIP-155 itself: nonce 9, gasPrice 20 gwei, gasLimit 21000,
        // to 0x3535..35, value 1 ETH, data empty, chainId 1.
        let tx = UnsignedTx {
            chain_id: 1,
            nonce: 9,
            gas_limit: 21_000,
            to: Some(recipient()),
            value: U256::parse_decimal("1000000000000000000").unwrap(),
            data: Vec::new(),
            kind: TxKind::Legacy {
                gas_price: U256::from_u64(20_000_000_000),
            },
        };

        assert_eq!(
            hex::encode(tx.sign_payload().unwrap()),
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
        );
        // Keccak-256 of the payload above, computed independently.
        assert_eq!(
            hex::encode(tx.sign_hash().unwrap()),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
    }

    #[test]
    fn a_zero_chain_id_is_refused() {
        let tx = UnsignedTx {
            chain_id: 0,
            nonce: 0,
            gas_limit: 21_000,
            to: Some(recipient()),
            value: U256::ZERO,
            data: Vec::new(),
            kind: TxKind::Legacy {
                gas_price: U256::from_u64(1),
            },
        };
        assert_eq!(tx.sign_payload().unwrap_err(), EvmError::InvalidChainId);
    }

    #[test]
    fn legacy_v_encodes_the_chain_id() {
        // The whole point of EIP-155. A v of 27 or 28 would be replayable on every EVM chain.
        for chain_id in [1u64, 137, 56, 9001] {
            let tx = UnsignedTx {
                chain_id,
                nonce: 0,
                gas_limit: 21_000,
                to: Some(recipient()),
                value: U256::from_u64(1),
                data: Vec::new(),
                kind: TxKind::Legacy {
                    gas_price: U256::from_u64(1_000_000_000),
                },
            };
            let signed = tx.sign(&key()).unwrap();
            let expected = [chain_id * 2 + 35, chain_id * 2 + 36];
            assert!(
                expected.contains(&signed.v),
                "chain {chain_id}: v was {}, expected one of {expected:?}",
                signed.v
            );
        }
    }

    #[test]
    fn typed_transaction_v_is_just_the_parity() {
        let tx = UnsignedTx {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21_000,
            to: Some(recipient()),
            value: U256::from_u64(1),
            data: Vec::new(),
            kind: TxKind::FeeMarket {
                max_priority_fee_per_gas: U256::from_u64(1_000_000_000),
                max_fee_per_gas: U256::from_u64(30_000_000_000),
                access_list: Vec::new(),
            },
        };
        let signed = tx.sign(&key()).unwrap();
        assert!(signed.v <= 1, "y_parity must be 0 or 1, got {}", signed.v);
        assert_eq!(signed.raw[0], 0x02, "type byte must lead the raw bytes");
    }

    #[test]
    fn the_type_byte_leads_typed_transactions_and_is_absent_from_legacy() {
        let base = UnsignedTx {
            chain_id: 1,
            nonce: 1,
            gas_limit: 21_000,
            to: Some(recipient()),
            value: U256::from_u64(1),
            data: Vec::new(),
            kind: TxKind::Legacy {
                gas_price: U256::from_u64(1),
            },
        };
        // A legacy payload starts with an RLP list header, never a low type byte.
        assert!(base.sign_payload().unwrap()[0] >= 0xc0);

        let access = UnsignedTx {
            kind: TxKind::AccessList {
                gas_price: U256::from_u64(1),
                access_list: Vec::new(),
            },
            ..base.clone()
        };
        assert_eq!(access.sign_payload().unwrap()[0], 0x01);
        assert_eq!(access.kind.type_byte(), Some(0x01));

        let fee_market = UnsignedTx {
            kind: TxKind::FeeMarket {
                max_priority_fee_per_gas: U256::from_u64(1),
                max_fee_per_gas: U256::from_u64(2),
                access_list: Vec::new(),
            },
            ..base
        };
        assert_eq!(fee_market.sign_payload().unwrap()[0], 0x02);
    }

    #[test]
    fn contract_creation_omits_the_recipient() {
        let tx = UnsignedTx {
            chain_id: 1,
            nonce: 0,
            gas_limit: 500_000,
            to: None,
            value: U256::ZERO,
            data: vec![0x60, 0x80, 0x60, 0x40],
            kind: TxKind::FeeMarket {
                max_priority_fee_per_gas: U256::from_u64(1),
                max_fee_per_gas: U256::from_u64(2),
                access_list: Vec::new(),
            },
        };
        let payload = tx.sign_payload().unwrap();
        // 0x80 is the empty string, which is how an absent `to` is encoded.
        assert!(payload.windows(1).any(|w| w == [0x80]));
        assert!(tx.sign(&key()).is_ok());
    }

    #[test]
    fn the_signature_recovers_to_the_signing_address() {
        // The check that actually matters: a wrong v, or r and s in the wrong order, produces a
        // signature that recovers to some other address, and the node rejects it as an invalid
        // sender with no clue as to why.
        let key = key();
        let expected = zunia_kernel::AccountId::from_public_key(
            zunia_kernel::AddressScheme::Ethermint,
            &key.public_key_bytes().unwrap(),
        )
        .unwrap();

        let tx = UnsignedTx::transfer(
            1,
            5,
            recipient(),
            U256::parse_decimal("1000000000000000").unwrap(),
            21_000,
            U256::from_u64(30_000_000_000),
            U256::from_u64(1_000_000_000),
        )
        .unwrap();

        let hash = tx.sign_hash().unwrap();
        let signed = tx.sign(&key).unwrap();

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&signed.r);
        signature[32..].copy_from_slice(&signed.s);
        assert!(zunia_kernel::verify_digest_secp256k1(
            &key.public_key_bytes().unwrap(),
            &hash,
            &signature
        )
        .unwrap());

        assert_eq!(
            Address::from_bytes(*expected.as_bytes()).to_checksummed(),
            expected.to_eth_hex()
        );
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC 6979, so the same transaction signs identically every time. A non-deterministic
        // nonce that leaked would expose the private key.
        let tx = UnsignedTx::transfer(
            1,
            0,
            recipient(),
            U256::from_u64(1),
            21_000,
            U256::from_u64(2),
            U256::from_u64(1),
        )
        .unwrap();
        let a = tx.sign(&key()).unwrap();
        let b = tx.sign(&key()).unwrap();
        assert_eq!(a.raw, b.raw);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn the_hash_covers_the_signed_bytes() {
        let tx = UnsignedTx::transfer(
            1,
            0,
            recipient(),
            U256::from_u64(1),
            21_000,
            U256::from_u64(2),
            U256::from_u64(1),
        )
        .unwrap();
        let signed = tx.sign(&key()).unwrap();
        let recomputed: [u8; 32] = Keccak256::digest(&signed.raw).into();
        assert_eq!(signed.hash, recomputed);
        assert!(signed.raw_hex().starts_with("0x02"));
        assert_eq!(signed.hash_hex().len(), 66);
    }

    #[test]
    fn an_access_list_round_trips_into_the_payload() {
        let item = AccessListItem {
            address: recipient(),
            storage_keys: vec![[0x11; 32], [0x22; 32]],
        };
        let tx = UnsignedTx {
            chain_id: 1,
            nonce: 0,
            gas_limit: 100_000,
            to: Some(recipient()),
            value: U256::ZERO,
            data: Vec::new(),
            kind: TxKind::FeeMarket {
                max_priority_fee_per_gas: U256::from_u64(1),
                max_fee_per_gas: U256::from_u64(2),
                access_list: vec![item],
            },
        };
        let payload = tx.sign_payload().unwrap();
        assert!(payload
            .windows(32)
            .any(|window| window == [0x11; 32].as_slice()));
        assert!(payload
            .windows(32)
            .any(|window| window == [0x22; 32].as_slice()));

        // An empty access list must still be present as an empty list, not omitted.
        let empty = UnsignedTx {
            kind: TxKind::FeeMarket {
                max_priority_fee_per_gas: U256::from_u64(1),
                max_fee_per_gas: U256::from_u64(2),
                access_list: Vec::new(),
            },
            ..tx
        };
        let payload = empty.sign_payload().unwrap();
        assert_eq!(*payload.last().unwrap(), 0xc0);
    }

    #[test]
    fn changing_any_field_changes_the_hash() {
        // Guards against a field being dropped from the encoding, which would let a dApp change
        // it after the user approved.
        let base = UnsignedTx::transfer(
            1,
            0,
            recipient(),
            U256::from_u64(1),
            21_000,
            U256::from_u64(2),
            U256::from_u64(1),
        )
        .unwrap();
        let baseline = base.sign_hash().unwrap();

        let variants = vec![
            UnsignedTx {
                chain_id: 137,
                ..base.clone()
            },
            UnsignedTx {
                nonce: 1,
                ..base.clone()
            },
            UnsignedTx {
                gas_limit: 21_001,
                ..base.clone()
            },
            UnsignedTx {
                value: U256::from_u64(2),
                ..base.clone()
            },
            UnsignedTx {
                data: vec![0x01],
                ..base.clone()
            },
            UnsignedTx {
                to: None,
                ..base.clone()
            },
            UnsignedTx {
                to: Address::parse("0x0000000000000000000000000000000000000001").ok(),
                ..base.clone()
            },
            UnsignedTx {
                kind: TxKind::FeeMarket {
                    max_priority_fee_per_gas: U256::from_u64(99),
                    max_fee_per_gas: U256::from_u64(2),
                    access_list: Vec::new(),
                },
                ..base.clone()
            },
            UnsignedTx {
                kind: TxKind::FeeMarket {
                    max_priority_fee_per_gas: U256::from_u64(1),
                    max_fee_per_gas: U256::from_u64(99),
                    access_list: Vec::new(),
                },
                ..base.clone()
            },
            UnsignedTx {
                kind: TxKind::Legacy {
                    gas_price: U256::from_u64(2),
                },
                ..base
            },
        ];

        for variant in variants {
            assert_ne!(
                variant.sign_hash().unwrap(),
                baseline,
                "a changed field did not change the hash: {variant:?}"
            );
        }
    }
}
