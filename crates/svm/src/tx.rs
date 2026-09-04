//! Transaction assembly, ed25519 signing and the wire format.

use crate::error::{Result, SvmError};
use crate::message::Message;
use crate::pubkey::Pubkey;
use crate::shortvec;
use zunia_kernel::ExtendedKey;

/// A validator will not accept a transaction larger than one UDP packet.
pub const PACKET_DATA_SIZE: usize = 1232;

/// An ed25519 signature. All-zero means unsigned, which is how partially signed multi-signer
/// transactions are represented on the wire.
pub const SIGNATURE_LEN: usize = 64;

/// A transaction: signatures in signer order, then the message they cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub signatures: Vec<[u8; SIGNATURE_LEN]>,
    pub message: Message,
}

impl Transaction {
    /// Creates an unsigned transaction with a zero signature slot per required signer.
    pub fn new_unsigned(message: Message) -> Self {
        let slots = usize::from(message.header.num_required_signatures);
        Self {
            signatures: vec![[0u8; SIGNATURE_LEN]; slots],
            message,
        }
    }

    /// Signs with one key, filling that signer's slot.
    ///
    /// Fails if the key is not a required signer of this message. That check is the point: a
    /// wallet asked to sign a transaction it is not party to should refuse rather than produce a
    /// signature that ends up in an unexpected slot.
    pub fn sign(&mut self, key: &ExtendedKey) -> Result<()> {
        let public_key = key.public_key_bytes()?;
        let address = Pubkey::from_public_key(&public_key)?;
        let index = self
            .message
            .required_signers()
            .iter()
            .position(|signer| *signer == address)
            .ok_or(SvmError::SignerMismatch)?;

        let bytes = self.message.serialize()?;
        // ed25519 signs the message directly; there is no separate digest step, so unlike Cosmos
        // and Ethereum there is no hash for a caller to substitute.
        let signature = zunia_kernel::sign_ed25519(key, &bytes)?;
        let slot: [u8; SIGNATURE_LEN] = *signature.as_bytes();

        *self
            .signatures
            .get_mut(index)
            .ok_or(SvmError::SignerMismatch)? = slot;
        Ok(())
    }

    /// Whether every required signature is present.
    pub fn is_fully_signed(&self) -> bool {
        self.signatures.len() == usize::from(self.message.header.num_required_signatures)
            && self
                .signatures
                .iter()
                .all(|signature| signature.iter().any(|byte| *byte != 0))
    }

    /// Verifies every present signature against its signer.
    pub fn verify(&self) -> Result<bool> {
        let bytes = self.message.serialize()?;
        let signers = self.message.required_signers();
        if self.signatures.len() != signers.len() {
            return Ok(false);
        }
        for (signature, signer) in self.signatures.iter().zip(signers) {
            match zunia_kernel::verify_ed25519(signer.as_bytes(), &bytes, signature) {
                Ok(true) => {}
                Ok(false) | Err(_) => return Ok(false),
            }
        }
        Ok(true)
    }

    /// The transaction id: base58 of the first signature. Solana has no separate hash.
    pub fn id(&self) -> Option<String> {
        self.signatures
            .first()
            .map(|signature| bs58::encode(signature).into_string())
    }

    /// Serialises to the wire format an RPC `sendTransaction` accepts.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        shortvec::encode_len(&mut out, self.signatures.len())?;
        for signature in &self.signatures {
            out.extend_from_slice(signature);
        }
        out.extend_from_slice(&self.message.serialize()?);

        if out.len() > PACKET_DATA_SIZE {
            return Err(SvmError::TransactionTooLarge(out.len()));
        }
        Ok(out)
    }

    /// Parses the wire format.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (count, consumed) = shortvec::decode(bytes).ok_or(SvmError::InvalidBlockhash)?;
        let count = usize::from(count);

        let signatures_end = consumed
            .checked_add(
                count
                    .checked_mul(SIGNATURE_LEN)
                    .ok_or(SvmError::SignerMismatch)?,
            )
            .filter(|end| *end <= bytes.len())
            .ok_or(SvmError::SignerMismatch)?;

        let mut signatures = Vec::with_capacity(count.min(64));
        for chunk in bytes[consumed..signatures_end].chunks_exact(SIGNATURE_LEN) {
            signatures.push(
                <[u8; SIGNATURE_LEN]>::try_from(chunk).map_err(|_| SvmError::SignerMismatch)?,
            );
        }

        let message = Message::parse(&bytes[signatures_end..])?;
        if signatures.len() != usize::from(message.header.num_required_signatures) {
            return Err(SvmError::SignerMismatch);
        }
        Ok(Self {
            signatures,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system;
    use zunia_kernel::{Curve, DerivationPath, ZuniaMnemonic};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn key_at(index: u32) -> ExtendedKey {
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        ExtendedKey::from_seed_and_path(
            Curve::Ed25519,
            seed.expose(),
            &DerivationPath::slip10_ed25519(501, index),
        )
        .unwrap()
    }

    fn address_of(key: &ExtendedKey) -> Pubkey {
        Pubkey::from_public_key(&key.public_key_bytes().unwrap()).unwrap()
    }

    fn transfer_tx(payer: &ExtendedKey, lamports: u64) -> Transaction {
        let from = address_of(payer);
        let message = Message::compile(
            from,
            &[system::transfer(
                from,
                Pubkey::from_bytes([9u8; 32]),
                lamports,
            )],
            [1u8; 32],
        )
        .unwrap();
        Transaction::new_unsigned(message)
    }

    #[test]
    fn signing_produces_a_verifiable_transaction() {
        let key = key_at(0);
        let mut tx = transfer_tx(&key, system::LAMPORTS_PER_SOL);

        assert!(!tx.is_fully_signed());
        tx.sign(&key).unwrap();
        assert!(tx.is_fully_signed());
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn a_key_that_is_not_a_signer_is_refused() {
        // The wallet holds many accounts. Signing with the wrong one must fail loudly rather
        // than write a valid signature into a slot it does not belong in.
        let payer = key_at(0);
        let stranger = key_at(1);
        let mut tx = transfer_tx(&payer, 1);

        assert_eq!(tx.sign(&stranger).unwrap_err(), SvmError::SignerMismatch);
        assert!(!tx.is_fully_signed());
    }

    #[test]
    fn a_secp256k1_key_cannot_sign_a_solana_transaction() {
        let payer = key_at(0);
        let mut tx = transfer_tx(&payer, 1);
        let seed = ZuniaMnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let secp = ExtendedKey::from_seed_and_path(
            Curve::Secp256k1,
            seed.expose(),
            &DerivationPath::bip44(60, 0, 0),
        )
        .unwrap();

        assert!(tx.sign(&secp).is_err());
    }

    #[test]
    fn changing_any_field_invalidates_the_signature() {
        let key = key_at(0);
        let mut tx = transfer_tx(&key, 1);
        tx.sign(&key).unwrap();
        assert!(tx.verify().unwrap());

        let mut tampered = tx.clone();
        tampered.message.recent_blockhash = [2u8; 32];
        assert!(!tampered.verify().unwrap());

        let mut tampered = tx.clone();
        tampered.message.instructions[0].data =
            system::transfer(address_of(&key), Pubkey::from_bytes([9u8; 32]), 999_999_999).data;
        assert!(
            !tampered.verify().unwrap(),
            "an amount change must break it"
        );

        let mut tampered = tx.clone();
        tampered.message.account_keys[1] = Pubkey::from_bytes([8u8; 32]);
        assert!(
            !tampered.verify().unwrap(),
            "a recipient change must break it"
        );
    }

    #[test]
    fn multi_signer_transactions_fill_the_right_slots() {
        let payer = key_at(0);
        let cosigner = key_at(1);
        let payer_address = address_of(&payer);
        let cosigner_address = address_of(&cosigner);

        let message = Message::compile(
            payer_address,
            &[system::transfer(cosigner_address, payer_address, 42)],
            [3u8; 32],
        )
        .unwrap();
        let mut tx = Transaction::new_unsigned(message);
        assert_eq!(tx.signatures.len(), 2);

        // Sign out of order: the slot is chosen by the signer's position in the message, not by
        // the order the wallet happens to get to the keys.
        tx.sign(&cosigner).unwrap();
        assert!(!tx.is_fully_signed());
        tx.sign(&payer).unwrap();
        assert!(tx.is_fully_signed());
        assert!(tx.verify().unwrap());

        let payer_slot = tx
            .message
            .required_signers()
            .iter()
            .position(|s| *s == payer_address)
            .unwrap();
        let mut expected = Transaction::new_unsigned(tx.message.clone());
        expected.sign(&payer).unwrap();
        assert_eq!(tx.signatures[payer_slot], expected.signatures[payer_slot]);
    }

    #[test]
    fn signing_is_deterministic() {
        // ed25519 signatures are deterministic by construction, so the same transaction signed
        // twice must be byte-identical. A difference would mean randomness leaked in.
        let key = key_at(0);
        let mut first = transfer_tx(&key, 7);
        let mut second = transfer_tx(&key, 7);
        first.sign(&key).unwrap();
        second.sign(&key).unwrap();
        assert_eq!(first.signatures, second.signatures);
    }

    #[test]
    fn the_wire_format_round_trips() {
        let key = key_at(0);
        let mut tx = transfer_tx(&key, 1);
        tx.sign(&key).unwrap();

        let bytes = tx.serialize().unwrap();
        // One signature, so a one-byte count, 64 signature bytes, then the message.
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..65], &tx.signatures[0]);

        let parsed = Transaction::parse(&bytes).unwrap();
        assert_eq!(parsed, tx);
        assert!(parsed.verify().unwrap());
    }

    #[test]
    fn the_id_is_base58_of_the_first_signature() {
        let key = key_at(0);
        let mut tx = transfer_tx(&key, 1);
        tx.sign(&key).unwrap();

        let id = tx.id().unwrap();
        assert_eq!(bs58::decode(&id).into_vec().unwrap(), tx.signatures[0]);
        // 64 bytes of base58 is 86 to 88 characters, the familiar Solana Explorer id length.
        assert!(
            (86..=88).contains(&id.len()),
            "unexpected id length {}",
            id.len()
        );
    }

    #[test]
    fn truncated_transactions_are_refused() {
        let key = key_at(0);
        let mut tx = transfer_tx(&key, 1);
        tx.sign(&key).unwrap();
        let bytes = tx.serialize().unwrap();

        for cut in 0..bytes.len() {
            assert!(
                Transaction::parse(&bytes[..cut]).is_err(),
                "accepted {cut} bytes"
            );
        }
    }

    #[test]
    fn a_signature_count_that_disagrees_with_the_header_is_refused() {
        let key = key_at(0);
        let mut tx = transfer_tx(&key, 1);
        tx.sign(&key).unwrap();

        // Claim two signatures without supplying the bytes.
        let mut bytes = tx.serialize().unwrap();
        bytes[0] = 2;
        assert!(Transaction::parse(&bytes).is_err());
    }

    #[test]
    fn oversized_transactions_are_refused() {
        // Instruction data big enough to pass the packet limit. Serialising it anyway would
        // produce something no validator accepts, and the caller would see a silent failure.
        let key = key_at(0);
        let from = address_of(&key);
        let message = Message::compile(
            from,
            &[crate::message::Instruction {
                program_id: Pubkey::from_bytes([5u8; 32]),
                accounts: vec![],
                data: vec![0u8; 1300],
            }],
            [0u8; 32],
        )
        .unwrap();
        let mut tx = Transaction::new_unsigned(message);
        tx.sign(&key).unwrap();

        assert!(matches!(
            tx.serialize().unwrap_err(),
            SvmError::TransactionTooLarge(_)
        ));
    }

    #[test]
    fn an_unsigned_transaction_does_not_verify() {
        let key = key_at(0);
        let tx = transfer_tx(&key, 1);
        assert!(!tx.verify().unwrap());
    }
}
