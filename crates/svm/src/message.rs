//! Legacy Solana message compilation and serialisation.
//!
//! A Solana message is a flat account table plus instructions that reference it by single-byte
//! index. Signing privileges are encoded positionally: the first `num_required_signatures`
//! accounts must sign, and within each privilege class the read-only accounts sit at the end.
//! Getting that layout wrong does not fail to sign, it signs a transaction granting different
//! privileges than the prompt showed, so the compiler below is the security boundary.
//!
//! Versioned (v0) messages with address lookup tables are deliberately not implemented. They
//! move accounts out of the signed table into on-chain lookups, which means the signer cannot
//! see every account it is authorising from the message alone. That is a blind-signing hazard,
//! and adding it needs a design that resolves the tables and shows the result.

use crate::error::{Result, SvmError};
use crate::pubkey::Pubkey;
use crate::shortvec;

/// An account reference inside an instruction, with the privileges the instruction needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn writable_signer(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: true,
        }
    }

    pub fn readonly_signer(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: false,
        }
    }

    pub fn writable(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: true,
        }
    }

    pub fn readonly(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: false,
        }
    }
}

/// An instruction before compilation, naming accounts by address rather than index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// An instruction after compilation, naming accounts by index into the message table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// The three privilege counts that head every Solana message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

/// A compiled legacy message, ready to be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    /// Compiles instructions into a message.
    ///
    /// The fee payer is forced to index 0 as a writable signer, which is what the runtime
    /// requires: it debits the fee from the first account.
    pub fn compile(
        fee_payer: Pubkey,
        instructions: &[Instruction],
        recent_blockhash: [u8; 32],
    ) -> Result<Self> {
        let mut table = KeyTable::default();
        table.add(fee_payer, true, true);
        for instruction in instructions {
            for meta in &instruction.accounts {
                table.add(meta.pubkey, meta.is_signer, meta.is_writable);
            }
            // A program is invoked, never signed, and never written. Adding it after the
            // instruction's own accounts matters: if the same address appears as both, the
            // privileges already recorded win, because `add` only ever grants.
            table.add(instruction.program_id, false, false);
        }

        let (account_keys, header) = table.into_message_components(fee_payer)?;

        let index_of = |key: &Pubkey| -> Result<u8> {
            let position = account_keys
                .iter()
                .position(|candidate| candidate == key)
                .ok_or_else(|| SvmError::UnknownAccount(key.to_base58()))?;
            u8::try_from(position).map_err(|_| SvmError::TooManyAccounts(account_keys.len()))
        };

        let compiled = instructions
            .iter()
            .map(|instruction| {
                Ok(CompiledInstruction {
                    program_id_index: index_of(&instruction.program_id)?,
                    accounts: instruction
                        .accounts
                        .iter()
                        .map(|meta| index_of(&meta.pubkey))
                        .collect::<Result<Vec<_>>>()?,
                    data: instruction.data.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled,
        })
    }

    /// The accounts that must sign, in signature order.
    pub fn required_signers(&self) -> &[Pubkey] {
        let count = usize::from(self.header.num_required_signatures);
        &self.account_keys[..count.min(self.account_keys.len())]
    }

    /// The fee payer, which is always the first account.
    pub fn fee_payer(&self) -> Option<&Pubkey> {
        self.account_keys.first()
    }

    /// Whether the account at `index` may be written by this transaction.
    pub fn is_writable(&self, index: usize) -> bool {
        let signers = usize::from(self.header.num_required_signatures);
        let readonly_signed = usize::from(self.header.num_readonly_signed_accounts);
        let readonly_unsigned = usize::from(self.header.num_readonly_unsigned_accounts);
        if index < signers {
            index < signers.saturating_sub(readonly_signed)
        } else {
            index < self.account_keys.len().saturating_sub(readonly_unsigned)
        }
    }

    /// Whether the account at `index` must sign.
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header.num_required_signatures)
    }

    /// Serialises the message. These are the bytes each signer signs, unhashed: ed25519 does its
    /// own hashing, so unlike Cosmos and Ethereum there is no separate digest step.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(self.header.num_required_signatures);
        out.push(self.header.num_readonly_signed_accounts);
        out.push(self.header.num_readonly_unsigned_accounts);

        shortvec::encode_len(&mut out, self.account_keys.len())?;
        for key in &self.account_keys {
            out.extend_from_slice(key.as_bytes());
        }

        out.extend_from_slice(&self.recent_blockhash);

        shortvec::encode_len(&mut out, self.instructions.len())?;
        for instruction in &self.instructions {
            out.push(instruction.program_id_index);
            shortvec::encode_len(&mut out, instruction.accounts.len())?;
            out.extend_from_slice(&instruction.accounts);
            shortvec::encode_len(&mut out, instruction.data.len())?;
            out.extend_from_slice(&instruction.data);
        }

        Ok(out)
    }

    /// Parses a serialised legacy message.
    ///
    /// Present so the approval prompt can decode a message handed over by a dApp rather than one
    /// it built itself, which is the only case that matters for signing safety.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let header = MessageHeader {
            num_required_signatures: cursor.byte()?,
            num_readonly_signed_accounts: cursor.byte()?,
            num_readonly_unsigned_accounts: cursor.byte()?,
        };

        // The high bit of the first byte marks a versioned message. Refuse rather than
        // misparse it as legacy, which would show the wrong accounts.
        if header.num_required_signatures & 0x80 != 0 {
            return Err(SvmError::UnknownAccount(
                "versioned messages are not supported".to_string(),
            ));
        }

        let key_count = cursor.short_len()?;
        let mut account_keys = Vec::with_capacity(key_count.min(256));
        for _ in 0..key_count {
            account_keys.push(Pubkey::from_slice(cursor.take(32)?)?);
        }

        let recent_blockhash: [u8; 32] = cursor
            .take(32)?
            .try_into()
            .map_err(|_| SvmError::InvalidBlockhash)?;

        let instruction_count = cursor.short_len()?;
        let mut instructions = Vec::with_capacity(instruction_count.min(256));
        for _ in 0..instruction_count {
            let program_id_index = cursor.byte()?;
            let account_count = cursor.short_len()?;
            let accounts = cursor.take(account_count)?.to_vec();
            let data_len = cursor.short_len()?;
            let data = cursor.take(data_len)?.to_vec();
            instructions.push(CompiledInstruction {
                program_id_index,
                accounts,
                data,
            });
        }

        if !cursor.is_empty() {
            return Err(SvmError::UnknownAccount(
                "trailing bytes after the message".to_string(),
            ));
        }

        let message = Self {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        };
        message.validate()?;
        Ok(message)
    }

    /// Checks the internal consistency a signer must not assume.
    ///
    /// A message whose header claims more signers than it has accounts, or whose instructions
    /// index past the table, is not merely malformed: displayed naively it would attribute
    /// privileges to the wrong addresses.
    pub fn validate(&self) -> Result<()> {
        if self.account_keys.len() > 256 {
            return Err(SvmError::TooManyAccounts(self.account_keys.len()));
        }
        let signers = usize::from(self.header.num_required_signatures);
        let readonly_signed = usize::from(self.header.num_readonly_signed_accounts);
        let readonly_unsigned = usize::from(self.header.num_readonly_unsigned_accounts);
        let total_readonly = readonly_signed.saturating_add(readonly_unsigned);

        // At least one signer, the table must cover the signers, the fee payer at index 0 must be
        // a writable signer (so read-only signers cannot fill the whole signer range), and the
        // read-only tail cannot be longer than the table.
        if signers == 0
            || signers > self.account_keys.len()
            || readonly_signed >= signers
            || total_readonly > self.account_keys.len()
        {
            return Err(SvmError::InvalidFeePayer);
        }
        for instruction in &self.instructions {
            if usize::from(instruction.program_id_index) >= self.account_keys.len() {
                return Err(SvmError::UnknownAccount(format!(
                    "program index {}",
                    instruction.program_id_index
                )));
            }
            for &index in &instruction.accounts {
                if usize::from(index) >= self.account_keys.len() {
                    return Err(SvmError::UnknownAccount(format!("account index {index}")));
                }
            }
        }
        Ok(())
    }
}

/// Accumulates account privileges before ordering.
#[derive(Default)]
struct KeyTable {
    entries: Vec<(Pubkey, bool, bool)>,
}

impl KeyTable {
    /// Records an account, only ever granting privileges.
    ///
    /// The union is the whole point: if one instruction needs an account read-only and another
    /// needs it writable, the message must grant writable, and if the later mention were allowed
    /// to downgrade it the transaction would fail at execution.
    fn add(&mut self, pubkey: Pubkey, is_signer: bool, is_writable: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|(key, _, _)| *key == pubkey) {
            entry.1 |= is_signer;
            entry.2 |= is_writable;
        } else {
            self.entries.push((pubkey, is_signer, is_writable));
        }
    }

    /// Orders accounts into the four privilege classes and derives the header.
    ///
    /// Within a class accounts are sorted by raw public key bytes, matching solana-sdk's
    /// `CompiledKeys`, which drains a `BTreeMap`. Note that `@solana/web3.js` sorts by the base58
    /// *string* instead, so the two libraries can produce different account orders for the same
    /// instructions. Both are valid on-chain, since indices are self-consistent, but it means
    /// byte-for-byte comparison against web3.js output is only meaningful when the ordering
    /// happens to agree. Tests here assert the privilege layout, not agreement with web3.js.
    fn into_message_components(self, fee_payer: Pubkey) -> Result<(Vec<Pubkey>, MessageHeader)> {
        let mut writable_signers = Vec::new();
        let mut readonly_signers = Vec::new();
        let mut writable_others = Vec::new();
        let mut readonly_others = Vec::new();

        for (pubkey, is_signer, is_writable) in self.entries {
            if pubkey == fee_payer {
                continue;
            }
            match (is_signer, is_writable) {
                (true, true) => writable_signers.push(pubkey),
                (true, false) => readonly_signers.push(pubkey),
                (false, true) => writable_others.push(pubkey),
                (false, false) => readonly_others.push(pubkey),
            }
        }

        for bucket in [
            &mut writable_signers,
            &mut readonly_signers,
            &mut writable_others,
            &mut readonly_others,
        ] {
            bucket.sort_unstable();
        }

        let mut keys = Vec::with_capacity(
            writable_signers
                .len()
                .saturating_add(readonly_signers.len())
                .saturating_add(writable_others.len())
                .saturating_add(readonly_others.len())
                .saturating_add(1),
        );
        keys.push(fee_payer);
        keys.extend(writable_signers.iter().copied());
        keys.extend(readonly_signers.iter().copied());
        keys.extend(writable_others.iter().copied());
        keys.extend(readonly_others.iter().copied());

        if keys.len() > 256 {
            return Err(SvmError::TooManyAccounts(keys.len()));
        }

        let signers = writable_signers
            .len()
            .saturating_add(readonly_signers.len())
            .saturating_add(1);
        let header = MessageHeader {
            num_required_signatures: u8::try_from(signers)
                .map_err(|_| SvmError::TooManyAccounts(signers))?,
            num_readonly_signed_accounts: u8::try_from(readonly_signers.len())
                .map_err(|_| SvmError::TooManyAccounts(readonly_signers.len()))?,
            num_readonly_unsigned_accounts: u8::try_from(readonly_others.len())
                .map_err(|_| SvmError::TooManyAccounts(readonly_others.len()))?,
        };

        Ok((keys, header))
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SvmError::InvalidBlockhash)?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn short_len(&mut self) -> Result<usize> {
        let (value, consumed) =
            shortvec::decode(&self.bytes[self.offset..]).ok_or(SvmError::InvalidBlockhash)?;
        self.offset = self
            .offset
            .checked_add(consumed)
            .ok_or(SvmError::InvalidBlockhash)?;
        Ok(usize::from(value))
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system;

    fn key(byte: u8) -> Pubkey {
        Pubkey::from_bytes([byte; 32])
    }

    #[test]
    fn a_transfer_compiles_to_the_expected_layout() {
        let payer = key(1);
        let recipient = key(2);
        let message = Message::compile(
            payer,
            &[system::transfer(payer, recipient, 1_000_000)],
            [9u8; 32],
        )
        .unwrap();

        // Payer first, recipient second, system program last and read-only.
        assert_eq!(
            message.account_keys,
            vec![payer, recipient, Pubkey::SYSTEM_PROGRAM]
        );
        assert_eq!(
            message.header,
            MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            }
        );
        assert!(message.is_writable(0));
        assert!(message.is_writable(1));
        assert!(!message.is_writable(2));
        assert!(message.is_signer(0));
        assert!(!message.is_signer(1));
        assert_eq!(message.instructions[0].program_id_index, 2);
        assert_eq!(message.instructions[0].accounts, vec![0, 1]);
    }

    #[test]
    fn privileges_are_unioned_across_instructions() {
        // The same account read-only in one instruction and writable in another must end up
        // writable. If a later mention could downgrade it, the transaction would fail at
        // execution after the user had already signed.
        let payer = key(1);
        let shared = key(2);
        let program = key(3);

        let message = Message::compile(
            payer,
            &[
                Instruction {
                    program_id: program,
                    accounts: vec![AccountMeta::readonly(shared)],
                    data: vec![],
                },
                Instruction {
                    program_id: program,
                    accounts: vec![AccountMeta::writable(shared)],
                    data: vec![],
                },
            ],
            [0u8; 32],
        )
        .unwrap();

        let index = message
            .account_keys
            .iter()
            .position(|k| *k == shared)
            .unwrap();
        assert!(message.is_writable(index));
    }

    #[test]
    fn a_program_that_is_also_a_signer_keeps_its_privileges() {
        // Adding the program id must not downgrade an account that an instruction already
        // required as a signer.
        let payer = key(1);
        let dual = key(2);
        let message = Message::compile(
            payer,
            &[Instruction {
                program_id: dual,
                accounts: vec![AccountMeta::readonly_signer(dual)],
                data: vec![],
            }],
            [0u8; 32],
        )
        .unwrap();

        assert_eq!(message.header.num_required_signatures, 2);
        assert_eq!(message.header.num_readonly_signed_accounts, 1);
        assert_eq!(message.required_signers(), &[payer, dual]);
    }

    #[test]
    fn the_fee_payer_is_first_even_when_mentioned_later() {
        let payer = key(200);
        let other = key(1);
        let message =
            Message::compile(payer, &[system::transfer(other, payer, 5)], [0u8; 32]).unwrap();

        assert_eq!(message.fee_payer(), Some(&payer));
        assert!(message.is_writable(0));
        assert!(message.is_signer(0));
        // `other` also signs, since it is the source of the transfer.
        assert_eq!(message.header.num_required_signatures, 2);
    }

    #[test]
    fn serialisation_round_trips() {
        let payer = key(1);
        let message = Message::compile(
            payer,
            &[
                system::transfer(payer, key(2), 1),
                system::transfer(payer, key(3), 2),
            ],
            [4u8; 32],
        )
        .unwrap();

        let bytes = message.serialize().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), message);
    }

    #[test]
    fn the_serialised_prefix_is_the_header_then_the_key_count() {
        let payer = key(1);
        let message =
            Message::compile(payer, &[system::transfer(payer, key(2), 1)], [4u8; 32]).unwrap();
        let bytes = message.serialize().unwrap();

        assert_eq!(&bytes[..3], &[1, 0, 1]);
        // Three accounts, so a one-byte compact length.
        assert_eq!(bytes[3], 3);
        assert_eq!(&bytes[4..36], &[1u8; 32]);
        assert_eq!(&bytes[100..132], &[4u8; 32], "blockhash follows the keys");
    }

    #[test]
    fn a_versioned_message_is_refused_rather_than_misread() {
        // The runtime marks v0 messages by setting the high bit of the first byte. Parsing one
        // as legacy would read the version byte as a signer count and shift every field.
        let payer = key(1);
        let mut bytes = Message::compile(payer, &[system::transfer(payer, key(2), 1)], [0u8; 32])
            .unwrap()
            .serialize()
            .unwrap();
        bytes[0] |= 0x80;
        assert!(Message::parse(&bytes).is_err());
    }

    #[test]
    fn malformed_messages_are_refused() {
        let payer = key(1);
        let good = Message::compile(payer, &[system::transfer(payer, key(2), 1)], [0u8; 32])
            .unwrap()
            .serialize()
            .unwrap();

        // Truncation at every length must be rejected, never partially accepted.
        for cut in 0..good.len() {
            assert!(
                Message::parse(&good[..cut]).is_err(),
                "accepted a message truncated to {cut} bytes"
            );
        }
        // Trailing bytes change nothing semantically but mean the sender and signer disagree
        // about what was signed.
        let mut extra = good.clone();
        extra.push(0);
        assert!(Message::parse(&extra).is_err());

        // Zero required signatures cannot be signed by anyone.
        let mut unsignable = good.clone();
        unsignable[0] = 0;
        assert!(Message::parse(&unsignable).is_err());

        // More signers than accounts.
        let mut too_many = good.clone();
        too_many[0] = 9;
        assert!(Message::parse(&too_many).is_err());
    }

    #[test]
    fn out_of_range_indices_are_refused() {
        let payer = key(1);
        let message =
            Message::compile(payer, &[system::transfer(payer, key(2), 1)], [0u8; 32]).unwrap();

        let mut bad = message.clone();
        bad.instructions[0].program_id_index = 7;
        assert!(bad.validate().is_err());

        let mut bad = message.clone();
        bad.instructions[0].accounts = vec![0, 7];
        assert!(bad.validate().is_err());
    }
}
