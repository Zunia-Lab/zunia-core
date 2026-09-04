//! Turns a compiled message into something an approval prompt can state honestly.
//!
//! Same rule as the Cosmos decoder in `zunia-cosmos`: anything not fully understood is reported
//! as unknown so the UI can say so, rather than being summarised into a confident sentence that
//! happens to be wrong. Solana makes this sharper than Cosmos, because an instruction's meaning
//! lives in program bytecode rather than a typed message, so most instructions genuinely cannot
//! be decoded and the prompt has to admit it.

use crate::message::Message;
use crate::pubkey::Pubkey;
use crate::system;

/// One instruction, described as precisely as it can honestly be described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionSummary {
    /// A system program transfer, fully decoded.
    Transfer {
        from: Pubkey,
        to: Pubkey,
        lamports: u64,
    },
    /// A recognised program invoked in a way we do not decode, or a program we do not recognise.
    /// `program` is shown to the user verbatim, and `writable_accounts` is the set of accounts
    /// this instruction may modify, which is the part that actually matters for risk.
    Opaque {
        program: Pubkey,
        writable_accounts: Vec<Pubkey>,
        data_len: usize,
    },
}

/// What signing this message authorises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    pub fee_payer: Pubkey,
    pub instructions: Vec<InstructionSummary>,
    /// Every account this message may write, including ones reached only by opaque
    /// instructions. This is the honest answer to "what can this transaction touch".
    pub writable_accounts: Vec<Pubkey>,
    /// Accounts required to sign beyond the fee payer.
    pub additional_signers: Vec<Pubkey>,
}

impl MessageSummary {
    /// Whether every instruction was decoded. When false the prompt must show the "cannot read
    /// this transaction" path, and blind signing must be enabled for it to proceed.
    pub fn is_fully_understood(&self) -> bool {
        self.instructions
            .iter()
            .all(|i| !matches!(i, InstructionSummary::Opaque { .. }))
    }

    /// Net lamport movement out of `account` across the decoded transfers.
    ///
    /// Only meaningful when `is_fully_understood` holds; an opaque instruction can move funds
    /// invisibly, which is exactly why the flag exists.
    pub fn lamports_leaving(&self, account: &Pubkey) -> u64 {
        self.instructions
            .iter()
            .filter_map(|i| match i {
                InstructionSummary::Transfer { from, lamports, .. } if from == account => {
                    Some(*lamports)
                }
                _ => None,
            })
            .fold(0u64, |total, lamports| total.saturating_add(lamports))
    }
}

/// Summarises a compiled message.
pub fn summarize(message: &Message) -> MessageSummary {
    let key_at = |index: u8| -> Pubkey {
        message
            .account_keys
            .get(usize::from(index))
            .copied()
            // Unreachable for a validated message; a placeholder is safer than a panic on a
            // path that renders untrusted input.
            .unwrap_or(Pubkey::from_bytes([0u8; 32]))
    };

    let instructions = message
        .instructions
        .iter()
        .map(|instruction| {
            let program = key_at(instruction.program_id_index);
            if program == Pubkey::SYSTEM_PROGRAM && instruction.accounts.len() == 2 {
                if let Some(lamports) = system::decode_transfer(&instruction.data) {
                    return InstructionSummary::Transfer {
                        from: key_at(instruction.accounts[0]),
                        to: key_at(instruction.accounts[1]),
                        lamports,
                    };
                }
            }
            InstructionSummary::Opaque {
                program,
                writable_accounts: instruction
                    .accounts
                    .iter()
                    .filter(|index| message.is_writable(usize::from(**index)))
                    .map(|index| key_at(*index))
                    .collect(),
                data_len: instruction.data.len(),
            }
        })
        .collect();

    let writable_accounts = message
        .account_keys
        .iter()
        .enumerate()
        .filter(|(index, _)| message.is_writable(*index))
        .map(|(_, key)| *key)
        .collect();

    MessageSummary {
        fee_payer: message
            .fee_payer()
            .copied()
            .unwrap_or(Pubkey::SYSTEM_PROGRAM),
        instructions,
        writable_accounts,
        additional_signers: message.required_signers().iter().skip(1).copied().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{AccountMeta, Instruction};

    fn key(byte: u8) -> Pubkey {
        Pubkey::from_bytes([byte; 32])
    }

    #[test]
    fn a_transfer_is_fully_decoded() {
        let payer = key(1);
        let recipient = key(2);
        let message = Message::compile(
            payer,
            &[system::transfer(payer, recipient, 1_500_000_000)],
            [0u8; 32],
        )
        .unwrap();

        let summary = summarize(&message);
        assert!(summary.is_fully_understood());
        assert_eq!(summary.fee_payer, payer);
        assert_eq!(
            summary.instructions,
            vec![InstructionSummary::Transfer {
                from: payer,
                to: recipient,
                lamports: 1_500_000_000
            }]
        );
        assert_eq!(summary.lamports_leaving(&payer), 1_500_000_000);
        assert_eq!(summary.lamports_leaving(&recipient), 0);
        assert!(summary.additional_signers.is_empty());
    }

    #[test]
    fn an_unknown_program_is_reported_as_opaque_with_its_write_set() {
        let payer = key(1);
        let program = key(200);
        let touched = key(3);
        let message = Message::compile(
            payer,
            &[Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::writable(touched),
                    AccountMeta::readonly(key(4)),
                ],
                data: vec![0xaa; 17],
            }],
            [0u8; 32],
        )
        .unwrap();

        let summary = summarize(&message);
        assert!(!summary.is_fully_understood());
        assert_eq!(
            summary.instructions,
            vec![InstructionSummary::Opaque {
                program,
                writable_accounts: vec![touched],
                data_len: 17,
            }]
        );
    }

    #[test]
    fn a_system_instruction_that_is_not_a_transfer_stays_opaque() {
        // Claiming this is a transfer would put a number in front of the user that the
        // instruction never contained.
        let payer = key(1);
        let message = Message::compile(
            payer,
            &[Instruction {
                program_id: Pubkey::SYSTEM_PROGRAM,
                accounts: vec![
                    AccountMeta::writable_signer(payer),
                    AccountMeta::writable(key(2)),
                ],
                // Discriminant 8, Allocate, not Transfer.
                data: vec![8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
            [0u8; 32],
        )
        .unwrap();

        let summary = summarize(&message);
        assert!(!summary.is_fully_understood());
        assert!(matches!(
            summary.instructions[0],
            InstructionSummary::Opaque { .. }
        ));
    }

    #[test]
    fn a_mixed_message_is_not_fully_understood() {
        // One readable transfer next to one opaque instruction must not be presented as
        // readable. The transfer is the decoy.
        let payer = key(1);
        let message = Message::compile(
            payer,
            &[
                system::transfer(payer, key(2), 1),
                Instruction {
                    program_id: key(200),
                    accounts: vec![AccountMeta::writable(payer)],
                    data: vec![1, 2, 3],
                },
            ],
            [0u8; 32],
        )
        .unwrap();

        let summary = summarize(&message);
        assert!(!summary.is_fully_understood());
        assert_eq!(summary.instructions.len(), 2);
    }

    #[test]
    fn the_write_set_includes_accounts_only_an_opaque_instruction_touches() {
        let payer = key(1);
        let drained = key(50);
        let message = Message::compile(
            payer,
            &[Instruction {
                program_id: key(200),
                accounts: vec![AccountMeta::writable(drained)],
                data: vec![],
            }],
            [0u8; 32],
        )
        .unwrap();

        let summary = summarize(&message);
        assert!(summary.writable_accounts.contains(&drained));
        assert!(summary.writable_accounts.contains(&payer));
        assert!(!summary.writable_accounts.contains(&key(200)));
    }

    #[test]
    fn additional_signers_are_surfaced() {
        // A transaction that needs another of the user's accounts to sign is a different risk
        // from one that does not, so the prompt has to name them.
        let payer = key(1);
        let cosigner = key(2);
        let message =
            Message::compile(payer, &[system::transfer(cosigner, payer, 10)], [0u8; 32]).unwrap();

        let summary = summarize(&message);
        assert_eq!(summary.additional_signers, vec![cosigner]);
        assert_eq!(summary.lamports_leaving(&cosigner), 10);
    }

    #[test]
    fn repeated_transfers_accumulate() {
        let payer = key(1);
        let message = Message::compile(
            payer,
            &[
                system::transfer(payer, key(2), 100),
                system::transfer(payer, key(3), 250),
            ],
            [0u8; 32],
        )
        .unwrap();

        assert_eq!(summarize(&message).lamports_leaving(&payer), 350);
    }
}
