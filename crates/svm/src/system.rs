//! System program instruction builders.
//!
//! Only the instructions the wallet actually needs. The system program's instruction data is a
//! bincode-encoded enum: a four-byte little-endian discriminant followed by the fields, so
//! `Transfer` is `[2, 0, 0, 0]` then the lamports as little-endian u64.

use crate::message::{AccountMeta, Instruction};
use crate::pubkey::Pubkey;

/// Discriminants from the system program's instruction enum, in declaration order.
const TRANSFER: u32 = 2;

/// Lamports per SOL. Nine decimals.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Moves lamports from one account to another.
pub fn transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&TRANSFER.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    Instruction {
        program_id: Pubkey::SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable_signer(from),
            AccountMeta::writable(to),
        ],
        data,
    }
}

/// Reads the lamport amount back out of a transfer instruction.
///
/// The approval prompt needs this: it receives compiled instructions from a dApp and has to
/// state the amount, and it must not simply trust a claimed amount alongside the bytes.
pub fn decode_transfer(data: &[u8]) -> Option<u64> {
    if data.len() != 12 {
        return None;
    }
    let discriminant = u32::from_le_bytes(data[..4].try_into().ok()?);
    if discriminant != TRANSFER {
        return None;
    }
    Some(u64::from_le_bytes(data[4..].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_one_sol_transfer_encodes_to_the_known_bytes() {
        let instruction = transfer(
            Pubkey::from_bytes([1u8; 32]),
            Pubkey::from_bytes([2u8; 32]),
            LAMPORTS_PER_SOL,
        );

        assert_eq!(
            instruction.data,
            vec![2, 0, 0, 0, 0x00, 0xca, 0x9a, 0x3b, 0, 0, 0, 0]
        );
        assert_eq!(instruction.program_id, Pubkey::SYSTEM_PROGRAM);
        // The source signs and is debited; the destination is credited but does not sign.
        assert!(instruction.accounts[0].is_signer && instruction.accounts[0].is_writable);
        assert!(!instruction.accounts[1].is_signer && instruction.accounts[1].is_writable);
    }

    #[test]
    fn amounts_round_trip_including_the_extremes() {
        for lamports in [0, 1, LAMPORTS_PER_SOL, u64::MAX] {
            let instruction = transfer(
                Pubkey::from_bytes([1u8; 32]),
                Pubkey::from_bytes([2u8; 32]),
                lamports,
            );
            assert_eq!(decode_transfer(&instruction.data), Some(lamports));
        }
    }

    #[test]
    fn other_instructions_do_not_decode_as_transfers() {
        // A different discriminant, the right length. Reading this as a transfer would show the
        // user "send 1 SOL" for an instruction that does something else entirely.
        let mut data = vec![3, 0, 0, 0];
        data.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(decode_transfer(&data), None);

        assert_eq!(decode_transfer(&[]), None);
        assert_eq!(decode_transfer(&[2, 0, 0, 0]), None);
        // Right prefix, one byte too long.
        let mut long = vec![2, 0, 0, 0];
        long.extend_from_slice(&[0u8; 9]);
        assert_eq!(decode_transfer(&long), None);
    }
}
