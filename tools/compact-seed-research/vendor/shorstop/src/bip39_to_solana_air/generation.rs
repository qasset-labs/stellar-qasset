//! Trace generation for the BIP-39 → Solana composition AIR.

use core::borrow::BorrowMut;

use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

use crate::bip39_to_solana_air::columns::{
    Bip39ToSolanaCols, BIP39_TO_SOLANA_TRACE_HEIGHT, NUM_BIP39_TO_SOLANA_COLS,
    NUM_PQ_DESTINATION_BYTES, NUM_RECENT_BLOCKHASH_BYTES, NUM_SOLANA_ADDRESS_BYTES,
};

pub struct Bip39ToSolanaWitness<F: PrimeField64> {
    pub trace: RowMajorMatrix<F>,
    /// 96-cell PV vector containing solana_address, pq_destination_address,
    /// and recent_blockhash.
    pub bip39_to_solana_pv: Vec<F>,
}

/// Build the witness from a 32-byte Solana address (= Ed25519 `y_A`
/// in big-endian byte form), a 32-byte PQ destination address, and a
/// 32-byte recent blockhash.
pub fn generate_bip39_to_solana_witness<F: PrimeField64>(
    solana_address_bytes: &[u8; 32],
    pq_destination_address_bytes: &[u8; 32],
    recent_blockhash_bytes: &[u8; 32],
) -> Bip39ToSolanaWitness<F> {
    let mut trace_values =
        vec![F::ZERO; BIP39_TO_SOLANA_TRACE_HEIGHT * NUM_BIP39_TO_SOLANA_COLS];

    // Row 0: populate cells
    {
        let row_0 = &mut trace_values[0..NUM_BIP39_TO_SOLANA_COLS];
        let cols: &mut Bip39ToSolanaCols<F> = row_0.borrow_mut();
        for byte_index in 0..NUM_SOLANA_ADDRESS_BYTES {
            cols.solana_address[byte_index] =
                F::from_u64(solana_address_bytes[byte_index] as u64);
        }
        for byte_index in 0..NUM_PQ_DESTINATION_BYTES {
            cols.pq_destination_address[byte_index] =
                F::from_u64(pq_destination_address_bytes[byte_index] as u64);
        }
        for byte_index in 0..NUM_RECENT_BLOCKHASH_BYTES {
            cols.recent_blockhash[byte_index] =
                F::from_u64(recent_blockhash_bytes[byte_index] as u64);
        }
    }
    // Row 1: padding (zeros). `is_extract_row = 0` gates the PV
    // constraint off.

    let mut bip39_to_solana_pv = Vec::with_capacity(96);
    bip39_to_solana_pv.extend(solana_address_bytes.iter().map(|&b| F::from_u64(b as u64)));
    bip39_to_solana_pv.extend(pq_destination_address_bytes.iter().map(|&b| F::from_u64(b as u64)));
    bip39_to_solana_pv.extend(recent_blockhash_bytes.iter().map(|&b| F::from_u64(b as u64)));

    Bip39ToSolanaWitness {
        trace: RowMajorMatrix::new(trace_values, NUM_BIP39_TO_SOLANA_COLS),
        bip39_to_solana_pv,
    }
}
