//! Trace generation for the Phase 4 minimal SLIP-0010 priv-extractor.

use core::borrow::BorrowMut;

use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

use crate::sha512_air::constants::WORD_BITS;
use crate::slip10_air::columns::{
    Slip10AirCols, NUM_PRIV_BYTES, NUM_SLIP10_AIR_COLS, SLIP10_AIR_TRACE_HEIGHT,
};

pub struct Slip10AirWitness<F: PrimeField64> {
    pub trace: RowMajorMatrix<F>,
    /// 32 × 8-bit limbs of the **clamped** Ed25519 scalar. Same shape
    /// and contents as the `scalar_packed` slot of `Ed25519Air`'s PV —
    /// the orchestrator passes one `Vec` to both AIR slots so equality
    /// is enforced by the verifier (not just by the trace generator
    /// constructing matching values).
    pub priv_packed: Vec<F>,
}

/// Apply RFC 8032 §5.1.5 clamping to a raw 32-byte Ed25519 private
/// scalar: clear the low 3 bits of byte 0, clear bit 7 of byte 31,
/// force bit 6 of byte 31 set.
fn clamp_ed25519_scalar(priv_bytes: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *priv_bytes;
    clamped[0] &= 0xF8;
    clamped[31] &= 0x7F;
    clamped[31] |= 0x40;
    clamped
}

/// Build the priv-extractor's trace from the 32-byte priv recovered
/// from `Slip10HmacAir`'s last outer row's `h_out_bits[0..4]` (in
/// big-endian byte form: `priv_bytes[0..32]`). The trace's `priv_bits`
/// column holds the **un-clamped** bits (matching what the
/// `slip10_priv_outputs` bus sends), while the emitted PV vector
/// holds the **clamped** scalar bytes — the AIR's per-byte packing
/// constraint encodes the clamp in-circuit.
pub fn generate_slip10_air_witness<F>(priv_bytes: &[u8; 32]) -> Slip10AirWitness<F>
where
    F: PrimeField64,
{
    let mut trace_values = vec![F::ZERO; SLIP10_AIR_TRACE_HEIGHT * NUM_SLIP10_AIR_COLS];

    // Row 0: priv_bits in word-flat layout matching what
    // `Slip10HmacAir`'s sender produces. Decompose 32 bytes → 4 u64
    // words (big-endian per SHA-512 output) → 64 bits per word.
    {
        let row_0 = &mut trace_values[0..NUM_SLIP10_AIR_COLS];
        let cols: &mut Slip10AirCols<F> = row_0.borrow_mut();
        for word_index in 0..4 {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&priv_bytes[word_index * 8..(word_index + 1) * 8]);
            let word_value = u64::from_be_bytes(word_bytes);
            for bit_in_word in 0..WORD_BITS {
                let bit_value = ((word_value >> bit_in_word) & 1) as u64;
                cols.priv_bits[word_index * WORD_BITS + bit_in_word] = F::from_u64(bit_value);
            }
        }
    }
    // Row 1: padding — copy row 0 verbatim. The
    // `is_extract_row` selector gates row 1 out of the bus and out
    // of the PV-binding constraint.
    let (head, tail) = trace_values.split_at_mut(NUM_SLIP10_AIR_COLS);
    tail.copy_from_slice(head);

    // priv_packed = clamp(priv_bytes). One field cell per byte,
    // 8-bit-limb byte-flat layout matching `Ed25519Air`'s `scalar_packed`
    // PV slot. The AIR's eval-time packing applies the same clamping
    // formula to the trace's `priv_bits` so this PV satisfies the
    // equality constraint on row 0.
    let clamped = clamp_ed25519_scalar(priv_bytes);
    let priv_packed: Vec<F> = clamped.iter().map(|&b| F::from_u64(b as u64)).collect();
    debug_assert_eq!(priv_packed.len(), NUM_PRIV_BYTES);

    Slip10AirWitness {
        trace: RowMajorMatrix::new(trace_values, NUM_SLIP10_AIR_COLS),
        priv_packed,
    }
}
