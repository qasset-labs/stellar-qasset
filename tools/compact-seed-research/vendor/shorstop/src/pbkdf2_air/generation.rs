//! Trace generation for the PBKDF2 orchestrator.

use core::borrow::BorrowMut;

use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

use crate::pbkdf2_air::columns::{Pbkdf2AirCols, NUM_PBKDF2_AIR_COLS};
use crate::sha512_air::constants::{STATE_WORDS, U64_LIMBS, WORD_BITS};

/// Aggregate output of the off-circuit orchestrator: the trace plus
/// the 32-cell `seed_packed` public-value vector that callers must
/// pass to `verify_batch`.
pub struct Pbkdf2AirWitness<F: PrimeField64> {
    pub trace: RowMajorMatrix<F>,
    pub seed_packed: Vec<F>,
}

/// Build the orchestrator's trace from the ordered `(U_1, …, U_c)`
/// digest sequence (typically `Pbkdf2HmacWitness::u_digests`). Returns
/// the trace + `seed_packed` PV vector.
///
/// Each row mirrors one PBKDF2 iteration:
///   row i: `u_bits` = U_{i+1} bits (word-flat),
///          `u_packed` = U_{i+1} as 16-bit limbs,
///          `u_xor_acc_bits` = U_1 ⊕ U_2 ⊕ … ⊕ U_{i+1} bits.
pub fn generate_pbkdf2_air_witness<F>(u_digests: &[[u8; 64]]) -> Pbkdf2AirWitness<F>
where
    F: PrimeField64,
{
    let trace_height = u_digests.len();
    assert!(trace_height > 0, "PBKDF2 requires ≥ 1 iteration");

    let mut trace_values = vec![F::ZERO; trace_height * NUM_PBKDF2_AIR_COLS];
    let mut accumulator: [u64; STATE_WORDS] = [0u64; STATE_WORDS];

    for (row_index, digest) in u_digests.iter().enumerate() {
        // Decode U_i into 8 × u64 (big-endian per the SHA-512 output).
        let mut u_words = [0u64; STATE_WORDS];
        for word_index in 0..STATE_WORDS {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&digest[word_index * 8..(word_index + 1) * 8]);
            u_words[word_index] = u64::from_be_bytes(word_bytes);
        }

        // XOR into the accumulator.
        for word_index in 0..STATE_WORDS {
            accumulator[word_index] ^= u_words[word_index];
        }

        let row_slice =
            &mut trace_values[row_index * NUM_PBKDF2_AIR_COLS..(row_index + 1) * NUM_PBKDF2_AIR_COLS];
        let cols: &mut Pbkdf2AirCols<F> = row_slice.borrow_mut();

        // u_packed: 16-bit-limb-low-first per word, matching the
        // `pbkdf2_outputs` bus tuple layout.
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                let limb_value = (u_words[word_index] >> (limb_index * 16)) & 0xFFFF;
                cols.u_packed[word_index * U64_LIMBS + limb_index] = F::from_u64(limb_value);
            }
        }

        // u_bits in word-flat layout (matches `Sha512Cols::h_out`).
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                let bit_value = (u_words[word_index] >> bit_in_word) & 1;
                cols.u_bits[word_index][bit_in_word] = F::from_u64(bit_value);
            }
        }

        // u_xor_acc_bits: same word-flat layout, accumulator state.
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                let bit_value = (accumulator[word_index] >> bit_in_word) & 1;
                cols.u_xor_acc_bits[word_index][bit_in_word] = F::from_u64(bit_value);
            }
        }
    }

    // Pack the final accumulator (= seed) as 32 × 16-bit limbs for the
    // PV vector. Same convention as `u_packed`.
    let mut seed_packed = Vec::with_capacity(STATE_WORDS * U64_LIMBS);
    for word_index in 0..STATE_WORDS {
        for limb_index in 0..U64_LIMBS {
            let limb_value = (accumulator[word_index] >> (limb_index * 16)) & 0xFFFF;
            seed_packed.push(F::from_u64(limb_value));
        }
    }

    Pbkdf2AirWitness {
        trace: RowMajorMatrix::new(trace_values, NUM_PBKDF2_AIR_COLS),
        seed_packed,
    }
}
