//! Trace-shape constants for the PBKDF2 orchestrator AIR.
//!
//! The orchestrator has exactly `num_iterations` rows (one per
//! PBKDF2 iteration). For BIP-39 c=2048 = 2^11 this is already a
//! power of two; tests use small values.

use crate::sha512_air::constants::{STATE_WORDS, U64_LIMBS, WORD_BITS};

/// Number of 16-bit limbs in a `U_i` digest packed for the
/// `pbkdf2_outputs` bus tuple. Matches the `compression_tuple` h_out
/// portion: 8 state words × 4 limbs/word = 32 limbs total.
pub const NUM_U_LIMBS: usize = STATE_WORDS * U64_LIMBS;

/// Bits per `U_i` digest in word-flat layout: 8 state words × 64 bits
/// = 512 cells. Matches `Sha512Cols::h_out` and
/// `Pbkdf2HmacCols::h_out_bits`.
pub const NUM_U_BITS: usize = STATE_WORDS * WORD_BITS;

/// Per-row tuple element count on the `pbkdf2_outputs` bus:
/// `[iter_index, U_i_limb_0, ..., U_i_limb_31]`.
pub const PBKDF2_OUTPUTS_TUPLE_LEN: usize = 1 + NUM_U_LIMBS;

/// The seed (= XOR-fold of all `U_i`) packed into 16-bit limbs in the
/// same low-first per-word convention. `seed_packed[w * 4 + j]` is
/// limb `j` of word `w`. This is the orchestrator's public-value
/// output — `Slip10Air` (Phase 4) consumes it as a PV input.
pub const NUM_SEED_LIMBS: usize = NUM_U_LIMBS;
