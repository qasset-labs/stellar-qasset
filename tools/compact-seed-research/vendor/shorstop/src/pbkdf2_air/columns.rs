//! Column layout for the PBKDF2 orchestrator AIR.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use crate::pbkdf2_air::constants::NUM_U_LIMBS;
use crate::sha512_air::constants::{STATE_WORDS, WORD_BITS};

/// Per-row main-trace columns. Mixed limb-and-bit representation:
/// `u_packed` is the cross-row carrier (efficient bus tuple),
/// `u_bits` is needed for the in-row XOR with the running accumulator
/// (XOR is degree-1 in bits, not in 16-bit limbs).
#[repr(C)]
pub struct Pbkdf2AirCols<T> {
    /// `U_i` as 32 × 16-bit limbs in low-first-per-word order, matching
    /// the `pbkdf2_outputs` bus tuple layout. Bound to `u_bits` via a
    /// per-limb degree-1 packing constraint.
    pub u_packed: [T; NUM_U_LIMBS],
    /// `U_i` as bits in **word-flat** layout
    /// (`u_bits[word * 64 + bit_in_word]`, LSB-first within each
    /// 64-bit word) — same convention as `Sha512Cols::h_out` and
    /// `Pbkdf2HmacCols::h_out_bits`. Used for the per-bit XOR
    /// accumulator transition.
    pub u_bits: [[T; WORD_BITS]; STATE_WORDS],
    /// Running XOR accumulator: `u_xor_acc_bits[i] = ⊕_{j=1..=row}
    /// u_bits_at_row_j[i]`. Bit-by-bit XOR (degree-1 in bits) chains
    /// across rows. The last row's value, packed to 16-bit limbs, is
    /// emitted as `seed_packed` (the AIR's public-value output).
    pub u_xor_acc_bits: [[T; WORD_BITS]; STATE_WORDS],
}

pub const NUM_PBKDF2_AIR_COLS: usize = size_of::<Pbkdf2AirCols<u8>>();

impl<T> Borrow<Pbkdf2AirCols<T>> for [T] {
    fn borrow(&self) -> &Pbkdf2AirCols<T> {
        debug_assert_eq!(self.len(), NUM_PBKDF2_AIR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Pbkdf2AirCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Pbkdf2AirCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Pbkdf2AirCols<T> {
        debug_assert_eq!(self.len(), NUM_PBKDF2_AIR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Pbkdf2AirCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

/// Preprocessed column: `iter_index` matches the `pbkdf2_outputs` bus
/// tuple's first element. Row 0 carries 0, row 1 carries 1, etc., up
/// to row `num_iterations - 1`. With `num_iterations = 2048` (BIP-39)
/// this is exactly 2^11 rows, no padding.
#[repr(C)]
pub struct Pbkdf2AirPreprocessedCols<T> {
    pub iter_index: T,
}

pub const NUM_PBKDF2_AIR_PREPROCESSED_COLS: usize =
    size_of::<Pbkdf2AirPreprocessedCols<u8>>();

impl<T> Borrow<Pbkdf2AirPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Pbkdf2AirPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_PBKDF2_AIR_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<Pbkdf2AirPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
