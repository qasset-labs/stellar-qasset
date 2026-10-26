//! Column layout for the Phase 4 minimal SLIP-0010 priv-extractor.
//!
//! Two rows (a single power-of-two-sized trace at FRI's minimum
//! height of 2). The first row holds the 256 priv bits received from
//! `Slip10HmacAir`'s `slip10_priv_outputs` bus; the second row is
//! padding (its multiplicity on the bus is 0 by the
//! `is_extract_row` selector).

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use crate::hmac_air::slip10_hmac::NUM_PRIV_BITS;
use crate::sha512_air::constants::WORD_BITS;

/// Number of bytes in the Ed25519 private scalar that this AIR emits
/// as 8-bit limbs: 32 bytes.
pub const NUM_PRIV_BYTES: usize = NUM_PRIV_BITS / 8;

/// Trace height: 2 (one extract row + one padding row to reach FRI's
/// minimum height of 2). The bus multiplicity is 1 only on row 0.
pub const SLIP10_AIR_TRACE_HEIGHT: usize = 2;

#[repr(C)]
pub struct Slip10AirCols<T> {
    /// 256 priv bits received on the bus, in the same word-flat
    /// layout `Slip10HmacAir` sends them in
    /// (`priv_bits[word * 64 + bit_in_word]` for words 0..4 of the
    /// last outer row's `h_out_bits`).
    pub priv_bits: [T; NUM_PRIV_BITS],
}

pub const NUM_SLIP10_AIR_COLS: usize = size_of::<Slip10AirCols<u8>>();

impl<T> Borrow<Slip10AirCols<T>> for [T] {
    fn borrow(&self) -> &Slip10AirCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_AIR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Slip10AirCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Slip10AirCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Slip10AirCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_AIR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Slip10AirCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

#[repr(C)]
pub struct Slip10AirPreprocessedCols<T> {
    /// 1 on row 0 (the priv-extract row), 0 on row 1 (padding). Gates
    /// the `slip10_priv_outputs` bus receive multiplicity AND
    /// activates the public-value binding constraint on this row only.
    pub is_extract_row: T,
}

pub const NUM_SLIP10_AIR_PREPROCESSED_COLS: usize =
    size_of::<Slip10AirPreprocessedCols<u8>>();

impl<T> Borrow<Slip10AirPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Slip10AirPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_AIR_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<Slip10AirPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Word-flat → byte-flat bit-position translation, per the helpers'
/// convention. Returns the word-flat bit index that corresponds to
/// the LSB of byte `byte_idx` (within the priv = first 32 bytes of
/// the HMAC output).
///
/// `byte_idx` ∈ `[0, 32)`, `bit_in_byte` ∈ `[0, 8)`. Output is the
/// index into the `priv_bits` column.
pub const fn priv_byte_bit_to_word_flat(byte_idx: usize, bit_in_byte: usize) -> usize {
    let word_idx = byte_idx / 8;
    let byte_in_word = byte_idx % 8;
    let bit_in_word_pos = (7 - byte_in_word) * 8 + bit_in_byte;
    word_idx * WORD_BITS + bit_in_word_pos
}
