//! Column layout for the SHA-512 compression AIR.
//!
//! Spec source: `docs/sha512-spec.md` §4 (column inventory), §5 (constraint
//! groups), §6 (carry strategy).
//! This module is an independent implementation based on the spec — not a port of any reference.
//! It was then cross-checked against Plonky3 PR #1563 and Binius64.
//!
//! All structs are `repr(C)` so the slice <-> struct transmutation in
//! `Borrow` / `BorrowMut` is well-defined: every field is an array of `T`,
//! the struct has no padding, and `size_of::<Sha512Cols<u8>>()` gives the
//! exact scalar column count.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use crate::sha512_air::constants::{
    CHAIN_LEN, NUM_COMPRESSION_ROUNDS, SCHEDULE_EXTENSIONS, STATE_WORDS, U64_LIMBS, WORD_BITS,
};

/// Number of carries committed per modular add. A 64-bit value is 4
/// limbs; carries flow between adjacent limbs. The carry out of the
/// top limb is discarded by the `mod 2^64` reduction and is enforced
/// implicitly by a cubic on the top-limb difference (§6.1, last
/// paragraph), so we commit only `U64_LIMBS - 1 = 3` carry columns.
pub const CARRIES_PER_ADD: usize = U64_LIMBS - 1;

/// Per-round packed intermediates and carry columns. One instance per
/// SHA-512 round, lined up with `Sha512Cols::rounds[t]`.
///
/// All packed values are 4 × 16-bit limbs (low limb first). All carry
/// values are single columns; their range constraint (`{0,1,2}` for
/// add3, `{0,1}` for add2) is enforced in `air.rs`, not at the column
/// definition.
#[repr(C)]
pub struct Sha512RoundCols<T> {
    /// `Σ_1(e)` — defined in `air.rs` as `Σ 2^i · (XOR3 of rotated e bits)`.
    pub sigma1_e: [T; U64_LIMBS],

    /// `Ch(e, f, g)` — defined in `air.rs` as a per-bit polynomial.
    pub ch: [T; U64_LIMBS],

    /// `tmp_1 = h + Σ_1(e) + Ch(e,f,g)  (mod 2^64)` — output of an `add3`.
    pub tmp1: [T; U64_LIMBS],

    /// Carries for the `tmp_1` add3, between adjacent limbs.
    /// Each `∈ {0, 1, 2}`. Top-limb carry not committed (§6.1).
    pub tmp1_carries: [T; CARRIES_PER_ADD],

    /// `T_1 = tmp_1 + K_t + W_t  (mod 2^64)` — output of an `add3`.
    pub t1: [T; U64_LIMBS],

    /// Carries for the `T_1` add3.
    pub t1_carries: [T; CARRIES_PER_ADD],

    /// `Σ_0(a)`.
    pub sigma0_a: [T; U64_LIMBS],

    /// `Maj(a, b, c)`.
    pub maj: [T; U64_LIMBS],

    /// Carries for `a'_t = T_1 + Σ_0(a) + Maj(a,b,c)  (mod 2^64)`.
    /// `a'_t` itself is the next slot of `a_chain` (bit view, range-
    /// checked by booleans), so no packed `a'_t` column is needed —
    /// only its add3 carries live here.
    pub a_prime_carries: [T; CARRIES_PER_ADD],

    /// Carries for `e'_t = d + T_1  (mod 2^64)` — an `add2`. Each carry
    /// `∈ {0, 1}`. `e'_t` lives in the next slot of `e_chain` (bit view).
    pub e_prime_carries: [T; CARRIES_PER_ADD],
}

/// One trace row = one SHA-512 compression call.
///
/// The struct is laid out so single-row constraints in `air.rs` only
/// reference fields of one row. There are no transition constraints.
#[repr(C)]
pub struct Sha512Cols<T> {
    /// Input chaining state `H^in_0..H^in_7`, packed view (4 limbs each).
    /// Range-checked indirectly via §5.3 binding to `a_chain[0..4]` and
    /// `e_chain[0..4]` bits.
    pub h_in: [[T; U64_LIMBS]; STATE_WORDS],

    /// Working-variable `a`-chain in bit view, length `4 + 80 = 84`.
    ///
    /// Indices `[0..4]` mirror the input state `(H_3, H_2, H_1, H_0)`;
    /// indices `[4..84]` are the freshly-computed `a'_0 .. a'_79`. See
    /// spec §4.4 for why initial entries are reversed.
    pub a_chain: [[T; WORD_BITS]; CHAIN_LEN],

    /// Working-variable `e`-chain in bit view, same shape.
    /// Indices `[0..4]` mirror `(H_7, H_6, H_5, H_4)`.
    pub e_chain: [[T; WORD_BITS]; CHAIN_LEN],

    /// Full message schedule `W_0..W_79` in bit view.
    /// Entries `[0..16]` are witness (the input block); entries
    /// `[16..80]` are constrained by the schedule recurrence.
    pub w: [[T; WORD_BITS]; NUM_COMPRESSION_ROUNDS],

    /// `σ_0(W_{t-15})` packed limbs, indexed by `i = t - 16`, length 64.
    pub sched_sigma0: [[T; U64_LIMBS]; SCHEDULE_EXTENSIONS],

    /// `σ_1(W_{t-2})` packed limbs, indexed by `i = t - 16`, length 64.
    pub sched_sigma1: [[T; U64_LIMBS]; SCHEDULE_EXTENSIONS],

    /// `sched_tmp_t = σ_1(W_{t-2}) + W_{t-7}  (mod 2^64)`, packed.
    /// Splits the 4-term recurrence into two ≤ 3-term adds.
    pub sched_tmp: [[T; U64_LIMBS]; SCHEDULE_EXTENSIONS],

    /// Carries for the `sched_tmp` add2 (`∈ {0, 1}`).
    pub sched_tmp_carries: [[T; CARRIES_PER_ADD]; SCHEDULE_EXTENSIONS],

    /// Carries for the `W_t = sched_tmp + σ_0(W_{t-15}) + W_{t-16}` add3.
    /// Each `∈ {0, 1, 2}`. `W_t` itself lives in `w[t]` (bit view).
    pub w_carries: [[T; CARRIES_PER_ADD]; SCHEDULE_EXTENSIONS],

    /// Per-round intermediates. One `Sha512RoundCols` per round.
    pub rounds: [Sha512RoundCols<T>; NUM_COMPRESSION_ROUNDS],

    /// Output chaining state `H^out_0..H^out_7` in **bit view** (not packed).
    /// Bit-only commitment closes the soundness gap §7.2 / §4.7
    /// (see PR #1563 question file). The packed form is reconstructed
    /// inline in `air.rs` as `Σ 2^i · bit_i` per limb.
    pub h_out: [[T; WORD_BITS]; STATE_WORDS],

    /// Carries for `H^out_i = H^in_i + (final var i)  (mod 2^64)` —
    /// an `add2` per output word. Each `∈ {0, 1}`.
    pub h_out_carries: [[T; CARRIES_PER_ADD]; STATE_WORDS],
}

/// Total scalar column count per row. Computed from the byte size of
/// `Sha512Cols<u8>` so it is automatically kept in sync with the struct
/// definition above.
pub const NUM_SHA512_COLS: usize = size_of::<Sha512Cols<u8>>();

/// Preprocessed-trace columns for the SHA-512 AIR. Currently a single
/// selector that gates LogUp sends on the `sha512_compressions` bus
/// (1 = real compression row, 0 = padding). See
/// `docs/pipeline-spec.md` §5.7.
#[repr(C)]
pub struct Sha512PreprocessedCols<T> {
    /// 1 on real compression rows (those holding a witness compression);
    /// 0 on padding rows the trace generator inserts to reach a power
    /// of two. Used as the multiplicity of the row's LogUp send so
    /// padding never appears on the bus.
    pub is_real_compression_row: T,
}

/// Preprocessed-trace column count.
pub const NUM_SHA512_PREPROCESSED_COLS: usize = size_of::<Sha512PreprocessedCols<u8>>();

impl<T> Borrow<Sha512PreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Sha512PreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_SHA512_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Sha512PreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Sha512PreprocessedCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Sha512PreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_SHA512_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Sha512PreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<T> Borrow<Sha512Cols<T>> for [T] {
    fn borrow(&self) -> &Sha512Cols<T> {
        debug_assert_eq!(self.len(), NUM_SHA512_COLS);
        // Safety: `Sha512Cols` is `repr(C)` and contains only `T` arrays;
        // its layout is a flat sequence of `NUM_SHA512_COLS` columns.
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Sha512Cols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Sha512Cols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Sha512Cols<T> {
        debug_assert_eq!(self.len(), NUM_SHA512_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Sha512Cols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;

    /// `NUM_SHA512_COLS` matches the spec's bookkeeping: a manual sum of
    /// every column group. If the struct grows or shrinks accidentally,
    /// this fires and forces a deliberate update of both numbers.
    #[test]
    fn num_cols_equals_explicit_sum() {
        const EXPECTED: usize =
            // h_in packed
            STATE_WORDS * U64_LIMBS
            // a_chain bits
            + CHAIN_LEN * WORD_BITS
            // e_chain bits
            + CHAIN_LEN * WORD_BITS
            // w bits
            + NUM_COMPRESSION_ROUNDS * WORD_BITS
            // sched_sigma0 + sched_sigma1 + sched_tmp packed
            + 3 * SCHEDULE_EXTENSIONS * U64_LIMBS
            // sched_tmp_carries + w_carries
            + 2 * SCHEDULE_EXTENSIONS * CARRIES_PER_ADD
            // rounds: 6 packed values × U64_LIMBS + 4 carry sets × CARRIES_PER_ADD
            + NUM_COMPRESSION_ROUNDS * (6 * U64_LIMBS + 4 * CARRIES_PER_ADD)
            // h_out bits
            + STATE_WORDS * WORD_BITS
            // h_out_carries
            + STATE_WORDS * CARRIES_PER_ADD;

        assert_eq!(NUM_SHA512_COLS, EXPECTED);
    }

    /// Sanity check the column count is in the order of magnitude the
    /// spec predicts (§4.8 estimate ≈ 19,104, plus 1,368 carry columns
    /// from §6.1, ≈ 20,472).
    #[test]
    fn num_cols_in_expected_range() {
        assert!(
            (20_000..=21_000).contains(&NUM_SHA512_COLS),
            "NUM_SHA512_COLS = {} fell outside the expected range; \
             update the spec §4.8 estimate or check for accidental drift",
            NUM_SHA512_COLS,
        );
    }

    /// Borrow trick round-trip: a flat `[u8; NUM_SHA512_COLS]` can be
    /// re-interpreted as `&Sha512Cols<u8>` and back without UB. This is
    /// the property that lets `air.rs` access columns by name.
    #[test]
    fn borrow_roundtrip_no_ub() {
        let buf = vec![0u8; NUM_SHA512_COLS];
        let cols: &Sha512Cols<u8> = buf.as_slice().borrow();
        // Touch a field at the end of the struct to confirm the
        // alignment / size assertions inside `borrow` would fire if
        // anything were misaligned. h_out_carries is the last field.
        let _ = cols.h_out_carries[STATE_WORDS - 1][CARRIES_PER_ADD - 1];
    }

    /// Round-cols size is exactly the sum of its fields.
    #[test]
    fn round_cols_size_is_flat() {
        const ROUND_EXPECTED: usize = 6 * U64_LIMBS               // sigma1_e, ch, tmp1, t1, sigma0_a, maj
            + 4 * CARRIES_PER_ADD; // tmp1, t1, a', e' carries

        assert_eq!(size_of::<Sha512RoundCols<u8>>(), ROUND_EXPECTED);
    }

    /// `repr(C)` introduces no padding when every field is `[T; N]` with
    /// the same `T` — `align_of::<[T; N]>() == align_of::<T>()`, so each
    /// field's offset is automatically aligned. This test pins that
    /// invariant for every `T` we actually instantiate (`u8` for size
    /// math, `u64` for the trace generator, `BabyBear` for the field
    /// trace). If anyone ever adds a non-array field or a field with a
    /// different `T`, padding will appear and one of these assertions
    /// will fire — alerting us before the `align_to` trick silently
    /// reads wrong cells.
    #[test]
    fn struct_is_flat_for_every_t_we_use() {
        // For any T where align_of(T) divides every offset (true for
        // power-of-2-sized T like u8/u32/u64/BabyBear), size_of the
        // struct should equal NUM_SHA512_COLS × size_of(T).
        assert_eq!(
            size_of::<Sha512Cols<u8>>(),
            NUM_SHA512_COLS,
            "u8 layout drift — padding introduced somewhere"
        );
        assert_eq!(
            size_of::<Sha512Cols<u32>>(),
            NUM_SHA512_COLS * size_of::<u32>(),
            "u32 layout drift — padding introduced somewhere"
        );
        assert_eq!(
            size_of::<Sha512Cols<u64>>(),
            NUM_SHA512_COLS * size_of::<u64>(),
            "u64 layout drift — padding introduced somewhere"
        );
        assert_eq!(
            size_of::<Sha512Cols<BabyBear>>(),
            NUM_SHA512_COLS * size_of::<BabyBear>(),
            "BabyBear layout drift — padding introduced somewhere"
        );

        // Bool is also 1 byte (Rust does NOT bit-pack bools in arrays);
        // including this assertion partly because the question came up.
        assert_eq!(size_of::<bool>(), 1);
        assert_eq!(
            size_of::<Sha512Cols<bool>>(),
            NUM_SHA512_COLS,
            "bool layout drift — Rust unexpectedly bit-packing bools?"
        );
    }
}
