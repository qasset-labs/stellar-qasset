//! `Slip10HmacAir` — the per-compression layer of SLIP-0010 derivation
//! for Ed25519, with full chain-integrity constraints. Spec source:
//! `docs/pipeline-spec.md` §6.3.3 + §8.
//!
//! ### Row layout (post-soundness-refactor)
//!
//! Per step, four rows in the order `[ipad_pre, inner, opad_pre, outer]`.
//! The reordering vs. the spec's `[ipad_pre, opad_pre, inner, outer]`
//! makes both within-step `h_in` chains adjacent transitions:
//!
//!   - `inner.h_in_packed = pack(ipad_pre.h_out_bits)` (rows 0→1)
//!   - `outer.h_in_packed = pack(opad_pre.h_out_bits)` (rows 2→3)
//!
//! The remaining within-step chain — `outer.msg = inner.h_out` —
//! still spans 2 rows (row 1 → row 3), so we propagate it via a
//! committed `inner_h_out_carrier_bits` column (snapshot at inner,
//! propagate forward, read at outer). Same idea for cross-step priv
//! propagation (`prev_step_priv_carrier_bits` carries the priv bytes
//! of step k's outer through step k+1's ipad_pre into step k+1's
//! inner row, where they go into the HMAC msg).
//!
//! Trace shape: 5 steps × 4 rows + 12 padding rows = 32 rows
//! (= `SLIP10_TRACE_HEIGHT`, a clean 2^5).
//!
//! ### Constraints
//!
//! The AIR enforces full chain integrity from the seed (PV input)
//! through five SLIP-0010 HMAC steps to the priv (final outer's
//! h_out). Specifically:
//!
//!   1. Bool checks on every primitive bit cell.
//!   2. **Keysched rows** (`is_ipad_pre + is_opad_pre`): `h_in_packed
//!      = SHA512_IV` per limb.
//!   3. **ipad/opad block construction** (per bit):
//!      `is_ipad_pre · (block_bits[i] - (key_bits[i] ⊕ ipad_pad_bit[i])) = 0`,
//!      same with opad. Binds keysched rows to a shared `key_bits`
//!      column.
//!   4. **Master anchor** (row 0 = step 0 ipad_pre):
//!      `key_bits[i] = master_key_bit[i]` where `master_key` =
//!      `"ed25519 seed"` zero-padded to 128 bytes.
//!   5. **Within-step key consistency**: when transitioning between
//!      two rows of the same step (i.e., when local is NOT outer),
//!      `next.key_bits = local.key_bits` per bit.
//!   6. **Cross-step key chain**: at the outer→ipad_pre boundary,
//!      `next.key_bits` for the first 32 bytes equals the chain code
//!      from `local.h_out_bits` (= bytes 32..64 of the outer's
//!      digest); the remaining 96 bytes are zero (zero-padded K').
//!   7. **Within-step h_in chains**:
//!      - ipad_pre→inner: `next.h_in_packed = pack(local.h_out_bits)`
//!      - opad_pre→outer: same.
//!   8. **inner.h_out carrier**: snapshot `inner_h_out_carrier_bits`
//!      at inner row (= local.h_out_bits); propagate through
//!      opad_pre into outer.
//!   9. **outer block construction**: msg bytes 0..64 = inner_h_out
//!      (via the carrier, with word-flat → byte-flat translation);
//!      msg byte 64 = 0x80; bytes 65..112 = 0; bytes 112..128 =
//!      length suffix `(128 + 64) * 8 = 1536` bits BE.
//!   10. **prev_priv carrier** (cross-step): snapshot priv (= bytes
//!       0..32 of previous outer h_out) at outer→ipad_pre boundary,
//!       propagate through ipad_pre and inner.
//!   11. **inner block construction** (master = step 0):
//!       - bytes 0..64 = seed_packed PV bits (cross-AIR PV input)
//!       - byte 64 = 0x80; bytes 65..112 = 0
//!       - bytes 112..128 = length suffix `(128 + 64) * 8 = 1536`
//!   12. **inner block construction** (non-master = steps 1..4):
//!       - byte 0 = 0x00 (constant prefix)
//!       - bytes 1..33 = prev_priv_carrier bits
//!       - bytes 33..37 = path index (preprocessed constants per step)
//!       - byte 37 = 0x80; bytes 38..112 = 0
//!       - bytes 112..128 = length suffix `(128 + 37) * 8 = 1320` BE
//!   13. **LogUp Receive** on `sha512_compressions`: per real row, one
//!       compression-tuple receive (multiplicity = is_real_row).
//!   14. **LogUp Send** on `slip10_priv_outputs`: on the last real
//!       outer row only (row 19), send the 256 priv bits to the
//!       Phase 4 priv-extractor AIR.
//!
//! ### Public values
//!
//! - **PV input** (32 cells, 16-bit limbs): `seed_packed` from
//!   `Pbkdf2Air`. Used by constraint #11.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::constants::{IPAD_BYTE, OPAD_BYTE};
use crate::hmac_air::helpers::{
    compression_tuple, BLOCK_BIT_COUNT_BYTE_FLAT, H_IN_LIMB_COUNT, H_OUT_BIT_COUNT,
};
use crate::sha512_air::constants::{
    BITS_PER_LIMB, BLOCK_WORDS, SHA512_COMPRESSIONS_BUS_NAME, SHA512_IV, STATE_WORDS, U64_LIMBS,
    WORD_BITS,
};

// ── Domain constants ──────────────────────────────────────────────────

pub const NUM_SLIP10_STEPS: usize = 5;
pub const ROWS_PER_HMAC: usize = 4;
pub const NUM_REAL_SLIP10_ROWS: usize = NUM_SLIP10_STEPS * ROWS_PER_HMAC;
pub const SLIP10_TRACE_HEIGHT: usize = NUM_REAL_SLIP10_ROWS.next_power_of_two();

/// Bit count of the Ed25519 private scalar that SLIP-0010's last step
/// produces: 32 bytes × 8 bits = 256 bits.
pub const NUM_PRIV_BITS: usize = 256;
pub const NUM_PRIV_BYTES: usize = 32;
pub const NUM_CHAIN_BYTES: usize = 32;

/// Name of the bus pairing this AIR's last real outer row with the
/// Phase 4 `Slip10Air` priv-extractor.
pub const SLIP10_PRIV_OUTPUTS_BUS_NAME: &str = "slip10_priv_outputs";

/// Bit count of one SHA-512 input block in **byte-flat** layout.
pub const NUM_BLOCK_BITS: usize = BLOCK_BIT_COUNT_BYTE_FLAT;

/// Bit count of `key_bits` (committed): 128-byte zero-padded HMAC key,
/// byte-flat layout.
pub const NUM_KEY_BITS: usize = NUM_BLOCK_BITS;

/// Bit count of `inner_h_out_carrier_bits`: 8 SHA-512 state words ×
/// 64 bits = 512 bits, **word-flat** layout (matches `Sha512Cols::h_out`).
pub const NUM_INNER_H_OUT_CARRIER_BITS: usize = STATE_WORDS * WORD_BITS;

/// Bit count of `prev_step_priv_carrier_bits`: 4 state words × 64 bits
/// = 256 bits, **word-flat** layout.
pub const NUM_PREV_PRIV_CARRIER_BITS: usize = NUM_PRIV_BITS;

/// PV vector layout:
/// - 16-bit limbs of the PBKDF2 seed (32 cells)
/// - BE byte representation of the BIP-44 `purpose'` index (4 cells)
/// - BE bytes of `coin_type'` (4 cells)
///
/// Steps 3 and 4 (account', change') of the account derivation stay private
/// and are bound to committed witness columns.
pub const NUM_SEED_PACKED_PV_CELLS: usize = STATE_WORDS * U64_LIMBS;
pub const SEED_PACKED_PV_OFFSET: usize = 0;
pub const NUM_PATH_INDEX_BE_BYTES: usize = 4;
pub const PURPOSE_BE_PV_OFFSET: usize = NUM_SEED_PACKED_PV_CELLS;
pub const COIN_TYPE_BE_PV_OFFSET: usize = PURPOSE_BE_PV_OFFSET + NUM_PATH_INDEX_BE_BYTES;
pub const NUM_PUBLIC_VALUES: usize = NUM_SEED_PACKED_PV_CELLS + 2 * NUM_PATH_INDEX_BE_BYTES;

/// Length of master step's HMAC msg = seed = 64 bytes.
pub const MASTER_MSG_BYTE_LEN: usize = 64;
/// Length of non-master step's HMAC msg = `0x00 || priv (32) || index (4)` = 37 bytes.
pub const NONMASTER_MSG_BYTE_LEN: usize = 37;

/// SHA-512 inner-compression input length = 128 (K'⊕pad) + msg_len.
/// Encoded as the 16-byte length suffix of the padded block. In bits.
pub const MASTER_INNER_LENGTH_BITS: u128 = ((128 + MASTER_MSG_BYTE_LEN) * 8) as u128;
pub const NONMASTER_INNER_LENGTH_BITS: u128 = ((128 + NONMASTER_MSG_BYTE_LEN) * 8) as u128;
/// Outer compression input length is always `128 + 64 = 192` bytes
/// (K'⊕opad + 64-byte inner digest).
pub const OUTER_LENGTH_BITS: u128 = ((128 + 64) * 8) as u128;

/// Master HMAC key: ASCII `"ed25519 seed"`, 12 bytes. Zero-padded to
/// 128 bytes for K'.
pub const MASTER_KEY_BYTES: &[u8; 12] = b"ed25519 seed";

// ── Main-trace columns ────────────────────────────────────────────────

#[repr(C)]
pub struct Slip10HmacCols<T> {
    /// HMAC key K' zero-padded to 128 bytes, in **byte-flat** layout
    /// (`key_bits[byte_idx * 8 + bit_in_byte]`, LSB-first within byte).
    /// Same value across all 4 rows of one step (transition-constrained).
    /// On step 0 row 0: pinned to `MASTER_KEY_BYTES` zero-padded.
    /// On step k>0 row 4k: bound to step k-1's outer h_out chain bytes.
    pub key_bits: [T; NUM_KEY_BITS],

    /// SHA-512 input chaining state, 16-bit-limb-packed (low-first).
    pub h_in_packed: [[T; U64_LIMBS]; STATE_WORDS],

    /// SHA-512 input block in **byte-flat** layout.
    pub block_bits: [T; NUM_BLOCK_BITS],

    /// SHA-512 output state in **word-flat** layout.
    pub h_out_bits: [[T; WORD_BITS]; STATE_WORDS],

    /// Cross-row carrier for inner row's h_out, propagated through
    /// opad_pre into outer (where it becomes the outer compression's
    /// msg). Word-flat layout matching `h_out_bits`.
    pub inner_h_out_carrier_bits: [T; NUM_INNER_H_OUT_CARRIER_BITS],

    /// Cross-step carrier for the previous step's priv (= bytes 0..32
    /// of previous outer row's h_out). Snapshotted at the
    /// outer→ipad_pre boundary, propagated through ipad_pre to the
    /// next step's inner row. Word-flat layout (4 SHA-512 state words
    /// × 64 bits).
    pub prev_step_priv_carrier_bits: [T; NUM_PREV_PRIV_CARRIER_BITS],

    pub account_change_byte_be: [T; NUM_PATH_INDEX_BE_BYTES],
}

pub const NUM_SLIP10_HMAC_COLS: usize = size_of::<Slip10HmacCols<u8>>();

impl<T> Borrow<Slip10HmacCols<T>> for [T] {
    fn borrow(&self) -> &Slip10HmacCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_HMAC_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Slip10HmacCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Slip10HmacCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Slip10HmacCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_HMAC_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Slip10HmacCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// ── Preprocessed-trace columns ─────────────────────────────────────────

#[repr(C)]
pub struct Slip10HmacPreprocessedCols<T> {
    /// 1 on rows 0..20, 0 on padding rows 20..32. Gates LogUp
    /// multiplicity for the `sha512_compressions` bus.
    pub is_real_row: T,
    /// 1 only on row 19 (the last step's outer row).
    pub is_last_real_outer: T,
    /// Role one-hot: 1 on `[ipad_pre, inner, opad_pre, outer]` rows.
    pub is_ipad_pre: T,
    pub is_inner: T,
    pub is_opad_pre: T,
    pub is_outer: T,
    /// 1 on rows 0..3 (the master step). Gates master-specific
    /// constraints.
    pub is_master_step: T,
    /// 1 only on row 0. Gates the master-key anchor constraint.
    pub is_first_real_row: T,
    /// 1 only on the inner row of SLIP-0010 step 1 (row 5). Gates the
    /// public-value binding for `purpose'`.
    pub is_step_1_inner: T,
    /// 1 only on the inner row of SLIP-0010 step 2 (row 9). Gates the
    /// public-value binding for `coin_type'`.
    pub is_step_2_inner: T,
    /// 1 only on the inner row of SLIP-0010 step 3 (row 13). Gates
    /// the committed-witness binding for `account'`.
    pub is_step_3_inner: T,
    /// 1 only on the inner row of SLIP-0010 step 4 (row 17). Gates
    /// the committed-witness binding for `change'`.
    pub is_step_4_inner: T,
}

pub const NUM_SLIP10_HMAC_PREPROCESSED_COLS: usize = size_of::<Slip10HmacPreprocessedCols<u8>>();

impl<T> Borrow<Slip10HmacPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Slip10HmacPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_HMAC_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Slip10HmacPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Slip10HmacPreprocessedCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Slip10HmacPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_SLIP10_HMAC_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<Slip10HmacPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// ── Helpers for preprocessed table construction ────────────────────────

/// Returns the role of row `r` within a step (0 = ipad_pre, 1 = inner,
/// 2 = opad_pre, 3 = outer). Padding rows return None.
fn row_role(row_index: usize) -> Option<usize> {
    if row_index >= NUM_REAL_SLIP10_ROWS {
        None
    } else {
        Some(row_index % ROWS_PER_HMAC)
    }
}

fn row_step_index(row_index: usize) -> Option<usize> {
    if row_index >= NUM_REAL_SLIP10_ROWS {
        None
    } else {
        Some(row_index / ROWS_PER_HMAC)
    }
}

/// Returns `master_key` zero-padded to 128 bytes.
fn master_key_padded() -> [u8; 128] {
    let mut buf = [0u8; 128];
    buf[..MASTER_KEY_BYTES.len()].copy_from_slice(MASTER_KEY_BYTES);
    buf
}

/// `key XOR pad`-pattern bit at byte-flat bit position `bit_index`,
/// for a pad byte that's repeated 128 times to fill a SHA-512 block.
fn pad_pattern_bit(pad_byte: u8, bit_index: usize) -> bool {
    let bit_in_byte = bit_index % 8;
    ((pad_byte >> bit_in_byte) & 1) == 1
}

/// Word-flat → byte-flat bit-position translation. Used to map h_out
/// bits (committed in word-flat layout) to msg-block bytes
/// (byte-flat layout).
const fn word_flat_to_byte_flat(word_flat_bit: usize) -> usize {
    let word_idx = word_flat_bit / WORD_BITS;
    let bit_in_word = word_flat_bit % WORD_BITS;
    let byte_in_word = 7 - bit_in_word / 8;
    let bit_in_byte = bit_in_word % 8;
    let byte_idx = word_idx * 8 + byte_in_word;
    byte_idx * 8 + bit_in_byte
}

/// Inverse of `word_flat_to_byte_flat`: byte-flat → word-flat. Maps a
/// bit position in the byte-flat block_bits layout to its
/// corresponding bit position in the word-flat carrier (when those
/// bits represent the same SHA-512 word's bits).
const fn byte_flat_to_word_flat(byte_flat_bit: usize) -> usize {
    let byte_idx = byte_flat_bit / 8;
    let bit_in_byte = byte_flat_bit % 8;
    let word_idx = byte_idx / 8;
    let byte_in_word = byte_idx % 8;
    let bit_in_word = (7 - byte_in_word) * 8 + bit_in_byte;
    word_idx * WORD_BITS + bit_in_word
}

// ── The AIR ────────────────────────────────────────────────────────────

#[derive(Clone, Default, Debug)]
pub struct Slip10HmacAir {
    num_lookups: usize,
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Slip10HmacAir {
    fn width(&self) -> usize {
        NUM_SLIP10_HMAC_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Most constraints are degree-1 (selector × diff). The LogUp
        // transition is degree 2 (one outer entry, deg-1 multiplicity).
        // Cap at 3 with headroom.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = vec![F::ZERO; SLIP10_TRACE_HEIGHT * NUM_SLIP10_HMAC_PREPROCESSED_COLS];

        for row_index in 0..SLIP10_TRACE_HEIGHT {
            let base = row_index * NUM_SLIP10_HMAC_PREPROCESSED_COLS;
            let cols: &mut Slip10HmacPreprocessedCols<F> =
                values[base..base + NUM_SLIP10_HMAC_PREPROCESSED_COLS].borrow_mut();

            if row_index < NUM_REAL_SLIP10_ROWS {
                cols.is_real_row = F::ONE;
            }
            if row_index == NUM_REAL_SLIP10_ROWS - 1 {
                cols.is_last_real_outer = F::ONE;
            }
            if row_index == 0 {
                cols.is_first_real_row = F::ONE;
            }

            let role = row_role(row_index);
            cols.is_ipad_pre = if role == Some(0) { F::ONE } else { F::ZERO };
            cols.is_inner = if role == Some(1) { F::ONE } else { F::ZERO };
            cols.is_opad_pre = if role == Some(2) { F::ONE } else { F::ZERO };
            cols.is_outer = if role == Some(3) { F::ONE } else { F::ZERO };

            let step = row_step_index(row_index);
            cols.is_master_step = if step == Some(0) { F::ONE } else { F::ZERO };

            if role == Some(1) {
                match step {
                    Some(1) => cols.is_step_1_inner = F::ONE,
                    Some(2) => cols.is_step_2_inner = F::ONE,
                    Some(3) => cols.is_step_3_inner = F::ONE,
                    Some(4) => cols.is_step_4_inner = F::ONE,
                    _ => {}
                }
            }
        }

        Some(RowMajorMatrix::new(
            values,
            NUM_SLIP10_HMAC_PREPROCESSED_COLS,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // We need the NEXT row's preprocessed selectors (is_inner,
        // is_opad_pre, is_outer, is_ipad_pre) to gate transition
        // constraints. Returning the column indices here makes them
        // available via `preprocessed_window.next_slice()`.
        // Layout offsets within Slip10HmacPreprocessedCols:
        //   0: is_real_row, 1: is_last_real_outer, 2: is_ipad_pre,
        //   3: is_inner, 4: is_opad_pre, 5: is_outer, 6: is_master_step,
        //   7: is_first_real_row, 8..12: is_step_{1,2,3,4}_inner.
        // We only need is_ipad_pre, is_inner, is_opad_pre, is_outer for
        // transitions.
        vec![2, 3, 4, 5]
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for Slip10HmacAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot the row windows so subsequent &mut builder calls
        // don't conflict.
        let main_window = builder.main();
        let local: &Slip10HmacCols<AB::Var> = (*main_window.current_slice()).borrow();
        let next: &Slip10HmacCols<AB::Var> = (*main_window.next_slice()).borrow();
        let preprocessed_window = builder.preprocessed().clone();
        let preprocessed_local: &Slip10HmacPreprocessedCols<AB::Var> =
            (*preprocessed_window.current_slice()).borrow();
        let preprocessed_next: &Slip10HmacPreprocessedCols<AB::Var> =
            (*preprocessed_window.next_slice()).borrow();

        let key_bits_local = local.key_bits;
        let block_bits_local = local.block_bits;
        let h_out_bits_local = local.h_out_bits;
        let h_in_packed_local = local.h_in_packed;
        let inner_h_out_carrier_local = local.inner_h_out_carrier_bits;
        let prev_priv_carrier_local = local.prev_step_priv_carrier_bits;

        let key_bits_next = next.key_bits;
        let h_in_packed_next = next.h_in_packed;
        let inner_h_out_carrier_next = next.inner_h_out_carrier_bits;
        let prev_priv_carrier_next = next.prev_step_priv_carrier_bits;

        // Public values snapshot.
        let public_values_snapshot: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public_values = builder.public_values();
            debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);
            let mut snapshot = [public_values[0]; NUM_PUBLIC_VALUES];
            for i in 0..NUM_PUBLIC_VALUES {
                snapshot[i] = public_values[i];
            }
            snapshot
        };

        // Selectors as Expr.
        let is_ipad_pre: AB::Expr = preprocessed_local.is_ipad_pre.into();
        let is_inner: AB::Expr = preprocessed_local.is_inner.into();
        let is_opad_pre: AB::Expr = preprocessed_local.is_opad_pre.into();
        let is_outer: AB::Expr = preprocessed_local.is_outer.into();
        let is_master_step: AB::Expr = preprocessed_local.is_master_step.into();
        let is_first_real_row: AB::Expr = preprocessed_local.is_first_real_row.into();
        let is_real_row: AB::Expr = preprocessed_local.is_real_row.into();
        let is_step_1_inner: AB::Expr = preprocessed_local.is_step_1_inner.into();
        let is_step_2_inner: AB::Expr = preprocessed_local.is_step_2_inner.into();
        let is_step_3_inner: AB::Expr = preprocessed_local.is_step_3_inner.into();
        let is_step_4_inner: AB::Expr = preprocessed_local.is_step_4_inner.into();
        let next_is_inner: AB::Expr = preprocessed_next.is_inner.into();
        let next_is_opad_pre: AB::Expr = preprocessed_next.is_opad_pre.into();
        let next_is_outer: AB::Expr = preprocessed_next.is_outer.into();
        let next_is_ipad_pre: AB::Expr = preprocessed_next.is_ipad_pre.into();

        let account_change_byte_be = local.account_change_byte_be;

        // Bool checks.
        for &bit in key_bits_local.iter() {
            builder.assert_bool(bit);
        }
        for &bit in block_bits_local.iter() {
            builder.assert_bool(bit);
        }
        for word in h_out_bits_local.iter() {
            for &bit in word.iter() {
                builder.assert_bool(bit);
            }
        }
        for &bit in inner_h_out_carrier_local.iter() {
            builder.assert_bool(bit);
        }
        for &bit in prev_priv_carrier_local.iter() {
            builder.assert_bool(bit);
        }

        // Keysched h_in = SHA512_IV.
        let keysched_selector = is_ipad_pre.clone() + is_opad_pre.clone();
        for word_index in 0..STATE_WORDS {
            let iv_word = SHA512_IV[word_index];
            for limb_index in 0..U64_LIMBS {
                let iv_limb = (iv_word >> (limb_index * BITS_PER_LIMB)) & 0xFFFF;
                let cell: AB::Expr = h_in_packed_local[word_index][limb_index].into();
                builder
                    .assert_zero(keysched_selector.clone() * (cell - AB::Expr::from_u64(iv_limb)));
            }
        }

        // ipad/opad block = key XOR pad pattern.
        for bit_index in 0..NUM_BLOCK_BITS {
            let key_bit: AB::Expr = key_bits_local[bit_index].into();
            let block_bit: AB::Expr = block_bits_local[bit_index].into();
            let ipad_xor: AB::Expr = if pad_pattern_bit(IPAD_BYTE, bit_index) {
                AB::Expr::ONE - key_bit.clone()
            } else {
                key_bit.clone()
            };
            builder.assert_zero(is_ipad_pre.clone() * (block_bit.clone() - ipad_xor));
            let opad_xor: AB::Expr = if pad_pattern_bit(OPAD_BYTE, bit_index) {
                AB::Expr::ONE - key_bit
            } else {
                key_bit
            };
            builder.assert_zero(is_opad_pre.clone() * (block_bit - opad_xor));
        }

        // Master anchor: row 0's key_bits = "ed25519 seed" zero-padded.
        let master_key = master_key_padded();
        for byte_idx in 0..128 {
            let byte_value = master_key[byte_idx];
            for bit_in_byte in 0..8 {
                let expected: u32 = ((byte_value >> bit_in_byte) & 1) as u32;
                let cell: AB::Expr = key_bits_local[byte_idx * 8 + bit_in_byte].into();
                builder
                    .assert_zero(is_first_real_row.clone() * (cell - AB::Expr::from_u32(expected)));
            }
        }

        // Outer block construction (intra-row, gated by is_outer).
        for byte_idx in 0..NUM_BLOCK_BITS / 8 {
            for bit_in_byte in 0..8 {
                let block_bit_idx = byte_idx * 8 + bit_in_byte;
                let block_bit: AB::Expr = block_bits_local[block_bit_idx].into();
                if byte_idx < 64 {
                    let word_flat_idx = byte_flat_to_word_flat(block_bit_idx);
                    let carrier_bit: AB::Expr = inner_h_out_carrier_local[word_flat_idx].into();
                    builder.assert_zero(is_outer.clone() * (block_bit.clone() - carrier_bit));
                } else if byte_idx == 64 {
                    let expected = if bit_in_byte == 7 { 1u32 } else { 0u32 };
                    builder.assert_zero(
                        is_outer.clone() * (block_bit.clone() - AB::Expr::from_u32(expected)),
                    );
                } else if byte_idx < 112 {
                    builder.assert_zero(is_outer.clone() * block_bit.clone());
                } else {
                    let length_byte_offset = byte_idx - 112;
                    let shift_bits = 8 * (15 - length_byte_offset);
                    let length_byte_value = ((OUTER_LENGTH_BITS >> shift_bits) & 0xFF) as u32;
                    let expected_bit = (length_byte_value >> bit_in_byte) & 1;
                    builder.assert_zero(
                        is_outer.clone() * (block_bit - AB::Expr::from_u32(expected_bit)),
                    );
                }
            }
        }

        // (11) Master inner block construction (step 0 inner = row 1):
        // bytes 0..64 = seed_packed PV (16-bit limbs decoded → bits, byte-flat),
        // byte 64 = 0x80, bytes 65..112 = 0,
        // bytes 112..128 = MASTER_INNER_LENGTH_BITS BE.
        let master_inner_selector = is_master_step.clone() * is_inner.clone();
        for byte_idx in 0..NUM_BLOCK_BITS / 8 {
            for bit_in_byte in 0..8 {
                let block_bit_idx = byte_idx * 8 + bit_in_byte;
                let block_bit: AB::Expr = block_bits_local[block_bit_idx].into();

                if byte_idx < MASTER_MSG_BYTE_LEN {
                    // Seed bytes: byte k of seed = high byte (when k%8==0) ...
                    // Map this byte-flat block_bit to the seed_packed limb that
                    // contains it. seed_packed has 32 cells × 16-bit limbs in
                    // low-first per-word order: cell `w * 4 + j` is limb j of
                    // word w. Byte byte_idx maps to:
                    //   word_idx = byte_idx / 8
                    //   byte_in_word = byte_idx % 8
                    //   word_flat_bit = byte_flat_to_word_flat(block_bit_idx)
                    //   limb_index = (word_flat_bit % WORD_BITS) / BITS_PER_LIMB
                    //   bit_in_limb = (word_flat_bit % WORD_BITS) % BITS_PER_LIMB
                    //   pv_index = word_idx * 4 + limb_index
                    let word_flat_bit = byte_flat_to_word_flat(block_bit_idx);
                    let word_idx = word_flat_bit / WORD_BITS;
                    let bit_in_word = word_flat_bit % WORD_BITS;
                    let limb_index = bit_in_word / BITS_PER_LIMB;
                    let bit_in_limb = bit_in_word % BITS_PER_LIMB;
                    let pv_index = word_idx * U64_LIMBS + limb_index;
                    // The bit value = (pv_value >> bit_in_limb) & 1. We
                    // constrain `block_bit * 2^bit_in_limb + (other bits)
                    // sum = pv` via per-limb aggregation. Easier:
                    // express block_bits as a packed limb and equate to
                    // pv. We do that AFTER this byte loop instead.
                    let _ = (limb_index, bit_in_limb, pv_index); // see below
                                                                 // For now, just constrain that block_bit * 1 = block_bit
                                                                 // (no-op). Real binding happens in the limb loop below.
                    let _ = block_bit;
                } else if byte_idx == MASTER_MSG_BYTE_LEN {
                    // 0x80 separator
                    let expected = if bit_in_byte == 7 { 1u32 } else { 0u32 };
                    builder.assert_zero(
                        master_inner_selector.clone()
                            * (block_bit.clone() - AB::Expr::from_u32(expected)),
                    );
                } else if byte_idx < 112 {
                    builder.assert_zero(master_inner_selector.clone() * block_bit.clone());
                } else {
                    let length_byte_offset = byte_idx - 112;
                    let shift_bits = 8 * (15 - length_byte_offset);
                    let length_byte_value =
                        ((MASTER_INNER_LENGTH_BITS >> shift_bits) & 0xFF) as u32;
                    let expected_bit = (length_byte_value >> bit_in_byte) & 1;
                    builder.assert_zero(
                        master_inner_selector.clone()
                            * (block_bit - AB::Expr::from_u32(expected_bit)),
                    );
                }
            }
        }
        // Master inner msg portion: bind block_bits to seed_packed PV
        // per limb. For each (word, limb), pack the 16 corresponding
        // block_bits (in byte-flat layout) and equate to the PV.
        for word_idx in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                let mut limb_expr: AB::Expr = AB::Expr::ZERO;
                for bit_in_limb in 0..BITS_PER_LIMB {
                    let word_flat_bit =
                        word_idx * WORD_BITS + limb_index * BITS_PER_LIMB + bit_in_limb;
                    let block_bit_idx = word_flat_to_byte_flat(word_flat_bit);
                    let block_bit: AB::Expr = block_bits_local[block_bit_idx].into();
                    let pow = AB::Expr::from_u32(1u32 << bit_in_limb);
                    limb_expr = limb_expr + pow * block_bit;
                }
                let pv_index = word_idx * U64_LIMBS + limb_index;
                let pv: AB::Expr = public_values_snapshot[pv_index].into();
                builder.assert_zero(master_inner_selector.clone() * (pv - limb_expr));
            }
        }

        // (12) Non-master inner block construction (rows 5, 9, 13, 17):
        // byte 0 = 0x00, bytes 1..33 = prev_priv (byte-flat from carrier),
        // bytes 33..37 = path_index (preprocessed BE bytes),
        // byte 37 = 0x80, bytes 38..112 = 0,
        // bytes 112..128 = NONMASTER_INNER_LENGTH_BITS BE.
        let nonmaster_inner_selector = (AB::Expr::ONE - is_master_step.clone()) * is_inner.clone();
        for byte_idx in 0..NUM_BLOCK_BITS / 8 {
            for bit_in_byte in 0..8 {
                let block_bit_idx = byte_idx * 8 + bit_in_byte;
                let block_bit: AB::Expr = block_bits_local[block_bit_idx].into();

                if byte_idx == 0 {
                    // 0x00 prefix: all bits zero.
                    builder.assert_zero(nonmaster_inner_selector.clone() * block_bit.clone());
                } else if byte_idx >= 1 && byte_idx < 1 + NUM_PRIV_BYTES {
                    // prev_priv byte. byte_idx in [1, 33). prev_priv
                    // byte k (k in 0..32) lives at byte-flat block byte
                    // 1+k. The carrier is word-flat. Map:
                    //   byte_flat_bit = block_bit_idx (within the block)
                    //   carrier_byte_idx = byte_idx - 1
                    //   carrier_byte_flat_bit = carrier_byte_idx * 8 + bit_in_byte
                    //   carrier_word_flat_bit =
                    //       byte_flat_to_word_flat(carrier_byte_flat_bit)
                    let carrier_byte_idx = byte_idx - 1;
                    let carrier_byte_flat = carrier_byte_idx * 8 + bit_in_byte;
                    let carrier_word_flat = byte_flat_to_word_flat(carrier_byte_flat);
                    let carrier_bit: AB::Expr = prev_priv_carrier_local[carrier_word_flat].into();
                    builder
                        .assert_zero(nonmaster_inner_selector.clone() * (block_bit - carrier_bit));
                } else if byte_idx >= 33 && byte_idx < 37 {
                    // Path-index BE bytes are bound to the path-byte
                    // sources (PVs for steps 1, 2; committed cells for
                    // steps 3, 4) by single per-byte equations asserted
                    // outside this bit loop.
                    let _ = block_bit;
                } else if byte_idx == 37 {
                    let expected = if bit_in_byte == 7 { 1u32 } else { 0u32 };
                    builder.assert_zero(
                        nonmaster_inner_selector.clone()
                            * (block_bit - AB::Expr::from_u32(expected)),
                    );
                } else if byte_idx < 112 {
                    builder.assert_zero(nonmaster_inner_selector.clone() * block_bit.clone());
                } else {
                    let length_byte_offset = byte_idx - 112;
                    let shift_bits = 8 * (15 - length_byte_offset);
                    let length_byte_value =
                        ((NONMASTER_INNER_LENGTH_BITS >> shift_bits) & 0xFF) as u32;
                    let expected_bit = (length_byte_value >> bit_in_byte) & 1;
                    builder.assert_zero(
                        nonmaster_inner_selector.clone()
                            * (block_bit - AB::Expr::from_u32(expected_bit)),
                    );
                }
            }
        }
        // Non-master inner path-index byte equality. The 4 BE bytes at
        // block offsets 33..37 must equal the path index for the
        // current step. Steps 1 and 2 (`purpose'`, `coin_type'`)
        // source their bytes from public values, gated by
        // `is_step_{1,2}_inner`; steps 3 and 4 (`account'`, `change'`)
        // source from the committed `account_change_byte_be` cells,
        // gated by `is_step_{3,4}_inner`. Selectors are degree 1, so
        // each constraint stays at degree 2.
        let path_byte_block_offset = NONMASTER_MSG_BYTE_LEN - NUM_PATH_INDEX_BE_BYTES;
        for path_byte_offset in 0..NUM_PATH_INDEX_BE_BYTES {
            let block_byte_idx = path_byte_block_offset + path_byte_offset;
            let mut packed_byte: AB::Expr = AB::Expr::ZERO;
            for bit_in_byte in 0..8 {
                let pow = AB::Expr::from_u32(1u32 << bit_in_byte);
                let bit: AB::Expr = block_bits_local[block_byte_idx * 8 + bit_in_byte].into();
                packed_byte = packed_byte + pow * bit;
            }

            let purpose_pv_byte: AB::Expr =
                public_values_snapshot[PURPOSE_BE_PV_OFFSET + path_byte_offset].into();
            builder.assert_zero(is_step_1_inner.clone() * (purpose_pv_byte - packed_byte.clone()));

            let coin_type_pv_byte: AB::Expr =
                public_values_snapshot[COIN_TYPE_BE_PV_OFFSET + path_byte_offset].into();
            builder
                .assert_zero(is_step_2_inner.clone() * (coin_type_pv_byte - packed_byte.clone()));

            let committed_path_byte: AB::Expr = account_change_byte_be[path_byte_offset].into();
            builder.assert_zero(
                is_step_3_inner.clone() * (committed_path_byte.clone() - packed_byte.clone()),
            );
            builder.assert_zero(is_step_4_inner.clone() * (committed_path_byte - packed_byte));
        }

        // Hardening on chain-const path indices (`purpose'`,
        // `coin_type'`): SLIP-0010 for Ed25519 is hardened-only, so
        // BE-byte 0 of those indices must have its high bit set. The
        // top bit of the byte at block offset 33 is bit 7 of that byte
        // in the LSB-first-within-byte block layout. Steps 3 and 4
        // (`account'`, `change'`) are left unconstrained on hardening
        // — the prover supplies whatever bytes are needed to reach
        // the target address, which is itself bound via the trailing
        // pipeline AIRs.
        let hardening_bit_idx = path_byte_block_offset * 8 + 7;
        let hardening_bit: AB::Expr = block_bits_local[hardening_bit_idx].into();
        builder.assert_zero(is_step_1_inner.clone() * (hardening_bit.clone() - AB::Expr::ONE));
        builder.assert_zero(is_step_2_inner.clone() * (hardening_bit - AB::Expr::ONE));

        // Transition constraints (key chain, h_in chain, carriers).
        // Scoped so when_trans's borrow on builder ends before the
        // function exits.
        {
            let mut when_trans = builder.when_transition();

            // (5) within-step key consistency: when local is NOT outer
            // (and is real), next.key_bits = local.key_bits.
            // (6) cross-step key chain: at outer→ipad_pre, next.key_bits
            // bytes [0,32) = local.h_out chain bytes; bytes [32,128) = 0.
            let within_step_key_selector = is_real_row.clone() * (AB::Expr::ONE - is_outer.clone());
            let cross_step_key_selector = is_outer.clone() * next_is_ipad_pre.clone();
            for bit_index in 0..NUM_KEY_BITS {
                let local_bit: AB::Expr = key_bits_local[bit_index].into();
                let next_bit: AB::Expr = key_bits_next[bit_index].into();
                when_trans
                    .assert_zero(within_step_key_selector.clone() * (next_bit.clone() - local_bit));
                if bit_index < NUM_PRIV_BITS {
                    let chain_byte_idx = bit_index / 8 + NUM_PRIV_BYTES;
                    let bit_in_byte = bit_index % 8;
                    let word_flat_pos = byte_flat_to_word_flat(chain_byte_idx * 8 + bit_in_byte);
                    let word_idx = word_flat_pos / WORD_BITS;
                    let bit_in_word = word_flat_pos % WORD_BITS;
                    let local_h_out_bit: AB::Expr = h_out_bits_local[word_idx][bit_in_word].into();
                    when_trans.assert_zero(
                        cross_step_key_selector.clone() * (next_bit - local_h_out_bit),
                    );
                } else {
                    when_trans.assert_zero(cross_step_key_selector.clone() * next_bit);
                }
            }

            // (7) within-step h_in chains: ipad_pre→inner and
            // opad_pre→outer pull next.h_in_packed = pack(local.h_out).
            let chain_to_inner_selector = is_ipad_pre.clone() * next_is_inner.clone();
            let chain_to_outer_selector = is_opad_pre.clone() * next_is_outer.clone();
            for word_index in 0..STATE_WORDS {
                for limb_index in 0..U64_LIMBS {
                    let mut packed: AB::Expr = AB::Expr::ZERO;
                    for bit_offset in 0..BITS_PER_LIMB {
                        let pow = AB::Expr::from_u32(1u32 << bit_offset);
                        let bit: AB::Expr = h_out_bits_local[word_index]
                            [limb_index * BITS_PER_LIMB + bit_offset]
                            .into();
                        packed = packed + pow * bit;
                    }
                    let next_h_in: AB::Expr = h_in_packed_next[word_index][limb_index].into();
                    when_trans.assert_zero(
                        chain_to_inner_selector.clone() * (next_h_in.clone() - packed.clone()),
                    );
                    when_trans.assert_zero(chain_to_outer_selector.clone() * (next_h_in - packed));
                }
            }

            // (8) inner_h_out_carrier: snapshot at inner→opad_pre,
            // forward at opad_pre→outer.
            let snapshot_selector = is_inner.clone() * next_is_opad_pre.clone();
            let forward_selector = is_opad_pre.clone() * next_is_outer.clone();
            for word_index in 0..STATE_WORDS {
                for bit_in_word in 0..WORD_BITS {
                    let word_flat_idx = word_index * WORD_BITS + bit_in_word;
                    let local_h_out: AB::Expr = h_out_bits_local[word_index][bit_in_word].into();
                    let local_carrier: AB::Expr = inner_h_out_carrier_local[word_flat_idx].into();
                    let next_carrier: AB::Expr = inner_h_out_carrier_next[word_flat_idx].into();
                    when_trans.assert_zero(
                        snapshot_selector.clone() * (next_carrier.clone() - local_h_out),
                    );
                    when_trans
                        .assert_zero(forward_selector.clone() * (next_carrier - local_carrier));
                }
            }

            // (10) prev_priv_carrier: snapshot at outer→ipad_pre (= priv
            // bytes from local h_out's first 4 words), forward at
            // ipad_pre→inner.
            let priv_snapshot_selector = is_outer.clone() * next_is_ipad_pre.clone();
            let priv_forward_selector = is_ipad_pre.clone() * next_is_inner.clone();
            for bit_index in 0..NUM_PREV_PRIV_CARRIER_BITS {
                let word_idx = bit_index / WORD_BITS;
                let bit_in_word = bit_index % WORD_BITS;
                let local_h_out_bit: AB::Expr = h_out_bits_local[word_idx][bit_in_word].into();
                let local_carrier: AB::Expr = prev_priv_carrier_local[bit_index].into();
                let next_carrier: AB::Expr = prev_priv_carrier_next[bit_index].into();
                when_trans.assert_zero(
                    priv_snapshot_selector.clone() * (next_carrier.clone() - local_h_out_bit),
                );
                when_trans
                    .assert_zero(priv_forward_selector.clone() * (next_carrier - local_carrier));
            }
        }
    }
}

impl<F: Field> LookupAir<F> for Slip10HmacAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_SLIP10_HMAC_COLS,
            preprocessed_width: NUM_SLIP10_HMAC_PREPROCESSED_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &Slip10HmacCols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &Slip10HmacPreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();

        // (13) sha512_compressions Receive: canonical compression tuple
        // per row.
        let mut h_in_limbs: Vec<SymbolicExpression<F>> = Vec::with_capacity(H_IN_LIMB_COUNT);
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                h_in_limbs.push(main_local.h_in_packed[word_index][limb_index].into());
            }
        }
        let mut block_bits_word_flat: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(NUM_BLOCK_BITS);
        for word_index in 0..BLOCK_WORDS {
            for bit_in_word in 0..WORD_BITS {
                let byte_in_word = 7 - bit_in_word / 8;
                let byte_idx = word_index * 8 + byte_in_word;
                let bit_in_byte = bit_in_word % 8;
                block_bits_word_flat.push(main_local.block_bits[byte_idx * 8 + bit_in_byte].into());
            }
        }
        let mut h_out_bits_exprs: Vec<SymbolicExpression<F>> = Vec::with_capacity(H_OUT_BIT_COUNT);
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                h_out_bits_exprs.push(main_local.h_out_bits[word_index][bit_in_word].into());
            }
        }
        let tuple = compression_tuple::<F>(&h_in_limbs, &block_bits_word_flat, &h_out_bits_exprs);

        let multiplicity: SymbolicExpression<F> = preprocessed_local.is_real_row.into();
        let lookup_inputs = [(tuple, multiplicity, Direction::Receive)];

        let mut lookups: Vec<Lookup<F>> = Vec::with_capacity(2);
        lookups.push(LookupAir::register_lookup(
            self,
            Kind::Global(SHA512_COMPRESSIONS_BUS_NAME.to_string()),
            &lookup_inputs,
        ));

        // (14) slip10_priv_outputs Send on the last real outer row only.
        let mut priv_bits_tuple: Vec<SymbolicExpression<F>> = Vec::with_capacity(NUM_PRIV_BITS);
        for word_index in 0..(NUM_PRIV_BITS / WORD_BITS) {
            for bit_in_word in 0..WORD_BITS {
                priv_bits_tuple.push(main_local.h_out_bits[word_index][bit_in_word].into());
            }
        }
        let priv_mult: SymbolicExpression<F> = preprocessed_local.is_last_real_outer.into();
        let priv_inputs = [(priv_bits_tuple, priv_mult, Direction::Send)];
        lookups.push(LookupAir::register_lookup(
            self,
            Kind::Global(SLIP10_PRIV_OUTPUTS_BUS_NAME.to_string()),
            &priv_inputs,
        ));

        lookups
    }
}

// ── Trace generation ──────────────────────────────────────────────────

/// One compression input tuple in the **new** row layout
/// `[ipad_pre, inner, opad_pre, outer]` per step.
#[derive(Clone, Copy, Debug)]
pub struct Slip10CompressionInput {
    pub h_in_words: [u64; STATE_WORDS],
    pub block_bytes: [u8; 128],
    pub h_out_bytes: [u8; 64],
}

/// Generate the Slip10HmacAir trace from 20 ordered compression inputs
/// in `[ipad_pre, inner, opad_pre, outer]`-per-step row order, plus
/// the 32-byte raw key for each step (so we can fill `key_bits`).
///
/// `seed_bytes` is needed to fill the master inner row's block_bits
/// per the chain semantics; for non-master steps the inner block is
/// built from `prev_priv` + path index + padding (computed off-circuit
/// to match the AIR's expectations).
pub fn generate_slip10_hmac_trace<F: PrimeField64>(
    inputs: [Slip10CompressionInput; NUM_REAL_SLIP10_ROWS],
    step_keys: [[u8; 128]; NUM_SLIP10_STEPS],
) -> RowMajorMatrix<F> {
    let mut values = vec![F::ZERO; SLIP10_TRACE_HEIGHT * NUM_SLIP10_HMAC_COLS];

    let mut prev_priv_carrier_bits: [u8; NUM_PREV_PRIV_CARRIER_BITS] =
        [0u8; NUM_PREV_PRIV_CARRIER_BITS];
    let mut inner_h_out_carrier_bits: [u8; NUM_INNER_H_OUT_CARRIER_BITS] =
        [0u8; NUM_INNER_H_OUT_CARRIER_BITS];

    for row_index in 0..NUM_REAL_SLIP10_ROWS {
        let role = row_role(row_index).unwrap();
        let step_idx = row_step_index(row_index).unwrap();
        let key_padded = &step_keys[step_idx];
        let input = &inputs[row_index];

        let row_slice =
            &mut values[row_index * NUM_SLIP10_HMAC_COLS..(row_index + 1) * NUM_SLIP10_HMAC_COLS];
        let cols: &mut Slip10HmacCols<F> = row_slice.borrow_mut();

        // key_bits: byte-flat from key_padded.
        for byte_idx in 0..128 {
            let byte_value = key_padded[byte_idx];
            for bit_in_byte in 0..8 {
                let bit_value = ((byte_value >> bit_in_byte) & 1) as u64;
                cols.key_bits[byte_idx * 8 + bit_in_byte] = F::from_u64(bit_value);
            }
        }

        // h_in_packed: 16-bit-limb-low-first per word.
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                let limb_value = (input.h_in_words[word_index] >> (limb_index * 16)) & 0xFFFF;
                cols.h_in_packed[word_index][limb_index] = F::from_u64(limb_value);
            }
        }

        // block_bits: byte-flat from input.block_bytes.
        for byte_idx in 0..128 {
            let byte_value = input.block_bytes[byte_idx];
            for bit_in_byte in 0..8 {
                let bit_value = ((byte_value >> bit_in_byte) & 1) as u64;
                cols.block_bits[byte_idx * 8 + bit_in_byte] = F::from_u64(bit_value);
            }
        }

        // h_out_bits: word-flat (matches Sha512Cols::h_out).
        for word_index in 0..STATE_WORDS {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&input.h_out_bytes[word_index * 8..(word_index + 1) * 8]);
            let word_value = u64::from_be_bytes(word_bytes);
            for bit_in_word in 0..WORD_BITS {
                let bit_value = ((word_value >> bit_in_word) & 1) as u64;
                cols.h_out_bits[word_index][bit_in_word] = F::from_u64(bit_value);
            }
        }

        // inner_h_out_carrier_bits: snapshot at inner row, propagate
        // through opad_pre and outer.
        if role == 1 {
            // inner row: snapshot h_out_bits (word-flat)
            for word_index in 0..STATE_WORDS {
                let mut word_bytes = [0u8; 8];
                word_bytes
                    .copy_from_slice(&input.h_out_bytes[word_index * 8..(word_index + 1) * 8]);
                let word_value = u64::from_be_bytes(word_bytes);
                for bit_in_word in 0..WORD_BITS {
                    inner_h_out_carrier_bits[word_index * WORD_BITS + bit_in_word] =
                        ((word_value >> bit_in_word) & 1) as u8;
                }
            }
        }
        // For all rows, write the current carrier value (the snapshot
        // is updated only at inner; on ipad_pre rows the carrier is
        // whatever was last stored — gated out by selectors in eval).
        for bit_idx in 0..NUM_INNER_H_OUT_CARRIER_BITS {
            cols.inner_h_out_carrier_bits[bit_idx] =
                F::from_u64(inner_h_out_carrier_bits[bit_idx] as u64);
        }

        // account_change_byte_be: only meaningful on step 3 and step 4
        // inner rows, where the constraint binds these committed cells
        // to the block's path-index BE bytes. Source from the
        // already-constructed msg block at offsets 33..37.
        let path_byte_block_offset = NONMASTER_MSG_BYTE_LEN - NUM_PATH_INDEX_BE_BYTES;
        if role == 1 && (step_idx == 3 || step_idx == 4) {
            for byte_offset in 0..NUM_PATH_INDEX_BE_BYTES {
                cols.account_change_byte_be[byte_offset] =
                    F::from_u32(input.block_bytes[path_byte_block_offset + byte_offset] as u32);
            }
        }

        // prev_step_priv_carrier_bits: snapshot at outer→ipad_pre
        // transition (from the outer row's h_out priv portion). Updated
        // AFTER this row's outer: on the outer row itself we still
        // write the OLD prev_priv (from before this step), then at the
        // next ipad_pre row we read the NEW snapshot (the one from
        // this step's outer).
        for bit_idx in 0..NUM_PREV_PRIV_CARRIER_BITS {
            cols.prev_step_priv_carrier_bits[bit_idx] =
                F::from_u64(prev_priv_carrier_bits[bit_idx] as u64);
        }
        if role == 3 {
            // outer row: snapshot priv (= h_out words 0..4) into
            // prev_priv_carrier for the NEXT step's rows.
            for word_index in 0..(NUM_PREV_PRIV_CARRIER_BITS / WORD_BITS) {
                let mut word_bytes = [0u8; 8];
                word_bytes
                    .copy_from_slice(&input.h_out_bytes[word_index * 8..(word_index + 1) * 8]);
                let word_value = u64::from_be_bytes(word_bytes);
                for bit_in_word in 0..WORD_BITS {
                    prev_priv_carrier_bits[word_index * WORD_BITS + bit_in_word] =
                        ((word_value >> bit_in_word) & 1) as u8;
                }
            }
        }
    }

    // Padding rows: just copy row 0 verbatim. The `is_real_row`
    // selector gates them out of the bus.
    for row_index in NUM_REAL_SLIP10_ROWS..SLIP10_TRACE_HEIGHT {
        let (head, tail) = values.split_at_mut(row_index * NUM_SLIP10_HMAC_COLS);
        let row_0_slice = &head[0..NUM_SLIP10_HMAC_COLS];
        tail[0..NUM_SLIP10_HMAC_COLS].copy_from_slice(row_0_slice);
    }

    RowMajorMatrix::new(values, NUM_SLIP10_HMAC_COLS)
}

/// Build the public-value vector callers must pass to `verify_batch`
/// for this AIR's instance: `seed_packed` (16-bit limbs, low-first
/// per word) cross-AIR PV from `Pbkdf2Air`, followed by `purpose'`
/// and `coin_type'` each as 4 big-endian byte cells. The seed slot
/// feeds the master-step inner-block construction; the path-index
/// slots bind steps 1 and 2's HMAC msg path-index bytes.
pub fn public_values_for_instance<F: PrimeField64>(
    seed_packed: &[F],
    purpose_be_bytes: &[F; NUM_PATH_INDEX_BE_BYTES],
    coin_type_be_bytes: &[F; NUM_PATH_INDEX_BE_BYTES],
) -> Vec<F> {
    assert_eq!(seed_packed.len(), NUM_SEED_PACKED_PV_CELLS);
    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    pv.extend_from_slice(seed_packed);
    pv.extend_from_slice(purpose_be_bytes);
    pv.extend_from_slice(coin_type_be_bytes);
    pv
}
