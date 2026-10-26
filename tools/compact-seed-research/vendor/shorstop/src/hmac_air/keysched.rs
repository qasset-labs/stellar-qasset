//! `HmacKeyschedAir` — one-time pre-compute of HMAC-SHA512's
//! `ipad_state` and `opad_state` (spec `docs/pipeline-spec.md` §6.3.1).
//!
//! HMAC's structure is
//!
//!   HMAC(K, m) = SHA512((K' ⊕ opad) || SHA512((K' ⊕ ipad) || m))
//!
//! The first SHA-512 compression of each leg is fully determined by the
//! key (`SHA512(IV, K' ⊕ ipad)` and `SHA512(IV, K' ⊕ opad)`). When the
//! same key is reused many times — PBKDF2's 2048 iterations — these
//! two states are computed once here and **passed as public values**
//! to `Pbkdf2HmacAir`, which then performs only one compression per
//! HMAC iteration instead of three.
//!
//! Trace shape (`KEYSCHED_TRACE_HEIGHT` = 4 rows):
//!
//!   row 0: ipad-pre — `h_in = IV`, `block = K' ⊕ ipad`, `h_out = ipad_state`
//!   row 1: opad-pre — `h_in = IV`, `block = K' ⊕ opad`, `h_out = opad_state`
//!   rows 2-3: padding (mirror rows 0/1, gated out of the bus by
//!             `is_real_row = 0`)
//!
//! Per-row committed columns (~1568 cells; `block_bits` are inline
//! polynomial expressions, not committed — §6.2 column-commitment
//! principle):
//!
//!   - `key_bits`:    1024 bits of `K_padded`, **byte-flat** layout
//!     (`key_bits[byte_idx * 8 + bit_in_byte]`, LSB-first within byte).
//!     Transition-constrained equal across rows (one key per proof).
//!   - `h_in_packed`: 32 × 16-bit limbs, constrained equal to `SHA512_IV`.
//!   - `h_out_bits`:  512 bits in **word-flat** layout matching
//!     `Sha512Cols::h_out`.
//!
//! Per-row preprocessed columns:
//!
//!   - `role`:        0 on ipad-pre rows, 1 on opad-pre rows.
//!   - `is_real_row`: 1 on real rows, 0 on padding (gates LogUp mult).
//!
//! Public values (64 = 32 + 32): `[ipad_state_packed, opad_state_packed]`,
//! both as 16-bit-limbs-low-first. Consumed by `Pbkdf2HmacAir` and
//! `Slip10HmacAir` as PV inputs.
//!
//! ### LogUp on `sha512_compressions`
//!
//! Each real row receives one `(h_in, block, h_out)` tuple from the
//! SHA-512 AIR via the global `sha512_compressions` bus. The block bits
//! are inline-derived from the row's `key_bits` XOR'd with the
//! role-appropriate pad pattern. To keep the constraint at low degree,
//! we register **two separate Lookups** (one per pad), each gated by a
//! degree-1 multiplicity selector — see degree analysis on
//! [`HmacKeyschedAir::get_lookups`].

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::constants::{IPAD_BYTE, OPAD_BYTE};
use crate::hmac_air::helpers::{
    compression_tuple, eval_state_packed_equals_h_out_bits,
    inline_block_bits_for_ipad_or_opad, BLOCK_BIT_COUNT_BYTE_FLAT, BLOCK_BIT_COUNT_WORD_FLAT,
    H_IN_LIMB_COUNT, H_OUT_BIT_COUNT,
};
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::constants::{
    BITS_PER_LIMB, SHA512_COMPRESSIONS_BUS_NAME, SHA512_IV, STATE_WORDS, U64_LIMBS, WORD_BITS,
};
use crate::sha512_air::generation::{fill_row_u64, h_out_bytes_be};

// ── Trace shape constants ──────────────────────────────────────────────

/// Number of `(h_in, block, h_out)` compressions the keyschedule
/// pre-computes: one for ipad, one for opad.
pub const NUM_REAL_KEYSCHED_ROWS: usize = 2;

/// Trace height: padded to the next power of two. With `NUM_REAL_KEYSCHED_ROWS
/// = 2` this is already a power of two, so the trace has exactly 2 rows
/// (no padding tail). Spec §6.3.1's "2 real + 2 padding" was conservative;
/// FRI's minimum-height constraint is satisfied at height 2 already.
pub const KEYSCHED_TRACE_HEIGHT: usize = NUM_REAL_KEYSCHED_ROWS.next_power_of_two();

/// Total public-value count exposed by the AIR:
/// `ipad_state_packed` (`H_IN_LIMB_COUNT` = 32) + `opad_state_packed` (32)
/// = 64. Indexed `[0..32]` for ipad, `[32..64]` for opad.
pub const NUM_PUBLIC_VALUES: usize = H_IN_LIMB_COUNT * 2;

/// Public-value index range for `ipad_state_packed`.
pub const IPAD_PV_OFFSET: usize = 0;
/// Public-value index range for `opad_state_packed`.
pub const OPAD_PV_OFFSET: usize = H_IN_LIMB_COUNT;

/// Role tag stored in the preprocessed `role` column.
pub const ROLE_IPAD: u32 = 0;
/// Role tag stored in the preprocessed `role` column.
pub const ROLE_OPAD: u32 = 1;

// ── Main-trace columns ────────────────────────────────────────────────

/// Per-row committed columns. `repr(C)` so the slice ↔ struct
/// transmutation in `Borrow` / `BorrowMut` is well-defined (every field
/// is an array of `T` of identical alignment).
#[repr(C)]
pub struct HmacKeyschedCols<T> {
    /// `K_padded` bit-decomposed in **byte-flat** layout
    /// (`key_bits[byte * 8 + bit_in_byte]`, LSB-first within byte).
    /// Same on every row — pinned by transition constraints.
    pub key_bits: [T; BLOCK_BIT_COUNT_BYTE_FLAT],

    /// SHA-512 input chaining state, 16-bit-limb-packed (low-first).
    /// Constrained equal to `SHA512_IV` on every row.
    pub h_in_packed: [[T; U64_LIMBS]; STATE_WORDS],

    /// SHA-512 output chaining state, **word-flat** bit layout matching
    /// `Sha512Cols::h_out` (`h_out_bits[word][bit_in_word]`, LSB-first
    /// within each 64-bit word). On row 0 = `ipad_state` bits, on row 1
    /// = `opad_state` bits. Bound to public values via
    /// `eval_state_packed_equals_h_out_bits`.
    pub h_out_bits: [[T; WORD_BITS]; STATE_WORDS],
}

/// Total committed-column count. Computed from `size_of` so it stays in
/// lockstep with the struct above.
pub const NUM_HMAC_KEYSCHED_COLS: usize = size_of::<HmacKeyschedCols<u8>>();

impl<T> Borrow<HmacKeyschedCols<T>> for [T] {
    fn borrow(&self) -> &HmacKeyschedCols<T> {
        debug_assert_eq!(self.len(), NUM_HMAC_KEYSCHED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<HmacKeyschedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<HmacKeyschedCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut HmacKeyschedCols<T> {
        debug_assert_eq!(self.len(), NUM_HMAC_KEYSCHED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<HmacKeyschedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// ── Preprocessed-trace columns ─────────────────────────────────────────

#[repr(C)]
pub struct HmacKeyschedPreprocessedCols<T> {
    /// `ROLE_IPAD` (= 0) on ipad-pre rows, `ROLE_OPAD` (= 1) on
    /// opad-pre rows.
    pub role: T,
    /// 1 on real compression rows, 0 on padding rows. Gates the LogUp
    /// receive multiplicity so padding rows do not appear on the bus.
    pub is_real_row: T,
}

pub const NUM_HMAC_KEYSCHED_PREPROCESSED_COLS: usize =
    size_of::<HmacKeyschedPreprocessedCols<u8>>();

impl<T> Borrow<HmacKeyschedPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &HmacKeyschedPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_HMAC_KEYSCHED_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<HmacKeyschedPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// ── The AIR ────────────────────────────────────────────────────────────

/// Marker AIR for the HMAC-SHA512 keyschedule. Stateful (`num_lookups`)
/// because [`LookupAir::add_lookup_columns`] mutates per-call to
/// allocate fresh permutation-trace column indices.
#[derive(Clone, Default)]
pub struct HmacKeyschedAir {
    num_lookups: usize,
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for HmacKeyschedAir {
    fn width(&self) -> usize {
        NUM_HMAC_KEYSCHED_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // `Air::eval` constraints are degree ≤ 2 (the role-gated PV
        // binding is `is_real · ((1-role) · ipad_diff + role · opad_diff)`,
        // deg ≤ 1+1+1 = 3 if all factors are deg-1 committed; with
        // role/is_real preprocessed → deg 2). LogUp transition is
        // deg 2 with the two-Lookup, fixed-pad scheme (see
        // `get_lookups`). Cap at 3 for safety.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        // 2-row table aligned with the main trace:
        //   row 0: [role=IPAD, is_real=1]
        //   row 1: [role=OPAD, is_real=1]
        // `is_real_row` is constant 1 for the v1 short-key path (no
        // padding tail). Kept as a column so future extensions
        // (long-key §1.1, batched HMAC variants) can introduce padding
        // without changing the AIR's preprocessed schema.
        let mut values =
            vec![F::ZERO; KEYSCHED_TRACE_HEIGHT * NUM_HMAC_KEYSCHED_PREPROCESSED_COLS];
        values[0] = F::from_u32(ROLE_IPAD);
        values[1] = F::ONE;
        values[2] = F::from_u32(ROLE_OPAD);
        values[3] = F::ONE;
        Some(RowMajorMatrix::new(
            values,
            NUM_HMAC_KEYSCHED_PREPROCESSED_COLS,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for HmacKeyschedAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot pattern (matches `Ed25519Air::eval`): clone the
        // owned/borrowed views off `builder` so subsequent `&mut`
        // calls (`assert_*`, `when_transition`) don't conflict with
        // the immutable borrows. `MainWindow: Clone` and
        // `PreprocessedWindow: Clone` are cheap (slice wrappers); the
        // public-value snapshot uses `Copy` cells.
        let main_window = builder.main();
        let local: &HmacKeyschedCols<AB::Var> = (*main_window.current_slice()).borrow();
        let next: &HmacKeyschedCols<AB::Var> = (*main_window.next_slice()).borrow();
        let preprocessed_window = builder.preprocessed().clone();
        let preprocessed_local: &HmacKeyschedPreprocessedCols<AB::Var> =
            (*preprocessed_window.current_slice()).borrow();

        let role_var = preprocessed_local.role;
        let is_real_var = preprocessed_local.is_real_row;
        let h_out_bits_local = local.h_out_bits;
        let h_in_packed_local = local.h_in_packed;
        let key_bits_local = local.key_bits;
        let key_bits_next = next.key_bits;

        let public_values_snapshot: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public_values = builder.public_values();
            debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);
            let mut snapshot = [public_values[0]; NUM_PUBLIC_VALUES];
            for index in 0..NUM_PUBLIC_VALUES {
                snapshot[index] = public_values[index];
            }
            snapshot
        };

        // 1. Boolean range checks on primitive bit columns.
        for &bit in key_bits_local.iter() {
            builder.assert_bool(bit);
        }
        for word in h_out_bits_local.iter() {
            for &bit in word.iter() {
                builder.assert_bool(bit);
            }
        }

        // 2. h_in_packed = SHA512_IV (per-limb constant equality).
        for word_index in 0..STATE_WORDS {
            let iv_word = SHA512_IV[word_index];
            for limb_index in 0..U64_LIMBS {
                let iv_limb = (iv_word >> (limb_index * BITS_PER_LIMB)) & 0xFFFF;
                let cell: AB::Expr = h_in_packed_local[word_index][limb_index].into();
                builder.assert_zero(cell - AB::Expr::from_u64(iv_limb));
            }
        }

        // 3. Transition: `key_bits` is identical across every adjacent
        // row pair. The key is a single proof-wide value; role / is_real
        // distinguish rows semantically. Padding rows mirror the real
        // key (per the trace generator), so this constraint is satisfied
        // tautologically on padding too.
        let mut when_trans = builder.when_transition();
        for bit_index in 0..BLOCK_BIT_COUNT_BYTE_FLAT {
            when_trans.assert_eq(key_bits_local[bit_index], key_bits_next[bit_index]);
        }

        // 4. Public-value binding, role-gated:
        //   is_real · [(1 - role) · (packed - ipad_pv)
        //            + role       · (packed - opad_pv)] = 0
        // On row 0 (ipad-pre, role=0, is_real=1): asserts packed = ipad_pv.
        // On row 1 (opad-pre, role=1, is_real=1): asserts packed = opad_pv.
        // On padding (is_real=0): tautological zero, no binding.
        //
        // Degree: role / is_real are preprocessed (deg 1), `packed` is
        // deg 1 in committed h_out_bits, PVs are deg 1. Branch product
        // is deg 2; outer `is_real ·` makes deg 3 — at the cap.
        let role_expr: AB::Expr = role_var.into();
        let one_minus_role_expr: AB::Expr = AB::Expr::ONE - role_expr.clone();
        let is_real_expr: AB::Expr = is_real_var.into();

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
                let pv_index = word_index * U64_LIMBS + limb_index;
                let ipad_pv: AB::Expr =
                    public_values_snapshot[IPAD_PV_OFFSET + pv_index].into();
                let opad_pv: AB::Expr =
                    public_values_snapshot[OPAD_PV_OFFSET + pv_index].into();

                let ipad_diff = packed.clone() - ipad_pv;
                let opad_diff = packed - opad_pv;
                let combined =
                    one_minus_role_expr.clone() * ipad_diff + role_expr.clone() * opad_diff;
                builder.assert_zero(is_real_expr.clone() * combined);
            }
        }

        // The `eval_state_packed_equals_h_out_bits` helper is reserved
        // for AIRs that need to bind a row's `h_in_packed` to an
        // upstream PV (e.g. `Pbkdf2HmacAir` reading `ipad_state_packed`
        // from this AIR). Here `h_in = SHA512_IV` is constrained
        // directly above — the helper is unused but kept available
        // for downstream phases.
        let _unused_helper_marker = eval_state_packed_equals_h_out_bits::<AB>;
    }
}

impl<F: Field> LookupAir<F> for HmacKeyschedAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        // Build symbolic references to the main and preprocessed traces.
        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_HMAC_KEYSCHED_COLS,
            preprocessed_width: NUM_HMAC_KEYSCHED_PREPROCESSED_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &HmacKeyschedCols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &HmacKeyschedPreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();

        // Common reusable expressions over the row's committed cells.
        let mut h_in_limbs: Vec<SymbolicExpression<F>> = Vec::with_capacity(H_IN_LIMB_COUNT);
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                h_in_limbs.push(main_local.h_in_packed[word_index][limb_index].into());
            }
        }
        let mut h_out_bits: Vec<SymbolicExpression<F>> = Vec::with_capacity(H_OUT_BIT_COUNT);
        for word_index in 0..STATE_WORDS {
            for bit_index in 0..WORD_BITS {
                h_out_bits.push(main_local.h_out_bits[word_index][bit_index].into());
            }
        }

        // Two separate Lookups, one per pad. Each uses a fixed pad_byte
        // for `block_bits`, so the inline expressions stay degree 1 in
        // committed cells. Multiplicity gates the active row:
        //   ipad receive: mult = is_real_row * (1 - role)  (deg 2)
        //   opad receive: mult = is_real_row * role        (deg 2)
        //
        // Constraint degree per Lookup: (s_next - s_local) * (α - cmb) - num
        //   = deg 1 * deg 1 - deg 2 = deg 2.  Within budget.
        //
        // Aggregating role-switching into a single Lookup with mixed
        // block_bits would push combined_elt to degree 2 (role × bit),
        // making (s_next - s_local) * (α - cmb) hit degree 3 — at the
        // cap with no headroom. Splitting trades one extra permutation
        // column for cleaner asymptotics.
        let role: SymbolicExpression<F> = preprocessed_local.role.into();
        let one_minus_role: SymbolicExpression<F> =
            SymbolicExpression::from(F::ONE) - role.clone();
        let is_real_row: SymbolicExpression<F> = preprocessed_local.is_real_row.into();

        let key_bits_slice = &main_local.key_bits[..];

        let ipad_block_bits = inline_block_bits_for_ipad_or_opad::<SymbolicAirBuilder<F>>(
            key_bits_slice,
            IPAD_BYTE,
        );
        let opad_block_bits = inline_block_bits_for_ipad_or_opad::<SymbolicAirBuilder<F>>(
            key_bits_slice,
            OPAD_BYTE,
        );
        debug_assert_eq!(ipad_block_bits.len(), BLOCK_BIT_COUNT_WORD_FLAT);
        debug_assert_eq!(opad_block_bits.len(), BLOCK_BIT_COUNT_WORD_FLAT);

        let ipad_tuple =
            compression_tuple::<F>(&h_in_limbs, &ipad_block_bits, &h_out_bits);
        let opad_tuple =
            compression_tuple::<F>(&h_in_limbs, &opad_block_bits, &h_out_bits);

        let ipad_mult = is_real_row.clone() * one_minus_role;
        let opad_mult = is_real_row * role;

        let mut lookups: Vec<Lookup<F>> = Vec::with_capacity(2);
        let ipad_inputs = [(ipad_tuple, ipad_mult, Direction::Receive)];
        lookups.push(LookupAir::register_lookup(
            self,
            Kind::Global(SHA512_COMPRESSIONS_BUS_NAME.to_string()),
            &ipad_inputs,
        ));
        let opad_inputs = [(opad_tuple, opad_mult, Direction::Receive)];
        lookups.push(LookupAir::register_lookup(
            self,
            Kind::Global(SHA512_COMPRESSIONS_BUS_NAME.to_string()),
            &opad_inputs,
        ));
        lookups
    }
}

// ── Trace generation ──────────────────────────────────────────────────

/// Aggregate output from running the HMAC keyschedule off-circuit:
/// the trace, plus the two state vectors that become the AIR's public
/// values.
pub struct KeyschedWitness<F: PrimeCharacteristicRing + Clone> {
    /// Main trace, sized `KEYSCHED_TRACE_HEIGHT × NUM_HMAC_KEYSCHED_COLS`.
    pub trace: RowMajorMatrix<F>,
    /// `ipad_state` as the 32 × 16-bit-limb public-value vector. `[0..32]`
    /// of the AIR's public values; `Pbkdf2HmacAir` reads these as PV
    /// inputs.
    pub ipad_state_packed: [F; H_IN_LIMB_COUNT],
    /// `opad_state` as the 32 × 16-bit-limb public-value vector
    /// (`[32..64]` of the AIR's public values).
    pub opad_state_packed: [F; H_IN_LIMB_COUNT],
}

/// Run the off-circuit keyschedule for a key `key` of any length up to
/// 128 bytes (see `pipeline-spec.md` §1.1 for the long-key extension).
/// Returns the trace + the 64-cell public-value vector.
///
/// This function pads `key` to 128 bytes with trailing zeros (the
/// short-key path) and runs one SHA-512 compression each for ipad and
/// opad to produce `ipad_state` and `opad_state`.
pub fn generate_keysched_witness<F>(key: &[u8]) -> KeyschedWitness<F>
where
    F: p3_field::PrimeField64,
{
    assert!(
        key.len() <= 128,
        "long-key path (>128 bytes) not yet implemented; spec §1.1"
    );

    // Build K_padded = key || 0^(128-key.len()).
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);

    // Compute ipad_block, opad_block as bytes.
    let mut ipad_block = [0u8; 128];
    let mut opad_block = [0u8; 128];
    for i in 0..128 {
        ipad_block[i] = key_padded[i] ^ IPAD_BYTE;
        opad_block[i] = key_padded[i] ^ OPAD_BYTE;
    }

    // Convert each to 16 × big-endian u64 words for the SHA-512 input.
    let ipad_words = bytes_to_be_u64_block(&ipad_block);
    let opad_words = bytes_to_be_u64_block(&opad_block);

    // Compute the resulting compression states off-circuit using the
    // existing SHA-512 reference path: `fill_row` populates a row with
    // the witness and we extract `h_out` via `h_out_bytes_be`.
    let mut sha_row = vec![0u64; NUM_SHA512_COLS];
    fill_row_u64(SHA512_IV, ipad_words, &mut sha_row);
    let ipad_digest_bytes = h_out_bytes_be(&sha_row);
    let ipad_state_words = be_bytes_to_u64_state(&ipad_digest_bytes);

    fill_row_u64(SHA512_IV, opad_words, &mut sha_row);
    let opad_digest_bytes = h_out_bytes_be(&sha_row);
    let opad_state_words = be_bytes_to_u64_state(&opad_digest_bytes);

    // Build the main trace: KEYSCHED_TRACE_HEIGHT (= 2) rows.
    let mut trace_values = vec![F::ZERO; KEYSCHED_TRACE_HEIGHT * NUM_HMAC_KEYSCHED_COLS];

    // Row 0 (ipad-pre): h_out = ipad_state.
    fill_keysched_row::<F>(
        &mut trace_values[0..NUM_HMAC_KEYSCHED_COLS],
        &key_padded,
        ipad_state_words,
    );
    // Row 1 (opad-pre): h_out = opad_state.
    fill_keysched_row::<F>(
        &mut trace_values[NUM_HMAC_KEYSCHED_COLS..2 * NUM_HMAC_KEYSCHED_COLS],
        &key_padded,
        opad_state_words,
    );

    // Pack ipad_state / opad_state as 16-bit-limbs-low-first vectors
    // (the AIR's PV layout matches `Sha512Cols::h_in`'s low-first form).
    let mut ipad_state_packed = [F::ZERO; H_IN_LIMB_COUNT];
    let mut opad_state_packed = [F::ZERO; H_IN_LIMB_COUNT];
    for word_index in 0..STATE_WORDS {
        for limb_index in 0..U64_LIMBS {
            let ipad_limb = (ipad_state_words[word_index] >> (limb_index * BITS_PER_LIMB)) & 0xFFFF;
            let opad_limb = (opad_state_words[word_index] >> (limb_index * BITS_PER_LIMB)) & 0xFFFF;
            ipad_state_packed[word_index * U64_LIMBS + limb_index] = F::from_u64(ipad_limb);
            opad_state_packed[word_index * U64_LIMBS + limb_index] = F::from_u64(opad_limb);
        }
    }

    KeyschedWitness {
        trace: RowMajorMatrix::new(trace_values, NUM_HMAC_KEYSCHED_COLS),
        ipad_state_packed,
        opad_state_packed,
    }
}

/// Fill one row's main-trace cells from a 128-byte K_padded and an
/// 8-word `h_out` state. `h_in_packed` is set to `SHA512_IV` (the
/// `Air::eval` constraint enforces this — the trace must reflect it
/// for the constraint to pass).
fn fill_keysched_row<F: p3_field::PrimeField64>(
    row_slice: &mut [F],
    key_padded: &[u8; 128],
    h_out_state: [u64; STATE_WORDS],
) {
    let cols: &mut HmacKeyschedCols<F> = row_slice.borrow_mut();

    // key_bits in byte-flat layout (LSB-first within each byte).
    for byte_index in 0..128 {
        let byte_value = key_padded[byte_index];
        for bit_in_byte in 0..8 {
            let bit_value = (byte_value >> bit_in_byte) & 1;
            cols.key_bits[byte_index * 8 + bit_in_byte] = F::from_u64(bit_value as u64);
        }
    }

    // h_in_packed = SHA512_IV (16-bit-limbs-low-first per word).
    for word_index in 0..STATE_WORDS {
        for limb_index in 0..U64_LIMBS {
            let limb_value = (SHA512_IV[word_index] >> (limb_index * BITS_PER_LIMB)) & 0xFFFF;
            cols.h_in_packed[word_index][limb_index] = F::from_u64(limb_value);
        }
    }

    // h_out_bits in word-flat layout (LSB-first within each 64-bit word).
    for word_index in 0..STATE_WORDS {
        let word_value = h_out_state[word_index];
        for bit_in_word in 0..WORD_BITS {
            let bit_value = (word_value >> bit_in_word) & 1;
            cols.h_out_bits[word_index][bit_in_word] = F::from_u64(bit_value);
        }
    }
}

fn bytes_to_be_u64_block(bytes: &[u8; 128]) -> [u64; 16] {
    let mut block = [0u64; 16];
    for word_index in 0..16 {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&bytes[word_index * 8..(word_index + 1) * 8]);
        block[word_index] = u64::from_be_bytes(word_bytes);
    }
    block
}

fn be_bytes_to_u64_state(bytes: &[u8; 64]) -> [u64; STATE_WORDS] {
    let mut state = [0u64; STATE_WORDS];
    for word_index in 0..STATE_WORDS {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&bytes[word_index * 8..(word_index + 1) * 8]);
        state[word_index] = u64::from_be_bytes(word_bytes);
    }
    state
}

/// Public-value vector built from the keyschedule witness, in the
/// `[ipad_state_packed (32) || opad_state_packed (32)]` order the AIR
/// expects.
pub fn public_values<F: PrimeCharacteristicRing + Clone>(
    witness: &KeyschedWitness<F>,
) -> Vec<F> {
    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    pv.extend_from_slice(&witness.ipad_state_packed);
    pv.extend_from_slice(&witness.opad_state_packed);
    pv
}
