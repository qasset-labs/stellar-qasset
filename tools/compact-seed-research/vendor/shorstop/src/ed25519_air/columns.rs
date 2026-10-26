//! Column layout for the Ed25519 fixed-base scalar-mult AIR.
//!
//! Spec source: `docs/ed25519-spec.md` §3.4 (per-row witness columns),
//! §4 (constraint inventory), §5 (non-native field arithmetic).
//! This is an independent implementation based on the spec — not a port of
//! any reference. Cross-check is reserved for after our tests pass.
//!
//! All structs are `repr(C)` so the slice <-> struct transmutation in
//! `Borrow` / `BorrowMut` is well-defined: every field is an array of `T`,
//! the struct has no padding, and `size_of::<Ed25519Cols<u8>>()` gives the
//! exact scalar column count.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use crate::ed25519_air::constants::NUM_LIMBS;
use crate::ed25519_air::mul_witness::{NUM_LINEAR_CARRY_CELLS, NUM_MUL_CARRY_CELLS};

/// One trace row = one scalar bit processed.
///
/// Layout reflects spec §3.4. Per-row: scalar bit, accumulator coordinates
/// in extended Edwards form, plus mixed-add intermediates and per-mul
/// witnesses.
///
/// **Scaffold note**: this struct currently holds only the high-level
/// shape (scalar bit + accumulator). Mixed-add intermediates and
/// non-native multiplication witnesses will be added as the constraints
/// in `air.rs` are written, one block at a time per the
/// "one-site-then-spread" workflow rule.
#[repr(C)]
pub struct Ed25519Cols<T> {
    /// Scalar bit $s_t \in \{0, 1\}$ processed at this row.
    pub scalar_bit: T,

    /// Running accumulator that builds the byte-level value of the
    /// scalar across 8 consecutive rows. At byte-start row k (k % 8
    /// == 0): `acc = scalar_bit_k`. Within a byte: `acc_{k+1} = acc_k
    /// + 2^{(k+1)%8} · scalar_bit_{k+1}`. At byte-end rows (k % 8 ==
    /// 7): the final `acc` value is pinned to `scalar_packed_PV[k/8]`
    /// via 32 byte-end indicator constraints — this is what binds
    /// the upstream priv (Slip10Air's `priv_packed`) to Ed25519's
    /// scalar.
    pub scalar_byte_accumulator: T,

    /// Running accumulator $X_t$ in extended Edwards coordinates,
    /// 16 × 16-bit little-endian limbs.
    pub accumulator_x: [T; NUM_LIMBS],

    /// Running accumulator $Y_t$.
    pub accumulator_y: [T; NUM_LIMBS],

    /// Running accumulator $Z_t$.
    pub accumulator_z: [T; NUM_LIMBS],

    /// Running accumulator $T_t$, satisfying $T_t \cdot Z_t = X_t \cdot Y_t$.
    pub accumulator_t: [T; NUM_LIMBS],

    /// Conditionally-selected mixed-add right-operand, derived from
    /// `scalar_bit` and the row-$t$ entry of the preprocessed
    /// `[2^t] B` table. Three field elements (each 16 × 16-bit limbs):
    ///
    ///   - `muxed_table_y_minus_x`: $y_R - x_R$ when bit = 1; $1$ when bit = 0
    ///     (identity's $y_\mathcal{O} - x_\mathcal{O} = 1 - 0 = 1$).
    ///   - `muxed_table_y_plus_x`:  $y_R + x_R$ when bit = 1; $1$ when bit = 0.
    ///   - `muxed_table_two_d_xy`:  $2d \cdot x_R \cdot y_R$ when bit = 1; $0$ when bit = 0
    ///     (identity's $x_\mathcal{O} \cdot y_\mathcal{O} = 0$).
    ///
    /// Committed (not preprocessed) because the mux depends on the witness
    /// `scalar_bit`. The mux constraint that binds these to the
    /// preprocessed table will be added in a later block; for now they are
    /// populated by the prover and only range-checked.
    pub muxed_table_y_minus_x: [T; NUM_LIMBS],
    pub muxed_table_y_plus_x: [T; NUM_LIMBS],
    pub muxed_table_two_d_xy: [T; NUM_LIMBS],

    /// $Y - X \pmod p$, fully reduced 16 × 16-bit LE limbs. Pre-mul
    /// operand for HWCD's $A$. Committed as a separate witness so the
    /// non-native multiplication constraint for $A$ has a non-negative
    /// left operand (its quotient witness must be range-checkable as
    /// u16 limbs).
    pub y_minus_x_reduced: [T; NUM_LIMBS],
    /// $Y + X \pmod p$, fully reduced. Pre-mul operand for HWCD's $B$.
    pub y_plus_x_reduced: [T; NUM_LIMBS],

    /// HWCD mixed-addition intermediates ([Hisil-Wong-Carter-Dawson 2008],
    /// "add-2008-hwcd-3" with $a = -1$). Each is one fully-reduced field
    /// element in 16 × 16-bit little-endian limbs. The single-letter
    /// names mirror the paper for direct cross-reference; the
    /// per-equation comments give the longer form.
    ///
    /// Populated by [`crate::ed25519_air::point::MixedAddIntermediates`]
    /// during trace generation. Constraints binding these to the
    /// surrounding columns (mul-with-carry-witness for $A, B, C$;
    /// linear add/sub for $D, E, F, G, H$) are added in subsequent
    /// implementation blocks.
    /// $A = (Y - X) \cdot \text{muxed\_y\_minus\_x} \pmod p$
    pub hwcd_a: [T; NUM_LIMBS],
    /// $B = (Y + X) \cdot \text{muxed\_y\_plus\_x} \pmod p$
    pub hwcd_b: [T; NUM_LIMBS],
    /// $C = T \cdot \text{muxed\_two\_d\_xy} \pmod p$
    pub hwcd_c: [T; NUM_LIMBS],
    /// $D = 2 Z \pmod p$
    pub hwcd_d: [T; NUM_LIMBS],
    /// $E = B - A \pmod p$
    pub hwcd_e: [T; NUM_LIMBS],
    /// $F = D - C \pmod p$
    pub hwcd_f: [T; NUM_LIMBS],
    /// $G = D + C \pmod p$
    pub hwcd_g: [T; NUM_LIMBS],
    /// $H = B + A \pmod p$
    pub hwcd_h: [T; NUM_LIMBS],

    /// Witness columns for the non-native multiplication
    /// $A = (Y - X) \cdot \text{muxed\_y\_minus\_x} \pmod p$. The
    /// AIR proves this via the integer identity
    /// `(Y-X) · muxed - q · p - hwcd_a = 0` per limb-position with
    /// carry propagation (see [`crate::ed25519_air::mul_witness`]).
    ///
    /// `mul_a_quotient` holds $q = \lfloor (Y-X) \cdot \text{muxed} / p \rfloor$
    /// in 16 × 16-bit LE limbs. `mul_a_carry` holds the 30 per-position
    /// carry cells $c_0, \ldots, c_{29}$.
    pub mul_a_quotient: [T; NUM_LIMBS],
    pub mul_a_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Witness for $B = (Y + X) \cdot \text{muxed\_y\_plus\_x} \pmod p$.
    pub mul_b_quotient: [T; NUM_LIMBS],
    pub mul_b_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Witness for $C = T \cdot \text{muxed\_two\_d\_xy} \pmod p$.
    pub mul_c_quotient: [T; NUM_LIMBS],
    pub mul_c_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Witness for output mul $X' = E \cdot F \pmod p$. Result binds to
    /// `next_row.accumulator_x` via the transition constraint.
    pub mul_xprime_quotient: [T; NUM_LIMBS],
    pub mul_xprime_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Witness for output mul $Y' = G \cdot H \pmod p$. Binds to
    /// `next_row.accumulator_y`.
    pub mul_yprime_quotient: [T; NUM_LIMBS],
    pub mul_yprime_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Witness for output mul $Z' = F \cdot G \pmod p$. Binds to
    /// `next_row.accumulator_z`.
    pub mul_zprime_quotient: [T; NUM_LIMBS],
    pub mul_zprime_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Witness for output mul $T' = E \cdot H \pmod p$. Binds to
    /// `next_row.accumulator_t`.
    pub mul_tprime_quotient: [T; NUM_LIMBS],
    pub mul_tprime_carry: [T; NUM_MUL_CARRY_CELLS],

    /// Linear-modular reduction-flag and per-limb carries for the seven
    /// add/sub/double operations that close the HWCD chain. Each
    /// operation commits one boolean `reduction_flag` ($\sigma$ in the
    /// integer identity) plus 15 signed carry cells (positions $0..14$;
    /// position 15 closes with no outflow).
    ///
    /// Order matches the definitions in
    /// [`crate::ed25519_air::point::MixedAddIntermediates`].
    pub linear_y_minus_x_reduction_flag: T,
    pub linear_y_minus_x_carry: [T; NUM_LINEAR_CARRY_CELLS],
    pub linear_y_plus_x_reduction_flag: T,
    pub linear_y_plus_x_carry: [T; NUM_LINEAR_CARRY_CELLS],
    pub linear_d_reduction_flag: T,
    pub linear_d_carry: [T; NUM_LINEAR_CARRY_CELLS],
    pub linear_e_reduction_flag: T,
    pub linear_e_carry: [T; NUM_LINEAR_CARRY_CELLS],
    pub linear_f_reduction_flag: T,
    pub linear_f_carry: [T; NUM_LINEAR_CARRY_CELLS],
    pub linear_g_reduction_flag: T,
    pub linear_g_carry: [T; NUM_LINEAR_CARRY_CELLS],
    pub linear_h_reduction_flag: T,
    pub linear_h_carry: [T; NUM_LINEAR_CARRY_CELLS],
}

/// Total scalar column count per row. Computed from the byte size of
/// `Ed25519Cols<u8>` so it stays in sync with the struct definition above.
pub const NUM_ED25519_COLS: usize = size_of::<Ed25519Cols<u8>>();

/// Preprocessed (fixed) columns. These are derived deterministically from
/// the AIR struct (no witness input) and committed to as part of the
/// verifying key. Both prover and verifier reconstruct the same table by
/// calling `preprocessed_trace()` on `Ed25519Air`.
///
/// Currently holds only the scalar-clamping selectors:
///
///   - `is_clamped` is 1 on rows {0, 1, 2, 254, 255} where the scalar bit
///     is forced by RFC 8032 clamping; 0 elsewhere.
///   - `clamp_value` is the value the scalar bit must take on rows where
///     `is_clamped = 1`. It is 0 on rows {0, 1, 2, 255} and 1 on row 254.
///     On rows where `is_clamped = 0`, it is also 0 (don't-care).
///
/// Constraint shape (one constraint, every row):
///
/// ```text
///   is_clamped · (scalar_bit − clamp_value) = 0
/// ```
///
/// Future preprocessed columns (planned blocks) will append the
/// $[2^t] B$ table — see `docs/ed25519-spec.md` §3.5.
#[repr(C)]
pub struct Ed25519PreprocessedCols<T> {
    pub is_clamped: T,
    pub clamp_value: T,

    /// Indicator column with value `1` at row `LAST_ROW_INDEX` and `0`
    /// elsewhere. Used as the LogUp `numerator` for the public-value
    /// range-check sends so they fire **exactly once per proof** (on
    /// the last row), not once per row. Without this gating, range-
    /// checking 64 public-value cells at every row would add ~16 k
    /// extraneous events to the `u16_range` bus.
    pub is_public_value_send_row: T,

    /// Row-$t$ entry of the fixed precomputed table $R_t = [2^t] B$,
    /// in the three derived components used by HWCD mixed addition:
    ///
    ///   - `precomputed_y_minus_x`: $y_{R_t} - x_{R_t} \pmod p$
    ///   - `precomputed_y_plus_x`:  $y_{R_t} + x_{R_t} \pmod p$
    ///   - `precomputed_two_d_xy`:  $2 d \cdot x_{R_t} \cdot y_{R_t} \pmod p$
    ///
    /// Each is `NUM_LIMBS` × `LIMB_BITS`-bit little-endian limbs. Source
    /// of truth:
    /// [`crate::ed25519_air::precomputed_base_multiples::PRECOMPUTED_BASE_MULTIPLES`].
    pub precomputed_y_minus_x: [T; NUM_LIMBS],
    pub precomputed_y_plus_x: [T; NUM_LIMBS],
    pub precomputed_two_d_xy: [T; NUM_LIMBS],

    /// `2^{row_index % 8}` — the bit-position weight inside the
    /// current byte. Cycles `1, 2, 4, 8, 16, 32, 64, 128`. Used by
    /// the `scalar_byte_accumulator` transition.
    pub bit_weight_in_byte: T,
    /// 1 on rows where `row_index % 8 == 0` (rows 0, 8, 16, …, 248).
    /// Gates the byte-start case of the accumulator constraint.
    pub is_byte_start: T,
    /// 32 indicators, one per byte. `is_byte_end_for_byte[i] = 1`
    /// only on row `8 * i + 7` (rows 7, 15, …, 255). Gates the
    /// byte-end PV-equality constraint that binds the accumulator
    /// to `scalar_packed_PV[i]`.
    pub is_byte_end_for_byte: [T; NUM_LIMBS],
}

/// Total preprocessed-column count per row.
pub const NUM_ED25519_PREPROCESSED_COLS: usize = size_of::<Ed25519PreprocessedCols<u8>>();

impl<T> Borrow<Ed25519PreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Ed25519PreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_ED25519_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<Ed25519PreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Ed25519PreprocessedCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Ed25519PreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_ED25519_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<Ed25519PreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<T> Borrow<Ed25519Cols<T>> for [T] {
    fn borrow(&self) -> &Ed25519Cols<T> {
        debug_assert_eq!(self.len(), NUM_ED25519_COLS);
        // Safety: `Ed25519Cols` is `repr(C)` and contains only `T` arrays;
        // its layout is a flat sequence of `NUM_ED25519_COLS` columns.
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Ed25519Cols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Ed25519Cols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Ed25519Cols<T> {
        debug_assert_eq!(self.len(), NUM_ED25519_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Ed25519Cols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
