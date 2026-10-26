//! AIR constraints for Ed25519 fixed-base scalar multiplication.
//!
//! Independent implementation from `docs/ed25519-spec.md`:
//!   - §3.3 (trace shape: 256 rows, transition constraints)
//!   - §4 (constraint inventory: clamping, accumulator transition, mixed-add
//!     intermediates, output coordinates, range checks, boundary)
//!   - §5 (non-native field arithmetic: schoolbook + per-digit carry)
//!
//! Cross-check is reserved for `docs/ed25519-reference-comparison.md` after
//! our tests pass.
//!
//! **Implementation status (this commit)**: only the minimal-slice
//! constraints are wired:
//!
//!   - Boolean constraint on the scalar bit, every row.
//!   - Row-0 boundary: accumulator $(X, Y, Z, T) = (0, 1, 1, 0)$.
//!
//! Subsequent commits add:
//!
//!   - Limb range checks (Logup against the 16-bit table shared with SHA-512).
//!   - Mixed-add intermediates: $A' = (Y - X)(y_R - x_R)$ etc.
//!   - Accumulator transition with the conditional-operand mux.
//!   - Row-256 boundary: public-input binding to $A = [s] B$.
//!   - Scalar clamping at boundary rows (bits 0, 1, 2 = 0; bit 254 = 1; bit 255 = 0).
//!   - Closure invariant $T \cdot Z = X \cdot Y$ (frequency TBD).

use core::borrow::Borrow;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use core::borrow::BorrowMut;

use crate::ed25519_air::columns::{
    Ed25519Cols, Ed25519PreprocessedCols, NUM_ED25519_COLS, NUM_ED25519_PREPROCESSED_COLS,
};
use crate::ed25519_air::constants::{
    CLAMP_HIGH_ONE_BIT_POS, CLAMP_HIGH_ZERO_BIT_POS, CLAMP_LOW_ZERO_BITS_POS, LAST_ROW_INDEX,
    LIMB_BASE, LINEAR_CARRY_OFFSET, MUL_CARRY_OFFSET, NUM_LIMBS, NUM_ROWS_PER_SCALAR_MUL,
    PRIME_LIMBS,
};
use crate::ed25519_air::mul_witness::{
    NUM_LINEAR_CARRY_CELLS, NUM_MUL_CARRY_CELLS, NUM_PRODUCT_POSITIONS,
};
use crate::ed25519_air::precomputed_base_multiples::PRECOMPUTED_BASE_MULTIPLES;
use crate::range_check_u16_air::constants::BUS_NAME as U16_RANGE_BUS_NAME;

/// Per-family toggle mask used by the spec §6.5 constraint-removal
/// sweep ([`crate::ed25519_air::coverage_tests`]). Each field gates
/// one `evaluate_*` call in [`Ed25519Air::eval`]: `true` ⇒ the
/// constraint family fires, `false` ⇒ it is silently skipped.
///
/// The default is **all-enabled**; production use never constructs a
/// non-default mask. Tests construct partial masks to verify that
/// disabling each family individually causes at least one
/// witness-mutation test to slip through (i.e., the family is
/// load-bearing).
#[derive(Clone, Copy, Debug)]
pub struct ConstraintMask {
    pub scalar_bit_boolean: bool,
    pub initial_accumulator_boundary: bool,
    pub scalar_clamping: bool,
    pub table_entry_mux: bool,
    pub mul_a: bool,
    pub mul_b: bool,
    pub mul_c: bool,
    pub output_mul_transitions: bool,
    pub linear_modular_chain: bool,
    pub output_mul_last_row_boundary: bool,
    /// Phase 5 scalar-byte-accumulator family: binds per-row
    /// `scalar_bit` cells to the `scalar_packed` PV input. Catches
    /// any scalar-bit mutation that doesn't simultaneously fix the
    /// byte accumulator + PV. Provides defense-in-depth against
    /// scalar mutations that the older `scalar_clamping` /
    /// `table_entry_mux` families also catch (the redundancy is
    /// intentional: the byte accumulator is the canonical anchor for
    /// the upstream mnemonic-to-priv chain).
    pub scalar_byte_accumulator: bool,
}

impl ConstraintMask {
    /// All families enabled — the production / honest-prover mask.
    pub const ALL_ENABLED: Self = Self {
        scalar_bit_boolean: true,
        initial_accumulator_boundary: true,
        scalar_clamping: true,
        table_entry_mux: true,
        mul_a: true,
        mul_b: true,
        mul_c: true,
        output_mul_transitions: true,
        linear_modular_chain: true,
        output_mul_last_row_boundary: true,
        scalar_byte_accumulator: true,
    };
}

impl Default for ConstraintMask {
    fn default() -> Self {
        Self::ALL_ENABLED
    }
}

/// Marker AIR for Ed25519 fixed-base scalar multiplication. Stateful
/// (`num_lookups`) because [`LookupAir::add_lookup_columns`] mutates per
/// call to allocate fresh permutation-trace column indices.
#[derive(Clone, Default)]
pub struct Ed25519Air {
    /// Number of LogUp lookup columns this AIR has allocated so far.
    /// Updated by [`LookupAir::add_lookup_columns`]; reset to 0 at the
    /// start of [`LookupAir::get_lookups`] for idempotence.
    num_lookups: usize,

    /// Constraint-family toggle mask. Defaults to all-enabled; only
    /// the spec §6.5 sweep tests construct non-default masks to
    /// confirm each family is load-bearing.
    pub constraint_mask: ConstraintMask,
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Ed25519Air {
    fn width(&self) -> usize {
        NUM_ED25519_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Hard ceiling: degree 3 (matches the spec's degree budget).
        //
        // Manual constraints in `eval` are degree ≤ 2. The global LogUp
        // transition constraint that `p3-lookup`'s `LogUpGadget` emits
        // at `logup.rs:247-249` is
        //
        //   when_transition: (s_next - s_local) * ∏_i(α - e_i) - num = 0
        //
        // where the product runs over OUTER ENTRIES (separate
        // "things being looked up" within a single `Lookup`), NOT over
        // tuple elements within a thing. Each outer entry's tuple is
        // collapsed to a single value via β-Horner inside the gadget
        // (`logup.rs:82-93`):
        //
        //   combined_elt[i] = e_i[k-1] + e_i[k-2]·β + … + e_i[0]·β^(k-1)
        //
        // — degree 1 in the committed cells (β is a challenge, treated
        // as a constant during constraint evaluation). So:
        //
        //   - One Lookup with ONE outer entry whose tuple has k elements
        //     → constraint degree 3 regardless of k. ✓
        //   - One Lookup with N outer entries (k=1 each) → degree N + 2.
        //   - Multiple separate Lookups, each with k=1, one outer entry
        //     each → each constraint is degree 3, but N aux columns.
        //
        // This AIR's current pattern (many separate Lookups with k=1)
        // gives degree 3 at the cost of many permutation columns. The
        // tuple-bundling alternative (one Lookup with one outer entry,
        // k=many) gives degree 3 with fewer permutation columns. Both
        // are degree-3 — there is no degree pressure forcing the
        // many-Lookups choice.
        //
        // Optimization opportunity: consolidate the
        // many k=1 Lookups into a single Lookup with one outer entry
        // whose tuple is the full per-row send list, reclaiming most
        // of the permutation-column cost.
        // The existing `p3-batch-stark::prove_batch` +
        // `LogUpGadget` already supports this pattern.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(build_preprocessed_trace::<F>())
    }

    /// Our `eval` only reads `preprocessed.current_slice()` — never the
    /// next row. Returning an empty list lets the prover/verifier skip
    /// opening preprocessed columns at $\zeta_{\text{next}}$.
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// $A = [s] B$ in extended-Edwards coords $(X, Y, Z, T)$, each
    /// `NUM_LIMBS` 8-bit LE limbs. Bound to the last-row HWCD output by
    /// [`evaluate_output_mul_last_row_boundary`].
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for Ed25519Air
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Both windows are cloned out so they don't actively borrow
        // `builder`, leaving us free to call `&mut builder` for each
        // constraint helper. `MainWindow: Clone` and
        // `PreprocessedWindow: Clone` (cheap clones — they hold
        // references / small slices internally).
        let main_window = builder.main();
        let local: &Ed25519Cols<AB::Var> = (*main_window.current_slice()).borrow();
        let next: &Ed25519Cols<AB::Var> = (*main_window.next_slice()).borrow();
        let preprocessed_window = builder.preprocessed().clone();
        let preprocessed_local: &Ed25519PreprocessedCols<AB::Var> =
            (*preprocessed_window.current_slice()).borrow();

        let mask = self.constraint_mask;
        if mask.scalar_bit_boolean {
            evaluate_scalar_bit_boolean(builder, local);
        }
        if mask.initial_accumulator_boundary {
            evaluate_initial_accumulator_boundary(builder, local);
        }
        if mask.scalar_clamping {
            evaluate_scalar_clamping(builder, local, preprocessed_local);
        }
        if mask.table_entry_mux {
            evaluate_table_entry_mux(builder, local, preprocessed_local);
        }
        if mask.mul_a {
            evaluate_mul_a_constraint(builder, local);
        }
        if mask.mul_b {
            evaluate_mul_b_constraint(builder, local);
        }
        if mask.mul_c {
            evaluate_mul_c_constraint(builder, local);
        }
        if mask.output_mul_transitions {
            evaluate_output_mul_transitions(builder, local, next);
        }
        if mask.linear_modular_chain {
            evaluate_linear_modular_chain(builder, local);
        }
        if mask.output_mul_last_row_boundary {
            evaluate_output_mul_last_row_boundary(builder, local);
        }
        if mask.scalar_byte_accumulator {
            evaluate_scalar_byte_accumulator(builder, local, next, preprocessed_local);
        }
    }
}

/// Build the preprocessed (fixed) trace for one scalar-mult run.
///
/// Two column groups, both `NUM_ROWS_PER_SCALAR_MUL` rows tall so they
/// line up 1-to-1 with the main trace:
///
///   1. **Clamping selectors** (`is_clamped`, `clamp_value`) — `is_clamped = 1`
///      on the five rows where RFC 8032 fixes the scalar bit, `0` elsewhere;
///      `clamp_value` is the expected bit on those rows.
///   2. **Precomputed table** (`precomputed_y_minus_x`, `precomputed_y_plus_x`,
///      `precomputed_two_d_xy`) — row $t$ holds the three derived
///      components of $R_t = [2^t] B$, sourced from
///      [`PRECOMPUTED_BASE_MULTIPLES`].
fn build_preprocessed_trace<F: PrimeCharacteristicRing + Clone + Send + Sync>() -> RowMajorMatrix<F>
{
    let total_cells = NUM_ROWS_PER_SCALAR_MUL * NUM_ED25519_PREPROCESSED_COLS;
    let mut preprocessed_values: Vec<F> = (0..total_cells).map(|_| F::ZERO).collect();

    for row_index in 0..NUM_ROWS_PER_SCALAR_MUL {
        let row_start = row_index * NUM_ED25519_PREPROCESSED_COLS;
        let row_end = row_start + NUM_ED25519_PREPROCESSED_COLS;
        let row_slice: &mut [F] = &mut preprocessed_values[row_start..row_end];
        let preprocessed_columns: &mut Ed25519PreprocessedCols<F> = row_slice.borrow_mut();

        let table_entry = &PRECOMPUTED_BASE_MULTIPLES[row_index];
        for limb_index in 0..NUM_LIMBS {
            preprocessed_columns.precomputed_y_minus_x[limb_index] =
                F::from_u64(table_entry[0][limb_index] as u64);
            preprocessed_columns.precomputed_y_plus_x[limb_index] =
                F::from_u64(table_entry[1][limb_index] as u64);
            preprocessed_columns.precomputed_two_d_xy[limb_index] =
                F::from_u64(table_entry[2][limb_index] as u64);
        }

        // Scalar-byte-accumulator selectors.
        let bit_pos = row_index % 8;
        preprocessed_columns.bit_weight_in_byte = F::from_u64(1u64 << bit_pos);
        if bit_pos == 0 {
            preprocessed_columns.is_byte_start = F::ONE;
        }
        if bit_pos == 7 {
            // row_index = 8 * byte_index + 7  →  byte_index = row_index / 8.
            let byte_index = row_index / 8;
            preprocessed_columns.is_byte_end_for_byte[byte_index] = F::ONE;
        }
    }

    // Mark the five clamped rows (low 3 bits + bit 254 + bit 255) using
    // the typed column accessor so the offsets stay correct when the
    // struct grows. `clamp_value = 1` only on the single row where the
    // clamped bit is 1 (`CLAMP_HIGH_ONE_BIT_POS`).
    let clamped_rows: [(usize, bool); 5] = [
        (CLAMP_LOW_ZERO_BITS_POS[0], false),
        (CLAMP_LOW_ZERO_BITS_POS[1], false),
        (CLAMP_LOW_ZERO_BITS_POS[2], false),
        (CLAMP_HIGH_ONE_BIT_POS, true),
        (CLAMP_HIGH_ZERO_BIT_POS, false),
    ];
    for (row_index, expected_bit_is_one) in clamped_rows {
        let row_start = row_index * NUM_ED25519_PREPROCESSED_COLS;
        let row_slice: &mut [F] =
            &mut preprocessed_values[row_start..row_start + NUM_ED25519_PREPROCESSED_COLS];
        let columns: &mut Ed25519PreprocessedCols<F> = row_slice.borrow_mut();
        columns.is_clamped = F::ONE;
        if expected_bit_is_one {
            columns.clamp_value = F::ONE;
        }
    }

    // Set the public-value send-row indicator at row `LAST_ROW_INDEX`
    // only. Used as the LogUp numerator that gates public-value range
    // checks to fire once per proof.
    {
        let row_start = LAST_ROW_INDEX * NUM_ED25519_PREPROCESSED_COLS;
        let row_slice: &mut [F] =
            &mut preprocessed_values[row_start..row_start + NUM_ED25519_PREPROCESSED_COLS];
        let columns: &mut Ed25519PreprocessedCols<F> = row_slice.borrow_mut();
        columns.is_public_value_send_row = F::ONE;
    }

    RowMajorMatrix::new(preprocessed_values, NUM_ED25519_PREPROCESSED_COLS)
}

/// Constrain the scalar bit to be in $\{0, 1\}$ on every row.
///
/// $$
/// s_t \cdot (s_t - 1) = 0
/// $$
fn evaluate_scalar_bit_boolean<AB: AirBuilder>(builder: &mut AB, local: &Ed25519Cols<AB::Var>) {
    builder.assert_bool(local.scalar_bit);
}

/// Constrain the row-0 accumulator to equal the identity element
/// $\mathcal{O} = (0, 1, 1, 0)$ in extended Edwards coordinates.
///
/// Per spec §3.6:
///
/// $$
/// X_0 = 0,\quad Y_0 = 1,\quad Z_0 = 1,\quad T_0 = 0
/// $$
///
/// where each coordinate is committed as 16 little-endian 16-bit limbs.
/// $Y_0$ and $Z_0$ have limb 0 = 1 and all higher limbs = 0; $X_0$ and
/// $T_0$ have all limbs = 0.
fn evaluate_initial_accumulator_boundary<AB: AirBuilder>(
    builder: &mut AB,
    local: &Ed25519Cols<AB::Var>,
) {
    let mut on_first_row = builder.when_first_row();

    // X_0 and T_0 are zero: every limb must be zero.
    for limb_index in 0..NUM_LIMBS {
        on_first_row.assert_zero(local.accumulator_x[limb_index]);
        on_first_row.assert_zero(local.accumulator_t[limb_index]);
    }

    // Y_0 = 1 and Z_0 = 1: limb 0 == 1, all higher limbs == 0.
    on_first_row.assert_one(local.accumulator_y[0]);
    on_first_row.assert_one(local.accumulator_z[0]);
    for limb_index in 1..NUM_LIMBS {
        on_first_row.assert_zero(local.accumulator_y[limb_index]);
        on_first_row.assert_zero(local.accumulator_z[limb_index]);
    }
}

/// Constrain RFC 8032 scalar clamping uniformly via two preprocessed
/// columns. Per spec §4.1, the clamped scalar satisfies:
///
///   - bits 0, 1, 2 = 0  (low 3 bits clear → $s \equiv 0 \pmod 8$)
///   - bit 254 = 1        (top-bit-but-one set → $s \ge 2^{254}$)
///   - bit 255 = 0        (high bit clear → $s < 2^{255}$)
///
/// All five forced rows are encoded in the preprocessed columns. On a
/// row where the bit is constrained, `is_clamped = 1` and `clamp_value`
/// is the expected bit. On every other row, `is_clamped = 0` and the
/// constraint vanishes.
///
/// One degree-2 constraint, applied on every row:
///
/// $$
///   \text{is\_clamped} \cdot (\text{scalar\_bit} - \text{clamp\_value}) = 0
/// $$
///
/// Soundness note: when `is_clamped = 0`,
/// this constraint does not enforce the correct value (0/1) for clamp_value,
/// but this is not exploitable anyway
fn evaluate_scalar_clamping<AB: AirBuilder>(
    builder: &mut AB,
    local: &Ed25519Cols<AB::Var>,
    preprocessed_local: &Ed25519PreprocessedCols<AB::Var>,
) {
    let is_clamped: AB::Expr = preprocessed_local.is_clamped.into();
    let clamp_value: AB::Expr = preprocessed_local.clamp_value.into();
    let scalar_bit: AB::Expr = local.scalar_bit.into();
    builder.assert_zero(is_clamped * (scalar_bit - clamp_value));
}

/// Constrain the three committed `muxed_table_*` field elements to be
/// the scalar-bit-conditional select between the row's preprocessed
/// table entry and the identity element's components:
///
/// ```text
///   muxed = (1 − scalar_bit) · identity + scalar_bit · precomputed
/// ```
///
/// In extended-Edwards form the identity is $(0, 1)$, so its mixed-add
/// derivatives are
/// $y - x = 1$, $y + x = 1$, $2 d x y = 0$. Per limb (LE):
///
///   - `muxed_y_minus_x[0] − 1 − bit · (precomp_y_minus_x[0] − 1) = 0`
///   - `muxed_y_minus_x[i] − bit · precomp_y_minus_x[i] = 0`   for $i > 0$
///   - same shape for `y_plus_x`
///   - `muxed_two_d_xy[i] − bit · precomp_two_d_xy[i] = 0`     for all $i$
///
/// All 48 constraints are degree 2 (`scalar_bit` × preprocessed limb).
fn evaluate_table_entry_mux<AB: AirBuilder>(
    builder: &mut AB,
    local: &Ed25519Cols<AB::Var>,
    preprocessed_local: &Ed25519PreprocessedCols<AB::Var>,
) {
    let scalar_bit: AB::Expr = local.scalar_bit.into();

    // y − x and y + x: identity field element is `1`, i.e. limb 0 = 1, others = 0.
    for limb_index in 0..NUM_LIMBS {
        let identity_limb_value: AB::Expr = if limb_index == 0 {
            AB::Expr::ONE
        } else {
            AB::Expr::ZERO
        };

        let muxed_y_minus_x: AB::Expr = local.muxed_table_y_minus_x[limb_index].into();
        let precomp_y_minus_x: AB::Expr =
            preprocessed_local.precomputed_y_minus_x[limb_index].into();
        builder.assert_zero(
            muxed_y_minus_x
                - identity_limb_value.clone()
                - scalar_bit.clone() * (precomp_y_minus_x - identity_limb_value.clone()),
        );

        let muxed_y_plus_x: AB::Expr = local.muxed_table_y_plus_x[limb_index].into();
        let precomp_y_plus_x: AB::Expr = preprocessed_local.precomputed_y_plus_x[limb_index].into();
        builder.assert_zero(
            muxed_y_plus_x
                - identity_limb_value.clone()
                - scalar_bit.clone() * (precomp_y_plus_x - identity_limb_value),
        );
    }

    // 2 d · x · y: identity is 0 across all limbs, so the constraint
    // collapses to `muxed = bit · precomputed`.
    for limb_index in 0..NUM_LIMBS {
        let muxed_two_d_xy: AB::Expr = local.muxed_table_two_d_xy[limb_index].into();
        let precomp_two_d_xy: AB::Expr = preprocessed_local.precomputed_two_d_xy[limb_index].into();
        builder.assert_zero(muxed_two_d_xy - scalar_bit.clone() * precomp_two_d_xy);
    }
}

/// Generic non-native field-multiplication constraint.
///
/// Enforces the integer identity
///
/// ```text
///   lhs · rhs  -  quotient · p  -  result  =  0    (over ℤ)
/// ```
///
/// per limb-position with carry propagation (spec §5.2). For each
/// position $k \in \{0, \ldots, 30\}$:
///
/// ```text
///   ∑_{i+j=k} lhs[i] · rhs[j]
///   - ∑_{i+j=k} quotient[i] · p[j]
///   - result_at(k)            (= 0 for k ≥ 16)
///   + (carry[k-1]   if k > 0)
///   - (carry[k] · 2^16   if k < 30)
///   = 0
/// ```
///
/// All emitted constraints are degree 2 (limb × limb in the schoolbook
/// product). The `result_at_position` closure decouples the result's
/// storage location: for HWCD intermediates it returns
/// `local.hwcd_*[k]`; for the four output multiplications it returns
/// `next_row.accumulator_*[k]` so the same helper drives the
/// transition constraint.
///
/// **Soundness note:** range-checks on `quotient_limbs` and
/// `carry_cells` are added in a separate constraint block — without
/// them, a malicious prover can pick out-of-range witnesses to satisfy
/// these per-position equations while the integer identity fails.
fn evaluate_nonnative_mul_constraint<AB: AirBuilder, LhsAt, RhsAt, ResultAt>(
    builder: &mut AB,
    lhs_at_position: LhsAt,
    rhs_at_position: RhsAt,
    quotient_limbs: &[AB::Var; NUM_LIMBS],
    carry_cells: &[AB::Var; NUM_MUL_CARRY_CELLS],
    result_at_position: ResultAt,
) where
    LhsAt: Fn(usize) -> AB::Expr,
    RhsAt: Fn(usize) -> AB::Expr,
    ResultAt: Fn(usize) -> AB::Expr,
{
    let two_to_limb_bits: AB::Expr = AB::Expr::from(AB::F::from_u64(LIMB_BASE));
    // Carry cells are committed offset-shifted (= honest carry +
    // MUL_CARRY_OFFSET) so they're non-negative for u16-bus range checks.
    // Subtract the offset back when reading to recover the signed honest
    // value. See `constants::MUL_CARRY_OFFSET` for the rationale.
    let mul_carry_offset_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(MUL_CARRY_OFFSET));
    let read_honest_carry = |column_index: usize| -> AB::Expr {
        AB::Expr::from(carry_cells[column_index]) - mul_carry_offset_expr.clone()
    };

    for position_index in 0..NUM_PRODUCT_POSITIONS {
        let mut signed_coefficient: AB::Expr = AB::Expr::ZERO;
        // ∑_{i+j=k} lhs[i] · rhs[j]   (degree 2)
        for left_index in 0..NUM_LIMBS {
            let right_index = position_index.wrapping_sub(left_index);
            if right_index < NUM_LIMBS {
                signed_coefficient =
                    signed_coefficient + lhs_at_position(left_index) * rhs_at_position(right_index);
            }
        }
        // − ∑_{i+j=k} q[i] · p[j]   (degree 1; p[j] is a compile-time constant)
        for left_index in 0..NUM_LIMBS {
            let right_index = position_index.wrapping_sub(left_index);
            if right_index < NUM_LIMBS {
                let quotient_expr: AB::Expr = quotient_limbs[left_index].into();
                let prime_limb_constant: AB::F = AB::F::from_u64(PRIME_LIMBS[right_index] as u64);
                signed_coefficient = signed_coefficient - quotient_expr * prime_limb_constant;
            }
        }
        // − result[k]   (only for k < NUM_LIMBS; result is zero-extended above)
        if position_index < NUM_LIMBS {
            signed_coefficient = signed_coefficient - result_at_position(position_index);
        }
        // + carry_in   (honest carry from previous position, 0 at position 0)
        if position_index > 0 {
            signed_coefficient = signed_coefficient + read_honest_carry(position_index - 1);
        }
        // − carry_out · LIMB_BASE   (no outflow at the last position)
        if position_index < NUM_MUL_CARRY_CELLS {
            signed_coefficient =
                signed_coefficient - read_honest_carry(position_index) * two_to_limb_bits.clone();
        }
        builder.assert_zero(signed_coefficient);
    }
}

/// Constrain mul A: $(Y - X) \cdot \text{muxed\_y\_minus\_x} \equiv
/// \text{hwcd\_a} \pmod p$.
fn evaluate_mul_a_constraint<AB: AirBuilder>(builder: &mut AB, local: &Ed25519Cols<AB::Var>) {
    let lhs_limbs = local.y_minus_x_reduced;
    let rhs_limbs = local.muxed_table_y_minus_x;
    let result_limbs = local.hwcd_a;
    evaluate_nonnative_mul_constraint(
        builder,
        |position| lhs_limbs[position].into(),
        |position| rhs_limbs[position].into(),
        &local.mul_a_quotient,
        &local.mul_a_carry,
        |position| result_limbs[position].into(),
    );
}

/// Constrain mul B: $(Y + X) \cdot \text{muxed\_y\_plus\_x} \equiv
/// \text{hwcd\_b} \pmod p$.
fn evaluate_mul_b_constraint<AB: AirBuilder>(builder: &mut AB, local: &Ed25519Cols<AB::Var>) {
    let lhs_limbs = local.y_plus_x_reduced;
    let rhs_limbs = local.muxed_table_y_plus_x;
    let result_limbs = local.hwcd_b;
    evaluate_nonnative_mul_constraint(
        builder,
        |position| lhs_limbs[position].into(),
        |position| rhs_limbs[position].into(),
        &local.mul_b_quotient,
        &local.mul_b_carry,
        |position| result_limbs[position].into(),
    );
}

/// Constrain mul C: $T \cdot \text{muxed\_two\_d\_xy} \equiv
/// \text{hwcd\_c} \pmod p$.
fn evaluate_mul_c_constraint<AB: AirBuilder>(builder: &mut AB, local: &Ed25519Cols<AB::Var>) {
    let lhs_limbs = local.accumulator_t;
    let rhs_limbs = local.muxed_table_two_d_xy;
    let result_limbs = local.hwcd_c;
    evaluate_nonnative_mul_constraint(
        builder,
        |position| lhs_limbs[position].into(),
        |position| rhs_limbs[position].into(),
        &local.mul_c_quotient,
        &local.mul_c_carry,
        |position| result_limbs[position].into(),
    );
}

/// Constrain the four HWCD output multiplications, each binding the
/// product to a coordinate of the **next-row** accumulator. Together
/// these form the row-to-row transition: row $t+1$'s accumulator is
/// the HWCD output of row $t$'s mixed-add (with the bit-0 case
/// projectively absorbed by the muxed table entry).
///
/// ```text
///   X' = E · F  ≡  next.accumulator_x  (mod p)
///   Y' = G · H  ≡  next.accumulator_y  (mod p)
///   Z' = F · G  ≡  next.accumulator_z  (mod p)
///   T' = E · H  ≡  next.accumulator_t  (mod p)
/// ```
///
/// All four are wrapped in `when_transition()`, so they don't fire on
/// the last row (where there is no `next`). The `when_transition`
/// selector is degree 1; combined with the underlying degree-2 mul
/// constraints, the emitted constraint is degree 3 — within budget.
fn evaluate_output_mul_transitions<AB: AirBuilder>(
    builder: &mut AB,
    local: &Ed25519Cols<AB::Var>,
    next: &Ed25519Cols<AB::Var>,
) {
    // Snapshot the four next-row accumulator-coordinate arrays AND the
    // four local HWCD intermediate arrays before creating the filtered
    // builder, so the closures borrow from local copies (not from
    // `builder` or `next`/`local` through a reborrow).
    let next_accumulator_x = next.accumulator_x;
    let next_accumulator_y = next.accumulator_y;
    let next_accumulator_z = next.accumulator_z;
    let next_accumulator_t = next.accumulator_t;
    let local_hwcd_e = local.hwcd_e;
    let local_hwcd_f = local.hwcd_f;
    let local_hwcd_g = local.hwcd_g;
    let local_hwcd_h = local.hwcd_h;

    let mut transition_builder = builder.when_transition();

    // X' = E · F = next.accumulator_x
    evaluate_nonnative_mul_constraint(
        &mut transition_builder,
        |position| local_hwcd_e[position].into(),
        |position| local_hwcd_f[position].into(),
        &local.mul_xprime_quotient,
        &local.mul_xprime_carry,
        |position| next_accumulator_x[position].into(),
    );
    // Y' = G · H = next.accumulator_y
    evaluate_nonnative_mul_constraint(
        &mut transition_builder,
        |position| local_hwcd_g[position].into(),
        |position| local_hwcd_h[position].into(),
        &local.mul_yprime_quotient,
        &local.mul_yprime_carry,
        |position| next_accumulator_y[position].into(),
    );
    // Z' = F · G = next.accumulator_z
    evaluate_nonnative_mul_constraint(
        &mut transition_builder,
        |position| local_hwcd_f[position].into(),
        |position| local_hwcd_g[position].into(),
        &local.mul_zprime_quotient,
        &local.mul_zprime_carry,
        |position| next_accumulator_z[position].into(),
    );
    // T' = E · H = next.accumulator_t
    evaluate_nonnative_mul_constraint(
        &mut transition_builder,
        |position| local_hwcd_e[position].into(),
        |position| local_hwcd_h[position].into(),
        &local.mul_tprime_quotient,
        &local.mul_tprime_carry,
        |position| next_accumulator_t[position].into(),
    );
}

/// Last-row boundary: bind the trace's row-`LAST_ROW_INDEX` HWCD
/// output to a public-input affine point $A = (x_A, y_A)$ via two
/// non-native multiplications, per spec §3.6 / §4.6.
///
/// **Why two muls suffice (and how we avoid the textbook three).**
/// The textbook product-form binding for an extended-Edwards point
/// $(X, Y, Z)$ at affine $(x, y)$ uses *three* equalities:
///
/// ```text
///   x_A · Z_256 ≡ X_256 (mod p)
///   y_A · Z_256 ≡ Y_256 (mod p)
/// ```
///
/// where $X_{256}, Y_{256}, Z_{256}$ are the row-256 (post-row-255-update)
/// extended-Edwards coordinates. We don't have a row-256 trace cell
/// (the trace is exactly 256 rows, with row 255's HWCD output going
/// nowhere by default), but the row-255 HWCD update gives them in
/// *factored* form via the four mul products
/// `(X_256, Y_256, Z_256, T_256) = (E·F, G·H, F·G, E·H)` from row
/// 255's HWCD intermediates.
///
/// Substituting these factorisations into the textbook equations and
/// dividing by the common factor $G$ in the $X$-equation and $F$ in
/// the $Y$-equation:
///
/// ```text
///   x_A · F · G ≡ E · F  ⇒  G · (x_A · G - E) ≡ 0  ⇒  x_A · G ≡ E (mod p)
///   y_A · F · G ≡ G · H  ⇒  F · (y_A · F - H) ≡ 0  ⇒  y_A · F ≡ H (mod p)
/// ```
///
/// (The cancellation is sound iff $F \neq 0$ and $G \neq 0$ in
/// $\mathbb{F}_p$, which is the HWCD non-exceptional condition we
/// already inherit — the exceptional set has measure zero on
/// ed25519's clamped-scalar input space; see the spec for the
/// inductive argument.)
///
/// **Result:** two non-native muls instead of four, with
/// $32 \cdot 2 = 64$ public-value limbs instead of 128. The two
/// boundary muls reuse the existing `mul_xprime_*` and
/// `mul_yprime_*` witness columns, which are otherwise unconstrained
/// at row `LAST_ROW_INDEX` (the transition is gated by
/// `when_transition` and excludes that row).
///
/// The `mul_zprime_*` and `mul_tprime_*` witnesses at row
/// `LAST_ROW_INDEX` are not constrained by any AIR constraint; the
/// trace generator fills them with offset-zero values so the existing
/// LookupAir limb / carry sends still succeed. They are essentially
/// unused cells at the last row — a small column-budget cost we pay
/// for keeping the column shape uniform across rows.
fn evaluate_output_mul_last_row_boundary<AB: AirBuilder>(
    builder: &mut AB,
    local: &Ed25519Cols<AB::Var>,
) {
    let public_values = builder.public_values();
    debug_assert_eq!(
        public_values.len(),
        NUM_PUBLIC_VALUES,
        "public_values must hold A = (x_A, y_A) in {NUM_PUBLIC_INPUT_COORDINATES} × NUM_LIMBS limbs"
    );
    // Snapshot the two affine-coordinate public-value blocks into
    // `[AB::PublicVar; NUM_LIMBS]` so the closures can read them after
    // we drop the `&[PublicVar]` borrow on `builder`.
    let mut public_a_x = [public_values[PUBLIC_INPUT_X_OFFSET]; NUM_LIMBS];
    let mut public_a_y = [public_values[PUBLIC_INPUT_Y_OFFSET]; NUM_LIMBS];
    for limb_index in 0..NUM_LIMBS {
        public_a_x[limb_index] = public_values[PUBLIC_INPUT_X_OFFSET + limb_index];
        public_a_y[limb_index] = public_values[PUBLIC_INPUT_Y_OFFSET + limb_index];
    }
    // Snapshot the four HWCD intermediate-result arrays before
    // creating the filtered `when_last_row` builder.
    let local_hwcd_e = local.hwcd_e;
    let local_hwcd_f = local.hwcd_f;
    let local_hwcd_g = local.hwcd_g;
    let local_hwcd_h = local.hwcd_h;

    let mut last_row_builder = builder.when_last_row();

    // x_A · G ≡ E (mod p)
    evaluate_nonnative_mul_constraint(
        &mut last_row_builder,
        |position| public_a_x[position].into(),
        |position| local_hwcd_g[position].into(),
        &local.mul_xprime_quotient,
        &local.mul_xprime_carry,
        |position| local_hwcd_e[position].into(),
    );
    // y_A · F ≡ H (mod p)
    evaluate_nonnative_mul_constraint(
        &mut last_row_builder,
        |position| public_a_y[position].into(),
        |position| local_hwcd_f[position].into(),
        &local.mul_yprime_quotient,
        &local.mul_yprime_carry,
        |position| local_hwcd_h[position].into(),
    );
}

/// Bind the per-row `scalar_bit` cells to the `scalar_packed` PV
/// input (32 × 8-bit limbs at `SCALAR_PACKED_OFFSET`). This is what
/// closes the soundness chain mnemonic → seed → priv → [s]B in the
/// full pipeline (Phase 5): upstream Slip10Air emits `priv_packed` as
/// PV output; here Ed25519Air consumes the same vector as PV input,
/// and the per-row constraints below verify that `priv_packed[i]` is
/// the byte-level reconstruction of `scalar_bit_{8i}, …, scalar_bit_{8i+7}`.
///
/// Three constraint families:
///   1. **Byte-start** (gated by `is_byte_start`): `accumulator =
///      scalar_bit` (since `bit_weight_in_byte = 1` at byte-start).
///   2. **Within-byte transition** (gated by `1 - is_byte_end_local`):
///      `next.accumulator = local.accumulator + 2 · bit_weight_local
///      · next.scalar_bit`. The `2 ·` factor is the byte-internal
///      doubling (`2^{(k+1)%8} = 2 · 2^{k%8}` within a byte).
///   3. **Byte-end PV equality** (gated by `is_byte_end_for_byte[i]`):
///      `accumulator = scalar_packed_PV[i]`, one constraint per byte
///      index.
fn evaluate_scalar_byte_accumulator<AB: AirBuilder>(
    builder: &mut AB,
    local: &Ed25519Cols<AB::Var>,
    next: &Ed25519Cols<AB::Var>,
    preprocessed_local: &Ed25519PreprocessedCols<AB::Var>,
) {
    // Snapshot all cells we'll need so we can later borrow `builder`
    // mutably for `assert_zero` / `when_transition`.
    let local_scalar_bit = local.scalar_bit;
    let local_accumulator = local.scalar_byte_accumulator;
    let next_scalar_bit = next.scalar_bit;
    let next_accumulator = next.scalar_byte_accumulator;
    let bit_weight_local = preprocessed_local.bit_weight_in_byte;
    let is_byte_start_local = preprocessed_local.is_byte_start;
    let is_byte_end_for_byte = preprocessed_local.is_byte_end_for_byte;

    let scalar_packed_pv: [AB::PublicVar; NUM_LIMBS] = {
        let public_values = builder.public_values();
        debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);
        let mut snapshot = [public_values[SCALAR_PACKED_OFFSET]; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            snapshot[i] = public_values[SCALAR_PACKED_OFFSET + i];
        }
        snapshot
    };

    // (1) Byte-start: accumulator = scalar_bit.
    let is_byte_start_expr: AB::Expr = is_byte_start_local.into();
    let acc_local_expr: AB::Expr = local_accumulator.into();
    let scalar_bit_local_expr: AB::Expr = local_scalar_bit.into();
    builder.assert_zero(
        is_byte_start_expr * (acc_local_expr.clone() - scalar_bit_local_expr),
    );

    // (3) Byte-end PV equality, one constraint per byte index.
    for byte_index in 0..NUM_LIMBS {
        let indicator: AB::Expr = is_byte_end_for_byte[byte_index].into();
        let pv: AB::Expr = scalar_packed_pv[byte_index].into();
        builder.assert_zero(indicator * (acc_local_expr.clone() - pv));
    }

    // (2) Within-byte transition. Sum of 32 byte_end indicators is 1
    // on byte-end rows, 0 elsewhere — used as an inline gate.
    let mut is_byte_end_local_expr: AB::Expr = AB::Expr::ZERO;
    for byte_index in 0..NUM_LIMBS {
        let indicator: AB::Expr = is_byte_end_for_byte[byte_index].into();
        is_byte_end_local_expr = is_byte_end_local_expr + indicator;
    }
    let bit_weight_local_expr: AB::Expr = bit_weight_local.into();
    let next_accumulator_expr: AB::Expr = next_accumulator.into();
    let next_scalar_bit_expr: AB::Expr = next_scalar_bit.into();
    let two: AB::Expr = AB::Expr::TWO;
    let mut when_trans = builder.when_transition();
    when_trans.assert_zero(
        (AB::Expr::ONE - is_byte_end_local_expr)
            * (next_accumulator_expr
                - acc_local_expr
                - two * bit_weight_local_expr * next_scalar_bit_expr),
    );
}

/// Sign of the $\sigma \cdot p$ term in a linear modular constraint.
/// Add ops use `Subtract` (the integer identity is $a + b - \sigma p =
/// r$); sub ops use `Add` ($a - b + \sigma p = r$).
#[derive(Clone, Copy)]
enum SigmaPolynomialSign {
    /// $\sigma p$ is **subtracted** from the LHS (used by add / double).
    Subtract,
    /// $\sigma p$ is **added** to the LHS (used by sub).
    Add,
}

/// Generic linear-modular constraint helper. Enforces the integer identity
///
/// ```text
///   signed_lhs(k)  +  σp_sign · σ · p[k]  -  result(k)  =  0   (over ℤ, per-limb)
/// ```
///
/// closed by a 15-cell carry sequence `c[0..14]`:
///
/// ```text
///   signed_lhs(k) + σp_sign · σ · p[k] - result(k) + c[k-1]  -  c[k] · 2^16  =  0
/// ```
///
/// for $k \in \{0, \ldots, 15\}$, with $c[-1] = 0$ and no $c[15]$
/// (last position closes with no outflow).
///
/// `signed_lhs_at_position` provides the per-limb LHS expression
/// (degree 1: a single sum/difference of committed limbs, or `2 * z[k]`
/// for double). `result_at_position` provides the per-limb result.
///
/// One additional constraint enforces `σ * (σ - 1) = 0` (boolean).
///
/// Total degree: 1 (the σ·p term is `σ · constant`). The full
/// constraint is degree 1 — well within budget.
fn evaluate_linear_modular_constraint<AB, SignedLhs, ResultAt>(
    builder: &mut AB,
    signed_lhs_at_position: SignedLhs,
    sigma_p_sign: SigmaPolynomialSign,
    sigma_var: AB::Var,
    carry_cells: &[AB::Var; NUM_LINEAR_CARRY_CELLS],
    result_at_position: ResultAt,
) where
    AB: AirBuilder,
    SignedLhs: Fn(usize) -> AB::Expr,
    ResultAt: Fn(usize) -> AB::Expr,
{
    builder.assert_bool(sigma_var);

    let two_to_limb_bits: AB::Expr = AB::Expr::from(AB::F::from_u64(LIMB_BASE));
    let sigma_expr: AB::Expr = sigma_var.into();
    // Carry cells are committed offset-shifted (= honest carry +
    // LINEAR_CARRY_OFFSET) for u16-bus range checks. Subtract back when
    // reading. See `constants::LINEAR_CARRY_OFFSET`.
    let linear_carry_offset_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(LINEAR_CARRY_OFFSET));
    let read_honest_carry = |column_index: usize| -> AB::Expr {
        AB::Expr::from(carry_cells[column_index]) - linear_carry_offset_expr.clone()
    };

    for position_index in 0..NUM_LIMBS {
        let prime_limb_constant: AB::F = AB::F::from_u64(PRIME_LIMBS[position_index] as u64);
        let sigma_p_term: AB::Expr = sigma_expr.clone() * prime_limb_constant;
        let sigma_p_signed: AB::Expr = match sigma_p_sign {
            SigmaPolynomialSign::Subtract => -sigma_p_term,
            SigmaPolynomialSign::Add => sigma_p_term,
        };

        let mut constraint_expr: AB::Expr = signed_lhs_at_position(position_index) + sigma_p_signed
            - result_at_position(position_index);

        if position_index > 0 {
            constraint_expr = constraint_expr + read_honest_carry(position_index - 1);
        }
        if position_index < NUM_LINEAR_CARRY_CELLS {
            constraint_expr =
                constraint_expr - read_honest_carry(position_index) * two_to_limb_bits.clone();
        }
        builder.assert_zero(constraint_expr);
    }
}

/// Wire all seven linear-modular constraints that close the HWCD chain:
///
/// ```text
///   y_minus_x_reduced  =  Y − X   (mod p)
///   y_plus_x_reduced   =  Y + X   (mod p)
///   hwcd_d             =  2 · Z   (mod p)
///   hwcd_e             =  hwcd_b − hwcd_a   (mod p)
///   hwcd_f             =  hwcd_d − hwcd_c   (mod p)
///   hwcd_g             =  hwcd_d + hwcd_c   (mod p)
///   hwcd_h             =  hwcd_b + hwcd_a   (mod p)
/// ```
///
/// Each contributes one boolean σ-constraint plus 16 per-limb identity
/// constraints (degree 1).
fn evaluate_linear_modular_chain<AB: AirBuilder>(builder: &mut AB, local: &Ed25519Cols<AB::Var>) {
    // y_minus_x_reduced = Y − X
    let acc_y = local.accumulator_y;
    let acc_x = local.accumulator_x;
    let result_ymx = local.y_minus_x_reduced;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(acc_y[position]) - AB::Expr::from(acc_x[position]),
        SigmaPolynomialSign::Add,
        local.linear_y_minus_x_reduction_flag,
        &local.linear_y_minus_x_carry,
        |position| result_ymx[position].into(),
    );

    // y_plus_x_reduced = Y + X
    let result_ypx = local.y_plus_x_reduced;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(acc_y[position]) + AB::Expr::from(acc_x[position]),
        SigmaPolynomialSign::Subtract,
        local.linear_y_plus_x_reduction_flag,
        &local.linear_y_plus_x_carry,
        |position| result_ypx[position].into(),
    );

    // D = 2 · Z (specialization of add with both operands = Z)
    let acc_z = local.accumulator_z;
    let result_d = local.hwcd_d;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(acc_z[position]) * AB::F::from_u64(2),
        SigmaPolynomialSign::Subtract,
        local.linear_d_reduction_flag,
        &local.linear_d_carry,
        |position| result_d[position].into(),
    );

    // E = B − A
    let hwcd_b = local.hwcd_b;
    let hwcd_a = local.hwcd_a;
    let result_e = local.hwcd_e;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(hwcd_b[position]) - AB::Expr::from(hwcd_a[position]),
        SigmaPolynomialSign::Add,
        local.linear_e_reduction_flag,
        &local.linear_e_carry,
        |position| result_e[position].into(),
    );

    // F = D − C
    let hwcd_d = local.hwcd_d;
    let hwcd_c = local.hwcd_c;
    let result_f = local.hwcd_f;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(hwcd_d[position]) - AB::Expr::from(hwcd_c[position]),
        SigmaPolynomialSign::Add,
        local.linear_f_reduction_flag,
        &local.linear_f_carry,
        |position| result_f[position].into(),
    );

    // G = D + C
    let result_g = local.hwcd_g;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(hwcd_d[position]) + AB::Expr::from(hwcd_c[position]),
        SigmaPolynomialSign::Subtract,
        local.linear_g_reduction_flag,
        &local.linear_g_carry,
        |position| result_g[position].into(),
    );

    // H = B + A
    let result_h = local.hwcd_h;
    evaluate_linear_modular_constraint(
        builder,
        |position| AB::Expr::from(hwcd_b[position]) + AB::Expr::from(hwcd_a[position]),
        SigmaPolynomialSign::Subtract,
        local.linear_h_reduction_flag,
        &local.linear_h_carry,
        |position| result_h[position].into(),
    );
}

// ---------------- Range-check send-count accounting ----------------------
//
// Every committed witness whose values must lie in `[0, LIMB_BASE)` (or in
// the offset-shifted carry range `[0, 2^MUL_CARRY_RANGE_BITS)` for carry
// cells) sends each cell as its own single-tuple LogUp Lookup to the
// global `u16_range` bus. The receiving side is
// [`crate::range_check_u16_air::air::RangeCheckU16Air`]. One `Lookup` per
// cell (k = 1 tuple per `Lookup`) per the degree-3 ceiling decision in
// [`Ed25519Air::max_constraint_degree`].

/// $(X, Y, Z, T)$ — extended-Edwards accumulator coordinates per row.
const NUM_ACCUMULATOR_COORDINATES: usize = 4;

/// `y_minus_x_reduced`, `y_plus_x_reduced` — the two reduced sub-operand
/// field elements committed to feed the mul constraints with non-negative
/// inputs.
const NUM_PRE_MUL_REDUCED_OPERANDS: usize = 2;

/// $A, B, C, D, E, F, G, H$ — the eight HWCD mixed-add intermediates.
const NUM_HWCD_INTERMEDIATES: usize = 8;

/// Mul A, B, C plus the four output muls X', Y', Z', T'.
const NUM_NONNATIVE_MULS: usize = 7;

/// `y_minus_x`, `y_plus_x`, `D = 2Z`, `E = B - A`, `F = D - C`,
/// `G = D + C`, `H = B + A` — seven linear modular ops per row.
const NUM_LINEAR_MOD_OPS: usize = 7;

/// Number of *affine* coordinates exposed as public input — the
/// final point $A = [s] B$ in $(x_A, y_A)$ form, per spec §3.6.
///
/// We expose affine, not extended-Edwards, because (a) the downstream
/// EdDSA-signature verifier consumes affine, and (b) the boundary
/// binding then needs only **two** non-native multiplications (instead
/// of the four that a $(X, Y, Z, T)$ binding requires) — see
/// [`evaluate_output_mul_last_row_boundary`].
const NUM_PUBLIC_INPUT_COORDINATES: usize = 2;

/// Total public-value cell count per Ed25519 instance.
///   `[x_A (32 × 8-bit) || y_A (32 × 8-bit) || scalar_packed (32 × 8-bit)]`
/// = 96 cells. `scalar_packed` is the PV INPUT that upstream pipeline
/// AIRs (Slip10Air via `priv_packed`) bind against — closes the
/// soundness chain mnemonic → seed → priv → [s]B = address. Bound
/// row-wise via `scalar_byte_accumulator` and 32 byte-end PV-equality
/// constraints; see `Ed25519Cols::scalar_byte_accumulator` and
/// `Ed25519PreprocessedCols::is_byte_end_for_byte`.
pub const NUM_PUBLIC_VALUES: usize =
    NUM_PUBLIC_INPUT_COORDINATES * NUM_LIMBS + NUM_LIMBS;

/// Public-value index of the start of `x_A`'s limbs.
pub const PUBLIC_INPUT_X_OFFSET: usize = 0 * NUM_LIMBS;
/// Public-value index of the start of `y_A`'s limbs.
pub const PUBLIC_INPUT_Y_OFFSET: usize = 1 * NUM_LIMBS;
/// Public-value index of the start of `scalar_packed` (32 × 8-bit
/// limbs, byte-flat little-endian — i.e. limb `k` holds byte `k` of
/// the 256-bit scalar with bit 0 = LSB of byte 0).
pub const SCALAR_PACKED_OFFSET: usize = 2 * NUM_LIMBS;

/// Total cells sent per row whose limbs must fit in `[0, LIMB_BASE)`.
const TOTAL_LIMB_RANGE_SENDS_PER_ROW: usize = (NUM_ACCUMULATOR_COORDINATES
    + NUM_PRE_MUL_REDUCED_OPERANDS
    + NUM_HWCD_INTERMEDIATES
    + NUM_NONNATIVE_MULS)
    * NUM_LIMBS;

/// Total mul-carry cells sent per row (offset-shifted, range
/// `[0, 2^MUL_CARRY_RANGE_BITS)`).
const TOTAL_MUL_CARRY_SENDS_PER_ROW: usize = NUM_NONNATIVE_MULS * NUM_MUL_CARRY_CELLS;

/// Total linear-add/sub-carry cells sent per row (offset-shifted, same
/// range as mul carries).
const TOTAL_LINEAR_CARRY_SENDS_PER_ROW: usize = NUM_LINEAR_MOD_OPS * NUM_LINEAR_CARRY_CELLS;

/// Sum of all range-check sends per row. Public so tests / downstream
/// code that builds the receive-side range-check trace can size their
/// event vectors precisely.
pub const TOTAL_RANGE_CHECK_SENDS_PER_ROW: usize = TOTAL_LIMB_RANGE_SENDS_PER_ROW
    + TOTAL_MUL_CARRY_SENDS_PER_ROW
    + TOTAL_LINEAR_CARRY_SENDS_PER_ROW;

impl<F: Field> LookupAir<F> for Ed25519Air {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        // Build symbolic references to the main trace, the preprocessed
        // trace, and the public values. The `Borrow` impl gives us a
        // typed view over each slice; field types are inferred to be
        // the symbolic column type (`SymbolicVariable<F>`), which
        // converts to `SymbolicExpression<F>` via `Into`.
        //
        // `num_public_values` is set so the per-proof public-value
        // range-check sends below can read `symbolic_builder.public_values()`.
        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_ED25519_COLS,
            preprocessed_width: NUM_ED25519_PREPROCESSED_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &Ed25519Cols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &Ed25519PreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();
        let public_value_vars = symbolic_builder.public_values();

        let one_multiplicity = SymbolicExpression::from(F::ONE);
        let mut lookups: Vec<Lookup<F>> =
            Vec::with_capacity(TOTAL_RANGE_CHECK_SENDS_PER_ROW + NUM_PUBLIC_VALUES);

        // Each helper closure pushes one (or many) range-check Lookup(s)
        // to the bus. We send each cell as its own single-tuple Lookup
        // (k = 1), per the degree-3 ceiling decision in
        // `Ed25519Air::max_constraint_degree`.
        let send_one_cell = |lookups: &mut Vec<Lookup<F>>,
                             air_self: &mut Self,
                             cell_expr: SymbolicExpression<F>| {
            let lookup_inputs = [(vec![cell_expr], one_multiplicity.clone(), Direction::Send)];
            lookups.push(LookupAir::register_lookup(
                air_self,
                Kind::Global(U16_RANGE_BUS_NAME.to_string()),
                &lookup_inputs,
            ));
        };

        // ---------- Accumulator coordinate limbs (always in [0, LIMB_BASE)) ----------
        for limb_index in 0..NUM_LIMBS {
            for coordinate_limbs in [
                &main_local.accumulator_x,
                &main_local.accumulator_y,
                &main_local.accumulator_z,
                &main_local.accumulator_t,
            ] {
                send_one_cell(&mut lookups, self, coordinate_limbs[limb_index].into());
            }
        }

        // ---------- HWCD intermediate-result limbs (in [0, LIMB_BASE)) ----------
        // Pre-mul reduced sub-operands.
        for limb_index in 0..NUM_LIMBS {
            send_one_cell(
                &mut lookups,
                self,
                main_local.y_minus_x_reduced[limb_index].into(),
            );
            send_one_cell(
                &mut lookups,
                self,
                main_local.y_plus_x_reduced[limb_index].into(),
            );
        }
        // The eight HWCD intermediates A, B, C, D, E, F, G, H.
        for limb_index in 0..NUM_LIMBS {
            for hwcd_limbs in [
                &main_local.hwcd_a,
                &main_local.hwcd_b,
                &main_local.hwcd_c,
                &main_local.hwcd_d,
                &main_local.hwcd_e,
                &main_local.hwcd_f,
                &main_local.hwcd_g,
                &main_local.hwcd_h,
            ] {
                send_one_cell(&mut lookups, self, hwcd_limbs[limb_index].into());
            }
        }

        // ---------- Mul quotient limbs (in [0, LIMB_BASE)) ----------
        for limb_index in 0..NUM_LIMBS {
            for quotient_limbs in [
                &main_local.mul_a_quotient,
                &main_local.mul_b_quotient,
                &main_local.mul_c_quotient,
                &main_local.mul_xprime_quotient,
                &main_local.mul_yprime_quotient,
                &main_local.mul_zprime_quotient,
                &main_local.mul_tprime_quotient,
            ] {
                send_one_cell(&mut lookups, self, quotient_limbs[limb_index].into());
            }
        }

        // ---------- Mul carry cells (offset-shifted, in [0, 2^MUL_CARRY_RANGE_BITS)) ----------
        for carry_cell_index in 0..NUM_MUL_CARRY_CELLS {
            for carry_cells in [
                &main_local.mul_a_carry,
                &main_local.mul_b_carry,
                &main_local.mul_c_carry,
                &main_local.mul_xprime_carry,
                &main_local.mul_yprime_carry,
                &main_local.mul_zprime_carry,
                &main_local.mul_tprime_carry,
            ] {
                send_one_cell(&mut lookups, self, carry_cells[carry_cell_index].into());
            }
        }

        // ---------- Linear add/sub carry cells (offset-shifted, same range) ----------
        for carry_cell_index in 0..NUM_LINEAR_CARRY_CELLS {
            for carry_cells in [
                &main_local.linear_y_minus_x_carry,
                &main_local.linear_y_plus_x_carry,
                &main_local.linear_d_carry,
                &main_local.linear_e_carry,
                &main_local.linear_f_carry,
                &main_local.linear_g_carry,
                &main_local.linear_h_carry,
            ] {
                send_one_cell(&mut lookups, self, carry_cells[carry_cell_index].into());
            }
        }

        debug_assert_eq!(
            lookups.len(),
            TOTAL_RANGE_CHECK_SENDS_PER_ROW,
            "per-row range-check send count must match TOTAL_RANGE_CHECK_SENDS_PER_ROW"
        );

        // ---------- Public-value range checks (once per proof) ----------
        //
        // SOUNDNESS NOTE. The boundary mul `x_A · G ≡ E (mod p)` reads
        // `x_A` (and `y_A` for the second mul) as the LHS of a non-
        // native multiplication. Per spec §5 / §6.4, the per-position
        // closure equations require **every** participant — lhs, rhs,
        // quotient, result, carry — to be limb-wise range-checked,
        // otherwise a malicious prover can pick non-canonical
        // BabyBear values for an unchecked participant and adjust
        // carries within `[0, 2^MUL_CARRY_RANGE_BITS)` to satisfy the
        // closure. SP1 (`crates/curves/src/params.rs`), plonky2-ed25519
        // (`src/gadgets/`), and halo2-ecc-bigint (`carry_mod.rs`) all
        // range-check every participant for this reason.
        //
        // We send each of the 64 public-value cells (32 for `x_A`, 32
        // for `y_A`) to the `u16_range` bus exactly once per proof,
        // gated by the preprocessed indicator
        // `is_public_value_send_row` (= 1 only at row `LAST_ROW_INDEX`,
        // 0 elsewhere). The receive side counts these 64 events into
        // its multiplicity column; the multiset-equality of the LogUp
        // bus pins each public-value cell to a value in
        // `[0, LIMB_BASE)`.
        let public_value_send_gate: SymbolicExpression<F> =
            preprocessed_local.is_public_value_send_row.into();
        for public_value_index in 0..NUM_PUBLIC_VALUES {
            let public_value_cell: SymbolicExpression<F> =
                public_value_vars[public_value_index].into();
            let lookup_inputs = [(
                vec![public_value_cell],
                public_value_send_gate.clone(),
                Direction::Send,
            )];
            lookups.push(LookupAir::register_lookup(
                self,
                Kind::Global(U16_RANGE_BUS_NAME.to_string()),
                &lookup_inputs,
            ));
        }

        debug_assert_eq!(
            lookups.len(),
            TOTAL_RANGE_CHECK_SENDS_PER_ROW + NUM_PUBLIC_VALUES,
            "lookup count must match per-row sends + once-per-proof public-value sends"
        );
        lookups
    }
}
