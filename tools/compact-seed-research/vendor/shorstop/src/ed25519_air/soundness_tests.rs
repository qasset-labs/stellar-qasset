//! Witness-mutation soundness tests for the Ed25519 AIR.
//!
//! For every constraint family in [`Ed25519Air::eval`], at least one
//! test here mutates a single trace cell (or public-value cell) that
//! the constraint reads, then runs `prove_batch` and asserts the run is
//! rejected. Two reject paths are accepted:
//!
//!   - **Debug mode** (the default for `cargo test --lib`): plonky3's
//!     `check_constraints` iterates every row before FRI and panics
//!     with the failed constraint indices. We catch the panic with
//!     [`std::panic::catch_unwind`] and assert it fired.
//!   - **Release mode**: no debug check, the prover happily produces a
//!     proof; the FRI low-degree extension catches the violation and
//!     `verify_batch` returns `Err(VerificationError::*)`.
//!
//! Either path counts as the constraint doing its job. A test failing
//! here means we have a *dead column* — a cell whose value is not
//! enforced by any AIR constraint.
//!
//! **Distinction from constraint-removal sweep.** This file proves
//! "every cell is covered by at least one constraint". The dual
//! property — "every constraint catches at least one mutation" — is
//! the spec §6.5 constraint-removal sweep, which lives in
//! [`coverage_tests`] (parameterizes the AIR over a constraint mask
//! and disables one family at a time).

#![cfg(test)]

use core::borrow::BorrowMut;
use std::panic::AssertUnwindSafe;

use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::ed25519_air::columns::{Ed25519Cols, NUM_ED25519_COLS};
use crate::ed25519_air::constants::{
    CLAMP_HIGH_ONE_BIT_POS, CLAMP_HIGH_ZERO_BIT_POS, CLAMP_LOW_ZERO_BITS_POS, LAST_ROW_INDEX,
};
use crate::ed25519_air::prove_verify_helpers::build_batched_inputs;
use crate::ed25519_air::prove_verify_tests::{
    ED25519_EXT_TRACE_LOG_HEIGHT, RANGE_CHECK_EXT_TABLE_LOG_HEIGHT,
};
use crate::{Val, make_config};

/// Same scalar as the positive test, reused for predictability of
/// mutated rows (we know which rows are clamped and what bit values are
/// forced there).
fn sample_clamped_scalar() -> [u8; 32] {
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 0xF8;
    scalar_bytes[1] = 0x12;
    scalar_bytes[15] = 0x9A;
    scalar_bytes[20] = 0x7C;
    scalar_bytes[31] = 0x40;
    scalar_bytes
}

/// Borrow row `row_index` of the ed25519 trace as a `&mut Ed25519Cols`
/// for in-place mutation.
fn row_columns_mut(
    trace: &mut RowMajorMatrix<Val>,
    row_index: usize,
) -> &mut Ed25519Cols<Val> {
    let row_offset = row_index * NUM_ED25519_COLS;
    let row_slice: &mut [Val] = &mut trace.values[row_offset..row_offset + NUM_ED25519_COLS];
    row_slice.borrow_mut()
}

/// Run prove + verify on a (possibly mutated) batched input bundle and
/// assert the run is rejected — by either the debug constraint check
/// (panic) or by `verify_batch` (returned `Err`).
fn assert_prove_or_verify_rejects(
    expectation_label: &'static str,
    mut inputs: crate::ed25519_air::prove_verify_helpers::BatchedInputs,
) {
    let config = make_config();
    let prover_data = ProverData::from_airs_and_degrees(
        &config,
        &mut inputs.airs,
        &[ED25519_EXT_TRACE_LOG_HEIGHT, RANGE_CHECK_EXT_TABLE_LOG_HEIGHT],
    );
    let traces = [&inputs.ed25519_trace, &inputs.range_check_trace];
    let public_values_per_instance =
        [inputs.ed25519_public_values.clone(), Vec::<Val>::new()];

    let common = &prover_data.common;
    let instances =
        StarkInstance::new_multiple(&inputs.airs, &traces, &public_values_per_instance, common);

    // Silence the panic message — it would otherwise dump the failed
    // constraint indices to stderr on every soundness run, drowning
    // honest test output. Restore the previous hook on the way out.
    let previous_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let prove_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        prove_batch(&config, &instances, &prover_data)
    }));
    std::panic::set_hook(previous_panic_hook);

    match prove_result {
        // Debug-mode reject path: prover's `check_constraints` panicked.
        Err(_panic_payload) => {}
        // Release-mode reject path: prover produced a proof; verifier
        // must reject it.
        Ok(proof) => {
            let public_values =
                vec![inputs.ed25519_public_values, Vec::<Val>::new()];
            let verify_result =
                verify_batch(&config, &inputs.airs, &proof, &public_values, common);
            assert!(
                verify_result.is_err(),
                "{expectation_label}: prove_batch succeeded AND verify_batch \
                 accepted the mutated trace — column is dead (not enforced \
                 by any constraint)"
            );
        }
    }
}

#[test]
fn mutating_scalar_bit_witness_rejects_two_valued_bit() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Pick a non-clamped row so we don't double-fail with the clamp
    // constraint (which would still reject, but it's cleaner to
    // isolate the boolean check here).
    let target_row = 100;
    row_columns_mut(&mut inputs.ed25519_trace, target_row).scalar_bit =
        Val::from_u64(2);
    assert_prove_or_verify_rejects("scalar-bit-boolean", inputs);
}

#[test]
fn mutating_initial_accumulator_witness_rejects_nonidentity_row_zero() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Row 0's accumulator must equal the identity (0, 1, 1, 0). Bumping
    // accumulator_x[0] from 0 to 1 violates the boundary on $X_0 = 0$.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 0);
    columns.accumulator_x[0] = Val::ONE;
    assert_prove_or_verify_rejects("initial-accumulator-boundary", inputs);
}

#[test]
fn mutating_scalar_bit_witness_rejects_unclamped_low_bit() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Force bit 0 to 1, contradicting the clamp `s ≡ 0 (mod 8)`.
    let target_row = CLAMP_LOW_ZERO_BITS_POS[0];
    row_columns_mut(&mut inputs.ed25519_trace, target_row).scalar_bit = Val::ONE;
    assert_prove_or_verify_rejects("scalar-clamping-low-bit", inputs);
}

#[test]
fn mutating_muxed_table_witness_rejects_wrong_zero_bit_value() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Row 0 has scalar_bit = 0 (clamped), so muxed_table_y_minus_x must
    // equal the identity component 1. Stomping limb 0 to 0 leaves the
    // mux constraint $\text{muxed}_0 - 1 = 0$ unsatisfied.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 0);
    columns.muxed_table_y_minus_x[0] = Val::ZERO;
    assert_prove_or_verify_rejects("table-entry-mux-zero-bit", inputs);
}

#[test]
fn mutating_muxed_table_witness_rejects_wrong_one_bit_value() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Bit 254 is forced to 1 by clamp, so muxed_table_y_minus_x must
    // equal precomputed_y_minus_x[254]. Add 1 to break the equality.
    let target_row = CLAMP_HIGH_ONE_BIT_POS;
    let columns = row_columns_mut(&mut inputs.ed25519_trace, target_row);
    columns.muxed_table_y_minus_x[5] = columns.muxed_table_y_minus_x[5] + Val::ONE;
    assert_prove_or_verify_rejects("table-entry-mux-one-bit", inputs);
}

#[test]
fn mutating_pre_mul_reduction_witness_rejects_corrupted_y_minus_x_reduced() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // y_minus_x_reduced is the result of the linear sub Y - X reduced
    // modulo p. Adding 1 to a limb breaks the linear-mod constraint.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.y_minus_x_reduced[0] = columns.y_minus_x_reduced[0] + Val::ONE;
    assert_prove_or_verify_rejects("pre-mul-linear-y-minus-x", inputs);
}

#[test]
fn mutating_input_mul_a_quotient_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.mul_a_quotient[0] = columns.mul_a_quotient[0] + Val::ONE;
    assert_prove_or_verify_rejects("input-mul-a-quotient", inputs);
}

#[test]
fn mutating_input_mul_a_carry_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.mul_a_carry[0] = columns.mul_a_carry[0] + Val::ONE;
    assert_prove_or_verify_rejects("input-mul-a-carry", inputs);
}

#[test]
fn mutating_output_mul_transition_witness_rejects_corrupted_next_row_x() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // The transition constraint at row 0 binds row-1's accumulator X
    // to the HWCD output computed from row 0's intermediates.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 1);
    columns.accumulator_x[0] = columns.accumulator_x[0] + Val::ONE;
    assert_prove_or_verify_rejects("output-mul-transition-X", inputs);
}

#[test]
fn mutating_linear_carry_witness_rejects_off_by_one_e_carry() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // The linear-mod chain constraints close per-position carry sums
    // for the seven add/sub ops (Y-X, Y+X, D, E, F, G, H).
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.linear_e_carry[0] = columns.linear_e_carry[0] + Val::ONE;
    assert_prove_or_verify_rejects("linear-mod-e-carry", inputs);
}

#[test]
fn mutating_x_a_public_value_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // The last-row boundary mul `x_A · G ≡ E (mod p)` reads x_A from
    // public_values[0..NUM_LIMBS]. Bumping x_A[0] by 1 (still in
    // range) breaks the mul's per-position closure — caught by the
    // mul constraint, NOT by the new public-value range check.
    inputs.ed25519_public_values[0] = inputs.ed25519_public_values[0] + Val::ONE;
    assert_prove_or_verify_rejects("last-row-boundary-x-a", inputs);
}

#[test]
fn mutating_y_a_public_value_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Symmetric to the x_A case: bumping y_A[0] (= public_values[NUM_LIMBS])
    // breaks the boundary mul `y_A · F ≡ H (mod p)`.
    use crate::ed25519_air::constants::NUM_LIMBS;
    inputs.ed25519_public_values[NUM_LIMBS] =
        inputs.ed25519_public_values[NUM_LIMBS] + Val::ONE;
    assert_prove_or_verify_rejects("last-row-boundary-y-a", inputs);
}

#[test]
fn mutating_x_a_public_value_rejects_out_of_range_value() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Set x_A[0] to a value far outside the per-limb range [0, 2^8).
    // Without the gated public-value LogUp send (the fix for the
    // independent reviewer's "Claim A" gap — public values are otherwise
    // not range-checked), an attacker could set this to an arbitrary
    // BabyBear value and adjust mul-boundary carries to satisfy the
    // per-position closure modulo BabyBear (mirroring the standard
    // textbook gap that SP1 / plonky2-ed25519 / halo2-ecc-bigint all
    // close by range-checking every multiplication participant).
    //
    // With the gated send, the receive-side LogUp multiset-equality
    // forces the cell to be in [0, 2^16) — and since neither the
    // receive table nor the honest extracted multiplicities cover
    // 0x12345 = 74565, the proof must be rejected.
    inputs.ed25519_public_values[0] = Val::from_u64(0x12345);
    assert_prove_or_verify_rejects("public-value-x-a-out-of-range", inputs);
}

#[test]
fn mutating_last_row_hwcd_e_witness_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Symmetric to the public-value mutation: leave public values honest,
    // but corrupt the last row's hwcd_e (= E in the boundary equation
    // `x_A · G ≡ E`). The boundary mul fails its per-position closure.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, LAST_ROW_INDEX);
    columns.hwcd_e[0] = columns.hwcd_e[0] + Val::ONE;
    assert_prove_or_verify_rejects("last-row-boundary-hwcd-e", inputs);
}

#[test]
fn mutating_linear_sigma_flag_rejects_flipped_witness() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // The sigma flag picks whether the per-position closure adds `p`
    // back to the LHS (when honest unreduced LHS underflowed). Toggling
    // it from honest 0 → 1 (or 1 → 0) shifts the LHS by ±p, breaking
    // the per-limb identity. Note: the boolean check still passes
    // (toggled value is still in {0, 1}); the per-position closure is
    // what catches the flip.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.linear_y_minus_x_reduction_flag =
        Val::ONE - columns.linear_y_minus_x_reduction_flag;
    assert_prove_or_verify_rejects("linear-mod-sigma-flip", inputs);
}

#[test]
fn mutating_scalar_bit_witness_rejects_unclamped_high_one_bit() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    row_columns_mut(&mut inputs.ed25519_trace, CLAMP_HIGH_ONE_BIT_POS).scalar_bit =
        Val::ZERO;
    assert_prove_or_verify_rejects("scalar-clamping-high-one-bit", inputs);
}

#[test]
fn mutating_scalar_bit_witness_rejects_unclamped_high_zero_bit() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    row_columns_mut(&mut inputs.ed25519_trace, CLAMP_HIGH_ZERO_BIT_POS).scalar_bit =
        Val::ONE;
    assert_prove_or_verify_rejects("scalar-clamping-high-zero-bit", inputs);
}

#[test]
fn mutating_input_mul_b_quotient_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    // Mul B is a separate constraint family from Mul A; mutating its
    // quotient catches a copy-paste bug where `evaluate_mul_b_constraint`
    // accidentally wires Mul A's columns instead.
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.mul_b_quotient[0] = columns.mul_b_quotient[0] + Val::ONE;
    assert_prove_or_verify_rejects("input-mul-b-quotient", inputs);
}

#[test]
fn mutating_input_mul_c_quotient_rejects_off_by_one() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 50);
    columns.mul_c_quotient[0] = columns.mul_c_quotient[0] + Val::ONE;
    assert_prove_or_verify_rejects("input-mul-c-quotient", inputs);
}

#[test]
fn mutating_output_mul_transition_witness_rejects_corrupted_next_row_t() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);
    let columns = row_columns_mut(&mut inputs.ed25519_trace, 1);
    columns.accumulator_t[0] = columns.accumulator_t[0] + Val::ONE;
    assert_prove_or_verify_rejects("output-mul-transition-T", inputs);
}
