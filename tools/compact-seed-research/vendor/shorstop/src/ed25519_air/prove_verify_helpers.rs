//! Shared helpers for the batched Ed25519 + RangeCheckU16 prove/verify
//! path. Used by integration tests AND by the production
//! `crate::bip39_to_solana::prove` chain proof.
//!
//! Two helpers are factored out:
//!
//!   - [`extract_all_range_check_send_events`] walks an ed25519 trace
//!     and reproduces the exact `LookupAir::Send` set so the receive
//!     side (range-check multiplicities) can be built from it.
//!   - [`build_batched_inputs`] composes the two AIRs, generates both
//!     traces, and packages the public values for `prove_batch` /
//!     `verify_batch`.

use core::borrow::Borrow;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;

use crate::batched_air::BatchedAir;
use crate::ed25519_air::air::{Ed25519Air, NUM_PUBLIC_VALUES, TOTAL_RANGE_CHECK_SENDS_PER_ROW};
use crate::ed25519_air::columns::{Ed25519Cols, NUM_ED25519_COLS};
use crate::ed25519_air::constants::{LIMB_BASE, MUL_CARRY_RANGE_BITS, NUM_LIMBS};
use crate::ed25519_air::generation::generate_trace as generate_ed25519_trace;
use crate::ed25519_air::mul_witness::{NUM_LINEAR_CARRY_CELLS, NUM_MUL_CARRY_CELLS};
use crate::ed25519_air::point::PointRepresentation;
use crate::range_check_u16_air::air::RangeCheckU16Air;
use crate::range_check_u16_air::generation::generate_trace as generate_range_check_trace;
use crate::Val;

/// Aggregate output of [`build_batched_inputs`].
///
/// Owning the `airs` here lets callers pass a `&mut` slice to
/// `ProverData::from_airs_and_degrees` (which mutates lookup-column
/// metadata) without juggling temporaries at the call site. The
/// `final_accumulator` field is exposed so RFC-vector tests can
/// cross-check the trace's final point against an external public-key
/// without regenerating the trace.
pub(crate) struct BatchedInputs {
    pub(crate) airs: [BatchedAir; 2],
    pub(crate) ed25519_trace: p3_matrix::dense::RowMajorMatrix<Val>,
    pub(crate) range_check_trace: p3_matrix::dense::RowMajorMatrix<Val>,
    pub(crate) ed25519_public_values: Vec<Val>,
    pub(crate) final_accumulator: PointRepresentation,
}

/// Walk the ed25519 trace and collect every value the AIR's `LookupAir`
/// `Send`s to the global `u16_range` bus, in `Lookup` order, into a
/// flat `Vec<u16>`. The receive side counts each value's frequency to
/// build the range-check multiplicity column.
///
/// Per-row send categories (matches `Ed25519Air::get_lookups` ordering):
///
///   - Accumulator coords $(X, Y, Z, T)$ — `NUM_LIMBS` limbs each.
///   - Pre-mul reduced sub-operands `y_minus_x_reduced`, `y_plus_x_reduced`.
///   - HWCD intermediates $A, B, C, D, E, F, G, H$.
///   - 7 mul quotient limb arrays (input + output muls).
///   - 7 mul carry-cell arrays, offset-shifted into `[0, 2^MUL_CARRY_RANGE_BITS)`.
///   - 7 linear add/sub carry-cell arrays, offset-shifted.
///
/// Plus 64 once-per-proof public-value cells (32 limbs of $x_A$ + 32
/// limbs of $y_A$), gated by the `is_public_value_send_row` indicator
/// to fire only at row `LAST_ROW_INDEX`. Receive side counts these
/// once each into the multiplicity column.
pub(crate) fn extract_all_range_check_send_events(
    trace: &p3_matrix::dense::RowMajorMatrix<Val>,
    final_accumulator: &PointRepresentation,
    scalar_bytes: &[u8; 32],
) -> Vec<u16> {
    let row_count = trace.height();
    let mut events: Vec<u16> = Vec::with_capacity(row_count * TOTAL_RANGE_CHECK_SENDS_PER_ROW);

    let push_limb_cell = |events: &mut Vec<u16>, val: Val| {
        let canonical: u32 = val.as_canonical_u32();
        debug_assert!(
            canonical < (LIMB_BASE as u32),
            "honest trace must produce LIMB_BITS-canonical limbs"
        );
        events.push(canonical as u16);
    };
    let push_shifted_carry_cell = |events: &mut Vec<u16>, val: Val| {
        let canonical: u32 = val.as_canonical_u32();
        debug_assert!(
            canonical < (1u32 << MUL_CARRY_RANGE_BITS as u32),
            "honest trace must produce MUL_CARRY_RANGE_BITS-bounded shifted carries"
        );
        events.push(canonical as u16);
    };

    for row_index in 0..row_count {
        let row_slice: &[Val] =
            &trace.values[row_index * NUM_ED25519_COLS..(row_index + 1) * NUM_ED25519_COLS];
        let columns: &Ed25519Cols<Val> = row_slice.borrow();

        // Accumulator coordinates.
        for limb_index in 0..NUM_LIMBS {
            for limb_value in [
                columns.accumulator_x[limb_index],
                columns.accumulator_y[limb_index],
                columns.accumulator_z[limb_index],
                columns.accumulator_t[limb_index],
            ] {
                push_limb_cell(&mut events, limb_value);
            }
        }
        // Pre-mul reduced sub-operands.
        for limb_index in 0..NUM_LIMBS {
            push_limb_cell(&mut events, columns.y_minus_x_reduced[limb_index]);
            push_limb_cell(&mut events, columns.y_plus_x_reduced[limb_index]);
        }
        // HWCD intermediates A..H.
        for limb_index in 0..NUM_LIMBS {
            for hwcd_value in [
                columns.hwcd_a[limb_index],
                columns.hwcd_b[limb_index],
                columns.hwcd_c[limb_index],
                columns.hwcd_d[limb_index],
                columns.hwcd_e[limb_index],
                columns.hwcd_f[limb_index],
                columns.hwcd_g[limb_index],
                columns.hwcd_h[limb_index],
            ] {
                push_limb_cell(&mut events, hwcd_value);
            }
        }
        // Mul quotient limbs.
        for limb_index in 0..NUM_LIMBS {
            for quotient_value in [
                columns.mul_a_quotient[limb_index],
                columns.mul_b_quotient[limb_index],
                columns.mul_c_quotient[limb_index],
                columns.mul_xprime_quotient[limb_index],
                columns.mul_yprime_quotient[limb_index],
                columns.mul_zprime_quotient[limb_index],
                columns.mul_tprime_quotient[limb_index],
            ] {
                push_limb_cell(&mut events, quotient_value);
            }
        }
        // Mul carry cells (offset-shifted).
        for carry_cell_index in 0..NUM_MUL_CARRY_CELLS {
            for carry_value in [
                columns.mul_a_carry[carry_cell_index],
                columns.mul_b_carry[carry_cell_index],
                columns.mul_c_carry[carry_cell_index],
                columns.mul_xprime_carry[carry_cell_index],
                columns.mul_yprime_carry[carry_cell_index],
                columns.mul_zprime_carry[carry_cell_index],
                columns.mul_tprime_carry[carry_cell_index],
            ] {
                push_shifted_carry_cell(&mut events, carry_value);
            }
        }
        // Linear add/sub carry cells (offset-shifted).
        for carry_cell_index in 0..NUM_LINEAR_CARRY_CELLS {
            for carry_value in [
                columns.linear_y_minus_x_carry[carry_cell_index],
                columns.linear_y_plus_x_carry[carry_cell_index],
                columns.linear_d_carry[carry_cell_index],
                columns.linear_e_carry[carry_cell_index],
                columns.linear_f_carry[carry_cell_index],
                columns.linear_g_carry[carry_cell_index],
                columns.linear_h_carry[carry_cell_index],
            ] {
                push_shifted_carry_cell(&mut events, carry_value);
            }
        }
    }
    debug_assert_eq!(
        events.len(),
        row_count * TOTAL_RANGE_CHECK_SENDS_PER_ROW,
        "per-row extracted send-event count must match TOTAL_RANGE_CHECK_SENDS_PER_ROW × rows"
    );

    // Public-value sends (96 cells, exactly once per proof). Order
    // matches `Ed25519Air::get_lookups`: x_A limbs, y_A limbs, then
    // scalar_packed bytes (Phase 5 addition that binds the scalar to
    // upstream `priv_packed` via the AIR's `scalar_byte_accumulator`).
    let (x_affine, y_affine) = final_accumulator.to_affine();
    for &limb_value in x_affine.limbs().iter() {
        push_limb_cell(&mut events, Val::from_u64(limb_value as u64));
    }
    for &limb_value in y_affine.limbs().iter() {
        push_limb_cell(&mut events, Val::from_u64(limb_value as u64));
    }
    for &byte_value in scalar_bytes.iter() {
        push_limb_cell(&mut events, Val::from_u64(byte_value as u64));
    }
    debug_assert_eq!(
        events.len(),
        row_count * TOTAL_RANGE_CHECK_SENDS_PER_ROW + NUM_PUBLIC_VALUES,
        "total event count must include the 96 once-per-proof public-value sends"
    );

    events
}

/// Build the two STARK instances for a batched ed25519 + range-check
/// proof of one fixed-base scalar multiplication.
pub(crate) fn build_batched_inputs(scalar_bytes: &[u8; 32]) -> BatchedInputs {
    let (ed25519_trace, final_accumulator) = generate_ed25519_trace::<Val>(scalar_bytes);
    let send_events =
        extract_all_range_check_send_events(&ed25519_trace, &final_accumulator, scalar_bytes);
    let range_check_trace = generate_range_check_trace::<Val>(&send_events);

    // Public values for the Ed25519 instance: laid out as
    //   [x_A (32 × 8-bit) || y_A (32 × 8-bit) || scalar_packed (32 × 8-bit)]
    // per the post-Phase-5 PV schema. `scalar_packed` is the byte-flat
    // little-endian encoding of the scalar bytes (== `scalar_bytes`),
    // bound to per-row scalar_bit cells via `evaluate_scalar_byte_accumulator`.
    let (x_affine, y_affine) = final_accumulator.to_affine();
    let mut ed25519_public_values: Vec<Val> = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &limb_value in x_affine.limbs().iter() {
        ed25519_public_values.push(Val::from_u64(limb_value as u64));
    }
    for &limb_value in y_affine.limbs().iter() {
        ed25519_public_values.push(Val::from_u64(limb_value as u64));
    }
    for &byte_value in scalar_bytes.iter() {
        ed25519_public_values.push(Val::from_u64(byte_value as u64));
    }
    debug_assert_eq!(ed25519_public_values.len(), NUM_PUBLIC_VALUES);

    let airs = [
        BatchedAir::Ed25519(Ed25519Air::default()),
        BatchedAir::RangeCheckU16(RangeCheckU16Air::default()),
    ];
    BatchedInputs {
        airs,
        ed25519_trace,
        range_check_trace,
        ed25519_public_values,
        final_accumulator,
    }
}
