//! Trace generation for the Ed25519 fixed-base scalar-mult AIR.
//!
//! Given a clamped scalar $s$, compute $A = [s] B$ in extended Edwards
//! coordinates, filling all columns of all 256 rows. The algorithm is the
//! LSB-first conditional-add against the precomputed table $R_t = [2^t] B$
//! described in `docs/ed25519-spec.md` §2.8.
//!
//! Independent implementation based on the spec — not a port of any
//! reference.

use core::borrow::BorrowMut;

use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

use crate::ed25519_air::columns::{Ed25519Cols, NUM_ED25519_COLS};
use crate::ed25519_air::constants::{
    LAST_ROW_INDEX, LINEAR_CARRY_OFFSET, MUL_CARRY_OFFSET, NUM_LIMBS, NUM_ROWS_PER_SCALAR_MUL,
};
use crate::ed25519_air::field::FieldLimbs;
use crate::ed25519_air::mul_witness::{
    compute_add_witness, compute_double_witness, compute_mul_witness, compute_sub_witness,
    LinearModWitness, MulWitness, NUM_LINEAR_CARRY_CELLS, NUM_MUL_CARRY_CELLS,
};
use crate::ed25519_air::point::{MixedAddIntermediates, PointRepresentation};
use crate::ed25519_air::precomputed_base_multiples::PRECOMPUTED_BASE_MULTIPLES;

/// Build the AIR trace for a single scalar multiplication $A = [s] B$.
///
/// `scalar_bytes_le` is the 32-byte little-endian scalar. The caller is
/// responsible for clamping; the AIR re-checks clamping via boundary
/// constraints.
///
/// Returns the trace plus the final accumulator $(X, Y, Z, T)$ — the
/// extended-Edwards representation of $[s] B$. The final accumulator is
/// not stored in the trace itself (the trace's row-$t$ accumulator is
/// the state *entering* row $t$); it's returned alongside for tests
/// and for the test harness to derive the public-input affine
/// coordinates $(x_A, y_A) = (X / Z, Y / Z) \pmod p$.
///
/// **Last-row witness shape**. Per spec §4.6, the row-`LAST_ROW_INDEX`
/// boundary uses `mul_xprime_*` to witness `x_A · G ≡ E (mod p)` and
/// `mul_yprime_*` to witness `y_A · F ≡ H (mod p)` — *not* the
/// transition products `(E·F, G·H, F·G, E·H)`. The transition is gated
/// by `when_transition`, which excludes the last row, so the
/// transition mul witnesses would be unused there anyway. To keep the
/// per-row column shape uniform we still commit `mul_zprime_*` and
/// `mul_tprime_*` at the last row, but with zeroed quotient + offset-
/// shifted-zero carries (the AIR has no constraint on them at the last
/// row).
pub fn generate_trace<F: PrimeField64>(
    scalar_bytes_le: &[u8; 32],
) -> (RowMajorMatrix<F>, PointRepresentation) {
    let total_rows = NUM_ROWS_PER_SCALAR_MUL;
    let mut trace_values = vec![F::ZERO; total_rows * NUM_ED25519_COLS];

    // First pass: walk all 256 rows computing the running accumulator and
    // populating the row's witness as if it were a transition row. The
    // last row will be patched after the loop, once we have the full
    // final accumulator and can recover its affine coords for the
    // boundary muls.
    let mut accumulator_point = PointRepresentation::IDENTITY;
    let mut last_row_intermediates: Option<MixedAddIntermediates> = None;
    // Running byte-accumulator: resets to 0 at byte starts, then
    // accumulates 2^bit_pos · scalar_bit per row. At byte-end rows
    // the value matches `scalar_packed[byte_index]` (the AIR's PV).
    let mut byte_accumulator: u64 = 0;
    for (bit_index, row_chunk) in trace_values
        .chunks_exact_mut(NUM_ED25519_COLS)
        .enumerate()
    {
        let scalar_bit_value = scalar_bit_at(scalar_bytes_le, bit_index);
        let bit_pos_in_byte = bit_index % 8;
        let bit_weight = 1u64 << bit_pos_in_byte;
        if bit_pos_in_byte == 0 {
            byte_accumulator = if scalar_bit_value { 1 } else { 0 };
        } else {
            byte_accumulator += bit_weight * if scalar_bit_value { 1 } else { 0 };
        }
        let table_entry = &PRECOMPUTED_BASE_MULTIPLES[bit_index];
        let (next_accumulator_point, mixed_add_intermediates) =
            accumulator_point.step(scalar_bit_value, table_entry);
        populate_row(
            row_chunk,
            scalar_bit_value,
            byte_accumulator,
            &accumulator_point,
            table_entry,
            &mixed_add_intermediates,
        );
        if bit_index == LAST_ROW_INDEX {
            last_row_intermediates = Some(mixed_add_intermediates);
        }
        accumulator_point = next_accumulator_point;
    }

    // Second pass: rewrite the last row's `mul_xprime_*`, `mul_yprime_*`,
    // `mul_zprime_*`, `mul_tprime_*` witnesses to match the boundary
    // constraint (spec §4.6). The first pass populated them as the
    // transition products; the AIR doesn't constrain those at the last
    // row, but the LookupAir sends every cell to `u16_range`, so the
    // committed cells must still be in range. We overwrite with the
    // boundary-mul quotients/carries (for xprime, yprime) and with
    // offset-shifted zero (for zprime, tprime).
    let last_row_intermediates = last_row_intermediates.expect("last row is always reached");
    let (x_affine, y_affine) = accumulator_point.to_affine();
    patch_last_row_with_boundary_witnesses(
        &mut trace_values,
        &x_affine,
        &y_affine,
        &last_row_intermediates,
    );

    (
        RowMajorMatrix::new(trace_values, NUM_ED25519_COLS),
        accumulator_point,
    )
}

/// Overwrite the last row's `mul_xprime_*`, `mul_yprime_*`,
/// `mul_zprime_*`, `mul_tprime_*` witnesses so they match the
/// row-`LAST_ROW_INDEX` boundary constraint
/// (`x_A · G ≡ E`, `y_A · F ≡ H`) instead of the transition's
/// `(E·F, G·H, F·G, E·H)` products.
fn patch_last_row_with_boundary_witnesses<F: PrimeField64>(
    trace_values: &mut [F],
    x_affine: &FieldLimbs,
    y_affine: &FieldLimbs,
    last_row_intermediates: &MixedAddIntermediates,
) {
    let row_offset = LAST_ROW_INDEX * NUM_ED25519_COLS;
    let row_slice = &mut trace_values[row_offset..row_offset + NUM_ED25519_COLS];
    let columns: &mut Ed25519Cols<F> = row_slice.borrow_mut();

    // x_A · G ≡ E (mod p) — uses the existing `mul_xprime_*` columns.
    let x_a_times_g_witness = compute_mul_witness(x_affine, &last_row_intermediates.g);
    debug_assert_eq!(
        x_a_times_g_witness.result, last_row_intermediates.e,
        "boundary mul x_A·G must equal E (modulo p) by HWCD output factorisation",
    );
    write_mul_witness_to_columns(
        &mut columns.mul_xprime_quotient,
        &mut columns.mul_xprime_carry,
        &x_a_times_g_witness,
    );

    // y_A · F ≡ H (mod p) — uses the existing `mul_yprime_*` columns.
    let y_a_times_f_witness = compute_mul_witness(y_affine, &last_row_intermediates.f);
    debug_assert_eq!(
        y_a_times_f_witness.result, last_row_intermediates.h,
        "boundary mul y_A·F must equal H (modulo p) by HWCD output factorisation",
    );
    write_mul_witness_to_columns(
        &mut columns.mul_yprime_quotient,
        &mut columns.mul_yprime_carry,
        &y_a_times_f_witness,
    );

    // mul_zprime_*, mul_tprime_*: unconstrained at the last row. Zero
    // quotient + offset-shifted-zero carries leaves the cells in range
    // for the LookupAir send.
    for quotient_slot in columns.mul_zprime_quotient.iter_mut() {
        *quotient_slot = F::ZERO;
    }
    for quotient_slot in columns.mul_tprime_quotient.iter_mut() {
        *quotient_slot = F::ZERO;
    }
    for carry_slot in columns.mul_zprime_carry.iter_mut() {
        *carry_slot = lift_offset_shifted_carry::<F>(0, MUL_CARRY_OFFSET);
    }
    for carry_slot in columns.mul_tprime_carry.iter_mut() {
        *carry_slot = lift_offset_shifted_carry::<F>(0, MUL_CARRY_OFFSET);
    }
}

/// Extract bit `bit_index` of the little-endian byte array `scalar_bytes`.
fn scalar_bit_at(scalar_bytes: &[u8; 32], bit_index: usize) -> bool {
    (scalar_bytes[bit_index / 8] >> (bit_index % 8)) & 1 == 1
}

/// Populate one row's `scalar_bit`, accumulator coordinates, the muxed
/// mixed-add right-operand columns, and the eight HWCD intermediates.
/// The mux value matches what [`PointRepresentation::step`] uses
/// internally: identity components $(1, 1, 0)$ when
/// `scalar_bit_value = false`, the precomputed table row otherwise.
fn populate_row<F: PrimeField64>(
    row: &mut [F],
    scalar_bit_value: bool,
    byte_accumulator: u64,
    accumulator_point: &PointRepresentation,
    table_entry: &[[u8; NUM_LIMBS]; 3],
    mixed_add_intermediates: &MixedAddIntermediates,
) {
    debug_assert_eq!(row.len(), NUM_ED25519_COLS);
    let columns: &mut Ed25519Cols<F> = row.borrow_mut();
    columns.scalar_bit = if scalar_bit_value { F::ONE } else { F::ZERO };
    columns.scalar_byte_accumulator = F::from_u64(byte_accumulator);
    write_field_to_columns(&mut columns.accumulator_x, &accumulator_point.x);
    write_field_to_columns(&mut columns.accumulator_y, &accumulator_point.y);
    write_field_to_columns(&mut columns.accumulator_z, &accumulator_point.z);
    write_field_to_columns(&mut columns.accumulator_t, &accumulator_point.t);

    let identity_y_minus_x = FieldLimbs::ONE.0;
    let identity_y_plus_x = FieldLimbs::ONE.0;
    let identity_two_d_xy = FieldLimbs::ZERO.0;
    let (muxed_y_minus_x, muxed_y_plus_x, muxed_two_d_xy) = if scalar_bit_value {
        (table_entry[0], table_entry[1], table_entry[2])
    } else {
        (identity_y_minus_x, identity_y_plus_x, identity_two_d_xy)
    };
    write_u8_limbs_to_columns(&mut columns.muxed_table_y_minus_x, &muxed_y_minus_x);
    write_u8_limbs_to_columns(&mut columns.muxed_table_y_plus_x, &muxed_y_plus_x);
    write_u8_limbs_to_columns(&mut columns.muxed_table_two_d_xy, &muxed_two_d_xy);

    write_field_to_columns(
        &mut columns.y_minus_x_reduced,
        &mixed_add_intermediates.y_minus_x,
    );
    write_field_to_columns(
        &mut columns.y_plus_x_reduced,
        &mixed_add_intermediates.y_plus_x,
    );

    write_field_to_columns(&mut columns.hwcd_a, &mixed_add_intermediates.a);
    write_field_to_columns(&mut columns.hwcd_b, &mixed_add_intermediates.b);
    write_field_to_columns(&mut columns.hwcd_c, &mixed_add_intermediates.c);
    write_field_to_columns(&mut columns.hwcd_d, &mixed_add_intermediates.d);
    write_field_to_columns(&mut columns.hwcd_e, &mixed_add_intermediates.e);
    write_field_to_columns(&mut columns.hwcd_f, &mixed_add_intermediates.f);
    write_field_to_columns(&mut columns.hwcd_g, &mixed_add_intermediates.g);
    write_field_to_columns(&mut columns.hwcd_h, &mixed_add_intermediates.h);

    // Mul A = (Y - X) · muxed_y_minus_x = hwcd_a (mod p).
    // Compute the quotient + carry witnesses the AIR will verify.
    let muxed_y_minus_x_field = FieldLimbs::from_limbs(muxed_y_minus_x);
    let mul_a_witness =
        compute_mul_witness(&mixed_add_intermediates.y_minus_x, &muxed_y_minus_x_field);
    debug_assert_eq!(
        mul_a_witness.result, mixed_add_intermediates.a,
        "mul A witness result must match the off-circuit field product"
    );
    write_mul_witness_to_columns(
        &mut columns.mul_a_quotient,
        &mut columns.mul_a_carry,
        &mul_a_witness,
    );

    // Mul B = (Y + X) · muxed_y_plus_x = hwcd_b (mod p).
    let muxed_y_plus_x_field = FieldLimbs::from_limbs(muxed_y_plus_x);
    let mul_b_witness =
        compute_mul_witness(&mixed_add_intermediates.y_plus_x, &muxed_y_plus_x_field);
    debug_assert_eq!(
        mul_b_witness.result, mixed_add_intermediates.b,
        "mul B witness result must match the off-circuit field product"
    );
    write_mul_witness_to_columns(
        &mut columns.mul_b_quotient,
        &mut columns.mul_b_carry,
        &mul_b_witness,
    );

    // Mul C = T · muxed_two_d_xy = hwcd_c (mod p).
    let muxed_two_d_xy_field = FieldLimbs::from_limbs(muxed_two_d_xy);
    let mul_c_witness = compute_mul_witness(&accumulator_point.t, &muxed_two_d_xy_field);
    debug_assert_eq!(
        mul_c_witness.result, mixed_add_intermediates.c,
        "mul C witness result must match the off-circuit field product"
    );
    write_mul_witness_to_columns(
        &mut columns.mul_c_quotient,
        &mut columns.mul_c_carry,
        &mul_c_witness,
    );

    // Output mul X' = E · F = next_row.accumulator_x (mod p).
    let mul_xprime_witness =
        compute_mul_witness(&mixed_add_intermediates.e, &mixed_add_intermediates.f);
    write_mul_witness_to_columns(
        &mut columns.mul_xprime_quotient,
        &mut columns.mul_xprime_carry,
        &mul_xprime_witness,
    );

    // Output mul Y' = G · H = next_row.accumulator_y (mod p).
    let mul_yprime_witness =
        compute_mul_witness(&mixed_add_intermediates.g, &mixed_add_intermediates.h);
    write_mul_witness_to_columns(
        &mut columns.mul_yprime_quotient,
        &mut columns.mul_yprime_carry,
        &mul_yprime_witness,
    );

    // Output mul Z' = F · G = next_row.accumulator_z (mod p).
    let mul_zprime_witness =
        compute_mul_witness(&mixed_add_intermediates.f, &mixed_add_intermediates.g);
    write_mul_witness_to_columns(
        &mut columns.mul_zprime_quotient,
        &mut columns.mul_zprime_carry,
        &mul_zprime_witness,
    );

    // Output mul T' = E · H = next_row.accumulator_t (mod p).
    let mul_tprime_witness =
        compute_mul_witness(&mixed_add_intermediates.e, &mixed_add_intermediates.h);
    write_mul_witness_to_columns(
        &mut columns.mul_tprime_quotient,
        &mut columns.mul_tprime_carry,
        &mul_tprime_witness,
    );

    // Linear modular witnesses for the seven add/sub/double operations
    // closing the HWCD chain. Order matches MixedAddIntermediates'
    // computation order so each derived value reuses prior results.
    let y_minus_x_witness = compute_sub_witness(&accumulator_point.y, &accumulator_point.x);
    debug_assert_eq!(y_minus_x_witness.result, mixed_add_intermediates.y_minus_x);
    write_linear_witness_to_columns(
        &mut columns.linear_y_minus_x_reduction_flag,
        &mut columns.linear_y_minus_x_carry,
        &y_minus_x_witness,
    );

    let y_plus_x_witness = compute_add_witness(&accumulator_point.y, &accumulator_point.x);
    debug_assert_eq!(y_plus_x_witness.result, mixed_add_intermediates.y_plus_x);
    write_linear_witness_to_columns(
        &mut columns.linear_y_plus_x_reduction_flag,
        &mut columns.linear_y_plus_x_carry,
        &y_plus_x_witness,
    );

    let d_witness = compute_double_witness(&accumulator_point.z);
    debug_assert_eq!(d_witness.result, mixed_add_intermediates.d);
    write_linear_witness_to_columns(
        &mut columns.linear_d_reduction_flag,
        &mut columns.linear_d_carry,
        &d_witness,
    );

    let e_witness = compute_sub_witness(&mixed_add_intermediates.b, &mixed_add_intermediates.a);
    debug_assert_eq!(e_witness.result, mixed_add_intermediates.e);
    write_linear_witness_to_columns(
        &mut columns.linear_e_reduction_flag,
        &mut columns.linear_e_carry,
        &e_witness,
    );

    let f_witness = compute_sub_witness(&mixed_add_intermediates.d, &mixed_add_intermediates.c);
    debug_assert_eq!(f_witness.result, mixed_add_intermediates.f);
    write_linear_witness_to_columns(
        &mut columns.linear_f_reduction_flag,
        &mut columns.linear_f_carry,
        &f_witness,
    );

    let g_witness = compute_add_witness(&mixed_add_intermediates.d, &mixed_add_intermediates.c);
    debug_assert_eq!(g_witness.result, mixed_add_intermediates.g);
    write_linear_witness_to_columns(
        &mut columns.linear_g_reduction_flag,
        &mut columns.linear_g_carry,
        &g_witness,
    );

    let h_witness = compute_add_witness(&mixed_add_intermediates.b, &mixed_add_intermediates.a);
    debug_assert_eq!(h_witness.result, mixed_add_intermediates.h);
    write_linear_witness_to_columns(
        &mut columns.linear_h_reduction_flag,
        &mut columns.linear_h_carry,
        &h_witness,
    );
}

/// Lift a linear-modular witness's reduction flag + carries into trace
/// columns. Carries are committed as `(honest_carry + LINEAR_CARRY_OFFSET)`
/// so they're non-negative and can be range-checked through the existing
/// `u16_range` bus. The AIR's constraint subtracts the offset back when
/// reading the carry.
fn write_linear_witness_to_columns<F: PrimeField64>(
    reduction_flag_destination: &mut F,
    carry_destination: &mut [F; NUM_LINEAR_CARRY_CELLS],
    witness: &LinearModWitness,
) {
    *reduction_flag_destination = F::from_u64(witness.reduction_flag as u64);
    for (slot, &carry_value) in carry_destination.iter_mut().zip(witness.carries.iter()) {
        *slot = lift_offset_shifted_carry::<F>(carry_value, LINEAR_CARRY_OFFSET);
    }
}

/// Lift a non-native-mul witness's quotient + carries into trace columns.
/// Quotient limbs are non-negative (in `[0, LIMB_BASE)`) and copy
/// directly. Carries are signed; we commit them offset-shifted by
/// `MUL_CARRY_OFFSET` so the committed value is non-negative and lies
/// in `[0, 2^MUL_CARRY_RANGE_BITS)`. The AIR's constraint subtracts the
/// offset back when reading the carry.
fn write_mul_witness_to_columns<F: PrimeField64>(
    quotient_destination: &mut [F; NUM_LIMBS],
    carry_destination: &mut [F; NUM_MUL_CARRY_CELLS],
    witness: &MulWitness,
) {
    for (slot, &limb) in quotient_destination.iter_mut().zip(witness.quotient_limbs.iter()) {
        *slot = F::from_u64(limb as u64);
    }
    for (slot, &carry_value) in carry_destination.iter_mut().zip(witness.carries.iter()) {
        *slot = lift_offset_shifted_carry::<F>(carry_value, MUL_CARRY_OFFSET);
    }
}

/// Convert a signed `i64` carry to a non-negative field element by
/// adding `offset` (in integer arithmetic) and then lifting through
/// `from_u64`. Caller must ensure `honest_carry + offset` fits in
/// `u64` (and well below the field characteristic).
fn lift_offset_shifted_carry<F: PrimeField64>(honest_carry: i64, offset: u64) -> F {
    let shifted: i64 = honest_carry + offset as i64;
    debug_assert!(
        shifted >= 0,
        "lift_offset_shifted_carry: carry magnitude exceeds offset bound"
    );
    F::from_u64(shifted as u64)
}

/// Copy a raw `[u8; NUM_LIMBS]` into a contiguous block of trace
/// columns, lifting `u8` → BabyBear via `from_u64`. Sibling of
/// [`write_field_to_columns`] for non-`FieldLimbs` raw inputs (e.g., the
/// precomputed-table rows of `PRECOMPUTED_BASE_MULTIPLES`).
fn write_u8_limbs_to_columns<F: PrimeField64>(
    destination_columns: &mut [F; NUM_LIMBS],
    raw_limbs: &[u8; NUM_LIMBS],
) {
    for (column_slot, &limb_value) in destination_columns.iter_mut().zip(raw_limbs.iter()) {
        *column_slot = F::from_u64(limb_value as u64);
    }
}

/// Copy one field element's `NUM_LIMBS` limbs into a contiguous block of
/// `NUM_LIMBS` trace-column slots, lifting limb → BabyBear via `from_u64`.
fn write_field_to_columns<F: PrimeField64>(
    destination_columns: &mut [F; NUM_LIMBS],
    field_value: &FieldLimbs,
) {
    for (column_slot, &limb_value) in destination_columns.iter_mut().zip(field_value.0.iter()) {
        *column_slot = F::from_u64(limb_value as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_air::test_helpers::compress;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use p3_baby_bear::BabyBear;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    /// Compute the dalek reference pubkey bytes for a scalar.
    fn dalek_pubkey(scalar_bytes_le: &[u8; 32]) -> [u8; 32] {
        let scalar = Scalar::from_bytes_mod_order(*scalar_bytes_le);
        let dalek_point = ED25519_BASEPOINT_POINT * scalar;
        dalek_point.compress().to_bytes()
    }

    /// Sanity: `invert(invert(a)) == a`; `a · invert(a) == 1`.
    #[test]
    fn invert_round_trip() {
        let value =
            FieldLimbs::from_limbs(crate::ed25519_air::constants::BASE_POINT_X_LIMBS);
        let inverse = value.invert();
        let inverse_of_inverse = inverse.invert();
        assert_eq!(value, inverse_of_inverse);
        assert_eq!(value.mul(&inverse), FieldLimbs::ONE);
    }

    /// Smoke test: for `s = 1`, our trace's final accumulator is the base
    /// point; dalek agrees.
    #[test]
    fn scalar_one_yields_base_point() {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[0] = 1;
        let (_unused_trace, final_accumulator) = generate_trace::<BabyBear>(&scalar_bytes);
        assert_eq!(compress(&final_accumulator), dalek_pubkey(&scalar_bytes));
    }

    /// Smoke test: a clamped, non-trivial scalar.
    #[test]
    fn random_clamped_scalar_matches_dalek() {
        // Hand-picked scalar; clamping pattern: bottom 3 bits 0,
        // bit 254 set, bit 255 clear.
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[0] = 0xF8; // some nonzero pattern, low 3 bits cleared
        scalar_bytes[1] = 0x12;
        scalar_bytes[15] = 0x9A;
        scalar_bytes[20] = 0x7C;
        scalar_bytes[31] = 0x40; // high bit clear, bit 254 set
        let (_unused_trace, final_accumulator) = generate_trace::<BabyBear>(&scalar_bytes);
        assert_eq!(compress(&final_accumulator), dalek_pubkey(&scalar_bytes));
    }

    /// Smoke test: another scalar pattern (high bits varied, low end clamped).
    #[test]
    fn another_clamped_scalar_matches_dalek() {
        let mut scalar_bytes = [0u8; 32];
        for (byte_index, byte) in scalar_bytes.iter_mut().enumerate() {
            *byte = (byte_index as u8).wrapping_mul(31).wrapping_add(7);
        }
        scalar_bytes[0] &= 0xF8;
        scalar_bytes[31] &= 0x7F;
        scalar_bytes[31] |= 0x40;
        let (_unused_trace, final_accumulator) = generate_trace::<BabyBear>(&scalar_bytes);
        assert_eq!(compress(&final_accumulator), dalek_pubkey(&scalar_bytes));
    }

    /// Fuzz: 64 random clamped scalars, compared against dalek. Trace
    /// generation is the only expensive step (no FRI), so this loop
    /// runs in well under a second.
    ///
    /// Seeded RNG (`ChaCha20`, fixed seed) keeps the test deterministic
    /// — a regression bisects to the same trial number — while still
    /// covering scalar patterns the hand-picked tests miss (uniform
    /// distribution across the clamped space `[2^254, 2^255)` minus the
    /// low 3 bits).
    #[test]
    fn random_fuzz_clamped_scalars_match_dalek() {
        const NUM_TRIALS: usize = 64;
        const FUZZ_SEED: u64 = 0xED25519_FA1B_5EED;

        let mut rng = ChaCha20Rng::seed_from_u64(FUZZ_SEED);
        for trial_index in 0..NUM_TRIALS {
            let mut scalar_bytes = [0u8; 32];
            rng.fill_bytes(&mut scalar_bytes);
            scalar_bytes[0] &= 0xF8;
            scalar_bytes[31] &= 0x7F;
            scalar_bytes[31] |= 0x40;

            let (_unused_trace, final_accumulator) =
                generate_trace::<BabyBear>(&scalar_bytes);
            assert_eq!(
                compress(&final_accumulator),
                dalek_pubkey(&scalar_bytes),
                "trial {trial_index}: scalar={scalar_bytes:?}",
            );
        }
    }
}
