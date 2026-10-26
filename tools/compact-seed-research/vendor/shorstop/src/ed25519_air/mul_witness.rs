//! Off-circuit witness computation for non-native field multiplication
//! constraints in the Ed25519 AIR.
//!
//! The AIR proves $a \cdot b \equiv r \pmod p$ via the integer identity
//!
//! ```text
//!     a · b  -  q · p  -  r  =  0   (over ℤ)
//! ```
//!
//! where $a, b, r$ are 16 × 16-bit LE limbs in $[0, p)$ and $q$ is the
//! integer quotient $\lfloor a \cdot b / p \rfloor$, also 16 × 16-bit LE
//! (since $a, b < p < 2^{255}$ ⇒ $a b < p^2$ ⇒ $q < p < 2^{256}$).
//!
//! This module computes the witnesses ($q$ and the per-limb-position
//! carry sequence) the prover commits so the AIR can verify the identity.
//!
//! ## Carry derivation
//!
//! For each output position $k \in \{0, \dots, 30\}$ define the
//! signed coefficient
//!
//! ```text
//!     S_k = ∑_{i+j=k} a[i]·b[j]  -  ∑_{i+j=k} q[i]·p[j]  -  r_k
//! ```
//!
//! where $r_k = r[k]$ for $k < 16$ and $0$ otherwise. The integer
//! identity $\sum_k S_k \cdot 2^{16k} = 0$ is equivalent to the
//! existence of a carry sequence $c_0, c_1, \ldots, c_{29}$ with
//! $c_{-1} = 0$ and $c_{30} = 0$ satisfying
//!
//! ```text
//!     S_k + c_{k-1}  -  c_k · 2^{16}  =  0    (k = 0..30)
//! ```
//!
//! This module computes $q$ via `num_bigint::BigUint`, then derives the
//! carries from the closed integer relation. The constraints in
//! `air.rs` will check these per-position equations directly.

use num_bigint::BigUint;

use crate::ed25519_air::constants::{LIMB_BASE, LIMB_BITS, NUM_LIMBS, PRIME_LIMBS};
use crate::ed25519_air::field::FieldLimbs;

/// Number of partial-product positions in a 16 × 16-limb schoolbook
/// product: positions $0$ through $2 \cdot 16 - 2 = 30$ inclusive.
pub const NUM_PRODUCT_POSITIONS: usize = 2 * NUM_LIMBS - 1;

/// Number of carry cells per multiplication. Position 30 has no
/// outgoing carry (the integer identity closes), so we commit
/// $c_0, \ldots, c_{29}$.
pub const NUM_MUL_CARRY_CELLS: usize = NUM_PRODUCT_POSITIONS - 1;

/// Witness for one non-native multiplication.
#[derive(Clone, Debug)]
pub struct MulWitness {
    /// Reduced result $r = a \cdot b \pmod p$, 32 × 8-bit LE limbs.
    pub result: FieldLimbs,
    /// Integer quotient $q = \lfloor a \cdot b / p \rfloor$, 32 × 8-bit
    /// LE limbs (each in $[0, 2^{8})$ — fits because $a, b < p < 2^{255}$
    /// so $q < p$).
    pub quotient_limbs: [u8; NUM_LIMBS],
    /// Carry cells $c_0, \ldots, c_{61}$ from the per-position identity.
    /// These can be negative (the polynomial coefficients $S_k$ are
    /// signed); we represent them as `i64` here and let the trace writer
    /// lift them to BabyBear via `F::ZERO - F::from_u64(|c|)` for the
    /// negative branch. Empirically bounded by $|c_k| < 2^{14}$ for the
    /// 8-bit limb size.
    pub carries: [i64; NUM_MUL_CARRY_CELLS],
}

/// Compute the multiplication witness for $a \cdot b \pmod p$.
///
/// Caller is responsible for `a, b` being canonical (limbs in
/// $[0, 2^{16})$, value in $[0, p)$); enforced by `FieldLimbs`'s own
/// debug assertions when constructed.
pub fn compute_mul_witness(left_operand: &FieldLimbs, right_operand: &FieldLimbs) -> MulWitness {
    let result = left_operand.mul(right_operand);

    // Quotient via num-bigint: q = (a*b - r) / p.
    let left_big = limbs_to_bigint(left_operand.limbs());
    let right_big = limbs_to_bigint(right_operand.limbs());
    let result_big = limbs_to_bigint(result.limbs());
    let prime_big = limbs_to_bigint(&PRIME_LIMBS);

    let product_big = &left_big * &right_big;
    let qp_big = &product_big - &result_big;
    debug_assert!(
        (&qp_big % &prime_big) == BigUint::from(0u32),
        "compute_mul_witness: a*b - r is not divisible by p"
    );
    let quotient_big = &qp_big / &prime_big;

    // q < p < 2^256, so 32 × 8-bit limbs is sufficient.
    let quotient_limbs = bigint_to_limbs::<NUM_LIMBS>(&quotient_big);

    // Carry derivation: walk positions 0..N-1, accumulating S_k - c_k * 2^L.
    let carries = derive_carries(left_operand.limbs(), right_operand.limbs(), &quotient_limbs, result.limbs());

    MulWitness {
        result,
        quotient_limbs,
        carries,
    }
}

/// Lift a little-endian array of `u8` limbs to a `BigUint`. Trivial
/// since each limb is exactly one byte.
fn limbs_to_bigint(limbs: &[u8]) -> BigUint {
    BigUint::from_bytes_le(limbs)
}

/// Project a `BigUint` (assumed to fit in `LIMB_COUNT` × 8 bits) onto a
/// little-endian limb array. Panics in debug if the value overflows.
fn bigint_to_limbs<const LIMB_COUNT: usize>(value: &BigUint) -> [u8; LIMB_COUNT] {
    let bytes_le = value.to_bytes_le();
    debug_assert!(
        bytes_le.len() <= LIMB_COUNT,
        "bigint_to_limbs: value larger than {} limbs",
        LIMB_COUNT
    );
    let mut limbs = [0u8; LIMB_COUNT];
    for (limb_index, limb_slot) in limbs.iter_mut().enumerate() {
        *limb_slot = bytes_le.get(limb_index).copied().unwrap_or(0);
    }
    limbs
}

/// Number of carry cells for a linear modular operation (add / sub /
/// double). Result has 16 limbs, position 15 has no outgoing carry, so
/// we commit $c_0, \ldots, c_{14}$.
pub const NUM_LINEAR_CARRY_CELLS: usize = NUM_LIMBS - 1;

/// Witness for one linear modular operation $a \pm b \pmod p$ or
/// $2 z \pmod p$.
#[derive(Clone, Debug)]
pub struct LinearModWitness {
    /// Reduced result, 16 × 16-bit LE limbs.
    pub result: FieldLimbs,
    /// Whether one $p$ was added/subtracted to canonicalize the result.
    /// Always 0 or 1; lifted to a single boolean trace cell.
    pub reduction_flag: u8,
    /// Carries $c_0, \ldots, c_{14}$ from the per-position identity.
    /// Bounded in $[-2, 2]$ for the operations we use.
    pub carries: [i64; NUM_LINEAR_CARRY_CELLS],
}

/// Compute the witness for $a + b \pmod p$ via the integer identity
/// $a + b = \text{result} + \sigma \cdot p$ with $\sigma \in \{0, 1\}$.
pub fn compute_add_witness(left_operand: &FieldLimbs, right_operand: &FieldLimbs) -> LinearModWitness {
    let result = left_operand.add(right_operand);
    let result_big = limbs_to_bigint(result.limbs());
    let prime_big = limbs_to_bigint(&PRIME_LIMBS);
    let sum_big = limbs_to_bigint(left_operand.limbs()) + limbs_to_bigint(right_operand.limbs());

    // sigma = (sum - result) / p; must be 0 or 1.
    let reduction_flag_big = (&sum_big - &result_big) / &prime_big;
    let reduction_flag: u8 = reduction_flag_big.to_bytes_le().first().copied().unwrap_or(0);
    debug_assert!(reduction_flag <= 1, "add witness sigma out of {{0,1}}");

    let carries = derive_linear_carries_add(
        left_operand.limbs(),
        right_operand.limbs(),
        reduction_flag,
        result.limbs(),
    );
    LinearModWitness {
        result,
        reduction_flag,
        carries,
    }
}

/// Compute the witness for $a - b \pmod p$ via $a - b + \sigma \cdot p =
/// \text{result}$ with $\sigma \in \{0, 1\}$.
pub fn compute_sub_witness(left_operand: &FieldLimbs, right_operand: &FieldLimbs) -> LinearModWitness {
    let result = left_operand.sub(right_operand);
    let result_big = limbs_to_bigint(result.limbs());
    let prime_big = limbs_to_bigint(&PRIME_LIMBS);
    let left_big = limbs_to_bigint(left_operand.limbs());
    let right_big = limbs_to_bigint(right_operand.limbs());

    // sigma = 1 iff left < right (i.e., we added p to recover).
    let reduction_flag: u8 = if left_big < right_big { 1 } else { 0 };
    // Sanity: a - b + sigma * p == result.
    debug_assert_eq!(
        if reduction_flag == 1 {
            &left_big + &prime_big - &right_big
        } else {
            &left_big - &right_big
        },
        result_big,
        "sub witness identity failed"
    );

    let carries = derive_linear_carries_sub(
        left_operand.limbs(),
        right_operand.limbs(),
        reduction_flag,
        result.limbs(),
    );
    LinearModWitness {
        result,
        reduction_flag,
        carries,
    }
}

/// Compute the witness for $2 z \pmod p$ — a specialization of `add`
/// with both operands equal to $z$.
pub fn compute_double_witness(value: &FieldLimbs) -> LinearModWitness {
    compute_add_witness(value, value)
}

/// Carry derivation for additive ops $a + b - \sigma \cdot p = \text{result}$.
/// At position $k$: $S_k = a[k] + b[k] - \sigma \cdot p[k] - r[k]$, with
/// $S_k + c_{k-1} = c_k \cdot 2^{16}$ closing each coefficient.
fn derive_linear_carries_add(
    left_limbs: &[u8; NUM_LIMBS],
    right_limbs: &[u8; NUM_LIMBS],
    reduction_flag: u8,
    result_limbs: &[u8; NUM_LIMBS],
) -> [i64; NUM_LINEAR_CARRY_CELLS] {
    let mut carries = [0i64; NUM_LINEAR_CARRY_CELLS];
    let mut carry_in: i64 = 0;
    for position_index in 0..NUM_LIMBS {
        let signed_coefficient = left_limbs[position_index] as i64
            + right_limbs[position_index] as i64
            - (reduction_flag as i64) * PRIME_LIMBS[position_index] as i64
            - result_limbs[position_index] as i64;
        let combined = signed_coefficient + carry_in;
        debug_assert_eq!(combined % (LIMB_BASE as i64), 0, "add carry position {} unclosed", position_index);
        let carry_out = combined >> LIMB_BITS;
        if position_index < NUM_LINEAR_CARRY_CELLS {
            carries[position_index] = carry_out;
        } else {
            debug_assert_eq!(carry_out, 0, "add: position 15 has nonzero carry-out");
        }
        carry_in = carry_out;
    }
    carries
}

/// Carry derivation for $a - b + \sigma \cdot p = \text{result}$. Same
/// shape as `add`, sign on the $\sigma p$ term flips.
fn derive_linear_carries_sub(
    left_limbs: &[u8; NUM_LIMBS],
    right_limbs: &[u8; NUM_LIMBS],
    reduction_flag: u8,
    result_limbs: &[u8; NUM_LIMBS],
) -> [i64; NUM_LINEAR_CARRY_CELLS] {
    let mut carries = [0i64; NUM_LINEAR_CARRY_CELLS];
    let mut carry_in: i64 = 0;
    for position_index in 0..NUM_LIMBS {
        let signed_coefficient = left_limbs[position_index] as i64
            - right_limbs[position_index] as i64
            + (reduction_flag as i64) * PRIME_LIMBS[position_index] as i64
            - result_limbs[position_index] as i64;
        let combined = signed_coefficient + carry_in;
        debug_assert_eq!(combined % (LIMB_BASE as i64), 0, "sub carry position {} unclosed", position_index);
        let carry_out = combined >> LIMB_BITS;
        if position_index < NUM_LINEAR_CARRY_CELLS {
            carries[position_index] = carry_out;
        } else {
            debug_assert_eq!(carry_out, 0, "sub: position 15 has nonzero carry-out");
        }
        carry_in = carry_out;
    }
    carries
}

/// Walk the per-position polynomial identity, computing the carry that
/// makes each position close: at $k$, $S_k + c_{k-1} = c_k \cdot 2^{16}$.
fn derive_carries(
    left_limbs: &[u8; NUM_LIMBS],
    right_limbs: &[u8; NUM_LIMBS],
    quotient_limbs: &[u8; NUM_LIMBS],
    result_limbs: &[u8; NUM_LIMBS],
) -> [i64; NUM_MUL_CARRY_CELLS] {
    let mut carries = [0i64; NUM_MUL_CARRY_CELLS];
    let mut carry_in: i64 = 0;
    for position_index in 0..NUM_PRODUCT_POSITIONS {
        let mut signed_coefficient: i64 = 0;
        for left_index in 0..NUM_LIMBS {
            let right_index = position_index.wrapping_sub(left_index);
            if right_index < NUM_LIMBS {
                signed_coefficient += left_limbs[left_index] as i64 * right_limbs[right_index] as i64;
                signed_coefficient -=
                    quotient_limbs[left_index] as i64 * PRIME_LIMBS[right_index] as i64;
            }
        }
        if position_index < NUM_LIMBS {
            signed_coefficient -= result_limbs[position_index] as i64;
        }
        let combined = signed_coefficient + carry_in;
        // The integer identity guarantees combined ≡ 0 (mod 2^8); carry_out
        // is the high "shift" portion. Use exact division via right-shift:
        // signed shift by 16 in i64 is arithmetic, preserving sign.
        debug_assert!(
            combined % (LIMB_BASE as i64) == 0,
            "derive_carries: position {} did not close mod 2^8 (combined = {})",
            position_index,
            combined
        );
        let carry_out = combined >> LIMB_BITS;
        if position_index < NUM_MUL_CARRY_CELLS {
            carries[position_index] = carry_out;
        } else {
            // Position 30 is the boundary: no further carry. The integer
            // identity must close exactly: combined = 0 ⇒ carry_out = 0.
            debug_assert_eq!(
                carry_out, 0,
                "derive_carries: position 30 has nonzero carry-out (closure failure)"
            );
        }
        carry_in = carry_out;
    }
    carries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_air::constants::{BASE_POINT_X_LIMBS, BASE_POINT_Y_LIMBS, D_LIMBS};

    /// Sanity: result from `compute_mul_witness` matches `FieldLimbs::mul`.
    #[test]
    fn witness_result_matches_field_mul() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let base_y = FieldLimbs::from_limbs(BASE_POINT_Y_LIMBS);
        let witness = compute_mul_witness(&base_x, &base_y);
        assert_eq!(witness.result, base_x.mul(&base_y));
    }

    /// Sanity: $0 \cdot x = 0$, witness has quotient 0 and zero carries.
    #[test]
    fn zero_times_anything_has_zero_witnesses() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let witness = compute_mul_witness(&FieldLimbs::ZERO, &base_x);
        assert_eq!(witness.result, FieldLimbs::ZERO);
        assert_eq!(witness.quotient_limbs, [0u8; NUM_LIMBS]);
        for &carry_value in witness.carries.iter() {
            assert_eq!(carry_value, 0);
        }
    }

    /// Sanity: $1 \cdot x = x$, witness has quotient 0 (since $1 \cdot x < p$).
    #[test]
    fn one_times_anything_has_zero_quotient() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let witness = compute_mul_witness(&FieldLimbs::ONE, &base_x);
        assert_eq!(witness.result, base_x);
        assert_eq!(witness.quotient_limbs, [0u8; NUM_LIMBS]);
    }

    /// Spot-check: $d \cdot 1 = d$ has zero quotient and zero carries.
    #[test]
    fn d_times_one_witness() {
        let curve_d = FieldLimbs::from_limbs(D_LIMBS);
        let witness = compute_mul_witness(&curve_d, &FieldLimbs::ONE);
        assert_eq!(witness.result, curve_d);
        assert_eq!(witness.quotient_limbs, [0u8; NUM_LIMBS]);
    }

    /// $a + b$ where $a + b < p$: reduction_flag should be 0.
    #[test]
    fn add_witness_no_reduction_when_sum_fits() {
        let one = FieldLimbs::ONE;
        let two = one.add(&one);
        let witness = compute_add_witness(&one, &two);
        assert_eq!(witness.result, FieldLimbs::ONE.add(&two));
        assert_eq!(witness.reduction_flag, 0);
    }

    /// $(p - 1) + 1 = 0$: reduction_flag = 1, result = 0.
    #[test]
    fn add_witness_wraps_when_sum_reaches_p() {
        let mut prime_minus_one_limbs = PRIME_LIMBS;
        prime_minus_one_limbs[0] -= 1;
        let prime_minus_one = FieldLimbs::from_limbs(prime_minus_one_limbs);
        let witness = compute_add_witness(&prime_minus_one, &FieldLimbs::ONE);
        assert_eq!(witness.result, FieldLimbs::ZERO);
        assert_eq!(witness.reduction_flag, 1);
    }

    /// $1 - 2 \pmod p = p - 1$: reduction_flag = 1.
    #[test]
    fn sub_witness_borrows_when_left_below_right() {
        let one = FieldLimbs::ONE;
        let two = one.add(&one);
        let witness = compute_sub_witness(&one, &two);
        let mut prime_minus_one_limbs = PRIME_LIMBS;
        prime_minus_one_limbs[0] -= 1;
        assert_eq!(witness.result, FieldLimbs::from_limbs(prime_minus_one_limbs));
        assert_eq!(witness.reduction_flag, 1);
    }

    /// $5 - 3 = 2$: reduction_flag = 0, no borrow.
    #[test]
    fn sub_witness_no_borrow_when_left_geq_right() {
        let five = FieldLimbs::ONE.add(&FieldLimbs::ONE).add(&FieldLimbs::ONE).add(&FieldLimbs::ONE).add(&FieldLimbs::ONE);
        let three = FieldLimbs::ONE.add(&FieldLimbs::ONE).add(&FieldLimbs::ONE);
        let witness = compute_sub_witness(&five, &three);
        let two = FieldLimbs::ONE.add(&FieldLimbs::ONE);
        assert_eq!(witness.result, two);
        assert_eq!(witness.reduction_flag, 0);
    }

    /// Identity reconstruction for add: rebuild $a + b - \sigma p =
    /// \text{result}$ position-by-position with the witness carries.
    #[test]
    fn add_polynomial_identity_closes() {
        let left = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let right = FieldLimbs::from_limbs(BASE_POINT_Y_LIMBS);
        let witness = compute_add_witness(&left, &right);
        let mut carry_in: i64 = 0;
        for position_index in 0..NUM_LIMBS {
            let signed_coefficient = left.limbs()[position_index] as i64
                + right.limbs()[position_index] as i64
                - (witness.reduction_flag as i64) * PRIME_LIMBS[position_index] as i64
                - witness.result.limbs()[position_index] as i64;
            let combined = signed_coefficient + carry_in;
            let expected_carry_out = if position_index < NUM_LINEAR_CARRY_CELLS {
                witness.carries[position_index]
            } else {
                0
            };
            assert_eq!(combined, expected_carry_out * (LIMB_BASE as i64),
                "add position {} mismatch", position_index);
            carry_in = expected_carry_out;
        }
        assert_eq!(carry_in, 0);
    }

    /// Identity reconstruction: rebuild the per-position polynomial value
    /// using the witnesses and confirm each position closes mod 2^8 with
    /// the given carry.
    #[test]
    fn polynomial_identity_closes_for_random_pair() {
        let left = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let right = FieldLimbs::from_limbs(D_LIMBS);
        let witness = compute_mul_witness(&left, &right);

        let mut carry_in: i64 = 0;
        for position_index in 0..NUM_PRODUCT_POSITIONS {
            let mut signed_coefficient: i64 = 0;
            for left_index in 0..NUM_LIMBS {
                let right_index = position_index.wrapping_sub(left_index);
                if right_index < NUM_LIMBS {
                    signed_coefficient +=
                        left.limbs()[left_index] as i64 * right.limbs()[right_index] as i64;
                    signed_coefficient -= witness.quotient_limbs[left_index] as i64
                        * PRIME_LIMBS[right_index] as i64;
                }
            }
            if position_index < NUM_LIMBS {
                signed_coefficient -= witness.result.limbs()[position_index] as i64;
            }
            let combined = signed_coefficient + carry_in;
            let expected_carry_out = if position_index < NUM_MUL_CARRY_CELLS {
                witness.carries[position_index]
            } else {
                0
            };
            assert_eq!(
                combined,
                expected_carry_out * (LIMB_BASE as i64),
                "position {} did not close: combined = {}, expected_carry_out = {}",
                position_index,
                combined,
                expected_carry_out
            );
            carry_in = expected_carry_out;
        }
        assert_eq!(carry_in, 0, "final carry must be zero");
    }
}
