//! Pure-Rust arithmetic on $\mathbb{F}_p$ where $p = 2^{255} - 19$, using
//! the AIR's 32 × 8-bit little-endian limb representation.
//!
//! Used by trace generation only. The AIR itself never invokes this code —
//! its constraints are emitted in BabyBear via `AirBuilder` expressions.
//!
//! Operation surface is deliberately minimal: only what the HWCD mixed-add
//! formula in `generation.rs` consumes (add, sub, mul). Inversion / byte
//! conversion / negation are absent — add them when something concrete
//! needs them.
//!
//! Spec reference: `docs/ed25519-spec.md` §3.2 (limb representation),
//! §5.1 (multiplication shape), §5.3 (reduction by $2^{255} \equiv 19$).
//! Limb size locked to 8 bits per the BabyBear soundness analysis (§5
//! header note); each per-position schoolbook sum stays comfortably
//! below $p_{\text{BB}} \approx 2^{30.91}$.
//!
//! Independent implementation. Cross-checked against
//! `scripts/derive_ed25519_constants.py` (Python reference) at unit-test
//! time, not against any reference circuit.

use crate::ed25519_air::constants::{
    LIMB_BASE, LIMB_BITS, LIMB_MASK, NUM_LIMBS, PRIME_LIMBS, TOP_LIMB_MASK, TOP_LIMB_WIDTH_BITS,
};

/// A field element of $\mathbb{F}_{2^{255}-19}$, stored as 32 little-endian
/// 8-bit limbs. Always **canonical**: every value is in $[0, p)$ at the
/// boundary of every public method (intermediate computations may
/// transiently exceed this).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldLimbs(pub [u8; NUM_LIMBS]);

impl FieldLimbs {
    /// The additive identity $0 \in \mathbb{F}_p$.
    pub const ZERO: Self = Self([0; NUM_LIMBS]);

    /// The multiplicative identity $1 \in \mathbb{F}_p$.
    pub const ONE: Self = Self({
        let mut limbs = [0u8; NUM_LIMBS];
        limbs[0] = 1;
        limbs
    });

    /// Construct from a raw limb array. Caller is responsible for the value
    /// being canonical (in $[0, p)$); debug builds assert this.
    pub fn from_limbs(limbs: [u8; NUM_LIMBS]) -> Self {
        let v = Self(limbs);
        debug_assert!(v.is_canonical(), "FieldLimbs::from_limbs: value ≥ p");
        v
    }

    /// Borrow the underlying limbs.
    pub fn limbs(&self) -> &[u8; NUM_LIMBS] {
        &self.0
    }

    /// True if `self < p`.
    fn is_canonical(&self) -> bool {
        // Compare limbs from most-significant downward.
        for i in (0..NUM_LIMBS).rev() {
            match self.0[i].cmp(&PRIME_LIMBS[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        false // self == p, not canonical
    }

    /// Reduce a 32-limb value in $[0, 2 p)$ to $[0, p)$ by conditional
    /// subtraction of $p$.
    fn reduce_once(mut input_limbs: [u32; NUM_LIMBS]) -> Self {
        let mut subtraction_borrow: i64 = 0;
        let mut difference_limbs = [0u32; NUM_LIMBS];
        for limb_index in 0..NUM_LIMBS {
            let signed_difference = input_limbs[limb_index] as i64
                - PRIME_LIMBS[limb_index] as i64
                - subtraction_borrow;
            if signed_difference < 0 {
                difference_limbs[limb_index] = (signed_difference + (LIMB_BASE as i64)) as u32;
                subtraction_borrow = 1;
            } else {
                difference_limbs[limb_index] = signed_difference as u32;
                subtraction_borrow = 0;
            }
        }
        if subtraction_borrow == 0 {
            // input_limbs ≥ p; use the difference
            input_limbs = difference_limbs;
        }
        let mut output_limbs = [0u8; NUM_LIMBS];
        for limb_index in 0..NUM_LIMBS {
            debug_assert!(
                input_limbs[limb_index] < (LIMB_BASE as u32),
                "limb overflow after reduce_once"
            );
            output_limbs[limb_index] = input_limbs[limb_index] as u8;
        }
        Self(output_limbs)
    }

    /// $self + other \pmod p$.
    pub fn add(&self, other: &Self) -> Self {
        let mut sum_limbs = [0u32; NUM_LIMBS];
        let mut carry: u32 = 0;
        for limb_index in 0..NUM_LIMBS {
            let limb_sum =
                self.0[limb_index] as u32 + other.0[limb_index] as u32 + carry;
            sum_limbs[limb_index] = limb_sum & (LIMB_MASK as u32);
            carry = limb_sum >> LIMB_BITS;
        }
        // After adding two values < p < 2^255, the result is < 2 p < 2^256,
        // so the only overflow is into bit 255 of limb 31. Fold the carry
        // out using $2^{255} \equiv 19 \pmod p$.
        let top_bit_of_sum = (sum_limbs[NUM_LIMBS - 1] >> TOP_LIMB_WIDTH_BITS) & 1;
        sum_limbs[NUM_LIMBS - 1] &= TOP_LIMB_MASK as u32;
        if top_bit_of_sum == 1 {
            let mut propagating_carry: u32 = 19;
            for limb_index in 0..NUM_LIMBS {
                let limb_with_carry = sum_limbs[limb_index] + propagating_carry;
                sum_limbs[limb_index] = limb_with_carry & (LIMB_MASK as u32);
                propagating_carry = limb_with_carry >> LIMB_BITS;
                if propagating_carry == 0 {
                    break;
                }
            }
        }
        // Final canonicalization: sum is in [0, 2 p), reduce_once handles it.
        Self::reduce_once(sum_limbs)
    }

    /// $self - other \pmod p$.
    pub fn sub(&self, other: &Self) -> Self {
        // Compute self - other; if negative, add p.
        let mut difference_limbs = [0i64; NUM_LIMBS];
        let mut borrow: i64 = 0;
        for limb_index in 0..NUM_LIMBS {
            let signed_difference =
                self.0[limb_index] as i64 - other.0[limb_index] as i64 - borrow;
            if signed_difference < 0 {
                difference_limbs[limb_index] = signed_difference + (LIMB_BASE as i64);
                borrow = 1;
            } else {
                difference_limbs[limb_index] = signed_difference;
                borrow = 0;
            }
        }
        if borrow == 1 {
            // result < 0; add p
            let mut wraparound_carry: i64 = 0;
            for limb_index in 0..NUM_LIMBS {
                let limb_with_p = difference_limbs[limb_index]
                    + PRIME_LIMBS[limb_index] as i64
                    + wraparound_carry;
                difference_limbs[limb_index] = limb_with_p & (LIMB_MASK as i64);
                wraparound_carry = limb_with_p >> LIMB_BITS;
            }
            // The final carry should be exactly 1 (cancelling the original
            // borrow), so the value is now in [0, p).
            debug_assert_eq!(
                wraparound_carry, 1,
                "sub: carry mismatch — wraparound did not produce expected residue"
            );
        }
        let mut output_limbs = [0u8; NUM_LIMBS];
        for limb_index in 0..NUM_LIMBS {
            output_limbs[limb_index] = difference_limbs[limb_index] as u8;
        }
        Self(output_limbs)
    }

    /// $self \cdot other \pmod p$.
    ///
    /// Schoolbook 32 × 32 limb multiplication into a 63-limb intermediate,
    /// then reduce using $2^{256} \equiv 38$. All intermediate values fit
    /// comfortably in `i64` (max single column ≤ 32 × 2^16 ≈ 2^21).
    pub fn mul(&self, other: &Self) -> Self {
        // 63 limbs of partial-product accumulator (degrees 0..=62).
        let mut wide_product_limbs = [0i64; 2 * NUM_LIMBS - 1];
        for self_limb_index in 0..NUM_LIMBS {
            for other_limb_index in 0..NUM_LIMBS {
                wide_product_limbs[self_limb_index + other_limb_index] +=
                    self.0[self_limb_index] as i64 * other.0[other_limb_index] as i64;
            }
        }
        // Carry-propagate so each limb is in [0, 2^8); top "limb" can be
        // larger temporarily.
        let mut propagating_carry: i64 = 0;
        for limb_index in 0..(2 * NUM_LIMBS - 1) {
            let limb_with_carry = wide_product_limbs[limb_index] + propagating_carry;
            wide_product_limbs[limb_index] = limb_with_carry & (LIMB_MASK as i64);
            propagating_carry = limb_with_carry >> LIMB_BITS;
        }
        // After the loop `propagating_carry` is the spillover above limb
        // (2*NUM_LIMBS - 2). Split into a top limb.
        let mut upper_half_limbs = [0i64; NUM_LIMBS];
        let mut lower_half_limbs = [0i64; NUM_LIMBS];
        for limb_index in 0..NUM_LIMBS {
            lower_half_limbs[limb_index] = wide_product_limbs[limb_index];
        }
        for upper_limb_index in 0..(NUM_LIMBS - 1) {
            upper_half_limbs[upper_limb_index] = wide_product_limbs[NUM_LIMBS + upper_limb_index];
        }
        upper_half_limbs[NUM_LIMBS - 1] = propagating_carry;

        // Now value = lower + upper * 2^256, reduce using 2^256 ≡ 38 (since
        // 2^255 ≡ 19  ⇒  2^256 = 2 * 2^255 ≡ 38).
        let mut reduction_accumulator = [0i64; NUM_LIMBS + 1];
        for limb_index in 0..NUM_LIMBS {
            reduction_accumulator[limb_index] =
                lower_half_limbs[limb_index] + 38 * upper_half_limbs[limb_index];
        }
        // Carry-propagate reduction_accumulator.
        let mut propagating_carry: i64 = 0;
        for limb_index in 0..NUM_LIMBS {
            let limb_with_carry = reduction_accumulator[limb_index] + propagating_carry;
            reduction_accumulator[limb_index] = limb_with_carry & (LIMB_MASK as i64);
            propagating_carry = limb_with_carry >> LIMB_BITS;
        }
        reduction_accumulator[NUM_LIMBS] = propagating_carry;

        // Top spillover: reduction_accumulator[32] represents value above
        // 2^256; fold once more using 2^256 ≡ 38.
        if reduction_accumulator[NUM_LIMBS] != 0 {
            let mut residual_carry = 38 * reduction_accumulator[NUM_LIMBS];
            for limb_index in 0..NUM_LIMBS {
                let limb_with_carry =
                    reduction_accumulator[limb_index] + residual_carry;
                reduction_accumulator[limb_index] = limb_with_carry & (LIMB_MASK as i64);
                residual_carry = limb_with_carry >> LIMB_BITS;
                if residual_carry == 0 {
                    break;
                }
            }
        }

        // reduction_accumulator[0..32] now represents the value in [0, 2 p)
        // (one extra fold of 38 beyond p is possible). Use the same
        // top-bit-fold trick as `add`:
        let mut sum_limbs = [0u32; NUM_LIMBS];
        for limb_index in 0..NUM_LIMBS {
            sum_limbs[limb_index] = reduction_accumulator[limb_index] as u32;
        }
        let top_bit_of_sum = (sum_limbs[NUM_LIMBS - 1] >> TOP_LIMB_WIDTH_BITS) & 1;
        sum_limbs[NUM_LIMBS - 1] &= TOP_LIMB_MASK as u32;
        if top_bit_of_sum == 1 {
            let mut top_bit_fold_carry: u32 = 19;
            for limb_index in 0..NUM_LIMBS {
                let limb_with_carry = sum_limbs[limb_index] + top_bit_fold_carry;
                sum_limbs[limb_index] = limb_with_carry & (LIMB_MASK as u32);
                top_bit_fold_carry = limb_with_carry >> LIMB_BITS;
                if top_bit_fold_carry == 0 {
                    break;
                }
            }
        }
        Self::reduce_once(sum_limbs)
    }

    /// Modular inverse via Fermat's little theorem: $a^{p-2} \pmod p$.
    ///
    /// Used by trace generation to recover the affine $(x_A, y_A)$ from
    /// the final extended-Edwards accumulator $(X_{256}, Y_{256}, Z_{256}, T_{256})$:
    /// $x_A = X_{256} \cdot Z_{256}^{-1}$ and $y_A = Y_{256} \cdot Z_{256}^{-1}$.
    /// The AIR itself never inverts in-circuit; this is purely off-circuit
    /// witness computation.
    ///
    /// Cost: $\sim 256 \cdot 2 = 512$ field multiplications via square-and-
    /// multiply over the binary expansion of $p - 2$. Called once per
    /// proof (only at row `LAST_ROW_INDEX`).
    pub fn invert(&self) -> Self {
        // p - 2 in `NUM_LIMBS × LIMB_BITS`-bit LE limbs: same as
        // PRIME_LIMBS but limb 0 decremented by 2.
        let mut exponent_limbs = PRIME_LIMBS;
        exponent_limbs[0] -= 2;

        let mut accumulated_product = Self::ONE;
        let mut current_base_power = *self;
        for &exponent_limb in exponent_limbs.iter() {
            for bit_index in 0..LIMB_BITS {
                if (exponent_limb >> bit_index) & 1 == 1 {
                    accumulated_product = accumulated_product.mul(&current_base_power);
                }
                current_base_power = current_base_power.mul(&current_base_power);
            }
        }
        accumulated_product
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_air::constants::{BASE_POINT_X_LIMBS, BASE_POINT_Y_LIMBS, D_LIMBS};

    fn prime_minus_one() -> FieldLimbs {
        // p - 1 = (PRIME_LIMBS with limb 0 decremented by 1)
        let mut limbs = PRIME_LIMBS;
        limbs[0] -= 1;
        FieldLimbs(limbs)
    }

    #[test]
    fn additive_identity() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        assert_eq!(base_x.add(&FieldLimbs::ZERO), base_x);
        assert_eq!(FieldLimbs::ZERO.add(&base_x), base_x);
    }

    #[test]
    fn multiplicative_identity() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        assert_eq!(base_x.mul(&FieldLimbs::ONE), base_x);
        assert_eq!(FieldLimbs::ONE.mul(&base_x), base_x);
    }

    #[test]
    fn zero_times_anything_is_zero() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        assert_eq!(base_x.mul(&FieldLimbs::ZERO), FieldLimbs::ZERO);
        assert_eq!(FieldLimbs::ZERO.mul(&base_x), FieldLimbs::ZERO);
    }

    #[test]
    fn p_minus_one_plus_one_is_zero() {
        let prime_minus_one_value = prime_minus_one();
        assert_eq!(prime_minus_one_value.add(&FieldLimbs::ONE), FieldLimbs::ZERO);
    }

    #[test]
    fn one_minus_two_wraps_to_p_minus_one() {
        let two = FieldLimbs::ONE.add(&FieldLimbs::ONE);
        assert_eq!(FieldLimbs::ONE.sub(&two), prime_minus_one());
    }

    #[test]
    fn base_point_satisfies_curve_equation() {
        // Spot-check our mul against the curve membership identity:
        //   -B_x^2 + B_y^2 == 1 + d * B_x^2 * B_y^2  (mod p)
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let base_y = FieldLimbs::from_limbs(BASE_POINT_Y_LIMBS);
        let curve_constant_d = FieldLimbs::from_limbs(D_LIMBS);

        let base_x_squared = base_x.mul(&base_x);
        let base_y_squared = base_y.mul(&base_y);
        let curve_lhs = base_y_squared.sub(&base_x_squared);
        let base_x_squared_times_y_squared = base_x_squared.mul(&base_y_squared);
        let curve_rhs = FieldLimbs::ONE.add(&curve_constant_d.mul(&base_x_squared_times_y_squared));
        assert_eq!(curve_lhs, curve_rhs, "base point fails curve equation");
    }

    #[test]
    fn squaring_via_mul_matches_self_mul() {
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        assert_eq!(base_x.mul(&base_x), base_x.mul(&base_x));
    }

    #[test]
    fn p_minus_one_squared_is_one() {
        // (p - 1)^2 ≡ 1 (mod p)
        let prime_minus_one_value = prime_minus_one();
        assert_eq!(
            prime_minus_one_value.mul(&prime_minus_one_value),
            FieldLimbs::ONE
        );
    }
}
