//! Extended-Edwards point arithmetic on Ed25519 over the AIR's
//! 16 × 16-bit limb representation.
//!
//! Used by trace generation. The AIR itself encodes the same formulas as
//! BabyBear constraints — this module is the off-circuit reference that
//! produces the witness values those constraints will check.
//!
//! Operation surface is minimal: extended-Edwards mixed addition against a
//! precomputed-table entry, plus a scalar-bit-conditional `step` that
//! either adds or no-ops. We do not implement projective doubling,
//! affine recovery, or compression — none are needed for trace generation.

use crate::ed25519_air::constants::NUM_LIMBS;
use crate::ed25519_air::field::FieldLimbs;

/// A point on the Ed25519 curve in extended Edwards coordinates
/// $(X, Y, Z, T)$ with $T \cdot Z = X \cdot Y$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointRepresentation {
    pub x: FieldLimbs,
    pub y: FieldLimbs,
    pub z: FieldLimbs,
    pub t: FieldLimbs,
}

impl PointRepresentation {
    /// The identity element $\mathcal{O} = (0, 1)$, lifted to extended
    /// coordinates as $(0, 1, 1, 0)$.
    pub const IDENTITY: Self = Self {
        x: FieldLimbs::ZERO,
        y: FieldLimbs::ONE,
        z: FieldLimbs::ONE,
        t: FieldLimbs::ZERO,
    };

    /// Recover the affine $(x_A, y_A)$ from the extended-Edwards
    /// $(X, Y, Z, T)$ via $x_A = X \cdot Z^{-1}$, $y_A = Y \cdot Z^{-1}$
    /// (mod $p$).
    ///
    /// Used by the trace generator to compute the public-input limbs
    /// the boundary mul constraints (`x_A · G ≡ E`, `y_A · F ≡ H`)
    /// will check at row `LAST_ROW_INDEX`. Single inversion per
    /// proof — Z is non-zero everywhere on the prime-order subgroup
    /// for clamped scalars (no point-at-infinity), so the inverse is
    /// well-defined.
    pub fn to_affine(&self) -> (FieldLimbs, FieldLimbs) {
        let z_inverse = self.z.invert();
        let x_affine = self.x.mul(&z_inverse);
        let y_affine = self.y.mul(&z_inverse);
        (x_affine, y_affine)
    }

    /// HWCD mixed addition against an affine constant operand $Q = (x_Q, y_Q)$
    /// supplied via its three precomputed derivatives:
    ///
    /// ```text
    ///   table_entry[0] = y_Q - x_Q   (mod p)
    ///   table_entry[1] = y_Q + x_Q   (mod p)
    ///   table_entry[2] = 2 d · x_Q · y_Q   (mod p)
    /// ```
    ///
    /// Returns the resulting extended-Edwards point alongside the
    /// per-multiplication intermediates that the AIR will commit as
    /// witness columns. Spec §2.7.
    pub fn mixed_add_with_table_entry(
        &self,
        table_entry: &[[u8; NUM_LIMBS]; 3],
    ) -> (Self, MixedAddIntermediates) {
        // Local-variable letters follow Hisil-Wong-Carter-Dawson 2008
        // ("add-2008-hwcd-3" with curve parameter a = -1) for direct
        // cross-reference to the paper.
        let ymx = FieldLimbs::from_limbs(table_entry[0]); // y_Q − x_Q (precomputed table entry)
        let ypx = FieldLimbs::from_limbs(table_entry[1]); // y_Q + x_Q (precomputed table entry)
        let kxy = FieldLimbs::from_limbs(table_entry[2]); // 2d · x_Q · y_Q (precomputed table entry)

        // Reduced sub-operands so the AIR's per-mul constraints can use
        // non-negative inputs (quotient witnesses must stay in [0, 2^16)).
        let y_minus_x = self.y.sub(&self.x); //   Y − X (mod p)
        let y_plus_x = self.y.add(&self.x); //    Y + X (mod p)

        let a = y_minus_x.mul(&ymx); //           A = (Y − X) · (y_Q − x_Q)
        let b = y_plus_x.mul(&ypx); //            B = (Y + X) · (y_Q + x_Q)
        let c = self.t.mul(&kxy); //              C = T · (2d · x_Q · y_Q)
        let d = self.z.add(&self.z); //           D = 2Z
        let e = b.sub(&a); //                     E = B − A
        let f = d.sub(&c); //                     F = D − C
        let g = d.add(&c); //                     G = D + C
        let h = b.add(&a); //                     H = B + A

        let new_point = Self {
            x: e.mul(&f), // X3 = E · F
            y: g.mul(&h), // Y3 = G · H
            z: f.mul(&g), // Z3 = F · G
            t: e.mul(&h), // T3 = E · H
        };
        let intermediates = MixedAddIntermediates {
            y_minus_x,
            y_plus_x,
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h,
        };
        (new_point, intermediates)
    }

    /// Conditional step: if `bit` is true, add the table entry; otherwise
    /// add the identity. The result is **always** the output of a
    /// mixed-add (never an in-place no-op), which keeps the per-row
    /// constraint shape uniform across both branches.
    ///
    /// When `bit = false`, the muxed table entry is the identity's:
    /// $(1, 1, 0)$. The mixed-add formula then yields $(4 X Z, 4 Y Z,
    /// 4 Z^2, 4 X Y)$ — projectively equivalent to the input point.
    ///
    /// Returns the new point plus the eight HWCD intermediates so callers
    /// (trace generation) can populate the matching witness columns.
    pub fn step(
        &self,
        bit: bool,
        table_entry: &[[u8; NUM_LIMBS]; 3],
    ) -> (Self, MixedAddIntermediates) {
        let muxed: [[u8; NUM_LIMBS]; 3] = if bit {
            *table_entry
        } else {
            [FieldLimbs::ONE.0, FieldLimbs::ONE.0, FieldLimbs::ZERO.0]
        };
        self.mixed_add_with_table_entry(&muxed)
    }
}

/// The eight HWCD mixed-add intermediates ($A, B, C, D, E, F, G, H$ in
/// the paper). Each is a fully reduced field element in 16 × 16-bit
/// little-endian limbs. The AIR commits these as witness columns so the
/// per-multiplication and per-add/sub constraints can be written
/// locally rather than as a single deeply-nested polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixedAddIntermediates {
    /// $Y - X \pmod p$ — reduced left operand for mul $A$.
    pub y_minus_x: FieldLimbs,
    /// $Y + X \pmod p$ — reduced left operand for mul $B$.
    pub y_plus_x: FieldLimbs,
    /// $A = (Y - X) \cdot (y_Q - x_Q) \pmod p$
    pub a: FieldLimbs,
    /// $B = (Y + X) \cdot (y_Q + x_Q) \pmod p$
    pub b: FieldLimbs,
    /// $C = T \cdot (2 d \cdot x_Q \cdot y_Q) \pmod p$
    pub c: FieldLimbs,
    /// $D = 2 Z \pmod p$
    pub d: FieldLimbs,
    /// $E = B - A \pmod p$
    pub e: FieldLimbs,
    /// $F = D - C \pmod p$
    pub f: FieldLimbs,
    /// $G = D + C \pmod p$
    pub g: FieldLimbs,
    /// $H = B + A \pmod p$
    pub h: FieldLimbs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_air::constants::{BASE_POINT_X_LIMBS, BASE_POINT_Y_LIMBS};
    use crate::ed25519_air::precomputed_base_multiples::PRECOMPUTED_BASE_MULTIPLES;

    /// Identity stays projectively equivalent to itself under bit=0 step.
    #[test]
    fn identity_step_zero_bit_preserves_class() {
        // For P = identity (0, 1, 1, 0), the bit=0 step gives:
        //   (0, 4, 4, 0) — projectively equivalent to (0, 1, 1, 0).
        let (result_point, _intermediates) =
            PointRepresentation::IDENTITY.step(false, &PRECOMPUTED_BASE_MULTIPLES[0]);
        // Verify x_after / z_after = 0 / 4 = 0 and y_after / z_after = 4/4 = 1
        // via the cross-multiplication form: x_after * 1 = 0 * z_after; y_after * 1 = 1 * z_after.
        // (We don't have invert; product form keeps it simple.)
        assert_eq!(result_point.x, FieldLimbs::ZERO);
        assert_eq!(result_point.y, result_point.z);
    }

    /// Identity + B (via bit=1 step at t=0) should give B in extended form.
    #[test]
    fn identity_plus_base_point_yields_base_point() {
        let (result_point, _intermediates) =
            PointRepresentation::IDENTITY.step(true, &PRECOMPUTED_BASE_MULTIPLES[0]);
        let base_x = FieldLimbs::from_limbs(BASE_POINT_X_LIMBS);
        let base_y = FieldLimbs::from_limbs(BASE_POINT_Y_LIMBS);
        // The result is in extended coords (X, Y, Z, T) with X/Z = B_x and
        // Y/Z = B_y. Verify via cross-mul (no invert):
        //   X * 1 == B_x * Z   ↔   X == B_x * Z
        //   Y * 1 == B_y * Z   ↔   Y == B_y * Z
        assert_eq!(result_point.x, base_x.mul(&result_point.z));
        assert_eq!(result_point.y, base_y.mul(&result_point.z));
        // Closure: T * Z == X * Y.
        assert_eq!(
            result_point.t.mul(&result_point.z),
            result_point.x.mul(&result_point.y)
        );
    }
}
