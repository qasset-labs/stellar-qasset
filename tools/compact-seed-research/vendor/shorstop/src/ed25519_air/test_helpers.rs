//! Test-only helpers shared across `ed25519_air` test modules.
//!
//! `compress` is not used by the AIR or trace generator — it exists
//! solely for cross-checking the trace generator's final accumulator
//! point against external references (dalek, RFC 8032 published pubkey
//! bytes, etc.).
//!
//! Independent implementation built on top of
//! [`PointRepresentation::to_affine`] (production) plus the canonical
//! Ed25519 compression rule (§5.1.2 of RFC 8032). Cross-checked
//! indirectly: the unit test
//! `generation::tests::scalar_one_yields_base_point` proves
//! `compress(generate_trace(1)) == dalek_pubkey(1)`, which exercises
//! both `to_affine` and `compress` against the dalek oracle.

#![cfg(test)]

use crate::ed25519_air::constants::NUM_LIMBS;
use crate::ed25519_air::point::PointRepresentation;

/// Compress an extended-Edwards point to its 32-byte little-endian
/// canonical pubkey form: bytes of `y_affine` with bit 255 holding the
/// parity of `x_affine`.
pub(crate) fn compress(point: &PointRepresentation) -> [u8; 32] {
    let (x_affine, y_affine) = point.to_affine();

    // 32 × 8-bit limbs are already byte-aligned: limb i = byte i.
    let mut output_bytes = [0u8; 32];
    for limb_index in 0..NUM_LIMBS {
        output_bytes[limb_index] = y_affine.limbs()[limb_index];
    }
    // Parity bit of x_affine = LSB of limb 0 → high bit of last byte.
    output_bytes[31] |= (x_affine.limbs()[0] & 1) << 7;
    output_bytes
}
