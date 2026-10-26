//! Exact mathematical scalar/key binding, not proof verification or recovery authority.
//!
//! The integrating caller must obtain the expected key from independently trusted
//! immutable/current account state. A key supplied by a claimant is not an anchor.
//! This check does not establish a seed preimage, request binding, eligibility,
//! retirement, expiry, one-time consumption or quantum proof-of-knowledge security.
#![no_std]
#![forbid(unsafe_code)]

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    traits::IsIdentity,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    InvalidLength,
    InvalidClampedScalar,
    InvalidPublicKeyEncoding,
    InvalidPublicKeySubgroup,
    ScalarKeyMismatch,
}

/// A canonical nonidentity prime-subgroup Ed25519 point. This type does not attest
/// who chose the key or grant it authority; the caller must pin the expected key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalEd25519PublicKey([u8; 32]);

impl CanonicalEd25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BindingError> {
        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or(BindingError::InvalidPublicKeyEncoding)?;
        // Dalek decompression alone is not a canonical-encoding check.
        if point.compress().to_bytes() != bytes {
            return Err(BindingError::InvalidPublicKeyEncoding);
        }
        if point.is_identity() || !point.is_torsion_free() {
            return Err(BindingError::InvalidPublicKeySubgroup);
        }
        Ok(Self(bytes))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Check the FULL original 32-byte RFC8032 clamped scalar, in little endian.
    /// Reduced scalars, seeds and silently reclamped inputs are not accepted.
    pub fn check_clamped_scalar_binding(&self, scalar: &[u8; 32]) -> Result<(), BindingError> {
        if scalar[0] & 7 != 0 || scalar[31] & 0xc0 != 0x40 {
            return Err(BindingError::InvalidClampedScalar);
        }
        // mul_base_clamped is trusted group arithmetic; the guard above ensures
        // its internal clamping cannot repair an invalid caller representation.
        let actual = EdwardsPoint::mul_base_clamped(*scalar)
            .compress()
            .to_bytes();
        if actual != self.0 {
            return Err(BindingError::ScalarKeyMismatch);
        }
        Ok(())
    }
}

/// Length-checked convenience boundary. `expected_protected_key` must come from
/// trusted account configuration, not from the recovery claimant's request.
pub fn check_clamped_scalar_binding(
    scalar: &[u8],
    expected_protected_key: &[u8],
) -> Result<(), BindingError> {
    let scalar: &[u8; 32] = scalar.try_into().map_err(|_| BindingError::InvalidLength)?;
    let key: [u8; 32] = expected_protected_key
        .try_into()
        .map_err(|_| BindingError::InvalidLength)?;
    CanonicalEd25519PublicKey::from_bytes(key)?.check_clamped_scalar_binding(scalar)
}

#[cfg(any(test, feature = "fixtures"))]
pub mod fixture_vectors;

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
        scalar::Scalar,
    };
    use sha2::{Digest, Sha512};

    #[test]
    fn official_rfc8032_and_sep5_vectors_bind_exact_keys() {
        assert_eq!(fixture_vectors::VECTORS.len(), 18);
        for fixture in fixture_vectors::VECTORS {
            let digest = Sha512::digest(fixture.seed);
            let mut expanded: [u8; 32] = digest[..32].try_into().unwrap();
            expanded[0] &= 248;
            expanded[31] &= 127;
            expanded[31] |= 64;
            assert_eq!(expanded, fixture.scalar);
            let key = CanonicalEd25519PublicKey::from_bytes(fixture.public_key).unwrap();
            assert_eq!(key.to_bytes(), fixture.public_key);
            assert_eq!(key.check_clamped_scalar_binding(&fixture.scalar), Ok(()));
        }
    }

    #[test]
    fn different_valid_key_and_changed_clamped_scalar_reject() {
        let first = fixture_vectors::VECTORS[0];
        let other = fixture_vectors::VECTORS[1];
        assert_eq!(
            check_clamped_scalar_binding(&first.scalar, &other.public_key),
            Err(BindingError::ScalarKeyMismatch)
        );
        let mut changed = first.scalar;
        changed[1] ^= 1;
        assert_eq!(
            check_clamped_scalar_binding(&changed, &first.public_key),
            Err(BindingError::ScalarKeyMismatch)
        );
    }

    #[test]
    fn every_forced_clamp_bit_and_reduced_scalar_reject() {
        let fixture = fixture_vectors::VECTORS[0];
        for (byte, bit) in [(0, 1), (0, 2), (0, 4), (31, 128), (31, 64)] {
            let mut changed = fixture.scalar;
            changed[byte] ^= bit;
            assert_eq!(
                check_clamped_scalar_binding(&changed, &fixture.public_key),
                Err(BindingError::InvalidClampedScalar)
            );
        }
        let reduced = Scalar::from_bytes_mod_order(fixture.scalar).to_bytes();
        assert_eq!(
            check_clamped_scalar_binding(&reduced, &fixture.public_key),
            Err(BindingError::InvalidClampedScalar)
        );
    }

    #[test]
    fn noncanonical_field_and_identity_sign_alias_reject() {
        for first in [0xed, 0xee] {
            let mut noncanonical = [0xff; 32];
            noncanonical[0] = first;
            noncanonical[31] = 0x7f;
            assert_eq!(
                CanonicalEd25519PublicKey::from_bytes(noncanonical),
                Err(BindingError::InvalidPublicKeyEncoding)
            );
        }
        let mut identity_alias = [0u8; 32];
        identity_alias[0] = 1;
        identity_alias[31] = 0x80;
        assert_eq!(
            CanonicalEd25519PublicKey::from_bytes(identity_alias),
            Err(BindingError::InvalidPublicKeyEncoding)
        );
    }

    #[test]
    fn all_small_order_and_mixed_order_public_keys_reject() {
        for point in EIGHT_TORSION {
            assert_eq!(
                CanonicalEd25519PublicKey::from_bytes(point.compress().to_bytes()),
                Err(BindingError::InvalidPublicKeySubgroup)
            );
        }
        let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert_eq!(
            CanonicalEd25519PublicKey::from_bytes(mixed.compress().to_bytes()),
            Err(BindingError::InvalidPublicKeySubgroup)
        );
    }

    #[test]
    fn external_lengths_are_exact_and_seed_is_not_scalar() {
        let f = fixture_vectors::VECTORS[0];
        assert_eq!(
            check_clamped_scalar_binding(&f.scalar[..31], &f.public_key),
            Err(BindingError::InvalidLength)
        );
        assert_eq!(
            check_clamped_scalar_binding(&[0u8; 33], &f.public_key),
            Err(BindingError::InvalidLength)
        );
        assert_eq!(
            check_clamped_scalar_binding(&f.scalar, &f.public_key[..31]),
            Err(BindingError::InvalidLength)
        );
        assert_eq!(
            check_clamped_scalar_binding(&f.scalar, &[0u8; 33]),
            Err(BindingError::InvalidLength)
        );
        assert_ne!(check_clamped_scalar_binding(&f.seed, &f.public_key), Ok(()));
    }
}
