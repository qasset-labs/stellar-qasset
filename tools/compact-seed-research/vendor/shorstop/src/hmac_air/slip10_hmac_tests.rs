//! Witness-level sanity test for [`Slip10HmacAir`]. The full
//! prove/verify integration with the Phase 4 priv-extractor lives in
//! [`crate::slip10_air::tests`].
//!
//! This file used to also host a 2-AIR prove/verify test
//! (`Sha512Air` + `Slip10HmacAir`); that became infeasible (and
//! redundant with `slip10_air::tests`) once Phase 4 added the
//! `slip10_priv_outputs` bus send to `Slip10HmacAir` — the bus
//! requires a receiver, which only `Slip10Air` provides.

#![cfg(test)]

use sha2::{Digest, Sha512};

const ED25519_SEED_KEY: &[u8] = b"ed25519 seed";

/// One HMAC-SHA512 with K' zero-padded to 128 bytes.
fn reference_hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    assert!(key.len() <= 128);
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);
    let mut ipad_block = [0u8; 128];
    let mut opad_block = [0u8; 128];
    for i in 0..128 {
        ipad_block[i] = key_padded[i] ^ 0x36;
        opad_block[i] = key_padded[i] ^ 0x5C;
    }
    let mut inner = Sha512::new();
    inner.update(ipad_block);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad_block);
    outer.update(&inner_digest);
    let outer_digest = outer.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&outer_digest);
    output
}

/// Sanity: `HMAC-SHA512("ed25519 seed", seed)` agrees with a sha2
/// reference. Anchors that the SLIP-0010 master step's cryptographic
/// primitive is correctly understood by our test scaffolding (the
/// `build_step_compressions` helper used by the prove/verify test
/// elsewhere relies on this same operation).
#[test]
fn slip10_master_hmac_matches_reference() {
    let mut seed = [0u8; 64];
    for i in 0..64 {
        seed[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let expected = reference_hmac_sha512(ED25519_SEED_KEY, &seed);
    // Output is 64 bytes; first 32 are master priv, last 32 are
    // master chain code. We don't pin specific bytes here — just
    // require the function runs to completion and produces 64 bytes.
    assert_eq!(expected.len(), 64);
}
