//! RFC 8032 §7.1 test vectors run end-to-end through the Ed25519 AIR.
//!
//! Each vector pins a `(secret_key, public_key)` pair where the public
//! key is the canonical compressed form of $A = [s] B$, with $s$ derived
//! from `secret_key` per RFC 8032 §5.1.5:
//!
//!   1. `h = SHA-512(secret_key)` (64 bytes).
//!   2. Take `h[0..32]` as the little-endian scalar.
//!   3. Clamp: `s[0] &= 0xF8; s[31] &= 0x7F; s[31] |= 0x40`.
//!
//! For each vector we:
//!
//!   - Run `generate_trace(s)` and assert that compressing the final
//!     accumulator produces exactly `public_key` (catches off-by-one in
//!     scalar bit ordering, table indexing, HWCD chain, and final
//!     compression).
//!   - On TEST 1, additionally drive the full `prove_batch`/
//!     `verify_batch` pipeline with the trace's final accumulator
//!     plumbed in as public values (catches public-value layout bugs
//!     and the row-`LAST_ROW_INDEX` boundary constraint divergence).
//!
//! Reference text: `references/ed25519/rfc8032/rfc8032.txt`, §7.1
//! (lines 1295–1398). Vectors are pinned as raw `[u8; 32]` byte
//! literals (decoded from the RFC's hex blocks) to keep this file
//! free of hex-decoding helpers.

#![cfg(test)]

use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use sha2::{Digest, Sha512};

use crate::ed25519_air::generation::generate_trace as generate_ed25519_trace;
use crate::ed25519_air::prove_verify_helpers::build_batched_inputs;
use crate::ed25519_air::prove_verify_tests::{
    ED25519_EXT_TRACE_LOG_HEIGHT, RANGE_CHECK_EXT_TABLE_LOG_HEIGHT,
};
use crate::ed25519_air::test_helpers::compress;
use crate::{Val, make_config};

/// A pinned RFC 8032 §7.1 test vector. `expected_public_key` is the
/// 32-byte canonical compressed form of $[s] B$ where $s$ is derived
/// from `secret_key` per the SHA-512 + clamp rule.
struct Rfc8032Vector {
    label: &'static str,
    secret_key: [u8; 32],
    expected_public_key: [u8; 32],
}

/// RFC 8032 §7.1 TEST 1.
const RFC_TEST_1: Rfc8032Vector = Rfc8032Vector {
    label: "RFC 8032 §7.1 TEST 1",
    secret_key: [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ],
    expected_public_key: [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ],
};

/// RFC 8032 §7.1 TEST 2.
const RFC_TEST_2: Rfc8032Vector = Rfc8032Vector {
    label: "RFC 8032 §7.1 TEST 2",
    secret_key: [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ],
    expected_public_key: [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ],
};

/// RFC 8032 §7.1 TEST 3.
const RFC_TEST_3: Rfc8032Vector = Rfc8032Vector {
    label: "RFC 8032 §7.1 TEST 3",
    secret_key: [
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ],
    expected_public_key: [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ],
};

/// RFC 8032 §7.1 TEST 1024 (large-message variant; same key-derivation
/// path, different secret-key seed).
const RFC_TEST_1024: Rfc8032Vector = Rfc8032Vector {
    label: "RFC 8032 §7.1 TEST 1024",
    secret_key: [
        0xf5, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95, 0x17, 0x63, 0x0f, 0x22, 0x68, 0x76, 0xb8,
        0x6c, 0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74, 0x4c, 0x6b, 0xf2, 0x55, 0xf5, 0xcc,
        0x0e, 0xe5,
    ],
    expected_public_key: [
        0x27, 0x81, 0x17, 0xfc, 0x14, 0x4c, 0x72, 0x34, 0x0f, 0x67, 0xd0, 0xf2, 0x31, 0x6e, 0x83,
        0x86, 0xce, 0xff, 0xbf, 0x2b, 0x24, 0x28, 0xc9, 0xc5, 0x1f, 0xef, 0x7c, 0x59, 0x7f, 0x1d,
        0x42, 0x6e,
    ],
};

/// Derive the clamped scalar `s` from an EdDSA secret key per RFC 8032
/// §5.1.5: `s = clamp(SHA-512(secret_key)[0..32])`.
fn derive_clamped_scalar(secret_key: &[u8; 32]) -> [u8; 32] {
    let secret_key_hash: [u8; 64] = Sha512::digest(secret_key).into();
    let mut clamped_scalar_bytes = [0u8; 32];
    clamped_scalar_bytes.copy_from_slice(&secret_key_hash[0..32]);
    // RFC 8032 §5.1.5 step 2.
    clamped_scalar_bytes[0] &= 0xF8;
    clamped_scalar_bytes[31] &= 0x7F;
    clamped_scalar_bytes[31] |= 0x40;
    clamped_scalar_bytes
}

/// Run the trace generator for one RFC vector and assert that the
/// compressed final accumulator equals the published public key.
fn assert_trace_recovers_rfc_public_key(vector: &Rfc8032Vector) {
    let clamped_scalar_bytes = derive_clamped_scalar(&vector.secret_key);
    let (_unused_trace, final_accumulator) =
        generate_ed25519_trace::<Val>(&clamped_scalar_bytes);
    let recovered_public_key_bytes = compress(&final_accumulator);
    assert_eq!(
        recovered_public_key_bytes, vector.expected_public_key,
        "{}: trace-derived public key does not match RFC vector",
        vector.label,
    );
}

#[test]
fn rfc8032_test_1_trace_matches_published_pubkey() {
    assert_trace_recovers_rfc_public_key(&RFC_TEST_1);
}

#[test]
fn rfc8032_test_2_trace_matches_published_pubkey() {
    assert_trace_recovers_rfc_public_key(&RFC_TEST_2);
}

#[test]
fn rfc8032_test_3_trace_matches_published_pubkey() {
    assert_trace_recovers_rfc_public_key(&RFC_TEST_3);
}

#[test]
fn rfc8032_test_1024_trace_matches_published_pubkey() {
    assert_trace_recovers_rfc_public_key(&RFC_TEST_1024);
}

/// Full prove + verify on RFC TEST 1.
///
/// This is the most expensive test in the suite (one full STARK proof);
/// we run it once on the canonical first vector to bind the published
/// public key into the public-input layout. The other vectors are
/// covered by the cheap trace-only assertions above — they exercise
/// the arithmetic without paying the FRI cost three more times.
#[test]
fn rfc8032_test_1_prove_batch_and_verify_batch_succeeds() {
    let vector = &RFC_TEST_1;
    let clamped_scalar_bytes = derive_clamped_scalar(&vector.secret_key);
    let mut inputs = build_batched_inputs(&clamped_scalar_bytes);

    // Self-consistency: the trace's final accumulator must compress to
    // the published RFC public key. Without this guard, the prove/verify
    // run below would still succeed against a self-consistent-but-wrong
    // trace, since it draws the public values from `inputs` rather than
    // from the RFC vector.
    assert_eq!(
        compress(&inputs.final_accumulator),
        vector.expected_public_key,
        "{}: final accumulator does not compress to RFC public key",
        vector.label,
    );

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
    let proof = prove_batch(&config, &instances, &prover_data);

    let public_values = vec![inputs.ed25519_public_values, Vec::<Val>::new()];
    verify_batch(&config, &inputs.airs, &proof, &public_values, common)
        .unwrap_or_else(|err| panic!("{}: verify_batch failed: {err:?}", vector.label));
}
