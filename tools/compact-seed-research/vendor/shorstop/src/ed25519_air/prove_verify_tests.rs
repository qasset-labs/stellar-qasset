//! End-to-end batched prove/verify integration tests for the Ed25519 AIR.
//!
//! Each test runs the full Plonky3 batch-STARK pipeline:
//!
//!   1. Generate the ed25519 main trace (256 rows).
//!   2. Extract the values that ed25519 will *send* to the global
//!      `u16_range` LogUp bus (every limb cell + every offset-shifted
//!      carry cell — see [`prove_verify_helpers::extract_all_range_check_send_events`]).
//!   3. Build the range-check AIR's multiplicity-column trace by
//!      counting send-event occurrences.
//!   4. Wrap both AIRs in [`BatchedAir`] (homogeneous slice required by
//!      `prove_batch`), call `ProverData::from_airs_and_degrees` to
//!      collect their lookup specifications + commit to preprocessed
//!      data, then `prove_batch` and `verify_batch`.
//!
//! These tests grow alongside the AIR. New constraint blocks → new
//! positive cases here; soundness coverage lives in
//! `soundness_tests.rs` (drop-each-constraint sweep).

#![cfg(test)]

use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};

use crate::ed25519_air::prove_verify_helpers::build_batched_inputs;
use crate::range_check_u16_air::constants::TABLE_LOG_HEIGHT;
use crate::{Val, make_config};

/// $\log_2$ of the **extended** ed25519 trace height as `from_airs_and_degrees`
/// expects. The extended degree includes the ZK-padding factor of our
/// hiding-FRI config: `ext_log_height = log2(256) + is_zk = 8 + 1 = 9`.
pub(crate) const ED25519_EXT_TRACE_LOG_HEIGHT: usize = 8 + 1;

/// Extended log-height of the range-check table. `log2(2^16) + is_zk = 16 + 1`.
pub(crate) const RANGE_CHECK_EXT_TABLE_LOG_HEIGHT: usize = TABLE_LOG_HEIGHT + 1;

/// A clamped, non-trivial scalar reused across positive prove/verify
/// tests. Bits: low 3 = 0, bit 254 = 1, bit 255 = 0.
fn sample_clamped_scalar() -> [u8; 32] {
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 0xF8;
    scalar_bytes[1] = 0x12;
    scalar_bytes[15] = 0x9A;
    scalar_bytes[20] = 0x7C;
    scalar_bytes[31] = 0x40;
    scalar_bytes
}

/// Positive test: an honest scalar-mult trace plus its matching
/// range-check trace pass batched prove/verify.
#[test]
fn prove_batch_and_verify_batch_succeeds_for_clamped_scalar() {
    let scalar_bytes = sample_clamped_scalar();
    let mut inputs = build_batched_inputs(&scalar_bytes);

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
        .expect("verification of an honest batched trace must succeed");
}

/// Positive test: a clamped scalar with a denser high-bit pattern.
/// Same flow, different scalar — exercises a different distribution of
/// limb values flowing through the global bus.
#[test]
fn prove_batch_and_verify_batch_succeeds_for_dense_clamped_scalar() {
    let mut scalar_bytes = [0u8; 32];
    for (byte_index, byte) in scalar_bytes.iter_mut().enumerate() {
        *byte = (byte_index as u8).wrapping_mul(31).wrapping_add(7);
    }
    scalar_bytes[0] &= 0xF8;
    scalar_bytes[31] &= 0x7F;
    scalar_bytes[31] |= 0x40;

    let mut inputs = build_batched_inputs(&scalar_bytes);

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
        .expect("verification of an honest batched trace must succeed");
}
