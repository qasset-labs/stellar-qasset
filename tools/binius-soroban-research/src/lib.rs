// SPDX-License-Identifier: MIT
//! Research-only actual Soroban ABI cost boundary. No account or asset authority.
#![no_std]
extern crate alloc;
#[allow(dead_code)]
mod frozen;
use soroban_sdk::{Bytes, BytesN, Env, contract, contractimpl};

const SETUP_BYTES: u32 = 2_714_051;
const MAX_PROOF_BYTES: u32 = 1_048_576;
// Public RFC8032 fixture only; generic protected-key integration is separate.
const FIXTURE_SCALAR: [u8; 32] = [
    48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104, 217,
    128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79,
];
#[contract]
pub struct BiniusCostResearch;
#[contractimpl]
impl BiniusCostResearch {
    /// Always false: this measurement component cannot authorize recovery.
    pub fn backend_available(_env: Env) -> bool {
        false
    }

    /// Execute a public-fixture proof check, without modifying any account state.
    /// Large Bytes inputs bypass transaction transport in this local diagnostic.
    pub fn verify_fixture(
        _env: Env,
        setup: Bytes,
        proof: Bytes,
        scalar: BytesN<32>,
        action: BytesN<64>,
    ) -> bool {
        if setup.len() != SETUP_BYTES
            || proof.is_empty()
            || proof.len() > MAX_PROOF_BYTES
            || scalar.to_array() != FIXTURE_SCALAR
        {
            return false;
        }
        let mut setup_buffer = alloc::vec![0u8; setup.len() as usize];
        setup.copy_into_slice(&mut setup_buffer);
        let verifier = match frozen::load(&setup_buffer) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let mut proof_buffer = alloc::vec![0u8; proof.len() as usize];
        proof.copy_into_slice(&mut proof_buffer);
        qasset_binius_nostd_verifier::verify_preprocessed(
            &verifier,
            &proof_buffer,
            &scalar.to_array(),
            &action.to_array(),
        )
    }
}
