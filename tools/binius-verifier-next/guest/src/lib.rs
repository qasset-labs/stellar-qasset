// SPDX-License-Identifier: MIT
//! Experimental actual verifier call boundary. This library is not a contract.
//! The caller must construct the verifier from independently trusted preprocessing.
#![no_std]
extern crate alloc;
use binius_core::Word;
use binius_transcript::VerifierTranscript;
use binius_verifier::hash::{StdCompression, StdDigest};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};

/// Execute the complete ZK verifier and reject unread trailing proof bytes.
///
/// `verifier` must originate from a trusted pinned circuit configuration.
/// The caller must separately check the exact scalar-to-protected-key binding.
/// Public inputs are derived here so a second scalar cannot be substituted.
/// No caller-supplied verifier configuration is authorized by this function.
/// The one MiB proof cap precedes this function's allocation; contract callers
/// must also bound reads before allocating their input buffers.
pub fn verify_preprocessed(
    verifier: &ZKVerifier<StdDigest, StdCompression>,
    proof: &[u8],
    scalar: &[u8; 32],
    action: &[u8; 64],
) -> bool {
    verify_preprocessed_detailed(verifier, proof, scalar, action).is_ok()
}
pub fn verify_preprocessed_detailed(
    verifier: &ZKVerifier<StdDigest, StdCompression>,
    proof: &[u8],
    scalar: &[u8; 32],
    action: &[u8; 64],
) -> Result<(), &'static str> {
    if proof.len() > 1024 * 1024 || scalar[0] & 7 != 0 || scalar[31] & 0xc0 != 0x40 {
        return Err("invalid proof or public layout");
    }
    let cs = verifier.constraint_system();
    let layout = &cs.value_vec_layout;
    if layout.n_inout != 4
        || cs.constants.len() > layout.offset_inout
        || layout
            .offset_inout
            .checked_add(4)
            .is_none_or(|n| n > layout.offset_witness)
    {
        return Err("invalid proof or public layout");
    }
    let mut public = alloc::vec![Word::ZERO; layout.offset_witness];
    public[..cs.constants.len()].copy_from_slice(&cs.constants);
    for i in 0..4 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&scalar[8 * i..8 * i + 8]);
        public[layout.offset_inout + i] = Word(u64::from_be_bytes(bytes));
    }
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    transcript
        .observe()
        .write_bytes(b"qasset-binius-leaf-clamp-research-v1\0");
    transcript.observe().write_bytes(scalar);
    transcript.observe().write_bytes(action);
    verifier
        .verify(&public, &mut transcript)
        .map_err(|_| "verification_failed")?;
    transcript
        .finalize()
        .map_err(|_| "trailing_or_unread_proof")
}

pub mod regression;
