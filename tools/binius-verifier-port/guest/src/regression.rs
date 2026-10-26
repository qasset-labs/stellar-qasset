// SPDX-License-Identifier: MIT
//! Native and Wasm transcript compatibility regression fixture.
use binius_transcript::{VerifierTranscript, fiat_shamir::CanSampleBits};
use binius_verifier::config::StdChallenger;

/// Exercise two transitions from sampling to observation, which serialize sampler indices.
pub fn transcript_vector() -> [u32; 3] {
    let mut t = VerifierTranscript::new(StdChallenger::default(), alloc::vec::Vec::new());
    t.observe()
        .write_bytes(b"qasset-canonical-u64-le-sampler-v1\0");
    let a = t.sample_bits(29);
    t.observe().write_bytes(b"after-first-sampling");
    let b = t.sample_bits(31);
    t.observe().write_bytes(b"after-second-sampling");
    let c = t.sample_bits(23);
    [a, b, c]
}

/// Independently measured original 64-bit upstream challenger output.
pub const GOLDEN: [u32; 3] = [394127921, 1463445479, 3541783];
#[cfg(test)]
mod tests {
    #[test]
    fn canonical_u64_le_transcript_matches_original_native() {
        assert_eq!(super::transcript_vector(), super::GOLDEN);
    }
}
