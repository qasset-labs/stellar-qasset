// Copyright 2026 The Binius Developers
//! Native and Wasm transcript compatibility regression fixture.
use binius_transcript::{VerifierTranscript, fiat_shamir::CanSampleBits};
use binius_verifier::config::StdChallenger;

/// Exercise two transitions from sampling to observation, which serialize sampler indices.
pub fn transcript_vector() -> [u32; 3] {
    let mut t=VerifierTranscript::new(StdChallenger::default(),std::vec::Vec::new());
    t.observe().write_bytes(b"qasset-canonical-u64-le-sampler-v1\0");
    let a=t.sample_bits(29);
    t.observe().write_bytes(b"after-first-sampling");
    let b=t.sample_bits(31);
    t.observe().write_bytes(b"after-second-sampling");
    let c=t.sample_bits(23);
    [a,b,c]
}

fn main() { println!("{:?}", transcript_vector()); }
