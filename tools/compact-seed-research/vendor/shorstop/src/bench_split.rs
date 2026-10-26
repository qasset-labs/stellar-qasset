//! Split prove/verify benchmarks with persistent proof artifacts.
//!
//! Each `*_split_prove_*` test runs the prover and writes the encoded
//! proof bytes to `<repo>/benchmarks/proofs/<name>.proof.bin`; the
//! matching `*_split_verify_*` test reads that file and runs the
//! verifier. Each test is `#[ignore]` so default `cargo test` skips
//! them; `scripts/bench_plonky3_split.py` invokes them under
//! `/usr/bin/time -l` to measure prover and verifier time/RSS in
//! isolation.
//!
//! Proof artifacts persist across runs (so the verifier can be
//! re-benched without re-proving). Re-running the prover overwrites
//! the file.

#![cfg(test)]

use std::fs;
use std::path::PathBuf;

// ── Persistent artifact path ─────────────────────────────────────────────

/// Repo-root `benchmarks/proofs/` resolved from the crate manifest dir.
/// Three `..` hops: `plonky3-adapter` → `mopro` → `libs` → repo root.
fn proof_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../benchmarks/proofs")
        .join(format!("{name}.proof.bin"))
}

fn write_proof_artifact(name: &str, bytes: &[u8]) {
    let path = proof_path(name);
    fs::create_dir_all(path.parent().unwrap()).expect("create proofs dir");
    fs::write(&path, bytes).expect("write proof artifact");
    eprintln!(
        "[bench-split] wrote {} bytes -> {}",
        bytes.len(),
        path.display()
    );
}

fn read_proof_artifact(name: &str) -> Vec<u8> {
    let path = proof_path(name);
    fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read proof artifact at {} ({}). \
             Run the matching `*_split_prove_*` test first.",
            path.display(),
            e
        )
    })
}

// ── SHA-512 single-table prove/verify ────────────────────────────────────

macro_rules! sha512_split_test {
    ($prove_fn:ident, $verify_fn:ident, $n:expr, $name:literal) => {
        #[test]
        #[ignore]
        fn $prove_fn() {
            let proof = crate::prove_sha512_compressions($n).expect("prove");
            write_proof_artifact($name, &proof);
        }

        #[test]
        #[ignore]
        fn $verify_fn() {
            let bytes = read_proof_artifact($name);
            assert!(
                crate::verify_sha512_compressions(&bytes).expect("verify decode"),
                "verifier rejected the persisted proof for {}",
                $name
            );
        }
    };
}

sha512_split_test!(sha512_split_prove_1,    sha512_split_verify_1,    1,    "sha512_n1");
sha512_split_test!(sha512_split_prove_2,    sha512_split_verify_2,    2,    "sha512_n2");
sha512_split_test!(sha512_split_prove_4,    sha512_split_verify_4,    4,    "sha512_n4");
sha512_split_test!(sha512_split_prove_8,    sha512_split_verify_8,    8,    "sha512_n8");
sha512_split_test!(sha512_split_prove_16,   sha512_split_verify_16,   16,   "sha512_n16");
sha512_split_test!(sha512_split_prove_256,  sha512_split_verify_256,  256,  "sha512_n256");
sha512_split_test!(sha512_split_prove_1024, sha512_split_verify_1024, 1024, "sha512_n1024");
sha512_split_test!(sha512_split_prove_2048, sha512_split_verify_2048, 2048, "sha512_n2048");
sha512_split_test!(sha512_split_prove_4096, sha512_split_verify_4096, 4096, "sha512_n4096");
sha512_split_test!(sha512_split_prove_4098, sha512_split_verify_4098, 4098, "sha512_n4098");
sha512_split_test!(sha512_split_prove_8192, sha512_split_verify_8192, 8192, "sha512_n8192");

// ── Ed25519 batched (Ed25519 + RangeCheckU16) prove/verify ──────────────
//
// Uses `p3_batch_stark::prove_batch` / `verify_batch`. The artifact
// captures (public values, encoded BatchProof) so the verifier can be
// re-run without re-generating the witness trace.

use p3_batch_stark::{prove_batch, verify_batch, BatchProof, Commitment, ProverData, StarkInstance};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};

use crate::batched_air::BatchedAir;
use crate::ed25519_air::air::Ed25519Air;
use crate::ed25519_air::prove_verify_helpers::build_batched_inputs;
use crate::ed25519_air::prove_verify_tests::{
    ED25519_EXT_TRACE_LOG_HEIGHT, RANGE_CHECK_EXT_TABLE_LOG_HEIGHT,
};
use crate::range_check_u16_air::air::RangeCheckU16Air;
use crate::{Cfg, Val, make_config};

const ED25519_BENCH_NAME: &str = "ed25519_n1";

/// Self-contained artifact for cross-process Ed25519 batch verification.
///
/// `verify_batch` takes a `CommonData` argument (the verification key)
/// that includes the global preprocessed commitment. With our hiding
/// MMCS, the preprocessed commit is randomly salted at commit time, so
/// the verifier process can't reproduce the prover's commitment by
/// re-running `from_airs_and_degrees`. We serialize the commitment into
/// the artifact so the verifier can plug it into its reconstructed
/// `CommonData` and verify without recomputing it.
///
/// Lookup metadata in `CommonData` is deterministic from the AIRs and
/// is reconstructed verbatim on the verifier side; only the salted
/// preprocessed commitment needs to ride along.
#[derive(Serialize, Deserialize)]
struct Ed25519Artifact {
    /// Canonical-u32 public values; `Vec<Val>` rebuilt on the verifier.
    public_values: Vec<u32>,
    /// Postcard-encoded `Commitment<Cfg>` of the global preprocessed
    /// trace (Ed25519 base-point multiples + u16 range-check table).
    preprocessed_commitment: Vec<u8>,
    /// Postcard-encoded `BatchProof<Cfg>`.
    proof_bytes: Vec<u8>,
}

/// Same scalar shape as `prove_verify_tests::sample_clamped_scalar` —
/// keeps the bench input deterministic across runs (same proof size,
/// same artifact path).
fn ed25519_bench_scalar() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xF8;
    s[1] = 0x12;
    s[15] = 0x9A;
    s[20] = 0x7C;
    s[31] = 0x40;
    s
}

#[test]
#[ignore]
fn ed25519_split_prove_1() {
    let scalar = ed25519_bench_scalar();
    let mut inputs = build_batched_inputs(&scalar);

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

    let proof_bytes =
        postcard::to_allocvec(&proof).expect("postcard serialize BatchProof");
    let public_values: Vec<u32> = inputs
        .ed25519_public_values
        .iter()
        .map(|f| f.as_canonical_u32())
        .collect();
    let preprocessed_commitment = postcard::to_allocvec(
        &prover_data
            .common
            .preprocessed
            .as_ref()
            .expect("Ed25519 batch must have preprocessed commitment")
            .commitment,
    )
    .expect("postcard serialize preprocessed Commitment");

    let artifact = Ed25519Artifact {
        public_values,
        preprocessed_commitment,
        proof_bytes,
    };
    let bytes = postcard::to_allocvec(&artifact).expect("postcard serialize artifact");
    write_proof_artifact(ED25519_BENCH_NAME, &bytes);
}

#[test]
#[ignore]
fn ed25519_split_verify_1() {
    let bytes = read_proof_artifact(ED25519_BENCH_NAME);
    let artifact: Ed25519Artifact =
        postcard::from_bytes(&bytes).expect("postcard deserialize artifact");
    let proof: BatchProof<Cfg> =
        postcard::from_bytes(&artifact.proof_bytes).expect("postcard deserialize BatchProof");

    // Verifier setup: AIRs + degrees + common. No trace generation —
    // the artifact carries the public values so the verifier never
    // touches the witness path.
    let mut airs = [
        BatchedAir::Ed25519(Ed25519Air::default()),
        BatchedAir::RangeCheckU16(RangeCheckU16Air::default()),
    ];
    let config = make_config();
    let mut prover_data = ProverData::from_airs_and_degrees(
        &config,
        &mut airs,
        &[ED25519_EXT_TRACE_LOG_HEIGHT, RANGE_CHECK_EXT_TABLE_LOG_HEIGHT],
    );
    // Override the preprocessed commitment with the prover's: with
    // hiding MMCS the in-process recommit produces a different (salted)
    // root, so the verifier loads the prover's root from the artifact.
    let pp_commit: Commitment<Cfg> = postcard::from_bytes(&artifact.preprocessed_commitment)
        .expect("postcard deserialize preprocessed Commitment");
    prover_data
        .common
        .preprocessed
        .as_mut()
        .expect("Ed25519 batch must have preprocessed commitment")
        .commitment = pp_commit;
    let common = &prover_data.common;

    let ed25519_pvs: Vec<Val> = artifact
        .public_values
        .iter()
        .map(|&u| Val::from_u32(u))
        .collect();
    let public_values = vec![ed25519_pvs, Vec::<Val>::new()];

    verify_batch(&config, &airs, &proof, &public_values, common)
        .expect("verifier rejected the persisted Ed25519 proof");
}


// ── Full BIP-39 → Solana pipeline split bench ─────────────────────────
//
// Wraps the canonical `crate::bip39_to_solana::prove` / `verify` entry
// points so the bench script can drive prove and verify in separate
// processes. The proof + verify logic itself lives in
// `bip39_to_solana.rs`; here we just write the artifact bytes to disk
// for split-process measurement.

const BIP39_TO_SOLANA_BENCH_NAME: &str = "bip39_to_solana";
/// Deterministic test mnemonic — same byte sequence across runs so
/// proof size / time are comparable.
const BIP39_TO_SOLANA_BENCH_MNEMONIC: &[u8] =
    b"abandon abandon abandon abandon abandon abandon abandon abandon \
      abandon abandon abandon about";

#[test]
#[ignore]
fn bip39_to_solana_split_prove() {
    let artifact_bytes = crate::bip39_to_solana::prove(
        BIP39_TO_SOLANA_BENCH_MNEMONIC,
        &[0u8; 32],
        &[0u8; 32],
        0,
        0,
    )
    .expect("prove must succeed");
    write_proof_artifact(BIP39_TO_SOLANA_BENCH_NAME, &artifact_bytes);
}

#[test]
#[ignore]
fn bip39_to_solana_split_verify() {
    let bytes = read_proof_artifact(BIP39_TO_SOLANA_BENCH_NAME);
    let (address, _pq_dest, _blockhash) =
        crate::bip39_to_solana::verify(&bytes).expect("verify of an honest proof must succeed");
    // Sanity: the verified Solana address is non-zero.
    assert!(
        address.iter().any(|&b| b != 0),
        "verified address is all zeros — suspicious"
    );
}
