//! Public-fixture experiment only. Not a production or approved quantum backend.
//!
//! Follow-up to `tools/binius-commit-prove-research`. That tool found that
//! proving `SHA256(seed) = commitment` instead of the full SHA-512/clamp/
//! scalar-mult relation barely shrank the Binius64 Iron Spartan proof,
//! because both relations' AND-constraint counts padded to the same
//! 2,048-word trace bucket. A probe comparing already-vetted 32-byte hash
//! gadgets in `binius-circuits` found BLAKE3 needs only 626 AND constraints
//! for the same input size, versus SHA-256's 912 — landing in a 1,024-word
//! bucket, half of SHA-256's. This tool measures what that actually does to
//! proof size/time, proving `BLAKE3(seed) = commitment` against the exact
//! same pinned Binius64 commit, Iron Spartan configuration, action-binding
//! discipline and RFC8032 fixture seed as the other two tools.
//!
//! BLAKE3 is an already-implemented, independently specified, widely used
//! hash function (not a novel or bespoke primitive introduced by this
//! project) — chosen here specifically because it is the smallest
//! *already-vetted* circuit gadget available in the pinned `binius-circuits`
//! crate, not because it is claimed to be the right production commitment
//! function. See docs/COMPACT_BACKEND_LATTICE_GATE.md section 2's caveats on
//! committing via a classical hash versus a genuinely algebraic ZK-friendly
//! one (Vision/Poseidon-over-binary-fields), which this tool does not
//! attempt to implement.
use binius_circuits::blake3::blake3_fixed;
use binius_core::{Word, constraint_system::ConstraintSystem};
use binius_frontend::{Circuit, CircuitBuilder, Wire};
use binius_hash::{ParallelCompressionAdaptor, StdCompression, StdDigest};
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};
use std::{env, fs, io::Read, path::Path, time::Instant};

use serde_json::json;

const DOMAIN: &[u8] = b"qasset-binius-commit-prove-blake3-research-v1\0";
const LOG_INV_RATE: usize = 1;
const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;
// Same public RFC8032 section 7.1 test1 32-byte seed as the other two
// comparators, reused ONLY so the witness size/content stays identical.
const FIXTURE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

type Verifier = ZKVerifier<StdDigest, StdCompression>;
type Prover = ZKProver<OptimalPackedB128, ParallelCompressionAdaptor<StdCompression>, StdDigest>;

struct Built {
    circuit: Circuit,
    seed: [Wire; 8],
    commitment: [Wire; 8],
}

fn build() -> Built {
    let b = CircuitBuilder::new();
    // blake3_fixed expects 32-bit little-endian words packed one per wire
    // (high 32 bits zero), both for the message and its returned digest.
    let commitment: [Wire; 8] = std::array::from_fn(|_| b.add_inout());
    let seed: [Wire; 8] = std::array::from_fn(|_| b.add_witness());
    let digest = blake3_fixed(&b, &seed, 32);
    b.assert_eq_v("commitment", digest, commitment);
    Built {
        circuit: b.build(),
        seed,
        commitment,
    }
}

fn decode<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|_| "invalid hex".to_owned())?;
    bytes.try_into().map_err(|_| format!("expected {N} bytes"))
}

/// Packs 32 bytes into 8 little-endian 32-bit words, one per wire's low 32
/// bits, matching `blake3_fixed`'s required wire layout (confirmed against
/// its own upstream test in crates/circuits/src/blake3/mod.rs).
fn words_le32(bytes: &[u8; 32]) -> [u64; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()) as u64)
}

#[cfg(test)]
fn bytes_from_words_le32(words: &[u64; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&(*w as u32).to_le_bytes());
    }
    out
}

/// Independently computes BLAKE3(seed) with the official `blake3` crate,
/// matching the hash upstream's own blake3_fixed test checks against — this
/// tool never hardcodes a commitment constant, to avoid any transcription
/// risk in a research fixture.
fn commitment_for(seed: &[u8; 32]) -> [u8; 32] {
    blake3::hash(seed).into()
}

fn public(cs: &ConstraintSystem, commitment: &[u8; 32]) -> Vec<Word> {
    let layout = &cs.value_vec_layout;
    assert_eq!(layout.n_inout, 8);
    let mut p = vec![Word::ZERO; layout.offset_witness];
    for (i, v) in cs.constants.iter().enumerate() {
        p[i] = *v;
    }
    for (i, w) in words_le32(commitment).iter().enumerate() {
        p[layout.offset_inout + i] = Word(*w);
    }
    p
}

fn setup_verifier(cs: ConstraintSystem) -> Result<Verifier, String> {
    ZKVerifier::setup(cs, LOG_INV_RATE, StdCompression::default())
        .map_err(|e| format!("setup: {e:?}"))
}

fn verify(proof: &[u8], commitment: &[u8; 32], action: &[u8; 64]) -> Result<bool, String> {
    if proof.len() as u64 > MAX_PROOF_BYTES {
        return Err("proof too large".into());
    }
    let built = build();
    let cs = built.circuit.constraint_system().clone();
    let p = public(&cs, commitment);
    let v = setup_verifier(cs)?;
    let mut t = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    t.observe().write_bytes(DOMAIN);
    t.observe().write_bytes(commitment);
    t.observe().write_bytes(action);
    Ok(v.verify(&p, &mut t).is_ok() && t.finalize().is_ok())
}

fn prove(action: &[u8; 64], output: &Path, report: &Path, wrong: bool) -> Result<(), String> {
    let start = Instant::now();
    let built = build();
    let cs = built.circuit.constraint_system().clone();
    let mut seed = decode::<32>(FIXTURE_SEED)?;
    let commitment = commitment_for(&seed);
    let v = setup_verifier(cs.clone())?;
    let pc = ParallelCompressionAdaptor::new(StdCompression::default());
    let p: Prover = ZKProver::setup(v, pc).map_err(|e| format!("prover setup: {e:?}"))?;
    let setup_seconds = start.elapsed().as_secs_f64();
    if wrong {
        seed[0] ^= 1;
    }
    let mut filler = built.circuit.new_witness_filler();
    for (i, w) in words_le32(&seed).iter().enumerate() {
        filler[built.seed[i]] = Word(*w);
    }
    for (i, w) in words_le32(&commitment).iter().enumerate() {
        filler[built.commitment[i]] = Word(*w);
    }
    // Wrong-witness experiment intentionally passes the evaluated,
    // unsatisfied assignment to the actual prover, mirroring the other two
    // tools' discipline: it does not replace constraints or recompute the
    // public commitment.
    let fill = built.circuit.populate_wire_witness(&mut filler);
    let rejected_locally = fill.is_err();
    if !wrong {
        fill.map_err(|e| format!("witness fill: {e:?}"))?;
    }
    let witness = filler.into_value_vec();
    let mut t = ProverTranscript::new(StdChallenger::default());
    t.observe().write_bytes(DOMAIN);
    t.observe().write_bytes(&commitment);
    t.observe().write_bytes(action);
    let begin = Instant::now();
    p.prove(witness, rand::rng(), &mut t)
        .map_err(|e| format!("prove: {e:?}"))?;
    let prove_seconds = begin.elapsed().as_secs_f64();
    let proof = t.finalize();
    fs::write(output, &proof).map_err(|e| e.to_string())?;
    let begin = Instant::now();
    let accepted = verify(&proof, &commitment, action)?;
    let verify_seconds = begin.elapsed().as_secs_f64();
    let r = json!({
        "status": "research_experiment_only",
        "relation": "exists_private_seed_32_bytes: BLAKE3(seed) = public_commitment (no clamp, no scalar-mult)",
        "comparator_relations": {
            "binius-seed-research": "clamp(SHA512(seed))[0:32] = scalar AND [scalar]B = point (1155 AND constraints, 2048-word bucket, 539888 proof bytes)",
            "binius-commit-prove-research": "SHA256(seed) = commitment (912 AND constraints, 2048-word bucket, 539856 proof bytes)"
        },
        "wrong_private_witness": wrong,
        "public_commitment_hex": hex::encode(commitment),
        "action_digest_sha512_hex": hex::encode(action),
        "proof_bytes": proof.len(),
        "setup_seconds": setup_seconds,
        "prove_seconds": prove_seconds,
        "verification_seconds_including_setup": verify_seconds,
        "verifier_accepted": accepted,
        "witness_assertions_rejected": rejected_locally,
        "log_inv_rate": LOG_INV_RATE,
        "upstream_configured_security_bits": 96,
        "security_approved": false,
        "production_enrollment_relation_claim": false,
        "total_seconds": start.elapsed().as_secs_f64()
    });
    fs::write(report, serde_json::to_vec_pretty(&r).unwrap()).map_err(|e| e.to_string())?;
    println!("{}", r);
    if accepted == wrong {
        return Err("unexpected proof acceptance result".into());
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") if args.len() == 5 || args.len() == 6 => {
            let action = decode::<64>(&args[2])?;
            let wrong = if args.len() == 6 {
                if args[5] != "wrong-witness" {
                    return Err("unknown prove option".into());
                }
                true
            } else {
                false
            };
            prove(&action, Path::new(&args[3]), Path::new(&args[4]), wrong)
        }
        Some("verify") if args.len() == 5 => {
            let commitment = decode::<32>(&args[3])?;
            let action = decode::<64>(&args[4])?;
            let size = fs::metadata(&args[2]).map_err(|e| e.to_string())?.len();
            if size > MAX_PROOF_BYTES {
                return Err("proof too large".into());
            }
            let mut proof = Vec::new();
            fs::File::open(&args[2])
                .map_err(|e| e.to_string())?
                .take(MAX_PROOF_BYTES + 1)
                .read_to_end(&mut proof)
                .map_err(|e| e.to_string())?;
            if proof.len() as u64 > MAX_PROOF_BYTES {
                return Err("proof too large".into());
            }
            let begin = Instant::now();
            let valid = verify(&proof, &commitment, &action)?;
            println!(
                "{}",
                json!({
                    "valid": valid,
                    "proof_bytes": size,
                    "seconds_including_setup": begin.elapsed().as_secs_f64(),
                    "action_digest_sha512_hex": hex::encode(action),
                    "public_commitment_hex": hex::encode(commitment),
                    "backend": "binius64-115108-zk-96-log-inv-rate1",
                    "relation": "blake3-preimage-commitment-v1"
                })
            );
            if !valid {
                std::process::exit(2);
            }
            Ok(())
        }
        _ => Err(
            "usage: prove ACTION64HEX PROOF REPORT [wrong-witness] | verify PROOF COMMITMENT32HEX ACTION64HEX"
                .into(),
        ),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independently_hashes_rfc_fixture_with_official_blake3_crate() {
        let seed = decode::<32>(FIXTURE_SEED).unwrap();
        let commitment = commitment_for(&seed);
        // Round-trips through the same word packing the circuit uses.
        assert_eq!(bytes_from_words_le32(&words_le32(&commitment)), commitment);
    }

    #[test]
    fn circuit_matches_measured_bucket() {
        let built = build();
        let cs = built.circuit.constraint_system();
        let layout = &cs.value_vec_layout;
        assert_eq!(cs.and_constraints.len(), 626);
        assert_eq!(cs.mul_constraints.len(), 0);
        assert_eq!(layout.committed_total_len, 1024);
    }

    #[test]
    fn public_section_and_unsatisfied_witness() {
        for wrong in [false, true] {
            let built = build();
            let mut seed = decode::<32>(FIXTURE_SEED).unwrap();
            let commitment = commitment_for(&seed);
            if wrong {
                seed[0] ^= 1;
            }
            let mut f = built.circuit.new_witness_filler();
            for (i, w) in words_le32(&seed).iter().enumerate() {
                f[built.seed[i]] = Word(*w);
            }
            for (i, w) in words_le32(&commitment).iter().enumerate() {
                f[built.commitment[i]] = Word(*w);
            }
            assert_eq!(built.circuit.populate_wire_witness(&mut f).is_err(), wrong);
            let vv = f.into_value_vec();
            assert_eq!(
                public(built.circuit.constraint_system(), &commitment),
                vv.public()
            );
        }
    }
}
