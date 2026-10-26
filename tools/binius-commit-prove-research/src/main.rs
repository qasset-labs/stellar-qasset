//! Public-fixture experiment only. Not a production or approved quantum backend.
//!
//! This tool measures the relation-reframing hypothesis from
//! docs/COMPACT_BACKEND_LATTICE_GATE.md: instead of proving the full
//! `clamp(SHA512(seed))[0:32] = scalar` AND `[scalar]B = point` relation (the
//! existing `binius-seed-research` comparator, 539,888 bytes), this circuit
//! proves only `SHA256(seed) = commitment` — a hash-preimage statement with no
//! elliptic-curve scalar multiplication in the circuit at all. It reuses the
//! exact same pinned Binius64 commit, the same ZKProver/ZKVerifier (Iron
//! Spartan) configuration, the same canonical action-binding transcript
//! discipline, and the same public RFC8032 test1 fixture seed as witness, so
//! the two proof sizes/costs are directly comparable.
//!
//! This is NOT a proposal that SHA-256-of-the-raw-seed is the production
//! enrollment commitment. A real design needs its own domain-separated
//! enrollment statement and a reviewed choice of commitment function (see the
//! research doc's caveats on Vision/Poseidon-over-binary-fields vs. SHA-256).
//! This tool answers one narrower, measurable question: how much of the
//! existing backend's proof size and verifier cost comes from the relation
//! (SHA-512 + clamp + scalar-mult) versus the backend itself.
use binius_circuits::sha256::sha256_fixed;
use binius_core::{Word, constraint_system::ConstraintSystem};
use binius_frontend::{Circuit, CircuitBuilder, Wire};
use binius_hash::{ParallelCompressionAdaptor, StdCompression, StdDigest};
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};
use serde_json::json;
use std::{env, fs, io::Read, path::Path, time::Instant};

const DOMAIN: &[u8] = b"qasset-binius-commit-prove-research-v1\0";
const LOG_INV_RATE: usize = 1;
const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;
// Same public RFC8032 section 7.1 test1 32-byte seed as the existing
// `binius-seed-research` comparator, reused ONLY so the witness size and
// content are identical between the two measured circuits.
const FIXTURE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
// SHA-256(FIXTURE_SEED), independently re-checked against the `sha2` crate in
// `independently_hashes_rfc_fixture` below.
const FIXTURE_COMMITMENT: &str = "644d50ab64864c20a12b3c4656d46b4a48f69ef7c47ecdc8415cd28316b22ef5";

type Verifier = ZKVerifier<StdDigest, StdCompression>;
type Prover = ZKProver<OptimalPackedB128, ParallelCompressionAdaptor<StdCompression>, StdDigest>;

struct Built {
    circuit: Circuit,
    seed: [Wire; 8],
    commitment: [Wire; 8],
}

fn build() -> Built {
    let b = CircuitBuilder::new();
    // `sha256_fixed` expects 32-bit words packed one per wire (high 32 bits
    // zero), big-endian, both for the message and for comparison with its
    // returned digest wires.
    let commitment: [Wire; 8] = std::array::from_fn(|_| b.add_inout());
    let seed: [Wire; 8] = std::array::from_fn(|_| b.add_witness());
    let digest = sha256_fixed(&b, &seed, 32);
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

/// Packs 32 bytes into 8 big-endian 32-bit words, one per wire's low 32 bits,
/// matching `sha256_fixed`'s required wire layout.
fn words32(bytes: &[u8; 32]) -> [u64; 8] {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()) as u64)
}

fn public(cs: &ConstraintSystem, commitment: &[u8; 32]) -> Vec<Word> {
    let layout = &cs.value_vec_layout;
    assert_eq!(layout.n_inout, 8);
    let mut p = vec![Word::ZERO; layout.offset_witness];
    for (i, v) in cs.constants.iter().enumerate() {
        p[i] = *v;
    }
    for (i, w) in words32(commitment).iter().enumerate() {
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
    let commitment = decode::<32>(FIXTURE_COMMITMENT)?;
    let v = setup_verifier(cs.clone())?;
    let pc = ParallelCompressionAdaptor::new(StdCompression::default());
    let p: Prover = ZKProver::setup(v, pc).map_err(|e| format!("prover setup: {e:?}"))?;
    let setup_seconds = start.elapsed().as_secs_f64();
    let mut seed = decode::<32>(FIXTURE_SEED)?;
    if wrong {
        seed[0] ^= 1;
    }
    let mut filler = built.circuit.new_witness_filler();
    for (i, w) in words32(&seed).iter().enumerate() {
        filler[built.seed[i]] = Word(*w);
    }
    for (i, w) in words32(&commitment).iter().enumerate() {
        filler[built.commitment[i]] = Word(*w);
    }
    // Wrong-witness experiment intentionally passes the evaluated, unsatisfied
    // assignment to the actual prover, mirroring binius-seed-research's
    // discipline: it does not replace constraints or recompute the public
    // commitment.
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
        "relation": "exists_private_seed_32_bytes: SHA256(seed) = public_commitment (no clamp, no scalar-mult)",
        "comparator_relation": "binius-seed-research: clamp(SHA512(seed))[0:32] = scalar AND [scalar]B = point",
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
                    "relation": "sha256-preimage-commitment-v1"
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
    fn independently_hashes_rfc_fixture() {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(decode::<32>(FIXTURE_SEED).unwrap());
        let commitment: [u8; 32] = hash.into();
        assert_eq!(commitment, decode::<32>(FIXTURE_COMMITMENT).unwrap());
    }

    #[test]
    fn public_section_and_unsatisfied_witness() {
        for wrong in [false, true] {
            let built = build();
            let commitment = decode::<32>(FIXTURE_COMMITMENT).unwrap();
            let mut seed = decode::<32>(FIXTURE_SEED).unwrap();
            if wrong {
                seed[0] ^= 1;
            }
            let mut f = built.circuit.new_witness_filler();
            for (i, w) in words32(&seed).iter().enumerate() {
                f[built.seed[i]] = Word(*w);
            }
            for (i, w) in words32(&commitment).iter().enumerate() {
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

/// Records the measured padded trace size this relation compiles to, so a
/// future change to this circuit (or to the upstream padding rule) that moves
/// it into a different power-of-two bucket is caught here rather than only
/// showing up as a silent proof-size change. See
/// docs/COMPACT_BACKEND_LATTICE_GATE.md section 5: the SHA-512+clamp+scalar-
/// mult comparator (1155 AND constraints) lands in this same 2048-word
/// bucket as this circuit's 912, which is why removing the scalar-mult
/// gadget barely changed the final proof size even though it meaningfully
/// reduced constraint count and prove/verify time.
#[cfg(test)]
mod circuit_size_bucket {
    use super::*;
    #[test]
    fn matches_measured_bucket() {
        let built = build();
        let cs = built.circuit.constraint_system();
        let layout = &cs.value_vec_layout;
        assert_eq!(cs.and_constraints.len(), 912);
        assert_eq!(cs.mul_constraints.len(), 0);
        assert_eq!(layout.committed_total_len, 2048);
    }
}

#[cfg(test)]
/// Records the measured AND-constraint cost of two already-vetted, already-
/// implemented 32-byte hash gadgets from the same `binius-circuits` crate,
/// which motivated building a BLAKE3 variant of this tool
/// (`tools/binius-commit-prove-blake3-research`): BLAKE3's 626 AND
/// constraints land in a 1,024-word trace bucket, half of SHA-256's 2,048.
/// See docs/binius-commit-prove-research.json for the resulting measured
/// proof size/time.
mod hash_gadget_probe {
    use binius_circuits::{blake3::blake3_fixed, sha256::sha256_fixed};
    use binius_frontend::CircuitBuilder;

    fn bucket(build: impl Fn(&CircuitBuilder)) -> (usize, usize) {
        let b = CircuitBuilder::new();
        build(&b);
        let circuit = b.build();
        let cs = circuit.constraint_system();
        (
            cs.and_constraints.len(),
            cs.value_vec_layout.committed_total_len,
        )
    }

    #[test]
    fn blake3_crosses_the_bucket_boundary_sha256_does_not() {
        let hash32 = |f: fn(
            &CircuitBuilder,
            &[binius_frontend::Wire],
            usize,
        ) -> [binius_frontend::Wire; 8]| {
            move |b: &CircuitBuilder| {
                let msg: Vec<_> = (0..8).map(|_| b.add_witness()).collect();
                let out = f(b, &msg, 32);
                let expect: [_; 8] = std::array::from_fn(|_| b.add_inout());
                b.assert_eq_v("out", out, expect);
            }
        };
        assert_eq!(bucket(hash32(sha256_fixed)), (912, 2048));
        assert_eq!(bucket(hash32(blake3_fixed)), (626, 1024));
    }
}
