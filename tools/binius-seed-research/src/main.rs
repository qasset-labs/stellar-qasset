//! Public-fixture experiment only. Not a production or approved quantum backend.
use binius_circuits::sha512::sha512_fixed;
use binius_core::{Word, constraint_system::ConstraintSystem};
use binius_frontend::{Circuit, CircuitBuilder, Wire};
use binius_hash::{ParallelCompressionAdaptor, StdCompression, StdDigest};
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};
use curve25519_dalek::edwards::EdwardsPoint;
use serde_json::json;
use std::{env, fs, io::Read, path::Path, time::Instant};

const DOMAIN: &[u8] = b"qasset-binius-leaf-clamp-research-v1\0";
const LOG_INV_RATE: usize = 1;
const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;
const FIXTURE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const FIXTURE_SCALAR: &str = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f";
const FIXTURE_POINT: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
type Verifier = ZKVerifier<StdDigest, StdCompression>;
type Prover = ZKProver<OptimalPackedB128, ParallelCompressionAdaptor<StdCompression>, StdDigest>;

struct Built {
    circuit: Circuit,
    seed: [Wire; 4],
    scalar: [Wire; 4],
}
fn build() -> Built {
    let b = CircuitBuilder::new();
    let scalar = std::array::from_fn(|_| b.add_inout());
    let seed = std::array::from_fn(|_| b.add_witness());
    let digest = sha512_fixed(&b, &seed, 32);
    // SHA512 wires use big endian words; byte0 low three bits sit at bits56..58.
    // byte31's high/next-high bits sit at bits7/6 of the fourth word.
    let mut clamped = [digest[0], digest[1], digest[2], digest[3]];
    clamped[0] = b.band(digest[0], b.add_constant_64(0xf8ff_ffff_ffff_ffff));
    clamped[3] = b.bor(
        b.band(digest[3], b.add_constant_64(0xffff_ffff_ffff_ff7f)),
        b.add_constant_64(0x40),
    );
    for i in 0..4 {
        b.assert_eq(format!("clamped_scalar[{i}]"), clamped[i], scalar[i]);
    }
    Built {
        circuit: b.build(),
        seed,
        scalar,
    }
}
fn decode<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|_| "invalid hex".to_owned())?;
    bytes.try_into().map_err(|_| format!("expected {N} bytes"))
}
fn words(bytes: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}
fn check_scalar(scalar: &[u8; 32]) -> Result<(), String> {
    if scalar[0] & 7 != 0 || scalar[31] & 0xc0 != 0x40 {
        return Err("invalid clamped encoding".into());
    }
    let point = EdwardsPoint::mul_base_clamped(*scalar)
        .compress()
        .to_bytes();
    if point != decode::<32>(FIXTURE_POINT)? {
        return Err("scalar does not match independent fixture public key".into());
    }
    Ok(())
}
fn public(cs: &ConstraintSystem, scalar: &[u8; 32]) -> Vec<Word> {
    let layout = &cs.value_vec_layout;
    assert_eq!(layout.n_inout, 4);
    let mut p = vec![Word::ZERO; layout.offset_witness];
    for (i, v) in cs.constants.iter().enumerate() {
        p[i] = *v;
    }
    for (i, v) in words(scalar).iter().enumerate() {
        p[layout.offset_inout + i] = Word(*v);
    }
    p
}
fn setup_verifier(cs: ConstraintSystem) -> Result<Verifier, String> {
    ZKVerifier::setup(cs, LOG_INV_RATE, StdCompression::default())
        .map_err(|e| format!("setup: {e:?}"))
}
fn verify(proof: &[u8], scalar: &[u8; 32], action: &[u8; 64]) -> Result<bool, String> {
    check_scalar(scalar)?;
    if proof.len() as u64 > MAX_PROOF_BYTES {
        return Err("proof too large".into());
    }
    let built = build();
    let cs = built.circuit.constraint_system().clone();
    let p = public(&cs, scalar);
    let v = setup_verifier(cs)?;
    let mut t = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    t.observe().write_bytes(DOMAIN);
    t.observe().write_bytes(scalar);
    t.observe().write_bytes(action);
    Ok(v.verify(&p, &mut t).is_ok() && t.finalize().is_ok())
}
fn prove(action: &[u8; 64], output: &Path, report: &Path, wrong: bool) -> Result<(), String> {
    let start = Instant::now();
    let built = build();
    let cs = built.circuit.constraint_system().clone();
    let scalar = decode::<32>(FIXTURE_SCALAR)?;
    check_scalar(&scalar)?;
    let v = setup_verifier(cs.clone())?;
    let pc = ParallelCompressionAdaptor::new(StdCompression::default());
    let p: Prover = ZKProver::setup(v, pc).map_err(|e| format!("prover setup: {e:?}"))?;
    let setup_seconds = start.elapsed().as_secs_f64();
    let mut seed = decode::<32>(FIXTURE_SEED)?;
    if wrong {
        seed[0] ^= 1;
    }
    let mut filler = built.circuit.new_witness_filler();
    for (i, w) in words(&seed).iter().enumerate() {
        filler[built.seed[i]] = Word(*w);
    }
    for (i, w) in words(&scalar).iter().enumerate() {
        filler[built.scalar[i]] = Word(*w);
    }
    // Wrong-witness experiment intentionally passes the evaluated, unsatisfied assignment
    // to the actual prover. It does not replace constraints or recompute public scalar.
    let fill = built.circuit.populate_wire_witness(&mut filler);
    let rejected_locally = fill.is_err();
    if !wrong {
        fill.map_err(|e| format!("witness fill: {e:?}"))?;
    }
    let witness = filler.into_value_vec();
    let mut t = ProverTranscript::new(StdChallenger::default());
    t.observe().write_bytes(DOMAIN);
    t.observe().write_bytes(&scalar);
    t.observe().write_bytes(action);
    let begin = Instant::now();
    p.prove(witness, rand::rng(), &mut t)
        .map_err(|e| format!("prove: {e:?}"))?;
    let prove_seconds = begin.elapsed().as_secs_f64();
    let proof = t.finalize();
    fs::write(output, &proof).map_err(|e| e.to_string())?;
    let begin = Instant::now();
    let accepted = verify(&proof, &scalar, action)?;
    let verify_seconds = begin.elapsed().as_secs_f64();
    let r = json!({"status":"research_experiment_only","wrong_private_witness":wrong,"public_scalar_hex":hex::encode(scalar),"fixture_public_key_hex":FIXTURE_POINT,"action_digest_sha512_hex":hex::encode(action),"proof_bytes":proof.len(),"setup_seconds":setup_seconds,"prove_seconds":prove_seconds,"verification_seconds_including_setup":verify_seconds,"verifier_accepted":accepted,"witness_assertions_rejected":rejected_locally,"log_inv_rate":LOG_INV_RATE,"upstream_configured_security_bits":96,"security_approved":false,"private_digest_tail_published":false,"total_seconds":start.elapsed().as_secs_f64()});
    fs::write(report, serde_json::to_vec_pretty(&r).unwrap()).map_err(|e| e.to_string())?;
    println!("{}", r);
    if accepted == wrong {
        return Err("unexpected proof acceptance result".into());
    }
    Ok(())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    match args.get(1).map(String::as_str){
        Some("prove") if args.len()==5||args.len()==6=>{
            let action=decode::<64>(&args[2])?;
            let wrong=if args.len()==6 {if args[5]!="wrong-witness"{return Err("unknown prove option".into());}true}else{false};
            prove(&action,Path::new(&args[3]),Path::new(&args[4]),wrong)
        },
        Some("verify") if args.len()==5=>{
            let scalar=decode::<32>(&args[3])?;let action=decode::<64>(&args[4])?;
            check_scalar(&scalar)?;
            let size=fs::metadata(&args[2]).map_err(|e|e.to_string())?.len();
            if size>MAX_PROOF_BYTES{return Err("proof too large".into());}
            let mut proof=Vec::new();
            fs::File::open(&args[2]).map_err(|e|e.to_string())?.take(MAX_PROOF_BYTES+1).read_to_end(&mut proof).map_err(|e|e.to_string())?;
            if proof.len() as u64>MAX_PROOF_BYTES{return Err("proof too large".into());}
            let begin=Instant::now();let valid=verify(&proof,&scalar,&action)?;
            println!("{}",json!({"valid":valid,"proof_bytes":size,"seconds_including_setup":begin.elapsed().as_secs_f64(),"action_digest_sha512_hex":hex::encode(action),"public_scalar_hex":hex::encode(scalar),"backend":"binius64-115108-zk-96-log-inv-rate1","relation":"rfc8032-leaf-clamped-seed-v1"}));
            if !valid {std::process::exit(2);}Ok(())
        },
        _=>Err("usage: prove ACTION64HEX PROOF REPORT [wrong-witness] | verify PROOF SCALAR32HEX ACTION64HEX".into())
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
        use sha2::{Digest, Sha512};
        let hash = Sha512::digest(decode::<32>(FIXTURE_SEED).unwrap());
        let mut scalar: [u8; 32] = hash[..32].try_into().unwrap();
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        assert_eq!(scalar, decode::<32>(FIXTURE_SCALAR).unwrap());
        assert!(check_scalar(&scalar).is_ok());
    }
    #[test]
    fn clamps_and_point_are_strict() {
        let s = decode::<32>(FIXTURE_SCALAR).unwrap();
        for (byte, bit) in [(0, 1), (31, 128), (31, 64), (1, 1)] {
            let mut bad = s;
            bad[byte] ^= bit;
            assert!(check_scalar(&bad).is_err());
        }
        assert!(decode::<32>("00").is_err());
        assert!(decode::<32>(&"00".repeat(33)).is_err());
    }
    #[test]
    fn public_section_and_unsatisfied_witness() {
        for wrong in [false, true] {
            let built = build();
            let scalar = decode::<32>(FIXTURE_SCALAR).unwrap();
            let mut seed = decode::<32>(FIXTURE_SEED).unwrap();
            if wrong {
                seed[0] ^= 1;
            }
            let mut f = built.circuit.new_witness_filler();
            for (i, w) in words(&seed).iter().enumerate() {
                f[built.seed[i]] = Word(*w);
            }
            for (i, w) in words(&scalar).iter().enumerate() {
                f[built.scalar[i]] = Word(*w);
            }
            assert_eq!(built.circuit.populate_wire_witness(&mut f).is_err(), wrong);
            let vv = f.into_value_vec();
            assert_eq!(
                public(built.circuit.constraint_system(), &scalar),
                vv.public()
            );
        }
    }
}
