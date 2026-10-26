// Copyright 2026 Q-Asset contributors
//! Isolated deterministic fixed-preprocessing split for the exact public fixture circuit.
mod frozen;
#[allow(dead_code)]
mod native;
use binius_verifier::{config::StdChallenger, transcript::VerifierTranscript};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, time::Instant};
const EXPECTED_SHA256: &str = include_str!("../setup.sha256");
const FIXED: &[u8] = include_bytes!("../fixed-setup.bin");
const DOMAIN: &[u8] = b"qasset-binius-leaf-clamp-research-v1\0";
const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;
fn verify(
    v: &frozen::Verifier,
    proof: &[u8],
    scalar: &[u8; 32],
    action: &[u8; 64],
) -> Result<bool, String> {
    native::check_scalar(scalar)?;
    if proof.len() as u64 > MAX_PROOF_BYTES {
        return Err("proof too large".into());
    }
    let public = native::public(v.constraint_system(), scalar);
    let mut t = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    t.observe().write_bytes(DOMAIN);
    t.observe().write_bytes(scalar);
    t.observe().write_bytes(action);
    let result = v.verify(&public, &mut t);
    let finalized = t.finalize();
    Ok(result.is_ok() && finalized.is_ok())
}
fn file(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    if fs::metadata(path).map_err(|e| e.to_string())?.len() > max {
        return Err("file too large".into());
    }
    let mut b = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > max {
        return Err("file too large".into());
    }
    Ok(b)
}
fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str){
 Some("export") if args.len()==3=>{
 let start=Instant::now();let built=native::build();let build_s=start.elapsed().as_secs_f64();let start=Instant::now();let v=native::setup_verifier(built.circuit.constraint_system().clone())?;let setup_s=start.elapsed().as_secs_f64();let start=Instant::now();let bytes=frozen::export(&v)?;let export_s=start.elapsed().as_secs_f64();
 let start=Instant::now();let again=native::setup_verifier(native::build().circuit.constraint_system().clone())?;let againbytes=frozen::export(&again)?;if bytes!=againbytes{return Err("nondeterministic preprocessing".into());}let repeated_s=start.elapsed().as_secs_f64();
 let hash=hex::encode(Sha256::digest(&bytes));let start=Instant::now();let loaded=frozen::export_roundtrip(&v,&bytes)?;let load_s=start.elapsed().as_secs_f64();if frozen::export(&loaded)?!=bytes{return Err("loaded preprocessing differs".into());}
 fs::write(&args[2],&bytes).map_err(|e|e.to_string())?;
 let inner=v.constraint_system();let outer=v.outer_iop_verifier().constraint_system();
 println!("{}",json!({"preprocessing_bytes":bytes.len(),"preprocessing_sha256":hash,"circuit_build_seconds":build_s,"symbolic_setup_seconds":setup_s,"export_seconds":export_s,"repeat_setup_export_seconds":repeated_s,"load_seconds":load_s,"repeat_export_equal":true,"loaded_reexport_equal":true,"inner_constants":inner.constants.len(),"inner_and_constraints":inner.and_constraints.len(),"inner_mul_constraints":inner.mul_constraints.len(),"inner_values":inner.value_vec_len(),"inner_public_words":1usize<<v.log_public_words(),"outer_constants":outer.constants().len(),"outer_inout":outer.n_inout(),"outer_precommit":outer.n_precommit(),"outer_private":outer.n_private(),"outer_padded_constraints":outer.mul_constraints().len(),"outer_padded_constraints_sha256":frozen::padded_constraints_sha256(&v)?,"native_usize_bytes":std::mem::size_of::<usize>(),"native_outer_constraint_bytes":std::mem::size_of::<binius_spartan_frontend::constraint_system::MulConstraint<binius_spartan_frontend::constraint_system::WitnessIndex>>(),"outer_unpadded_constraints":outer.unpadded_constraint_system().mul_constraints().len(),"fri":v.basefold_compiler().fri_params().iter().map(|p|json!({"log_dimension":p.rs_code().log_dim(),"log_inverse_rate":p.rs_code().log_inv_rate(),"log_batch":p.log_batch_size(),"queries":p.n_test_queries(),"folds":p.fold_arities(),"basis_len":p.rs_code().subspace().basis().len()})).collect::<Vec<_>>()}));Ok(())
 },
 Some("verify") if args.len()==5=>{
 let start=Instant::now();let v=frozen::load(FIXED)?;let load_s=start.elapsed().as_secs_f64();let proof=file(Path::new(&args[2]),MAX_PROOF_BYTES)?;let scalar=native::decode::<32>(&args[3])?;let action=native::decode::<64>(&args[4])?;
 let start=Instant::now();let accepted=verify(&v,&proof,&scalar,&action)?;let verify_s=start.elapsed().as_secs_f64();println!("{}",json!({"valid":accepted,"load_seconds":load_s,"verify_seconds_excluding_load":verify_s,"proof_bytes":proof.len(),"setup_bytes":FIXED.len(),"setup_sha256":EXPECTED_SHA256.trim(),"symbolic_setup_called":false,"security_approved":false}));if !accepted{std::process::exit(2);}Ok(())
 },
 Some("selfcheck") if args.len()==5=>{
 let v=frozen::load(FIXED)?;let proof=file(Path::new(&args[2]),MAX_PROOF_BYTES)?;let scalar=native::decode::<32>(&args[3])?;let action=native::decode::<64>(&args[4])?;let mut checks=Vec::new();
 checks.push(("valid_actual_proof",verify(&v,&proof,&scalar,&action)?));
 let mut changed_action=action;changed_action[31]^=1;checks.push(("changed_action_rejected",!verify(&v,&proof,&scalar,&changed_action)?));
 let mut corrupt=proof.clone();corrupt[proof.len()/2]^=1;checks.push(("corrupt_proof_rejected",!verify(&v,&corrupt,&scalar,&action)?));
 checks.push(("truncated_proof_rejected",!verify(&v,&proof[..proof.len()-1],&scalar,&action)?));
 let mut trailing=proof.clone();trailing.push(0);checks.push(("trailing_proof_rejected",!verify(&v,&trailing,&scalar,&action)?));
 checks.push(("empty_proof_rejected",!verify(&v,&[],&scalar,&action)?));
 for (name,byte,bit) in [("invalid_clamp_rejected",0,1),("changed_scalar_rejected",1,1)]{let mut s=scalar;s[byte]^=bit;checks.push((name,verify(&v,&proof,&s,&action).is_err()));}
 let mut bad=FIXED.to_vec();bad[FIXED.len()/2]^=1;checks.push(("modified_setup_rejected",frozen::load(&bad).is_err()));
 let mut bad=FIXED.to_vec();bad.push(0);checks.push(("trailing_setup_rejected",frozen::load(&bad).is_err()));
 checks.push(("truncated_setup_rejected",frozen::load(&FIXED[..FIXED.len()-1]).is_err()));
 checks.push(("empty_setup_rejected",frozen::load(&[]).is_err()));
 if checks.iter().any(|(_,pass)|!*pass){return Err(format!("failed checks: {checks:?}"));}println!("{}",json!({"checks":checks,"count":checks.len(),"all_passed":true,"security_approved":false,"artifact_whitelist_compiled":true}));Ok(())
 },
 _=>Err("usage: export OUTPUT | verify PROOF SCALAR32HEX ACTION64HEX | selfcheck PROOF SCALAR32HEX ACTION64HEX".into())
 }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
