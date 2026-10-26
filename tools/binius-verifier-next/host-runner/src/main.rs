// SPDX-License-Identifier: MIT
//! Native verification of public fixtures using the exact port and trusted preprocessing.
extern crate alloc;
mod frozen;
use std::{fs, path::Path};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: qasset-binius-port-host SETUP PROOF".into());
    }
    if fs::metadata(&args[1])?.len() != frozen::MAX_SETUP_BYTES as u64 {
        return Err("setup byte bound".into());
    }
    let setup = fs::read(&args[1])?;
    let proof_path = Path::new(&args[2]);
    if fs::metadata(proof_path)?.len() > 1024 * 1024 {
        return Err("proof too large".into());
    }
    let proof = fs::read(proof_path)?;
    let verifier = frozen::load(&setup)?;
    let mut checks = Vec::new();
    for id in 0..6 {
        let mut bytes = proof.clone();
        let mut action = ACTION;
        let label = match id {
            0 => "canonical",
            1 => {
                action[0] ^= 1;
                "changed_action"
            }
            2 => {
                bytes[100] ^= 1;
                "corrupt"
            }
            3 => {
                bytes.push(0);
                "trailing"
            }
            4 => {
                bytes.pop();
                "truncated"
            }
            _ => {
                bytes.clear();
                "empty"
            }
        };
        let result = qasset_binius_nostd_verifier::verify_preprocessed_detailed(
            &verifier, &bytes, &SCALAR, &action,
        );
        let passed = result.is_ok() == (id == 0);
        checks.push(serde_json::json!({"name":label,"accepted":result.is_ok(),"error":result.err(),"passed":passed}));
    }
    let vector = qasset_binius_nostd_verifier::regression::transcript_vector();
    let vector_passed = vector == qasset_binius_nostd_verifier::regression::GOLDEN;
    let padded = frozen::padded_constraints_sha256(&verifier)?;
    let padded_passed =
        padded == "0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938";
    let all = checks.iter().all(|x| x["passed"] == true) && vector_passed && padded_passed;
    println!(
        "{}",
        serde_json::json!({"scope":"fixed_public_fixture_native_port_only","checks":checks,"transcript_vector":vector,"transcript_vector_passed":vector_passed,"padded_constraints_sha256":padded,"padded_constraints_passed":padded_passed,"all_passed":all,"setup_bytes":setup.len(),"padded_count":verifier.outer_iop_verifier().constraint_system().mul_constraints().len(),"retained_unpadded_count":verifier.outer_iop_verifier().constraint_system().retained_unpadded_constraint_system().map_or(0, |cs| cs.mul_constraints().len()),"unpadded_count_metadata":verifier.outer_iop_verifier().constraint_system().n_unpadded_constraints()})
    );
    if !all {
        std::process::exit(2)
    }
    Ok(())
}
const SCALAR: [u8; 32] = [
    48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104, 217,
    128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79,
];
const ACTION: [u8; 64] = [
    255, 44, 210, 159, 4, 68, 214, 65, 255, 84, 87, 83, 209, 204, 191, 239, 221, 102, 225, 214,
    141, 237, 234, 32, 57, 231, 221, 100, 244, 218, 180, 73, 24, 108, 200, 187, 177, 179, 10, 130,
    101, 223, 172, 144, 165, 93, 46, 100, 28, 77, 60, 40, 6, 154, 168, 29, 108, 24, 216, 187, 157,
    93, 190, 100,
];
