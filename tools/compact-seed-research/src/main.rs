use plonky3_adapter::qasset_leaf_seed;
use sha2::{Digest, Sha512};
use std::{path::PathBuf, time::Instant};
fn decode<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("hex"))
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("verify") {
        assert_eq!(args.len(), 5, "verify PROOF CLAMP_HEX ACTION_SHA512_HEX");
        if std::fs::metadata(&args[2]).unwrap().len() > 256 * 1024 * 1024 {
            println!(
                "{}",
                serde_json::json!({"accepted":false,"error":"proof exceeds research limit"})
            );
            std::process::exit(2);
        }
        let proof = std::fs::read(&args[2]).unwrap();
        let accepted =
            qasset_leaf_seed::verify(&proof, decode(&args[3]), decode(&args[4])).unwrap_or(false);
        println!("{}", serde_json::json!({"accepted":accepted}));
        std::process::exit(if accepted { 0 } else { 2 });
    }
    // RFC8032 test1 PUBLIC secret fixture; never accept a user's secret.
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let digest = Sha512::digest(seed);
    let mut clamp: [u8; 32] = digest[..32].try_into().unwrap();
    clamp[0] &= 248;
    clamp[31] &= 63;
    clamp[31] |= 64;
    let action: [u8;64] = Sha512::digest(b"qasset-public-dummy-action-v1:network=test;contract=counter;epoch=0;replacement=public-fixture;expiry=100").into();
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "/tmp/qasset-compact-seed-proof".into()),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let begin = Instant::now();
    let proof = qasset_leaf_seed::prove(seed, clamp, action).unwrap();
    let prove_seconds = begin.elapsed().as_secs_f64();
    std::fs::write(dir.join("proof.postcard"), &proof).unwrap();
    let begin = Instant::now();
    assert!(qasset_leaf_seed::verify(&proof, clamp, action).unwrap());
    let verify_seconds = begin.elapsed().as_secs_f64();
    let mut wrong = clamp;
    wrong[1] ^= 1;
    assert!(!qasset_leaf_seed::verify(&proof, wrong, action).unwrap());
    let mut wrong_action = action;
    wrong_action[0] ^= 1;
    assert!(!qasset_leaf_seed::verify(&proof, clamp, wrong_action).unwrap());
    std::fs::write(dir.join("checkpoint.json"),serde_json::to_string_pretty(&serde_json::json!({"proof_bytes":proof.len(),"prove_seconds":prove_seconds,"verify_seconds":verify_seconds,"valid_accepted":true,"changed_clamp_rejected":true,"changed_action_rejected":true,"trace_rows":128})).unwrap()).unwrap();
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(qasset_leaf_seed::verify(&trailing, clamp, action).is_err());
    let mut wrong_seed = seed;
    wrong_seed[0] ^= 1;
    let begin = Instant::now();
    let invalid_proof = qasset_leaf_seed::prove(wrong_seed, clamp, action).unwrap();
    let invalid_relation_prove_seconds = begin.elapsed().as_secs_f64();
    assert!(!qasset_leaf_seed::verify(&invalid_proof, clamp, action).unwrap());
    let mut corrupt = proof.clone();
    corrupt[0] ^= 1;
    let corrupt_rejected =
        std::panic::catch_unwind(|| qasset_leaf_seed::verify(&corrupt, clamp, action))
            .map(|r| !r.unwrap_or(false))
            .unwrap_or(true);
    assert!(corrupt_rejected);
    let truncated_rejected = qasset_leaf_seed::verify(&proof[..proof.len() / 2], clamp, action)
        .map(|r| !r)
        .unwrap_or(true);
    assert!(truncated_rejected);
    let record = serde_json::json!({"status":"functional_research_only","relation":"exists_private_seed_32_bytes:clamp(SHA512(seed)[0:32])=public_clamp","upstream_pin":"e7692712c601814d03acc5b638e0a15962f50452","plonky3_version":"0.5.2","fixture":"RFC8032 section7.1 test1","proof_bytes":proof.len(),"prove_seconds":prove_seconds,"verify_seconds":verify_seconds,"valid_accepted":true,"trailing_data_rejected":true,"wrong_seed_same_public_statement_rejected":true,"invalid_relation_prove_seconds":invalid_relation_prove_seconds,"trace_rows":128,"changed_clamp_rejected":true,"corrupt_proof_rejected":corrupt_rejected,"truncated_proof_rejected":truncated_rejected,"action_sha512_hex":action.iter().map(|b|format!("{b:02x}")).collect::<String>(),"clamped_scalar_hex":clamp.iter().map(|b|format!("{b:02x}")).collect::<String>(),"security":"Upstream query parameters are not an end-to-end 128-bit PQ claim; BabyBear4 proximity-gap term, QROM knowledge and ZK composition unproven here.","changed_action_rejected":true,"action_binding":"fixed domain and 64-byte digest observed in Plonky3 Fiat-Shamir public-values transcript; action encoding is only a dummy fixture, no QROM SOK theorem established","onchain_verification":false,"root_derivation":false});
    std::fs::write(
        dir.join("result.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
    println!("{}", record);
}
