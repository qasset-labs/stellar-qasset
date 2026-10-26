// SPDX-License-Identifier: LGPL-3.0-or-later
//! Research-only reduced-round integration. PUBLIC RFC fixture; never real secrets.
use std::{fs, io::Read, time::Instant};
use zeroize::Zeroize;
use zkboo::{
    Repetitions,
    backend::{Backend, Frontend},
    circuit::{Assertions, Circuit},
    crypto::{HashPRG, Hasher},
    executor::{ExecOptions, OwnedFlexibleWordPool, exec},
    prover::{
        proof::{Proof, ProofOptions, Response},
        prove,
        views::OwnedFlexibleWordTriplePool,
    },
    verifier::{VerifyOptions, replay::OwnedFlexibleWordPairPool, verify},
    word::Words,
};
use zkboo_bip32::{
    ed25519_public_key, ed25519_public_key_affine, slip10_ed25519_child, slip10_ed25519_master,
};
use zkboo_ecc::edwards::{ComputedWindowTables, Point};
use zkboo_modular::montgomery::Montgomery;
#[derive(Debug)]
struct Blake3Hasher(blake3::Hasher);
impl Hasher for Blake3Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;
    fn new() -> Self {
        Self(blake3::Hasher::new())
    }
    fn update(&mut self, b: &[u8]) {
        self.0.update(b);
    }
    fn finalize_into(&mut self, out: &mut [u8; 32]) {
        out.copy_from_slice(self.0.finalize().as_bytes());
        self.0.reset();
    }
}
impl Zeroize for Blake3Hasher {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for Blake3Hasher {
    fn drop(&mut self) {
        self.zeroize();
    }
}
type H = Blake3Hasher;
type Prg = HashPRG<H>;
type P = Proof<[u8; 32], [u8; 32]>;
type WP = OwnedFlexibleWordPool<usize>;
type TP = OwnedFlexibleWordTriplePool<usize>;
type PP = OwnedFlexibleWordPairPool<usize>;
struct SeedCircuit {
    seed: Vec<u8>,
    sep5_root: bool,
    advice: Option<[Montgomery<u64, 4>; 2]>,
}
impl Circuit for SeedCircuit {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        Assertions::scope(fe, |asserts| {
            let seed = if self.sep5_root {
                let root = self.seed.iter().map(|b| fe.input(*b)).collect();
                let (mut key, mut chain) = slip10_ed25519_master(fe.allocator(), root);
                for index in [44u32, 148, 0] {
                    (key, chain) = slip10_ed25519_child(fe.allocator(), &key, &chain, index);
                }
                key
            } else {
                core::array::from_fn(|i| fe.input(self.seed[i]))
            };
            ed25519_public_key(fe, &seed, self.advice, asserts)
                .into_iter()
                .for_each(|v| fe.output(v));
        });
    }
}
fn hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2) && s.is_ascii(),
        "even-length ASCII hexadecimal required"
    );
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn accepts(c: &SeedCircuit, expected: &Words, p: &P, binding: &[u8], rounds: usize) -> bool {
    verify::<_, H, Prg, [u8; 32], PP, _>(
        c,
        expected,
        p,
        binding,
        Repetitions::exactly(rounds),
        VerifyOptions::new(),
    )
    .unwrap_or(false)
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 || !["prove", "verify"].contains(&args[1].as_str()) {
        eprintln!(
            "PUBLIC FIXTURE ONLY. Usage: prove DIGEST_64_BYTES_HEX PROOF_FILE REPORT_FILE [ROUNDS=8] [leaf|sep5-root] | verify DIGEST_64_BYTES_HEX PROOF_FILE [ROUNDS=8] [leaf|sep5-root]"
        );
        std::process::exit(2);
    }
    let is_prove = args[1] == "prove";
    if is_prove && args.len() < 5 {
        std::process::exit(2);
    }
    let digest = hex(&args[2]);
    assert_eq!(
        digest.len(),
        64,
        "message must be a 64-byte recovery-statement digest"
    );
    let mut binding = b"qasset-seed-proof-research-v1".to_vec();
    binding.extend_from_slice(&digest);
    let binding = binding.as_slice();
    let rounds: usize = args
        .get(if is_prove { 5 } else { 4 })
        .map(|v| v.parse().expect("round count"))
        .unwrap_or(8);
    assert!(
        (1..=16).contains(&rounds),
        "Reduced-round research only (1..=16)"
    );
    let mode = args
        .get(if is_prove { 6 } else { 5 })
        .map(String::as_str)
        .unwrap_or("leaf");
    assert!(
        ["leaf", "sep5-root"].contains(&mode),
        "relation must be leaf or sep5-root"
    );
    let sep5_root = mode == "sep5-root";
    let dummy = SeedCircuit {
        seed: vec![0; if sep5_root { 64 } else { 32 }],
        sep5_root,
        advice: None,
    };
    let mut expected = Words::new();
    expected.u8 = hex(if sep5_root {
        "e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544"
    } else {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    });
    expected.u8.push(1);
    if !is_prove {
        assert!(
            fs::metadata(&args[3]).expect("proof file metadata").len() <= 256 * 1024 * 1024,
            "proof exceeds research limit"
        );
        let encoded = fs::read(&args[3]).expect("read proof file");
        let started = Instant::now();
        let valid = match postcard::take_from_bytes::<P>(&encoded) {
            Ok((proof, [])) => {
                std::panic::catch_unwind(|| accepts(&dummy, &expected, &proof, binding, rounds))
                    .unwrap_or(false)
            }
            _ => false,
        };
        println!(
            "{}",
            serde_json::json!({"valid":valid,"status":"experimental_reduced_rounds_not_secure","rounds":rounds,"verify_ms":started.elapsed().as_millis(),"verifier_uses_seed":false,"relation_mode":mode,"message_digest_hex":args[2],"proof_blake3":blake3::hash(&encoded).to_hex().to_string()})
        );
        std::process::exit(if valid { 0 } else { 1 });
    }
    let leaf: [u8; 32] = hex(if sep5_root {
        "4d691bc19b44a1383b1a0a130aaca3e05c3c1a371dbe45930ef9b761f7a74691"
    } else {
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    })
    .try_into()
    .unwrap();
    let mut tables = ComputedWindowTables::new(Point::base(), 5);
    let advice = ed25519_public_key_affine(leaf, &mut tables, ExecOptions::new());
    let prover = SeedCircuit {
        seed: if sep5_root {
            hex(
                "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497ee4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186",
            )
        } else {
            leaf.to_vec()
        },
        sep5_root,
        advice: Some(advice),
    };
    eprintln!("Checking upstream circuit against independent official public key...");
    let got = exec::<_, WP, _>(&prover, ExecOptions::new());
    assert_eq!(got, expected);

    // Fresh OS entropy; never publish or reuse prover randomness for secret witnesses.
    let mut entropy = [0u8; 64];
    fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut entropy)
        .unwrap();
    let started = Instant::now();
    eprintln!("Generating {rounds} reduced-round responses (NOT secure)...");
    let proof = prove::<_, H, Prg, Prg, [u8; 32], _, TP, _>(
        &prover,
        rounds,
        &entropy,
        binding,
        ProofOptions::new(),
    );
    let prove_ms = started.elapsed().as_millis();
    entropy.zeroize();
    let encoded = postcard::to_allocvec(&proof).unwrap();
    fs::write(&args[3], &encoded).unwrap();
    let (proof2, rest): (P, &[u8]) = postcard::take_from_bytes(&encoded).unwrap();
    assert!(rest.is_empty());
    assert_eq!(proof, proof2);
    let started = Instant::now();
    assert!(accepts(&dummy, &expected, &proof2, binding, rounds));
    let verify_ms = started.elapsed().as_millis();
    let mut changed_pk = expected.clone();
    changed_pk.u8[0] ^= 1;
    let mut bad_assertion = expected.clone();
    bad_assertion.u8[32] = 0;
    let mut tampered = proof.clone();
    let r = &proof[0];
    let mut digest = *r.commitment_digest_unopened();
    digest[0] ^= 1;
    let a = *r.seeds()[0];
    let b = *r.seeds()[1];
    let msgs = r.and_msg_next_party().clone();
    tampered[0] = match r.challenge().index() {
        0 => Response::new_0(a, b, digest, msgs),
        1 => Response::new_1(digest, a, b, msgs, r.input_share_2().unwrap().clone()),
        2 => Response::new_2(b, digest, a, msgs, r.input_share_2().unwrap().clone()),
        _ => unreachable!(),
    };
    let mut changed_binding = binding.to_vec();
    let changed_index = changed_binding.len() - 1;
    changed_binding[changed_index] ^= 1;
    let checks = serde_json::json!({"valid_exact_statement":true,"wrong_public_key_rejected":!accepts(&dummy,&changed_pk,&proof,binding,rounds),"wrong_assertion_rejected":!accepts(&dummy,&bad_assertion,&proof,binding,rounds),"changed_action_rejected":!accepts(&dummy,&expected,&proof,&changed_binding,rounds),"tampered_commitment_rejected":!accepts(&dummy,&expected,&tampered,binding,rounds),"truncated_response_rejected":!accepts(&dummy,&expected,&proof[..rounds-1].to_vec(),binding,rounds),"empty_proof_rejected":!accepts(&dummy,&expected,&vec![],binding,rounds),"increased_required_rounds_rejected":!accepts(&dummy,&expected,&proof,binding,rounds+1)});
    let checks_passed = checks.as_object().unwrap().values().all(|v| v == true);
    let report = serde_json::json!({"status":if checks_passed{"passed_reduced_round_functional_checks_only"}else{"failed_functional_check"},"security":"NOT_SECURE_REDUCED_ROUNDS_UNAUDITED_BACKEND","message_digest_hex":args[2],"relation":if sep5_root{"private64byteSEP5root -> SLIP10Ed25519m/44h/148h/0h -> SHA512 -> clamp -> Ed25519 public key; assertion flag1"}else{"private RFC8032 32-byte leaf seed -> SHA512 -> clamp -> Ed25519 compressed public key; assertion flag=1"},"relation_mode":mode,"root_path":if sep5_root{Some("m/44'/148'/0'")}else{None},"public_fixture":if sep5_root{"SEP5 test1 account0"}else{"RFC8032 section 7.1 TEST1"},"rounds":rounds,"upstream_claimed_128bit_pq_rounds":438,"proof_bytes_postcard":encoded.len(),"proof_bytes_upstream_raw":proof.iter().map(|r|r.as_bytes().len()).sum::<usize>(),"prove_ms":prove_ms,"verify_ms":verify_ms,"proof_blake3":blake3::hash(&encoded).to_hex().to_string(),"public_seed_fixture_only":true,"fresh_os_prover_randomness":true,"verifier_uses_seed":false,"checks":checks,"onchain_verified":false,"soroban_feasibility_established":false});
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    fs::write(&args[4], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    if !checks_passed {
        std::process::exit(1);
    }
}
