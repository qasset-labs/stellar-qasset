// SPDX-License-Identifier: LGPL-3.0-or-later
//! Research-only upstream-parameter integration. PUBLIC fixtures; never real secrets.
use curve25519_dalek::edwards::EdwardsPoint;
use std::{fs, io::Read, time::Instant};
use zeroize::Zeroize;
use zkboo::{
    Repetitions,
    backend::{Backend, Frontend},
    circuit::Circuit,
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
use zkboo_bip32::{slip10_ed25519_child, slip10_ed25519_master};
use zkboo_sha2::sha512bytes;
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
}
impl Circuit for SeedCircuit {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
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
        let digest = sha512bytes(fe.allocator(), seed.to_vec());
        let mut scalar: Vec<_> = digest.into_iter().take(32).collect();
        scalar[0] = (scalar[0].clone() >> 3) << 3;
        scalar[31] = ((scalar[31].clone() << 1) >> 1) | 0x40u8;
        scalar.into_iter().for_each(|v| fe.output(v));
    }
}
/// Scalars here are deliberately public, so variable-time/memory concerns do not
/// expose a secret witness. Never use this variant while classical spending remains.
fn public_scalar_matches_key(scalar: &[u8], key: &[u8]) -> bool {
    let Ok(s): Result<[u8; 32], _> = scalar.try_into() else {
        return false;
    };
    if s[0] & 7 != 0 || s[31] & 0xc0 != 0x40 {
        return false;
    }
    EdwardsPoint::mul_base_clamped(s)
        .compress()
        .as_bytes()
        .as_slice()
        == key
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
    if !matches!(args.get(1).map(String::as_str), Some("prove" | "verify"))
        || args.len() != if args[1] == "prove" { 7 } else { 6 }
    {
        eprintln!(
            "PUBLIC FIXTURE ONLY. Usage: prove DIGEST_64_BYTES_HEX PROOF_FILE REPORT_FILE ROUNDS MODE | verify DIGEST_64_BYTES_HEX PROOF_FILE ROUNDS MODE; ROUNDS=8|438 MODE=leaf|sep5-root"
        );
        std::process::exit(2);
    }
    let is_prove = args[1] == "prove";
    let digest = hex(&args[2]);
    assert_eq!(
        digest.len(),
        64,
        "message must be a 64-byte recovery-statement digest"
    );
    let mut binding = b"qasset-public-scalar-proof-research-v1".to_vec();
    binding.extend_from_slice(&digest);

    let rounds: usize = args[if is_prove { 5 } else { 4 }]
        .parse()
        .expect("round count");
    assert!(
        [8, 438].contains(&rounds),
        "Research benchmark accepts exactly 8 or 438 rounds; no security certification"
    );
    let mode = args[if is_prove { 6 } else { 5 }].as_str();
    assert!(
        ["leaf", "sep5-root"].contains(&mode),
        "relation must be leaf or sep5-root"
    );
    let sep5_root = mode == "sep5-root";
    binding.extend_from_slice(mode.as_bytes());
    let binding = binding.as_slice();
    let dummy = SeedCircuit {
        seed: vec![0; if sep5_root { 64 } else { 32 }],
        sep5_root,
    };
    let mut expected = Words::new();
    expected.u8 = hex(if sep5_root {
        "406f5c48cb41e1cec23aa006aea9eda7a1aa7536c821087fa762c470fa3cd946"
    } else {
        "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f"
    });
    assert!(
        public_scalar_matches_key(
            &expected.u8,
            &hex(if sep5_root {
                "e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544"
            } else {
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            })
        ),
        "public scalar must map to independently pinned fixture public key"
    );
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
            serde_json::json!({"valid":valid,"status":"experimental_unaudited_not_security_certified","rounds":rounds,"verify_ms":started.elapsed().as_millis(),"verifier_uses_seed":false,"relation_mode":mode,"message_digest_hex":args[2],"proof_blake3":blake3::hash(&encoded).to_hex().to_string()})
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
    let prover = SeedCircuit {
        seed: if sep5_root {
            hex(
                "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497ee4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186",
            )
        } else {
            leaf.to_vec()
        },
        sep5_root,
    };
    eprintln!(
        "Checking upstream circuit against independent SHA512-clamped scalar and public key..."
    );
    let got = exec::<_, WP, _>(&prover, ExecOptions::new());
    assert_eq!(got, expected);

    // Fresh OS entropy; never publish or reuse prover randomness for secret witnesses.
    let mut entropy = [0u8; 64];
    fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut entropy)
        .unwrap();
    let started = Instant::now();
    eprintln!("Generating {rounds} responses (unreviewed research only)...");
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
    bad_assertion.u8[31] ^= 0x40;
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
    let changed_index = b"qasset-public-scalar-proof-research-v1".len() + 63;
    changed_binding[changed_index] ^= 1;
    let mut changed_mode_binding = binding.to_vec();
    let last = changed_mode_binding.len() - 1;
    changed_mode_binding[last] ^= 1;
    let pinned_key = hex(if sep5_root {
        "e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544"
    } else {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    });
    let mut changed_public_key = pinned_key.clone();
    changed_public_key[0] ^= 1;
    let checks = serde_json::json!({"valid_exact_statement":true,"wrong_public_scalar_rejected":!accepts(&dummy,&changed_pk,&proof,binding,rounds),"nonclamped_output_rejected":!accepts(&dummy,&bad_assertion,&proof,binding,rounds),"changed_action_digest_rejected":!accepts(&dummy,&expected,&proof,&changed_binding,rounds),"changed_mode_binding_rejected":!accepts(&dummy,&expected,&proof,&changed_mode_binding,rounds),"correct_scalar_matches_independent_key":public_scalar_matches_key(&expected.u8,&pinned_key),"changed_public_key_rejected_by_native_anchor":!public_scalar_matches_key(&expected.u8,&changed_public_key),"changed_scalar_rejected_by_native_anchor":!public_scalar_matches_key(&changed_pk.u8,&pinned_key),"tampered_commitment_rejected":!accepts(&dummy,&expected,&tampered,binding,rounds),"truncated_response_rejected":!accepts(&dummy,&expected,&proof[..rounds-1].to_vec(),binding,rounds),"empty_proof_rejected":!accepts(&dummy,&expected,&vec![],binding,rounds),"increased_required_rounds_rejected":!accepts(&dummy,&expected,&proof,binding,rounds+1)});
    let checks_passed = checks.as_object().unwrap().values().all(|v| v == true);
    let report = serde_json::json!({"status":if checks_passed{"passed_functional_checks_only"}else{"failed_functional_check"},"security":if rounds == 8 { "REDUCED_ROUNDS_UNSAFE_UNAUDITED_BACKEND" } else { "UPSTREAM_PARAMETER_COUNT_ONLY_UNAUDITED_NOT_QUANTUM_KNOWLEDGE_PROVEN" },"message_digest_hex":args[2],"relation":if sep5_root{"private64byteSEP5root -> SLIP10Ed25519m/44h/148h/0h -> SHA512 -> PUBLIC clamped scalar; native point anchor"}else{"private RFC8032 32-byte leaf seed -> SHA512 -> PUBLIC clamped scalar; native point anchor"},"relation_mode":mode,"root_path":if sep5_root{Some("m/44'/148'/0'")}else{None},"public_fixture":if sep5_root{"SEP5 test1 account0"}else{"RFC8032 section 7.1 TEST1"},"public_scalar_disclosed":true,"classical_signing_authority_must_be_retired":true,"point_anchor_checked_outside_circuit":true,"rounds":rounds,"upstream_claimed_128bit_pq_rounds":438,"proof_bytes_postcard":encoded.len(),"proof_bytes_upstream_raw":proof.iter().map(|r|r.as_bytes().len()).sum::<usize>(),"prove_ms":prove_ms,"verify_ms":verify_ms,"proof_blake3":blake3::hash(&encoded).to_hex().to_string(),"public_seed_fixture_only":true,"fresh_os_prover_randomness":true,"verifier_uses_seed":false,"checks":checks,"onchain_verified":false,"soroban_feasibility_established":false});
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    fs::write(&args[4], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    if !checks_passed {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_anchor_checks_exact_scalar_encoding_and_pinned_key() {
        let scalar = hex("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f");
        let key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(public_scalar_matches_key(&scalar, &key));
        let mut wrong = scalar.clone();
        wrong[5] ^= 1;
        assert!(!public_scalar_matches_key(&wrong, &key));
        wrong = scalar.clone();
        wrong[0] |= 1;
        assert!(!public_scalar_matches_key(&wrong, &key));
        let mut wrong_key = key.clone();
        wrong_key[5] ^= 1;
        assert!(!public_scalar_matches_key(&scalar, &wrong_key));
        assert!(!public_scalar_matches_key(&scalar[..31], &key));
    }
    #[test]
    fn both_public_fixtures_are_anchored_independently() {
        assert!(public_scalar_matches_key(
            &hex("406f5c48cb41e1cec23aa006aea9eda7a1aa7536c821087fa762c470fa3cd946"),
            &hex("e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544")
        ));
    }
    #[test]
    fn native_anchor_rejects_alternate_scalar_and_point_encodings() {
        let scalar = hex("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f");
        let key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        for (byte, mask) in [(0, 1), (0, 2), (0, 4), (31, 0x40), (31, 0x80)] {
            let mut changed = scalar.clone();
            changed[byte] ^= mask;
            assert!(!public_scalar_matches_key(&changed, &key));
        }
        let mut too_long = scalar.clone();
        too_long.push(0);
        assert!(!public_scalar_matches_key(&too_long, &key));
        let mut reversed = scalar.clone();
        reversed.reverse();
        assert!(!public_scalar_matches_key(&reversed, &key));
        let reduced = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
            scalar.clone().try_into().unwrap(),
        );
        assert!(!public_scalar_matches_key(reduced.as_bytes(), &key));
        // Exact canonical byte comparison also excludes identity, noncanonical,
        // and differently sized anchor encodings without permissive decoding.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!public_scalar_matches_key(&scalar, &identity));
        let mut noncanonical = [0xffu8; 32];
        noncanonical[0] = 0xed;
        noncanonical[31] = 0x7f;
        assert!(!public_scalar_matches_key(&scalar, &noncanonical));
        assert!(!public_scalar_matches_key(&scalar, &key[..31]));
    }
}
