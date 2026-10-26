//! Plonky3 adapter — naive PoC.
//!
//! Fibonacci AIR proven over BabyBear with Poseidon2-FRI. Pattern copied
//! from the canonical `p3-uni-stark/tests/fib_air.rs` for v0.5.2 — the API
//! shifts with each release, so when we bump versions we re-sync against
//! that test file.
//!
//! SHA-512 compression AIR lives in [`sha512_air`]; spec at
//! `docs/sha512-spec.md`.
//!
//! Ed25519 fixed-base scalar-mult AIR lives in [`ed25519_air`]; spec at
//! `docs/ed25519-spec.md`. (Module is currently a compile-clean scaffold;
//! constraints land in subsequent commits.)

pub mod batched_air;
pub mod bip39_to_solana;
pub mod bip39_to_solana_air;
pub mod ed25519_air;
pub mod hmac_air;
pub mod pbkdf2_air;
pub mod range_check_u16_air;
pub mod sha512_air;
pub mod slip10_air;

#[cfg(test)]
mod bench_split;

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField32, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_keccak_air::{KeccakAir, generate_trace_rows};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Seed a fresh `SecureRng` from OS entropy. Performs `O(1)` `getentropy`
/// syscalls (one per 32-byte ChaCha seed) instead of one per random
/// field element.
fn fresh_secure_rng() -> SecureRng {
    SecureRng::from_rng(&mut UnwrapErr(SysRng))
}

/// Cryptographically-secure userspace CSPRNG, seeded once from OS entropy.
///
/// Rationale: an earlier `UnwrapErr<SysRng>` configuration funnelled every
/// `next_u32()` from Hiding-FRI's mask generation through a `getentropy(2)`
/// syscall — `samply` showed the syscall path dominating ~88% of wall time
/// at 4098-compression scale. `ChaCha20Rng` from the (independently-versioned,
/// stable) `rand_chacha` 0.10 crate is cryptographically secure once seeded;
/// seeded once from `OsRng`, it gives the same security guarantee as `SysRng`
/// while eliminating the per-call syscall overhead.
type SecureRng = rand_chacha::ChaCha20Rng;

const NUM_FIBONACCI_COLS: usize = 2;

// ── Hiding (ZK) STARK config ─────────────────────────────────────────────
//
// The base Plonky3 prover (using `MerkleTreeMmcs` + `TwoAdicFriPcs`) is a
// sound argument of knowledge but is NOT zero-knowledge — its FRI
// commitments leak evaluations of the witness polynomial that, with
// enough queries, can reconstruct bits of the secret. For a recovery
// system whose witness is the secret, that's fatal.
//
// The hiding variants (`MerkleTreeHidingMmcs` + `HidingFriPcs`) add salt
// to Merkle leaves and mask the trace polynomial. Same protocol surface
// but ZK — see `poseidon2-air/examples/prove_poseidon2_baby_bear_keccak_zk.rs`.
//
// We mirror that example's setup (Keccak-based Merkle hashing, since
// SHA-NI/crypto extensions make Keccak faster on host than Poseidon2).
//
// We use `UnwrapErr<SysRng>` (rand 0.10's OS-entropy RNG, always
// cryptographically secure) for the masking randomness. The upstream
// `_zk` example uses `SmallRng` (xoshiro), which is fast and deterministic
// but NOT CSPRNG-grade — its hiding masks would be predictable and ZK
// moot. `SysRng` is stateless and reads from `getentropy(2)` on Apple
// and `getrandom(2)` on Linux/Android; its native trait is `TryRng`
// (since OS reads can theoretically fail). `UnwrapErr` adapts that to
// the infallible `Rng` trait by panicking on the basically-impossible
// failure path — Plonky3's hiding MMCS requires `Rng + Clone`.
type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    SecureRng,
    2,
    4,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SecureRng>;
type Cfg = StarkConfig<Pcs, Challenge, Challenger>;

/// Width-2 Fibonacci AIR. Public values: `[a_0, a_1, claimed_final]`.
/// Constraints:
///   - first row:  left == a_0, right == a_1
///   - transition: next.left == cur.right, next.right == cur.left + cur.right
///   - last row:   right == claimed_final
pub struct FibonacciAir;

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
    fn num_public_values(&self) -> usize {
        3
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

struct FibonacciRow<F> {
    left: F,
    right: F,
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let local: &FibonacciRow<AB::Var> = main.current_slice().borrow();
        let next: &FibonacciRow<AB::Var> = main.next_slice().borrow();

        let mut when_first_row = builder.when_first_row();
        when_first_row.assert_eq(local.left, a);
        when_first_row.assert_eq(local.right, b);

        let mut when_transition = builder.when_transition();
        when_transition.assert_eq(local.right, next.left);
        when_transition.assert_eq(local.left + local.right, next.right);

        builder.when_last_row().assert_eq(local.right, x);
    }
}

fn generate_trace<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());
    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty());
    assert!(suffix.is_empty());
    assert_eq!(rows.len(), n);
    rows[0].left = F::from_u64(a);
    rows[0].right = F::from_u64(b);
    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }
    trace
}

fn make_config() -> Cfg {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);

    // The MMCS RNG salts each Merkle leaf; the PCS RNG masks the trace.
    // Independent seeds so the two streams don't share state. Each is a
    // ChaCha-based CSPRNG seeded once from OS entropy (see SecureRng doc).
    let val_mmcs = ValMmcs::new(field_hash, compress, 0, fresh_secure_rng());
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    // FRI parameters chosen so the FRI-query soundness term clears
    // 128-bit post-quantum security under two strong interpretations
    // simultaneously:
    //
    //   1. Conjectured FRI (BCIKS list-decoding to capacity) +
    //      full-Grover-halving model: λ_pq = (lb·nq + pow)/2 capped
    //      by digest/2. (3·78 + 24)/2 = 129 → capped at 128 by the
    //      256-bit Keccak digest's Grover-preimage bound.
    //
    //   2. Johnson-bound FRI (provable, no proximity-gap conjecture) +
    //      refined-Grover (only search components halve):
    //      λ_pq = (lb/2)·nq + pow/2 = 117 + 12 = 129 → also 128-capped.
    //
    // Scope of the 128-PQ claim: it covers the FRI query-soundness
    // term, the PoW grinding term, and the Keccak Merkle digest under
    // Grover preimage attack. The full per-regime, per-cap arithmetic
    // is auditable via `scripts/fri_pq_security.py`.
    //
    // Known weaker term at these parameters: the BCIKS proximity-gap
    // term `|BAD|/|F^k|` (with |BAD| ≤ d ≈ 2^20 and ext degree 4,
    // |F^k| ≈ 2^124) gives a Grover sqrt-search PQ cap of ~52. Whether
    // that cap is a binding constraint for ShorStop's adversary model
    // is a separate question; tightening it to a strict 128 PQ would
    // require raising the extension degree or moving to a larger base
    // field, both of which are field-migration-scale changes rather
    // than parameter tweaks.
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 78,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 24,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, fresh_secure_rng());
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    Cfg::new(pcs, challenger)
}

#[derive(Serialize, Deserialize)]
struct EncodedProof {
    proof_bytes: Vec<u8>,
    /// `[a_0, a_1, claimed_final]` — kept alongside the proof so the verifier
    /// can reconstruct the public-value vector without the caller passing all
    /// three.
    public_values: Vec<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum Plonky3Error {
    #[error("num_steps must be a power of two and >= 4")]
    BadStepCount,
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
}

/// Prove the Fibonacci sequence starting `(a_0=0, a_1=1)`, run for `num_steps`
/// rows. Public values committed: `[0, 1, fib_{num_steps - 1}]`.
pub fn prove_fibonacci(num_steps: u32) -> Result<Vec<u8>, Plonky3Error> {
    let n = num_steps as usize;
    if n < 4 || !n.is_power_of_two() {
        return Err(Plonky3Error::BadStepCount);
    }

    let trace = generate_trace::<Val>(0, 1, n);
    // Last row, right column. By trace construction this equals the
    // (n-1)-th Fibonacci-style number for our recurrence.
    let final_right = trace.values[(n - 1) * NUM_FIBONACCI_COLS + 1];

    let pis = vec![Val::ZERO, Val::ONE, final_right];

    let config = make_config();
    let proof = prove(&config, &FibonacciAir, trace, &pis);

    let proof_bytes =
        postcard::to_allocvec(&proof).map_err(|e| Plonky3Error::Encode(e.to_string()))?;
    let encoded = EncodedProof {
        proof_bytes,
        public_values: pis.iter().map(|f| f.as_canonical_u32()).collect(),
    };
    postcard::to_allocvec(&encoded).map_err(|e| Plonky3Error::Encode(e.to_string()))
}

/// Prove `num_perms` independent Keccak-f permutations using
/// `p3-keccak-air` over BabyBear. Mirrors the upstream
/// `prove_goldilocks_keccak.rs` example but with our existing BabyBear /
/// Poseidon2-FRI config — same field as our Fibonacci adapter so the
/// memory/time numbers can be compared apples-to-apples.
///
/// Returns the encoded proof. No public values (the keccak-air is
/// self-contained: it asserts state transitions, not specific I/O).
pub fn prove_keccak_perms(num_perms: u32) -> Result<Vec<u8>, Plonky3Error> {
    let n = num_perms as usize;
    if n == 0 {
        return Err(Plonky3Error::BadStepCount);
    }
    // Userspace CSPRNG for trace inputs — same rationale as in `make_config`.
    let mut rng = fresh_secure_rng();
    let inputs: Vec<[u64; 25]> = (0..n)
        .map(|_| std::array::from_fn(|_| rng.random::<u64>()))
        .collect();
    let trace = generate_trace_rows::<Val>(inputs, 1);

    let config = make_config();
    let proof = prove(&config, &KeccakAir {}, trace, &[]);
    postcard::to_allocvec(&proof).map_err(|e| Plonky3Error::Encode(e.to_string()))
}

/// Prove `num_compressions` SHA-512 compressions of pseudorandom
/// `(state, block)` inputs. One row per compression in the trace; rows
/// are padded up to the next power of two with copies of input 0
/// (which remain valid because the AIR has no transition constraints).
///
/// Returns the encoded proof. No public inputs — this is the
/// memory/time benchmark surface; the digest's correctness is enforced
/// internally by the AIR but not exposed for verifier-side comparison.
/// (For an end-to-end "I know X such that SHA-512(X) = Y" proof, layer
/// the public-input plumbing on top — out of scope for the benchmark.)
pub fn prove_sha512_compressions(num_compressions: u32) -> Result<Vec<u8>, Plonky3Error> {
    let n = num_compressions as usize;
    if n == 0 {
        return Err(Plonky3Error::BadStepCount);
    }
    let mut rng = fresh_secure_rng();
    let inputs: Vec<([u64; 8], [u64; 16])> = (0..n)
        .map(|_| {
            let h_in: [u64; 8] = std::array::from_fn(|_| rng.random::<u64>());
            let block: [u64; 16] = std::array::from_fn(|_| rng.random::<u64>());
            (h_in, block)
        })
        .collect();
    let trace = sha512_air::generation::generate_trace::<Val>(&inputs);

    let config = make_config();
    let proof = prove(&config, &sha512_air::air::Sha512Air::default(), trace, &[]);
    postcard::to_allocvec(&proof).map_err(|e| Plonky3Error::Encode(e.to_string()))
}

/// Test-only: prove a single SHA-512 compression on a *deterministic*
/// input. Used to verify ZK property (two proofs of the same witness must
/// differ — see `proofs_of_same_witness_differ` test). Each call still
/// freshly seeds the hiding-FRI RNG, so masks differ across calls.
#[cfg(test)]
fn prove_sha512_one_fixed(input: ([u64; 8], [u64; 16])) -> Result<Vec<u8>, Plonky3Error> {
    let trace = sha512_air::generation::generate_trace::<Val>(&[input]);
    let config = make_config();
    let proof = prove(&config, &sha512_air::air::Sha512Air::default(), trace, &[]);
    postcard::to_allocvec(&proof).map_err(|e| Plonky3Error::Encode(e.to_string()))
}

/// Verify a proof produced by `prove_sha512_compressions`. Returns
/// `Ok(false)` if the proof is well-formed but rejected.
pub fn verify_sha512_compressions(proof_bytes: &[u8]) -> Result<bool, Plonky3Error> {
    let proof: p3_uni_stark::Proof<Cfg> = postcard::from_bytes(proof_bytes)
        .map_err(|e| Plonky3Error::Decode(e.to_string()))?;
    let config = make_config();
    Ok(verify(&config, &sha512_air::air::Sha512Air::default(), &proof, &[]).is_ok())
}

/// Verify a proof produced by `prove_fibonacci`. Returns `Ok(false)` if the
/// proof is well-formed but rejected, or if the embedded public values don't
/// match `claimed_final`.
pub fn verify_fibonacci(proof_bytes: &[u8], claimed_final: u32) -> Result<bool, Plonky3Error> {
    let encoded: EncodedProof =
        postcard::from_bytes(proof_bytes).map_err(|e| Plonky3Error::Decode(e.to_string()))?;

    if encoded.public_values.len() != 3
        || encoded.public_values[0] != 0
        || encoded.public_values[1] != 1
        || encoded.public_values[2] != claimed_final
    {
        return Ok(false);
    }

    let pis: Vec<Val> = encoded
        .public_values
        .iter()
        .map(|&u| Val::from_u32(u))
        .collect();

    let proof: p3_uni_stark::Proof<Cfg> = postcard::from_bytes(&encoded.proof_bytes)
        .map_err(|e| Plonky3Error::Decode(e.to_string()))?;

    let config = make_config();
    Ok(verify(&config, &FibonacciAir, &proof, &pis).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fibonacci_roundtrip_small() {
        let proof = prove_fibonacci(8).unwrap();
        assert!(verify_fibonacci(&proof, 21).unwrap());
        assert!(!verify_fibonacci(&proof, 99).unwrap());
    }

    #[test]
    fn rejects_non_power_of_two() {
        assert!(matches!(
            prove_fibonacci(7),
            Err(Plonky3Error::BadStepCount)
        ));
    }

    /// Sweep tests for memory benchmarking against binius. Ignored; invoke
    /// individually via `/usr/bin/time -l <bin> --include-ignored --exact <name>`.
    /// We're measuring how Plonky3 prover memory scales with trace length —
    /// a direct comparison with the binius PBKDF2 sweep in MoproSetup.md §25.
    #[test]
    #[ignore]
    fn fibonacci_zk_roundtrip_1024() {
        let _ = prove_fibonacci(1024).unwrap();
    }

    #[test]
    #[ignore]
    fn fibonacci_zk_roundtrip_16384() {
        let _ = prove_fibonacci(16384).unwrap();
    }

    #[test]
    #[ignore]
    fn fibonacci_zk_roundtrip_262144() {
        let _ = prove_fibonacci(262144).unwrap();
    }

    #[test]
    #[ignore]
    fn fibonacci_zk_roundtrip_1048576() {
        let _ = prove_fibonacci(1048576).unwrap();
    }

    /// Keccak-f permutation count sweep. Ignored; invoke individually with
    /// `/usr/bin/time -l` to compare against binius keccak per-permutation
    /// memory/time. Each Keccak-256 absorption of a 64-byte message ≈ 1 perm,
    /// so n=1 is the closest analog to `binius_adapter::prove_eth_address`'s
    /// L6 Keccak portion.
    #[test]
    #[ignore]
    fn keccak_zk_roundtrip_1() {
        let _ = prove_keccak_perms(1).unwrap();
    }

    #[test]
    #[ignore]
    fn keccak_zk_roundtrip_8() {
        let _ = prove_keccak_perms(8).unwrap();
    }

    #[test]
    #[ignore]
    fn keccak_zk_roundtrip_64() {
        let _ = prove_keccak_perms(64).unwrap();
    }

    #[test]
    #[ignore]
    fn keccak_zk_roundtrip_512() {
        let _ = prove_keccak_perms(512).unwrap();
    }

    #[test]
    #[ignore]
    fn keccak_zk_roundtrip_4096() {
        let _ = prove_keccak_perms(4096).unwrap();
    }

    /// SHA-512 compression sweep. End-to-end prove + verify roundtrip on
    /// a small input as the smoke test; the rest are ignored sweep
    /// benchmarks invoked individually under `/usr/bin/time -l` to
    /// compare per-compression memory/time vs binius's L1 SHA-512 and
    /// vs Plonky3's keccak baseline.
    ///
    /// Per-compression: ~20,472 columns × 1 row = ~20k cells.
    /// PBKDF2 (BIP-39) = 4098 compressions ≈ 84M cells of trace.
    #[test]
    fn sha512_compressions_roundtrip_1() {
        let proof = prove_sha512_compressions(1).unwrap();
        assert!(verify_sha512_compressions(&proof).unwrap());
    }

    #[test]
    fn sha512_compressions_roundtrip_2() {
        let proof = prove_sha512_compressions(2).unwrap();
        assert!(verify_sha512_compressions(&proof).unwrap());
    }

    #[test]
    #[ignore]
    fn sha512_compressions_zk_roundtrip_1() {
        let _ = prove_sha512_compressions(1).unwrap();
    }

    #[test]
    #[ignore]
    fn sha512_compressions_zk_roundtrip_8() {
        let _ = prove_sha512_compressions(8).unwrap();
    }

    #[test]
    #[ignore]
    fn sha512_compressions_zk_roundtrip_64() {
        let _ = prove_sha512_compressions(64).unwrap();
    }

    #[test]
    #[ignore]
    fn sha512_compressions_zk_roundtrip_256() {
        let _ = prove_sha512_compressions(256).unwrap();
    }

    #[test]
    #[ignore]
    fn sha512_compressions_zk_roundtrip_1024() {
        let _ = prove_sha512_compressions(1024).unwrap();
    }

    /// PBKDF2 BIP-39 scale: 4098 compressions per derivation. This is
    /// the headline number for the multi-backend comparison.
    #[test]
    #[ignore]
    fn sha512_compressions_zk_roundtrip_4098() {
        let _ = prove_sha512_compressions(4098).unwrap();
    }

    // ── RNG-correctness + ZK property tests ─────────────────────────────

    /// Two fresh `SecureRng` instances must produce different streams.
    /// If this fails, `from_rng` is not actually pulling fresh entropy
    /// per call — masks would be deterministic across proofs and ZK
    /// would silently leak that "this is the same secret" across runs.
    #[test]
    fn fresh_secure_rng_produces_distinct_streams() {
        let mut rng_a = fresh_secure_rng();
        let mut rng_b = fresh_secure_rng();
        let a: [u64; 8] = std::array::from_fn(|_| rng_a.random::<u64>());
        let b: [u64; 8] = std::array::from_fn(|_| rng_b.random::<u64>());
        // Probability of collision between two cryptographic streams of
        // 64 bytes is 2^-512 — astronomically below any flake threshold.
        assert_ne!(
            a, b,
            "two fresh RNGs produced identical first-64-byte streams; \
             entropy is not flowing from OsRng"
        );
    }

    /// `prove`-ing the same witness twice must yield byte-different
    /// proofs because the Hiding-FRI masks are randomly drawn per call.
    /// If proofs are identical, masking randomness isn't being applied —
    /// `HidingFriPcs` would degrade to non-hiding `TwoAdicFriPcs`,
    /// silently breaking the ZK property even though the proof is still
    /// sound.
    #[test]
    fn proofs_of_same_witness_differ() {
        // Fixed nontrivial input. Specific value doesn't matter; the
        // point is that we run prove twice on identical witness data.
        let input: ([u64; 8], [u64; 16]) = (
            [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
             0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
             0x1f83d9abfb41bd6b, 0x5be0cd19137e2179],
            [0x6162638000000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x18],
        );

        let proof1 = prove_sha512_one_fixed(input).unwrap();
        let proof2 = prove_sha512_one_fixed(input).unwrap();

        // Both proofs must verify (same statement, same trace).
        assert!(verify_sha512_compressions(&proof1).unwrap());
        assert!(verify_sha512_compressions(&proof2).unwrap());

        // ZK property: hiding masks differ across runs → proofs differ.
        assert_ne!(
            proof1, proof2,
            "two proofs of the same witness produced identical bytes; \
             Hiding-FRI masks are not being randomized per proof — ZK is broken"
        );
    }
}

pub mod qasset_leaf_seed;
