# Separate Binius recovery review — 2026-10-20

Scope: first-party AI-assisted cross-review by a separate agent, not an external independent cryptographic audit.

Verdict: go for an isolated, public-fixture native research probe; no-go for enabling the existing recovery contract or asserting production quantum knowledge security. A smaller proof would resolve only a measured transport obstacle. It does not resolve the verifier platform, cryptographic composition, or lifecycle gates below.

Inspected Binius64 commit: 115108d5a661d95c0b474b6ab02558bfe6c6bec7, using git show against that exact object. The shared checkout was moving while inspected, so its working tree was not used as evidence. ShorStop adapter reference is `libs/mopro/binius-adapter/src/{common,sha512}.rs` at `e7692712c601814d03acc5b638e0a15962f50452`.

## Confirmed implementation facts

* ARCHITECTURE.md explicitly distinguishes non-ZK Binius64 from ZK Iron Spartan. common.rs selects ZKProver and ZKVerifier. Replacing these with plain Prover/Verifier would violate seed privacy.
* crates/verifier/src/zk_config.rs wraps the inner protocol with GF(2^128) Iron Spartan and BaseFoldZK. This is a hash-based polynomial commitment construction, not Microsoft's discrete-log libSpartan or a pairing wrapper. Merely seeing the name Spartan is insufficient to classify it as quantum vulnerable.
* crates/verifier/src/verify.rs hardcodes SECURITY_BITS=96. ZKVerifier::setup feeds that into calculate_n_test_queries. With log_inv_rate=1, the query count is 232. The query calculator explicitly excludes folding errors and every other protocol. This is a 96-bit query-phase budget, not a proven 96-bit system guarantee and certainly not a 128-bit quantum guarantee.
* crates/hash/src/lib.rs selects SHA-256 for StdDigest and SHA-256 compression for StdCompression; crates/verifier/src/config.rs selects HasherChallenger<Sha256>. A generic quantum collision algorithm costs about 2^(256/3) hash queries in its idealized model; this motivates a concrete collision-security review, not a claimed demonstrated forgery or universal numerical system security level.
* The inner IOPVerifier::verify observes the reconstructed public vector before challenges. Transcript observe().write_bytes permits a fixed application domain and canonical action digest to be bound before invoking prove/verify. The native verifier must derive these independently from the exact request.
* VerifierTranscript requires an explicit finalize() call after successful verification to reject remaining bytes. Its Drop implementation only logs. A wrapper which forgets finalize() accepts noncanonical trailing data.
* The SHA-512 adapter example makes the entire 64-byte hash public. It must not be used unchanged as Q-Asset's scalar-only relation. Keep the second digest half private and constrain exactly clamp(SHA512(seed)[0..32])=public_scalar in the circuit.
* The transcript crate imports std::fs::File, std::io::Write and uses std::env, std::thread and proof-dump behavior unconditionally. The inspected crate roots are std libraries; default-features=false does not establish no_std. Native timing does not establish Soroban execution feasibility.

## Relation and request acceptance gates

1. Fixed private witness is exactly 32 bytes for leaf mode. The circuit, not a trusted input-population function, enforces SHA-512 padding/length and clamp equality. Root mode remains unsupported until exact SEP-5 derivation is constrained and separately tested.
2. SHA words use big endian; Ed25519 scalar bytes are little endian. For canonical scalar a: a[0]&7==0; a[31]&0x80==0; a[31]&0x40==0x40. Check all 32 output bytes. Do not reduce a modulo l as a substitute for canonical clamped bytes.
3. Independently compute canonical [a]B and compare exact compressed bytes with the fixed, independently enrolled Ed25519 public key. Do not accept a scalar/public-key pair supplied solely by the proof envelope. Reject malformed, noncanonical or wrong-length values.
4. Derive public inputs/action from the canonical request: actual network, parent contract, immutable protected identity, relation/path, current epoch and policy, exact replacement/algorithm/action, expiry, program and parameters. Bind a fixed versioned domain before challenges. Recheck live eligibility, revocation, retirement and expiry during the atomic commit.
5. Tests must include actual native rejection of changed action, changed scalar, wrong private seed against unchanged expected scalar, malformed proof, truncation, trailing bytes, and oversized input. A prover error before proof generation is not a verifier rejection test.
6. Enforce file size before reading, contain malformed-proof panics/process failures, and classify process errors separately from cryptographic rejection. Do not expose a production network service without bounded CPU/memory/time handling.
7. The scalar is a working classical signing secret. Retirement must already be final before any scalar-bearing proof/request is exposed to an untrusted party. Publishing retirement and the scalar together leaves a prepublication/front-running gap. Shared/reused keys elsewhere are also affected.

## Cryptographic release gates

The current primary Binius64 Blueprint (October 7, 2026) describes hash-based IronSpartan, HVZK masking and ROM knowledge compilation, calling PQ security plausible. It does not supply a demonstrated QROM quantum-extraction theorem for this pinned implementation. The generic three-round Fiat-Shamir QROM paper cannot simply be cited as proof for this multi-round composition. Exact quantum proof-of-knowledge, quantum zero-knowledge, commitment/hash assumptions, Fiat-Shamir/BCS losses and concrete parameters remain external-review gates. Ordinary soundness alone does not authorize recovery: the account public key is already a true statement, so the required property is knowledge of an acceptable seed witness.

Do not lower query counts or use a non-ZK configuration to hit a size target. Do not add a Groth16/BN254 or ordinary discrete-log Spartan wrapper and preserve PQ claims. Do not publish a 128-bit strength claim from GF(2^128), ML-DSA-65, or the hash name alone.

## Safe near-term integration

Retain the disabled on-chain seed verifier. Add the exact pinned native ZK probe, independent proof verification, source/parameter fingerprints, canonical request binding, and honest security labels. If proofs fit, measure the complete transaction including request and replacement proof of possession, then compile an actual deterministic no_std verifier and simulate its real Soroban CPU/memory/storage costs before proposing deployment. Chunking alone cannot solve a verifier's memory/instruction limits. Any off-chain attestation gateway must be presented as an explicit additional trust model and separately authorized architecture, not a transparent replacement for seed-proof verification.

## Primary sources

* Exact pinned architecture: https://github.com/IrreducibleOSS/binius64/blob/115108d5a661d95c0b474b6ab02558bfe6c6bec7/ARCHITECTURE.md
* Exact pinned parameters: https://github.com/IrreducibleOSS/binius64/blob/115108d5a661d95c0b474b6ab02558bfe6c6bec7/crates/verifier/src/verify.rs
* Exact pinned ZK configuration: https://github.com/IrreducibleOSS/binius64/blob/115108d5a661d95c0b474b6ab02558bfe6c6bec7/crates/verifier/src/zk_config.rs
* FRI query-only budget: https://github.com/IrreducibleOSS/binius64/blob/115108d5a661d95c0b474b6ab02558bfe6c6bec7/crates/iop/src/fri/common.rs
* Transcript: https://github.com/IrreducibleOSS/binius64/blob/115108d5a661d95c0b474b6ab02558bfe6c6bec7/crates/transcript/src/transcript.rs
* Canonical current protocol specification: https://www.binius.xyz/spec.pdf (reviewed abstract, construction overview and Sections 5–7; current specification is newer than the pinned code and does not establish code/spec equivalence).
* Fiat-Shamir QROM scope: https://arxiv.org/abs/1902.07556
* Underlying binary BaseFold/ring-switching source: https://eprint.iacr.org/2024/504
* Idealized quantum collision query model: https://arxiv.org/abs/quant-ph/9705002 (a query-complexity statement; practical hardware/memory/time costs and actual proof-forgery implications are separate questions).

## Verifier portability and transport follow-up

Follow-up: [VERIFIER_PORT_EVIDENCE.md](VERIFIER_PORT_EVIDENCE.md) records a preserved-native64 transcript correction, pinned preprocessing and exact constraint identity in actual Wasm. This substantial verifier fork needs independent review; raw memory bounds exclude Soroban host overhead. The separate [mailbox](PROOF_MAILBOX_EVIDENCE.md) authenticates transport only and always rejects proof approval.
