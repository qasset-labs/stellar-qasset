# Scalar-exposed recovery experiments and strict local ceremony

2026-10-20. First-party, AI-assisted research with parallel code/security review. **No production security approval or deployment.** The existing full-root proof and its sources remain unchanged.

## Measured improvement and remaining size limit

The private proof can omit its final Ed25519 scalar multiplication by exposing the clamped scalar and checking its exact canonical point against the pinned public key outside the circuit. It still proves a **seed** preimage; knowing the scalar alone does not supply that witness. [The mathematical review](SCALAR_RECOVERY_REVIEW.md) states the equivalence and its changed threat boundary.

| Relation | Repetitions | Serialized proof bytes | Native proving | Native verification |
| --- | ---: | ---: | ---: | ---: |
| Hidden scalar, SEP-5 root | 8 | 83,779,038 | 33.208 s | 11.803 s |
| Public scalar, SEP-5 root | 8 | 2,067,691 | 0.523 s | 0.160 s |
| Public scalar, RFC8032 leaf | 438 | 6,709,511 | 1.935 s | 0.534 s |
| Public scalar, SEP-5 root | 438 | 113,194,119 | 33.298 s | 10.190 s |

At the same deliberately insecure eight-round count and the same SEP-5 fixture relation, exposing the scalar reduced the serialized proof by approximately **40.5 times**. Proving/verification timings are native observations from separate runs on this environment; they are not a controlled performance study or Soroban instruction measurements. Full hidden-scalar 438-round proofs were not generated.

The 438-round cases execute the upstream library's recommended repetition count. That is an **upstream parameter-count experiment**, not a validated 128-bit quantum knowledge-security claim. Hash composition, extraction/QROM assumptions, actual ZK, seed entropy and the implementation still require review. The eight-round cases are deliberately insecure.

Even the 438-round leaf proof exceeds the observed whole-transaction limit of 132,096 bytes; full-root derivation remains much more expensive. The earlier [read-only Testnet snapshot](seed-proof-network-limits.json) carries a CLI26/protocol29 warning. No current mainnet limit, complete protocol29 configuration or complete Soroban verification budget was established. This backend is still not suitable for direct single-transaction recovery in the measured form.

Exact canonical statements, scalar/parameter identifiers, source fingerprints, independent native point-anchor checks and separate verifier results are in [leaf438](scalar-leaf438-research.json), [root438](scalar-root438-research.json) and [root8](scalar-root8-research.json). Each run verifies its proof in another process and rejects the same proof for a changed epoch. Fixtures are cross-checked with Python SHA512 and libsodium independently of the Rust circuit and Dalek anchor.

## Retirement must precede disclosure

A public scalar enables immediate ordinary Ed25519 signature forgery. This optimization is appropriate only after independently authenticated **retirement has been finalized before disclosure**, including spend, admin, upgrade, cancel, enrollment and pending/cached authority paths. Reused keys in other accounts, chains or applications would also be compromised. A retirement flag in a local model is not evidence that these paths were disabled.

Combining retirement and scalar publication in one public transaction leaves a prepublication race: an observer may use the scalar while the old authority is still live. Enrollment authorized only by the old signature is also insufficient if the attacker already has its scalar. This is a prospective migration design for enrolled authority, not rescue of arbitrary unprepared classic accounts. This research accepts only published fixtures and never a user's seed.

## Strict local ceremony

The new [request verifier](../scripts/verify_recovery_research.py) closes an integration gap in the earlier demo: the native proof binary receives an opaque digest and fixed fixture relation, so an outer verifier must check that the typed request's public key/path match that actual circuit. It now:

1. Decodes exactly one bounded canonical XDR statement with exact field types and domain; trailing bytes reject.
2. Checks key, root/leaf relation, fixed path/index, source/parameter identifiers and current fixture policy.
3. Requires a real ML-DSA signature under the replacement key over a distinct, statement-bound possession digest.
4. Invokes the pinned native proof verifier for that exact canonical request.
5. Returns a new immutable local state with the replacement key, incremented epoch and recovery permission consumed.

The [ceremony record](recovery-ceremony-research.json) passed **12 checks** with the actual existing hidden-scalar root proof. It rejects wrong key/path, malformed XDR, stale/revoked/unretired policy, forged replacement possession, and reuse of the returned consumed state. A changed-epoch request has a separately verified valid replacement signature before the old proof is rejected; only the dedicated native proof-rejection response counts as that evidence. Finally, a real replacement signature verifies under the new model key and an old-key signature fails under it.

Fourteen new adversarial unit tests cover strict decoding, fixed circuit identity, guards, failed-possession atomicity, and proof-rejection classification. Unit mocks exercise only rejection/control flow; they are not counted as successful cryptographic evidence. The positive ceremony invokes real native verifiers.

This is a **sequential in-memory model**. The caller must retain the returned state. Reusing an old unconsumed input can recompute the transition; there is no durable storage, cross-process concurrency protection or on-chain consumption. Retirement and eligibility are caller-provided fixture assumptions. Old-key signature rejection under a new key does not prove retirement of actual Stellar authority, external approvals or authorization caches. Proofs still use insecure eight-round parameters in this ceremony.

## Reproduction

Install the documented Python requirements, build the public fixture helper and each isolated Rust tool with locked dependencies. Git revisions are exact; cached builds can use `--offline`.

```sh
cargo build --release --locked --manifest-path tools/pq-demo/Cargo.toml
python3 scripts/run_scalar_seed_research.py --relation leaf --rounds 438 --report-path docs/scalar-leaf438-research.json --output-dir /tmp/qasset-scalar-leaf438
python3 scripts/run_scalar_seed_research.py --relation sep5-root --rounds 438 --report-path docs/scalar-root438-research.json --output-dir /tmp/qasset-scalar-root438
python3 scripts/run_scalar_seed_research.py --relation sep5-root --rounds 8 --report-path docs/scalar-root8-research.json --output-dir /tmp/qasset-scalar-root8
python3 scripts/run_recovery_ceremony_research.py
```

The ceremony's default proof path is the retained original root artifact under `target/seed-recovery-research`. To regenerate it, use the original [root proof runner](../scripts/run_seed_proof_research.py), retain its corresponding record and proof, and pass `--proof`, `--proof-binary` and `--fixture-helper` when build directories differ. A changed source fingerprint requires a fresh corresponding proof. Generated binary proofs stay in ignored build/output directories.

The scalar circuit uses attributed, pinned ZKBoo code under LGPL-3.0-or-later; the transformation is not a new cryptographic primitive. The project contribution under investigation is exact Stellar integration, supported recovery semantics and verified authority coverage. The legacy on-chain seed verifier remains disabled, and no new transaction was signed or submitted during this work.
