# Binius recovery experiment and remaining release blockers

2026-10-20. First-party, AI-assisted implementation and separate-agent review. No production security certification, deployment or transaction submission.

The previous 8,893,905-byte SHA512 leaf STARK has a genuine ZK comparator using the existing, exact-pinned Binius64 Iron Spartan implementation. The canonical recovery experiment produces a **539,888-byte** proof, about 16.5 times smaller in measured serialized size. These configurations do not have matched or approved security levels; this is not an equal-security performance claim. The new proof is still too large for the recorded 132,096-byte whole-transaction cap. The exact hypothetical invocation envelope is **545,884 bytes** with the canonical request, public scalar, ML-DSA replacement possession and one outer signature placeholder.

## Implemented and measured

The private witness is exactly the RFC8032 test1 32-byte leaf seed. The circuit uses pinned Binius64 `115108d5a661d95c0b474b6ab02558bfe6c6bec7` SHA512 constraints, fixed message length/IV/padding, and exact RFC8032 clamping. Four public 64-bit words contain the first clamped digest half. The remaining digest half and discarded bits are private wires. The native wrapper checks the canonical scalar bytes against the independently pinned RFC public key. Python SHA512 and libsodium independently reproduce that binding. No arbitrary user-seed input exists.

The prover and verifier observe the application domain, scalar and 64-byte recovery digest before protocol challenges. The Python adapter derives that digest from the canonical typed request, matches source/parameter IDs and the fixed leaf relation, and invokes the actual native verifier. The request binds network, parent, protected identity, relation, epoch/policy, exact replacement/action/algorithm, expiry and backend parameters. Source fingerprints include the adapter, runner, statement codec, local transactional model and fixture signer source.

| Final canonical run | Observed native value |
| --- | ---: |
| Proof bytes | 539,888 |
| Proving, excluding setup | 1.086 seconds |
| Setup | 0.752 seconds |
| Separate verifier process, including setup | 0.619 seconds |
| Peak RSS, prover plus its internal verification | 109,632 KiB |
| Hypothetical invocation envelope | 545,884 bytes |
| Zlib9 proof bytes | 529,630 |

See [binius-seed-research.json](binius-seed-research.json) for exact inputs, timings, proof/binary hashes and 13 checks. The final proof and metadata are retained under ignored `target/binius-seed-research`. This is leaf-only evidence: a compatible SEP-5 root can derive the leaf privately offline, but the proof does not establish root-only knowledge, mnemonic entropy, checksum or historical wallet provenance.

Actual separate-process checks accept the genuine proof and reject changed action, trailing/truncated/corrupted/empty proofs. Scalar guard failures are explicitly distinguished from proof failures. A newly signed, otherwise-current replacement request with a different epoch reaches the real proof verifier and rejects. Real ML-DSA replacement possession plus the Binius proof commits the local SQLite handoff; reopening preserves consumption and rejects replay.

The wrong-private-seed attempt keeps the original scalar and action. The real upstream prover aborts with `WitnessError` before emitting a proof. This is an actual unsatisfied-witness prover rejection, **not verifier rejection of an adversarially generated wrong-witness proof**. Process failures and explicit native proof rejection have separate classifications. The final adapter enforces a 600-second timeout, 4 GiB address-space limit and two Rayon threads for native proof verification; the runner applies the same limits to proof-generation and mutation subprocesses. Cargo builds and the fixed-size fixture-signature helper are outside those memory/thread caps. These generous native bounds do not establish Soroban resource feasibility.

## Existing parameter tradeoffs were tested

A separate [rate study](../tools/binius-seed-research/rate-study/provenance.json) changes the existing `log_inv_rate` API parameter while retaining the upstream `SECURITY_BITS=96` query calculation and automatic query-dependent masking. No upstream cryptographic source or manually chosen query count is changed. Rate is explicitly bound in this variant's transcript. The action is a zero dummy digest, so these are parameter-size comparisons, not additional canonical recovery ceremonies.

| log inverse rate | Queries | Proof bytes | Prove seconds | Peak KiB |
| --- | ---: | ---: | ---: | ---: |
| 2 | 142 | 432,176 | 2.200 | 154,032 |
| 3 | 116 | 436,112 | 2.819 | 238,404 |
| 4 | 106 | 467,760 | 4.454 | 417,596 |
| 5 | 101 | 512,592 | 11.237 | 748,608 |

Each proof passes a separate verifier; changed-action and cross-rate inputs reject. A portable rerun also passed. The smallest proof alone is about 3.27 times the historical whole-transaction cap. Larger expansion increases memory and does not monotonically shrink the proof. The query formula approaches a 96-query floor, so increasing the rate is not an unlimited compression mechanism. All measurements retain unapproved overall security; no 96-bit system or 128-bit quantum guarantee is inferred.

## Concrete audit disposition

Three blockers remain open:

1. **Transport and execution.** Neither the canonical proof nor the smallest rate experiment fits one recorded transaction. A later [mailbox experiment](PROOF_MAILBOX_EVIDENCE.md) actually moves these bytes in immutable bounded sessions, but final recovery still requires an actual bounded verifier and atomic current-authority checks. Uploading a commitment is not verifying a recovery proof. Transport alone is complete only as local research; no complete recovery workaround is declared.
2. **Soroban verifier integration.** The unmodified exact dependency graph fails `cargo check --target wasm32v1-none` with `E0463: can't find crate for std`, initially in `rand_core`. Disabling the direct verifier's default features does not remove upstream explicit standard-library features. The retained [build probe](../tools/binius-seed-research/wasm-probe/build-probe.json) includes source hashes and logs. The later [verifier-only port](VERIFIER_PORT_EVIDENCE.md) now supplies a core/alloc raw Wasm execution with fixed deterministic preprocessing and no floating-point operators. Smaller deployable code, a Soroban ABI and complete host memory/instruction/storage measurements remain unresolved.
3. **Cryptographic authorization security.** The pin's 96-bit setting covers its query phase and omits other protocol errors. The current Blueprint discusses ROM knowledge compilation and plausible PQ security; it is not an established QROM quantum-extraction theorem for this code. Quantum knowledge, zero knowledge, composition, hash assumptions and concrete parameters require external specialist review. See [BINIUS_SECURITY_REVIEW.md](BINIUS_SECURITY_REVIEW.md).

The scalar is a working classical signing secret. Every effective classical authority, including reused-key systems, must already be retired with finality before disclosure to an untrusted party. An atomic public retire-and-reveal transaction does not close prepublication front-running. Retirement and current entitlement remain fixture assumptions in these local runs. No attestation committee, pairing wrapper or lower-security configuration has replaced the intended trust model. The existing on-chain seed verifier remains disabled.

These are completed feasibility experiments and evidence of engineering progress. The production seed-recovery backend remains a conditional research milestone; successful native demonstrations do not support promising a production on-chain recovery deployment on a fixed timetable.

## Reproduce

```sh
python3 tools/binius-seed-research/verify_provenance.py
python3 scripts/run_binius_seed_research.py --offline
```

The canonical runner builds the pinned tool, generates the proof, executes real negative checks and local handoff, then writes a new execution record. Building first requires cached Rust dependencies and the existing public-fixture ML-DSA helper. The rate study has its own isolated Cargo manifest and portable `run_matrix.py`; its README describes the distinct CLI and dummy-action scope. Expensive experiments are opt-in; routine validation checks their source lineage and unit/lint/build checks without regenerating proofs.

## Verifier portability and transport follow-up

The later [verifier port evidence](VERIFIER_PORT_EVIDENCE.md) supersedes the unmodified-build failure as the latest portability result: an attributed verifier-only fork now verifies the unchanged proof in raw Wasm. The separate [mailbox](PROOF_MAILBOX_EVIDENCE.md) demonstrates staged local Soroban transport. A single oversized invocation remains invalid, but multi-transaction staging warrants investigation. Neither result establishes a deployable Soroban verifier or quantum-security approval.
