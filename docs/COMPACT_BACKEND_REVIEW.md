# Additional compact proof backend investigation

2026-10-20. First-party, AI-assisted native research. **This experiment remains unsuitable for production authorization.** It is a second attributed proof backend, not a new cryptographic primitive or an implementation of Stellar recovery.

## Exact source and statement

The tool reuses LimeChain/ShorStop's MIT-licensed SHA512 AIR/configuration at commit `e7692712c601814d03acc5b638e0a15962f50452`, with direct Plonky3 dependencies pinned to 0.5.2 and all resolved versions in Cargo.lock. Our wrapper fixes the RFC8032 32-byte leaf message, SHA512 initial state and padding, then constrains the public result to the clamped first digest half. The underlying SHA512 AIR is unchanged.

The public vector also includes a fixed domain and a 64-byte action digest. Plonky3 0.5.2 observes that entire vector in the Fiat-Shamir transcript before its constraint challenges. The action is an explicitly dummy fixture, not the canonical recovery request implemented in the separate local ceremony. No QROM signature-of-knowledge theorem is established by this binding test.

The AIR contains no root derivation, Ed25519 public-key multiplication, current wallet eligibility, expiry, replacement possession or authority transition. The parent independently checked the public scalar against the fixed RFC8032 key with libsodium; that check is outside the AIR and is not a general wallet integration. As with the other scalar experiment, disclosure would compromise a live classical signing key. Only published RFC test credentials are used.

## Actual execution

| Measurement | Native result |
| --- | ---: |
| Trace rows | 128 |
| Proof bytes | 8,893,905 |
| Proving | 70.235 seconds |
| First verification | 0.467 seconds |
| Peak RSS for complete experiment | 242,688 KiB |

A separate process accepted the proof without receiving the leaf seed. Changed public scalar/action, corrupt, truncated, trailing, invalid-clamp and oversized inputs reject with the final decoder. A malicious prover also generated a proof using a **wrong private seed with the original public scalar/action unchanged**; verification rejected it. This tests the actual output constraints rather than only a changed transcript.

See [compact-seed-research.json](compact-seed-research.json), the tool's [evidence folder](../tools/compact-seed-research/evidence), and [source provenance](../tools/compact-seed-research/provenance.json). The source inventory verifies 74 hashes and lists 47 compiler-consumed local inputs. Upstream and local hashes, exact vendor patch, license and initial generation fingerprints are retained. The native proof was first generated before a later decoder hardening; the same proof was verified again with the final binary. Generation and final-verification source/binary hashes are deliberately separate.

The 8,893,905-byte proof is about 67.33 times the recorded 132,096-byte whole-transaction limit before envelope overhead. The [snapshot](seed-proof-network-limits.json) includes a CLI26/protocol29 compatibility warning. No Soroban verifier, live-network simulation or on-chain resource estimate was performed. Native proof size/runtime cannot establish feasibility on Stellar.

The scalar ZKBoo leaf experiment is approximately 6.7 MB at the upstream 438-response setting. This STARK primitive is approximately 8.9 MB under a different, unvalidated security configuration. Those are not equal-security benchmarks. Neither is a direct single-transaction candidate. Comparing this narrower leaf relation to the 83.8 MB full-root proof as a backend speedup would also be misleading.

## Findings and remaining security obligations

The initial one-row wrapper was rejected during review: 78 FRI queries and a tiny masking trace did not justify a hiding claim. The completed experiment uses 128 repeated valid rows, independent fresh OS-seeded ChaCha masking streams and the upstream hiding PCS/MMCS. That is an experimental design choice, not proof that the complete construction is zero knowledge.

The initial decoder accepted a valid proof with an appended zero byte. It now uses `postcard::take_from_bytes` with an empty-remainder check, and enforces a 256 MiB research size bound before reading/deserialization. An actual trailing-data negative passed after the fix. This was encoding hardening, not an ability to forge the constrained statement.

Upstream query/PoW parameters do not establish end-to-end 128-bit PQ security. Its source explicitly acknowledges a weaker extension-field proximity-gap term in its large-degree example; the exact term depends on degree and is not computed as a Q-Asset security bound here. Quantum extraction, QROM assumptions, repeated-witness hiding, OOD/quotient masking, adaptive composition and implementation correctness remain unreviewed. The vendor's unrelated Ed25519 test helper also emits an inherited dead-code warning; its bytes are preserved for attribution rather than silently reformatted or patched.

A complete recovery design still needs authoritative scalar/key/path binding, finalized retirement before disclosure, canonical action/state checks, replacement possession, durable atomic consumption and coverage of all external/cached authority. The existing on-chain seed verifier remains disabled.

## Reproduce

```sh
python3 tools/compact-seed-research/verify_provenance.py
cargo build --release --locked --manifest-path tools/compact-seed-research/Cargo.toml
tools/compact-seed-research/target/release/qasset-compact-seed-research /tmp/qasset-compact-seed-proof
```

After caching dependencies, builds can use `--offline`. The run uses only the hardcoded public RFC fixture and takes roughly a few minutes. Generated proofs belong outside tracked source. Standalone verification accepts `verify PROOF_FILE CLAMP_HEX ACTION_SHA512_HEX`, using public values in the result record.

The useful result is a reproducible measured comparator and concrete constraints, not a claim that this backend solves the compact Soroban verifier requirement.
