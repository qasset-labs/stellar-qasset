# Cryptographic research relevant to this demonstration

The implemented authority credential is ML-DSA-65 over the host's 32-byte
Soroban authorization digest, with context `qasset-sac-admin-auth-v1`.
The fresh signer and contract pin RustCrypto `ml-dsa` 0.1.1. Verification
runs inside Wasm, not a CAP-87 host function; this implementation is unaudited.

The signer obtains a new 32-byte seed from the OS random generator. It does
not use the published-root keys in `tools/pq-demo`. Deterministic signing
with the fresh secret seed uses the same message and context interface as
the contract tests. The host supplies network, nonce, expiry and invocation
binding; the custom account further restricts the allowed authorization tree.

This does not integrate a zero-knowledge seed-recovery backend. The existing
research remains separate:

- [Current recovery implementation status](RECOVERY_IMPLEMENTATION_STATUS.md)
  describes the disabled seed-recovery interface and remaining integration gates.
- [Binius recovery evidence](BINIUS_RECOVERY_EVIDENCE.md) records the separate
  proof experiments and their parameter and transport limitations.
- [Successor verifier evidence](VERIFIER_NEXT_EVIDENCE.md) records raw-Wasm
  portability and the remaining Soroban wrapper limits.
- [Binius A-01 review scope](BINIUS_A01_REVIEW_SCOPE.md) describes the unresolved
  quantum-soundness review requirements.
- [RoKoko relation research](../tools/rokoko-relation-research/README.md) and
  the existing baseline record the superseded unsound AND/XOR gadget and
  the bounded replacement work. This continuation changes none of that source.

**A-01 remains open:** there is no validated quantum-secure seed-recovery
backend integrated into the account lifecycle. **F-01 remains open:** the
seed-recovery verifier has not met the complete Soroban code and CPU gates.
SAC credential verification fitting a live transaction does not resolve
either finding.

## Retained measurements and blockers

The compact preimage experiment records an 8,893,905-byte public-fixture proof.
It remains 7,986,385 bytes with recorded zlib encoding and 7,767,592 bytes with
recorded xz encoding, far above the historical whole-transaction limit. The
public proof is retained under `evidence/research-fixtures/`; reproduction
remeasures encoding without changing the original research record.

The successor Binius raw module records 127,068 bytes, while its Soroban SDK
wrapper records 183,090 bytes. Compact setup is 1,286,664 bytes and the tested
raw canonical memory is 27,852,800 bytes. Raw ABI size fit does not establish
Soroban deployment or complete SDK verification. The SDK budget experiments
record execution failures, not proof rejections. Source inventories, pins,
negative cases and known failures remain preserved. No new proof generation,
quantum-soundness review, hash caching change or upstream code change was made
for this authority PoC. A-01 and F-01 remain open.
