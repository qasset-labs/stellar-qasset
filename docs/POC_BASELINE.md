# Proof-of-concept baseline

Current remediation results: 90 workspace tests, 124 Python tests and 4 signer tests pass. The fresh revision-checked registry run has 28 successful transactions, ten enforced negative simulations and one correctly signed classic Payment rejected before inclusion. The versioned assessment covers 32 paths. Required baseline source and pinned research dependencies are now captured in version control. Clean-checkout reproduction passed from an export with empty build directories and isolated Python dependencies; the final result is recorded in `evidence/qasset-remediation-validation.json`. Earlier results and backlog statements below are historical.

Recorded 2026-10-25 before any proof-of-concept code was written. Every count
below was produced by rerunning the command shown, not copied from an earlier
report.

## Repository state

- Branch `master`, HEAD `76f86a8424ad293ca1b6dc517109f0a69b23f975`.
- The working tree carries a large uncommitted backlog from earlier work
  (89 paths in `git status --short`), including changes to
  `contracts/qasset-registry`, `contracts/seed-recovery-verifier`, the root
  `Cargo.toml`/`Cargo.lock`, and many untracked research directories and
  documents. The proof of concept does not modify or commit that backlog;
  the baseline below describes the working tree as it builds today.

## Toolchain and network

- Rust 1.94.1 (stable), `wasm32v1-none` target installed.
- `soroban-sdk` 25.3.2 (resolved in `Cargo.lock`).
- Stellar CLI 26.0.0 (`stellar-xdr` 26.0.0).
- Python `stellar-sdk` 14.0.0. No JavaScript SDK is used in this repository.
- Stellar Testnet, queried live with `getLatestLedger`: **protocol 29**,
  ledger 5,372,707.
- The Protocol 30 upgrade guide (stellar.org, updated 2026-10-23) lists
  CAP-87, adding `verify_sig_ml_dsa_44/65/87` host functions, with the
  Testnet vote on 2026-11-03 and the Mainnet vote on 2026-11-23. It is
  therefore **not active** on Testnet at this baseline, and it states that
  network-level transaction signatures remain Ed25519.

## Contracts and their interfaces

`qasset-registry`: `__constructor(admin)`, `register_asset`,
`asset_admin`, `transfer_asset_admin`, `keep_alive`, `set_role_quorum`,
`get_role_quorum`, `list_weak_paths`, `declared_security_level`,
`policy_assessment`, `quantum_security_level`, `require_min_qs`. Policies
are keyed by an arbitrary address, carry a revision counter incremented on
every change, and emit `AssetAdminChanged`/`QuorumSet` events.
`policy_assessment` always returns `Unverified`; `quantum_security_level`
and `require_min_qs` always fail with `UnverifiedPolicy`.

`pq-recovery-demo`: `__constructor`, `active_key`, `epoch`,
`recovery_enabled`, `counter`, `protected`, `recovery_digest`, `recover`,
and a custom-account `__check_auth` that verifies an ML-DSA-65 signature
over the host's authorization payload with domain context
`qasset-pq-auth-v1`, and only for a single argument-free call to its own
`protected` function (the restriction added after the authorization-caching
finding).

`seed-recovery-verifier`: `__constructor`, `config`, `backend_available`
(always false; authorization returns `BackendUnavailable`).

`recovery-proof-mailbox`: `open`, `append`, `seal`, `metadata`,
`read_slice`, `backend_available`, `require_verified`.

## Build and test results (rerun)

- `cargo test --workspace --offline`: **67 passed, 0 failed**
  (registry 34, recovery candidate 14, mailbox 13, seed verifier 6). The
  authorization-caching regression
  `authorization_must_not_survive_a_handoff_in_an_unrelated_invocation_tree`
  passes, as do the official ML-DSA test vectors
  (`official_external_pure_vectors_check_underlying_library_interface`,
  `official_wycheproof_vectors_exercise_actual_digest_wrapper`,
  `official_noncanonical_hint_and_norm_fixtures_fail_at_signature_decode`).
- `cargo build --workspace --release --target wasm32v1-none --offline`:
  succeeds. Wasm SHA-256:
  - `qasset_registry.wasm` (27,332 bytes) `fab41a07a9686c18cdffafd503ab96bdfc01ef9d9c03aa3be0e3079c5a8e5aed`
  - `pq_recovery_demo.wasm` (63,267 bytes) `a58af4f2d547e0f2f97200703269446e9ed9e1a970c6768125c31dd5b97e163c`
  - `recovery_proof_mailbox.wasm` (11,940 bytes) `86453cb9bc79826889787a56a6bda5c5f493316148bee11e6b7a2b03c9b275bc`
  - `seed_recovery_verifier.wasm` (3,862 bytes) `9657b5bbcc24bb298fcab864e50b12047896943f1f42d08462ef9cb7c73e6bde`
- Python test files under `scripts/test_*.py`, each run with the standard
  library runner: **81 passed, 0 failed** across 9 files.
- Evidence consistency checkers, all exit 0:
  `check_seed_recovery_evidence.py`, `check_verifier_next_evidence.py`,
  `check_verifier_port_evidence.py`, `check_proof_transport_research.py`,
  and `check_recovery_relation.py`, which reran the SEP-5 relation at
  **168 checks** across 5 fixture groups. These checkers verify recorded
  research artifacts against their sources; they do not regenerate proofs.

## Existing Testnet deployments (fetched live)

- Registry `CCAUPFWUQD2GFSREMVWAJH7YEPKNXPW4EVSN5JNN52H64OE4K5DYCMCT`:
  live; on-chain Wasm `fab41a07…`, identical to today's build. Recorded
  2026-10-18 with 17 transactions and 20 checks (`docs/testnet-deployment.json`).
- Seed verifier `CAYCCTVTONT6HKHD2T7SYRFSO2LFSKZL4NJ2ZPVLO64NXOPQUE3NAECP`:
  live; on-chain Wasm `9657b5bb…`, identical to today's build.
- ML-DSA recovery candidate `CAU3EUMD27VGQOBWLPD66SS2752L4BHYU547LEWYEOWTWQ2JZ3IK3PLA`:
  live; on-chain Wasm `a927b6ee…`, the **pre-audit** build. The patched
  source builds to `a58af4f2…` and has not been deployed. Recorded
  2026-10-18 with 4 transactions and 17 checks (`docs/recovery-testnet.json`),
  historical only.

The old transaction counts are records of past runs; this baseline confirms
the contracts still exist and match their recorded Wasm, not that those
transactions were repeated.

## Unresolved findings carried in

From `docs/SECURITY_REVIEW.md` and the research documents:

- C-01 (authorization caching in the recovery candidate): fixed in source,
  regression passing, not redeployed.
- A-01 (no validated quantum-secure seed-recovery backend): open.
- F-01 (seed-recovery verifier exceeds Soroban code and CPU limits): open.
- V-03 (trusted account-key integration for the point-binding helper): open.
- T-04 (hermetic build reproduction): partially addressed.
- The RoKoko research's first AND/XOR gadget was found unsound and is
  superseded; the replacement has not been run through the commitment layer.

Registry limitations relevant to the proof of concept:

- The registry has no compare-and-set on revisions: concurrent updates are
  serialized by the ledger, but a caller cannot require "update only if the
  revision is still N". Revision conflicts are therefore detected by
  readers comparing revisions, not rejected by the contract.
- The registry administrator is whatever address registered the tenant,
  typically an Ed25519 account, so the declared policy itself is controlled
  by a classical key.
- The existing ML-DSA signer helper (`tools/pq-demo`) derives every key from
  a publicly known root. Its keys are fixtures that anyone can use and must
  not protect any authority in the proof of concept.

## Research artifacts

`tools/binius-soroban-research/research-scripts/wasm_sections.py`, referenced
with its hash by the committed `docs/sdk-code-size-breakdown.json`, was not
tracked in Git at this baseline. It is added alongside this document so the
recorded Wasm section analysis can be repeated.
