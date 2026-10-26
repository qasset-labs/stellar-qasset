# Continuation brief

Current release: see `QASSET_POC_EVIDENCE.md` and `POC_TEST_REPORT.md`.
The remediation request superseded the earlier unchanged-registry and
uncommitted-baseline restrictions for the guarded write API and reproducible
source snapshot. The historical instructions below describe the earlier phase.

Historical brief. Read `POC_TEST_REPORT.md` and `QASSET_POC_EVIDENCE.md` for
completed continuation work, including the approved fresh issuer lock and live
revision change, before rerunning the original instructions below.

Paste the text below as the task for the engineer or tool continuing the
proof of concept.

---

You are continuing the Q-Asset authority-coverage proof of concept in this
repository (`stellar-qasset`, Rust/Soroban contracts plus Python scripts,
Stellar Testnet only).

Read these files first, completely, before changing anything:

1. `docs/POC_HANDOFF.md`: current status, decisions already made, the
   ordered remaining tasks, and the rules.
2. `docs/POC_BASELINE.md`: the reproduced baseline every report compares
   against.
3. `contracts/qasset-sac-admin/src/lib.rs` and `src/test.rs`: the new SAC
   administrator contract and its adversarial tests (written, never built).
4. `contracts/pq-recovery-demo/src/test.rs`: a known-good helper that builds
   real Soroban authorization entries signed with ML-DSA-65.

Then work through the tasks in `docs/POC_HANDOFF.md` section 4 strictly in
order:

1. Build and test `qasset-sac-admin`. Fix compile errors in the tests
   without weakening any security check. Run the full workspace tests and
   confirm the 67 earlier tests still pass. Build the release Wasm and record
   size and SHA-256.
2. Build the fresh-key signer tool `tools/qasset-sac-signer/` (OS RNG seed,
   stored outside the repository with mode 0600, context
   `qasset-sac-admin-auth-v1`).
3. Write and run `scripts/qasset_poc_testnet.py` (QEXP exposed, QCTL
   restricted). The issuer lock runs only when
   `QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK=YES` is set and the issuer was created
   in the same run; otherwise record it as pending and stop before the lock.
   Write `deployments/testnet/qasset-poc.json` from real results only.
4. Write the analyzer and generate
   `evidence/qasset-authority-assessment.json` with only these statuses:
   DECLARED, TESTED_PASS, TESTED_REJECT, EXPOSED, UNCOVERED, STALE,
   INCONCLUSIVE.
5. Write the independent verifier and its tamper and staleness tests.
6. Write the six documents listed in the handoff.
7. Do the eight internal review passes and record them.
8. Produce the final summary, then stop.

Hard rules (from the handoff, repeated because they matter most):

- Never commit seeds, secret keys or key files. Inspect `git diff --cached`
  before each commit. Stage files by explicit path only; never `git add -A`
  or `git add .`. Leave the existing uncommitted backlog untouched.
- Testnet only. Never reuse an existing issuer account. Never try to undo an
  issuer lock.
- No blanket `mock_all_auths()` behind any authentication claim.
- No `QUANTUM_SAFE` status, no overall security score, no claim that a
  declared registry policy is verified.
- ML-DSA-65 runs inside contract Wasm via the unaudited RustCrypto `ml-dsa`
  0.1.1 crate, not the CAP-87 host function (Testnet is protocol 29). Say so
  wherever verification is described.
- Never invent tx hashes, addresses, counts or benchmarks. If a step could not
  run, record it as not run and say why.
- Distinguish a rejection in simulation from a failed transaction recorded
  on-chain.
- Internal reviews are internal; never describe them as independent audits.
- Do not modify `contracts/pq-recovery-demo` semantics, the registry
  semantics, pinned/vendored upstream code, or the Binius64 and RoKoko
  research.
- Keep documents and code free of references to grant programs and to
  automated or assisted authorship tools.
- Stay inside the repository for file searches; do not touch unrelated
  Stellar CLI identities.

Commit in small logical steps (contract, signer tool, Testnet script and
record, analyzer and verifier, documents), each message describing what
changed and why.
