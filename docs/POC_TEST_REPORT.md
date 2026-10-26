# SAC authority demonstration test report

Current remediation results: 90 workspace tests, 124 Python tests and 4 signer tests pass. The fresh revision-checked registry run has 28 successful transactions, ten enforced negative simulations and one correctly signed classic Payment rejected before inclusion. The versioned assessment covers 32 paths. Required baseline source and pinned research dependencies are now captured in version control. Clean-checkout reproduction passed from an export with empty build directories and isolated Python dependencies; the final result is recorded in `evidence/qasset-remediation-validation.json`. Earlier results and backlog statements below are historical.

The explicitly approved fresh run has now completed the issuer lock, post-lock
classic authentication rejection, post-lock ML-DSA authorization and live registry
staleness demonstration. The primary record contains **28 successful transactions,
eight rejected simulations and one txBAD_AUTH rejection before inclusion**.
Current Python validation passes 112 tests. The earlier results below are
historical; current completion results follow them.

Recorded 2026-10-25. Results describe this working tree, whose substantial
pre-existing backlog is documented in [the baseline](POC_BASELINE.md).
The backlog was not committed as part of this continuation. In particular,
the root lockfile and earlier contract/research changes remain outside these
focused commits. A clean checkout alone does not recreate that working tree.
Machine-readable command summaries and hygiene results are in
[`qasset-local-validation.json`](../evidence/qasset-local-validation.json).

## Initial continuation: local commands and observed results

| Command | Observed result |
| --- | --- |
| `cargo test -p qasset-sac-admin --offline` | Initial compile failed on a test-only missing `std` import; next run had 10 passed and 10 failed fixture state assertions; corrected fixture passed all 20. |
| `cargo test --workspace --offline` | First completed run: 87 passed, 0 failed (the prior 67 plus 20). After the lease change: 88 passed, 0 failed (14 recovery, 34 registry, 21 SAC admin, 13 mailbox, 6 seed verifier). |
| `cargo build -p qasset-sac-admin --release --target wasm32v1-none --offline` | Succeeded before and after the lease change. |
| `sha256sum target/wasm32v1-none/release/qasset_sac_admin.wasm` | Final hash `f7ed9b81ca062af1b52c793fa068d43220d900c0d572e648f6e2d0f5a2a472b6`. |
| `wc -c target/wasm32v1-none/release/qasset_sac_admin.wasm` | Final size 59,167 bytes; documented code limit 131,072 bytes. Initial maximum-lease build was 59,139 bytes, hash `b324b912b8ad3e65960b595a05f99ce709406d0968ef3c4f3ce8ea9709c87eb1`. |
| `sha256sum target/wasm32v1-none/release/qasset_registry.wasm` | Unchanged baseline `fab41a07a9686c18cdffafd503ab96bdfc01ef9d9c03aa3be0e3079c5a8e5aed`, 27,332 bytes. |
| `cargo test --manifest-path tools/qasset-sac-signer/Cargo.toml --offline` | 4 passed, 0 failed. A preliminary implementation compile error treating a signing Result as an Option was corrected before use. |
| `cargo build --manifest-path tools/qasset-sac-signer/Cargo.toml --release --offline` | Succeeded; fresh operator keys were then generated outside the repository. |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | Initial combined run 84 passed; final combined run 100 passed, 0 failed. This preserves the previous 81 and adds 3 runner tests, 4 analyzer tests and 12 evidence tests. |
| `cargo clippy -p qasset-sac-admin --offline --all-targets -- -D warnings` | Passed. |
| `cargo clippy --manifest-path tools/qasset-sac-signer/Cargo.toml --offline --all-targets -- -D warnings` | Passed. |
| `python3 -m py_compile scripts/qasset_poc_testnet.py scripts/qasset_authority_analyzer.py scripts/verify_qasset_evidence.py` | Passed. |
| `python3 scripts/verify_qasset_evidence.py --offline` | Passed: 30 paths; offline consistency only. |
| `python3 scripts/verify_qasset_evidence.py --report evidence/qasset-evidence-verification.json` | Passed live: 25 transactions rechecked, 30 paths, both registry revisions 3. |

The Python SDK emits a deprecation warning when decoding integer SetOptions
flags from XDR. It does not indicate a failed test. The fee-assembly regression
checks that an int64 resource fee survives serialization in a signed fee bump.

## Initial continuation: live commands and recorded outcomes

`python3 scripts/qasset_poc_testnet.py` was attempted four times, each with
fresh issuers and a fresh operator key. Failed public records were preserved
before the next attempt. No existing issuer was supplied to the script.

| Attempt | Real outcome | Public record |
| --- | --- | --- |
| 1 | No submitted transaction; SDK fee-field serialization overflow before upload submission. | `evidence/attempts/qasset-poc-fee-overflow.json` |
| 2 | Two successful uploads, then contract creation rejected in enforced simulation because a source-account auth entry was missing. | `evidence/attempts/qasset-poc-source-auth.json` |
| 3 | Five successful transactions, then admin deployment rejected before inclusion for insufficient balance under the maximum storage lease. | `evidence/attempts/qasset-poc-max-lease.json` |
| 4 | 25 successful transactions and 8 rejected enforced simulations; stopped before the gated issuer lock. | `deployments/testnet/history/qasset-poc-unlocked.json` |

The initial unlocked run spans ledgers 5,379,790–5,379,824. Its eight rejected simulations
are corrupted signature, wrong-network signature, operator-signed mint and
replayed authorization, each for both assets. These are not failed on-chain
transactions. Earlier attempts' seven confirmed transactions are not added
to that historical record's count of 25.

That initial run's positive ML-DSA `set_authorized` simulations declared 102,504,931
instructions for QEXP and 102,501,961 for QCTL. Their estimated resource fees
were 57,417 and 57,416 stroops. These are simulation estimates for this build
and network state, not native-test benchmarks or production cost promises.

The initial `python3 scripts/qasset_authority_analyzer.py` invocation collected live reads across
ledgers 5,379,838–5,379,840 and produced 30 paths: 7 `EXPOSED`, 4 `TESTED_PASS`,
8 `TESTED_REJECT`, 8 `UNCOVERED`, 2 `DECLARED`, and 1 `INCONCLUSIVE`.
These counts are classifications, not a security score.

## Gates at the end of the initial run

The required lock environment variable was absent. No issuer lock,
post-lock classic rejection or post-lock ML-DSA transaction was run. QCTL's
restricted-issuer result remained pending at that point. No live registry revision bump was
performed; changed-revision fixtures establish affected-path `STALE` output
and a nonzero verifier command result.

Live code bytes, getters, issuer authority and transaction receipts were
rechecked by the separate verifier. Historical negative simulation transcripts
remain recorded RPC responses. The eight internal reviews are recorded in
[security findings](POC_SECURITY_FINDINGS.md); no independent audit was performed.

## Approved completion run

The fresh locked run spans ledgers 5,380,502–5,380,542; the subsequent registry declaration was confirmed in ledger 5,380,584.
Its immutable pre-revision record is `deployments/testnet/qasset-poc-locked.json`.
The primary `deployments/testnet/qasset-poc.json` additionally records that
declaration receipt and current revisions: QEXP 4, QCTL 3.

| Command | Observed result |
| --- | --- | --- |
| `QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK=YES python3 scripts/qasset_poc_testnet.py --output deployments/testnet/qasset-poc-locked.json` | Completed: 27 successful transactions, 8 negative simulations, one txBAD_AUTH submission rejection. |
| `python3 scripts/qasset_authority_analyzer.py --deployment deployments/testnet/qasset-poc-locked.json --snapshot evidence/history/qasset-authority-inputs-locked-revision3.json --output evidence/history/qasset-authority-assessment-locked-revision3.json` | Generated the 30-path pre-revision assessment with both post-lock citations. |
| `python3 scripts/verify_qasset_evidence.py --assessment evidence/history/qasset-authority-assessment-locked-revision3.json --report evidence/history/qasset-evidence-verification-locked-revision3.json` | Passed live before mutation: 27 confirmed transactions, both revisions 3. |
| `python3 scripts/qasset_poc_staleness.py` with the preserved revision-3 assessment and private external deployer file | Repeated the unchanged Freeze declaration on this run's fresh registry only. QEXP revision 3 became 4. The separate verifier returned STALE for exactly 15 QEXP paths and exited 1. |
| `python3 scripts/qasset_authority_analyzer.py` | Refreshed primary evidence at current revisions 4 and 3. |
| `python3 scripts/verify_qasset_evidence.py --report evidence/qasset-evidence-verification.json` | Passed live: 28 successful transactions rechecked, 30 paths, no stale current paths. |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 112 passed, 0 failed: the previous 100 plus 7 post-lock/archive evidence tests and 5 staleness-tool guard tests. |
| `python3 -m py_compile scripts/qasset_poc_staleness.py scripts/qasset_authority_analyzer.py scripts/verify_qasset_evidence.py` | Passed. |

Rust contract and signer source were unchanged during completion. The prior
88 workspace tests and 4 signer tests remain the recorded results for those
same sources and Wasm; no new Rust test execution is claimed for this phase.

| Operation | Asset | Estimated instructions | Estimated resource fee (stroops) |
| --- | --- | --- | --- |
| ml_dsa_set_authorized | QEXP | 102,495,704 | 59,194 |
| ml_dsa_set_authorized | QCTL | 102,500,188 | 59,196 |
| ml_dsa_after_lock | QCTL | 102,492,873 | 57,893 |

The current snapshot covers ledgers 5,380,600–5,380,602. Its classifications are 5 `EXPOSED`, 4 `TESTED_PASS`, 9 `TESTED_REJECT`, 10 `UNCOVERED`, 2 `DECLARED`.

Issuer lock: `64abbe8deb5145e347d1562a82ac00723749d31c263063927ae2010ca0f3ceb2`.
Post-lock ML-DSA: `36c5d3671f6841c5ccdf8dc38121c9b0dded8ecff16a5050cf7ad5acec8e455c`.
Live revision declaration: `79cf98dcc4d5ad5dc44e9a4c7e8b2d86cd0d0c509a8e6bae11e7ec543919f0e0`.

QCTL's classic Payment was rejected by sendTransaction with txBAD_AUTH.
Its computed envelope hash is recorded as a submission rejection, not a
failed on-chain transaction. The verifier checks ledger application order
for the post-lock success and rejects a balance error presented as an
authentication rejection.

The original unlocked deployment and snapshot were copied unchanged into
history. Its archived assessment updates only input paths and archive
metadata, with a new body checksum and the original checksum recorded.
The relocated assessment still passes offline consistency checks.
The locked revision-3 assessment remains immutable and demonstrates STALE
against the current live revision 4. The primary refreshed assessment passes.

## Final remediation verification

The clean source export of `52845f7a364ddcf09de7eb8b48f217ec4f9be8ca` passed all 14 reproduction
commands. Initial workspace and tool build directories were absent. Python
dependencies were installed into a separate environment with required wheel
hashes. Cargo commands were locked and offline against cached dependency
sources. Host test debug information was disabled; assertions and authentication
checks were unchanged.

| Validation | Observed result |
| --- | --- |
| Workspace tests | 90 passed: recovery 14, registry 36, SAC administrator 21, mailbox 13, seed verifier 6. |
| Signer tests | 4 passed. |
| Python tests | 124 passed, including 31 evidence tests. |
| Public credential helper | Release build passed; real credentials exercised by evidence tests and live verification. No standalone helper unit tests are counted. |
| Release Wasm | Both hashes matched the deployed references: administrator 59,167 bytes and registry 28,553 bytes. |
| Research checks | Five passed within their source/record, public relation and transport scopes. No fresh proof generation. |
| Current live evidence | SUCCESS, 28 receipts rechecked, 32 paths, revisions QEXP 4 and QCTL 3. |
| Preserved pre-change assessment | STALE, 27 receipts rechecked and exactly 16 QEXP paths stale, exit 1. |
| Tracked key hygiene | No valid Stellar secret-seed patterns or private-key filenames found in 1241 tracked files. |

Exact commands and output are retained in
[`qasset-clean-reproduction.json`](../evidence/qasset-clean-reproduction.json).
The [remediation record](../evidence/qasset-remediation-validation.json) records
four closed findings, the additional tool-version and guarded-write requirements,
and eight internal review passes. It is not an external security audit.
