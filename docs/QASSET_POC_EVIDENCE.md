# SAC authority PoC evidence and reproduction

The current release uses schema v2 and assessment tool 2.0.0. It contains
28 successful Testnet transactions, 10 enforced negative simulations and
one correctly signed classic Payment rejected before inclusion with `txBAD_AUTH`.
ML-DSA-65 verification runs inside Wasm using unaudited RustCrypto `ml-dsa`
0.1.1, not CAP-87. Testnet reported protocol 29 during this run.

## Current public configuration

Registry: `CAT6N26Q6W7ONAAGKZ3P6AGRLQVDBANJNGECH6NHZSZE2C4O7YIFQI6P`.

| Asset | Issuer | SAC | Administrator | Policy revision |
| --- | --- | --- | --- | --- |
| QEXP | `GC5SXB4PO5FWSTO4LYYPDZODXA6VEA3W3EDCFKXLQXOUYW2GLY7LUXBL` | `CBM4OANSC4M3HVKEFHBQHUAKLJH64OE73FSIDAPBPDFFAEQJ26XALLIS` | `CCCZU3NFFPP7WKZ2TP6FH5OHWTHMKBVPQA3V2LYVOHMYTWTTFFPX6CVE` | 4 |
| QCTL | `GCXL44OHQ65L5RM2UKBFA6WD7637W5TMEVLAETX4MMLO7GE2SXH7KG7L` | `CCIKADRSXS6SOVDNZPIAPDACIK4ARXB5M4M26GZE7R6I6CWQJOCIFMYR` | `CBHLG3HZ6XTDRFP4MNNP57P5NMQSVW6L54SKVUZBFG22LEBX2GJASB4R` | 3 |

The [deployment](../deployments/testnet/qasset-poc.json),
[raw inputs](../evidence/qasset-authority-inputs.json),
[assessment](../evidence/qasset-authority-assessment.json) and
[live verification](../evidence/qasset-evidence-verification.json) describe
this release. Its 32 paths include two revision-conflict probes. QEXP retains
classic issuer signing weight. QCTL has no positive-weight issuer signer;
a subsequent ML-DSA authorization succeeded after the lock.

## Reproduce from a clean checkout

Reference environment: Linux x86_64, Python 3.10 (including venv support),
Rust 1.94.1 and the `wasm32v1-none` target. Python dependencies are pinned by
version and wheel SHA-256; Cargo dependencies are locked.

```sh
python3 -m venv /tmp/qasset-poc-env
/tmp/qasset-poc-env/bin/python -m pip install --require-hashes -r scripts/requirements-poc.lock
/tmp/qasset-poc-env/bin/python scripts/reproduce_poc.py
```

If the host lacks `ensurepip`, the isolated environment can also be provisioned
with an existing pip that supports `--python`:

```sh
python3 -m venv --without-pip /tmp/qasset-poc-env
python3 -m pip --python /tmp/qasset-poc-env/bin/python install --require-hashes -r scripts/requirements-poc.lock
```

Add `--offline` when Cargo dependencies are cached. The command builds all
five contracts, tests the workspace and signer, builds the public-credential
verifier, runs all Python tests, compares reference Wasm hashes and checks
retained research records and the public transport fixture. It never submits
transactions. It writes its result outside the repository, normally
`/tmp/qasset-poc-reproduction.json`. It does not regenerate research proofs.

Add `--live` for read-only verification of current Testnet evidence and the
preserved pre-change assessment. Live verification needs RPC/Horizon access
and retained Testnet history; unavailable evidence is `INCONCLUSIVE`.

## Inspect the demonstrated authority paths

1. Verify each `handover` receipt and the live SAC administrator.
2. Inspect each `ml_dsa_set_authorized` receipt and authorized trustline.
3. Inspect corrupted-signature, wrong-network, operator-mint and replay probes.
   The verifier checks the actual credentials and expected error diagnostics.
4. Compare QEXP's successful classic Payment and SetTrustLineFlags with QCTL's
   correctly signed classic Payment rejection after its issuer lock.
5. Check `lock_issuer` and `ml_dsa_after_lock` ledger order. A missing signature,
   unrelated failure, retained signing weight or reused pre-lock success is invalid evidence.
6. Inspect `registry_revision_conflict`: the tenant source supplies an old
   expected revision and receives contract error 15. All declarations in this
   release use `set_role_quorum_if_revision`. The legacy unconditional API
   remains available for existing callers and does not promise conflict rejection.
7. Compare the preserved
   [revision-3 assessment](../evidence/history/qasset-authority-assessment-revisioned-before-bump.json)
   with the [staleness experiment](../evidence/qasset-poc-staleness.json).
   The guarded write `4453b55e47b3cc530c0215d59cd4ab81a211cafcd71854f86d15a32af6e626e1` advanced QEXP from 3 to 4.
   Exactly 16 QEXP paths became `STALE`, with verifier exit 1; refreshed evidence
   binds revisions QEXP 4 and QCTL 3.

```sh
python3 scripts/verify_qasset_evidence.py --offline
python3 scripts/verify_qasset_evidence.py
python3 scripts/verify_qasset_evidence.py --assessment evidence/history/qasset-authority-assessment-revisioned-before-bump.json
```

Exit 0 means `SUCCESS` within the reported scope; exit 1 means `STALE` or
`INVALID`, distinguished by the JSON `status`; exit 2 means `INCONCLUSIVE`.
Offline mode establishes consistency only. Changed authority returns affected
`STALE` paths. Missing required live evidence never establishes freshness.

## Run another disposable demonstration

The runner refuses an existing output and creates every issuer and operator
key afresh. Keys stay in a private directory outside the repository. Enabling
the lock gate permanently retires only that run's newly generated QCTL issuer.

```sh
QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK=YES python3 scripts/qasset_poc_testnet.py --output deployments/testnet/reviewer-run.json
python3 scripts/qasset_authority_analyzer.py --deployment deployments/testnet/reviewer-run.json --snapshot evidence/reviewer-inputs.json --output evidence/reviewer-assessment.json
python3 scripts/verify_qasset_evidence.py --assessment evidence/reviewer-assessment.json
```

The staleness command takes that assessment, the private external accounts
file printed by the runner and new output paths. It first verifies the fresh
registry creation and current evidence, then writes the guarded declaration
and verifies that the prior assessment is stale. Never substitute an older
registry or issuer.

## Provenance and boundaries

`evidence/input-archive/` stores content-addressed historical source and Wasm
inputs. Their hashes preserve earlier assessments when a current source or
build changes. The verifier checks every archived byte; altered historical
assessments cannot use legacy-schema compatibility. Historical records remain
unchanged; current evidence uses the versioned schema and tool-source hashes.

Checksums are not signatures. Historical negative responses remain recorded
RPC transcripts: credential validity, mutation, replay correlation, interval
and error diagnostics are checked, but no signed historical rejection
attestation is claimed. Generator timestamps are explicitly untrusted clock
metadata; raw read ledgers must fit the declared collection interval.

Only SAC `set_authorized` is admitted by the fixed administrator. Registry
declarations, classical fee-payer authority, untested functions, key loss,
lease availability and recovery research retain their documented boundaries.
No overall security score or asset-wide safety classification is issued.

The final [clean reproduction output](../evidence/qasset-clean-reproduction.json)
and [remediation validation](../evidence/qasset-remediation-validation.json)
record the source commit, environment, all 218 passing tests, matched Wasm,
fresh live verification and eight internal review passes.
