# Scripts

Python tools for assessment, evidence verification, Testnet scenarios and research.
Files stay in this flat layout because recorded assessments pin the paths and
hashes of the core tools; reorganization is tracked as `FW-REPO-02` in the
[future-work register](../docs/FUTURE_WORK.md). Setup and commands are in
[development](../docs/DEVELOPMENT.md).

## Core authority assessment

| Script | Purpose | Tests |
| --- | --- | --- |
| `qasset_authority_analyzer.py` | Collects issuer, SAC and registry state and writes the assessment | `test_qasset_authority_analyzer.py` |
| `verify_qasset_evidence.py` | Separate verifier: recomputes classifications; offline and read-only live modes | `test_qasset_evidence.py` |
| `qasset_poc_testnet.py` | Disposable Testnet deployment and authority probes (submits transactions) | `test_qasset_poc_testnet.py` |
| `qasset_poc_staleness.py` | Policy-revision staleness experiment | `test_qasset_poc_staleness.py` |
| `reproduce_poc.py` | Builds, tests and verifies the reference proof of concept without submitting transactions | — |
| `requirements-poc.lock` | Hashed Python dependency lock for the reference environment | — |

## Earlier registry prototype

| Script | Purpose | Tests |
| --- | --- | --- |
| `testnet_demo.py` | Deploys and exercises the earlier metadata registry prototype on Testnet | — |
| `verify_testnet.py` | Rechecks that prototype's public receipts (read-only) | `test_verify_testnet.py` |
| `receipt_coverage.py` | Receipt capture completeness for that prototype | `test_receipt_coverage.py` |
| `validate.py` | Local checks that write `docs/validation.json` | — |
| `requirements-testnet.txt` | Dependencies for the earlier Testnet scripts | — |

## Optional extension: recovery research

These scripts support the optional recovery research and are not used by the core
platform: `recovery_demo.py`, `recovery_statement.py`, `durable_recovery_research.py`,
`check_recovery_relation.py`, `check_seed_recovery_evidence.py`,
`check_proof_transport_research.py`, `check_verifier_next_evidence.py`,
`check_verifier_port_evidence.py`, `read_verifier_network_limits.py`,
`verify_recovery_research.py`, `verify_binius_recovery_research.py`, the `run_*.py`
research runners, their `test_*.py` files, and `requirements-crypto-demo.txt`.
They use public fixture keys only.

Run all Python tests:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```
