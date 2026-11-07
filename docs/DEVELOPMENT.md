# Development guide

How to build, test and verify the repository. Commands run from the repository
root unless stated otherwise. The [architecture](ARCHITECTURE.md) explains the
system; the [future-work register](FUTURE_WORK.md) lists open engineering work.

## Requirements

* Linux x86_64 (the signer uses Unix file permissions).
* Rust 1.94.1 with the `wasm32v1-none` target.
* Python 3.10 with the hashed reference lock `scripts/requirements-poc.lock`.

```bash
rustup toolchain install 1.94.1
rustup target add wasm32v1-none --toolchain 1.94.1

python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r scripts/requirements-poc.lock
```

`.venv/` is ignored by Git. Add `--offline` to Cargo commands when dependencies are
already cached. All Cargo commands use `--locked`.

## Repository layout

| Path | Contents | Index |
| --- | --- | --- |
| `contracts/` | Soroban contracts (Cargo workspace members) | [contracts](../contracts/README.md) |
| `scripts/` | Analyzer, evidence verifier, Testnet runners, research runners and their tests | [scripts](../scripts/README.md) |
| `tools/` | Signer, evidence helper and isolated research crates | [tools](../tools/README.md) |
| `deployments/` | Recorded Testnet deployments | — |
| `evidence/` | Assessments, input snapshots, verification reports, archived inputs | — |
| `docs/` | Architecture, specifications, reviews and research records | [documentation index](README.md) |

## Build

```bash
RUSTUP_TOOLCHAIN=1.94.1 cargo build --locked --workspace --target wasm32v1-none --release
sha256sum target/wasm32v1-none/release/qasset_sac_admin.wasm \
          target/wasm32v1-none/release/qasset_registry.wasm
```

Expected reference hashes:

```text
f7ed9b81ca062af1b52c793fa068d43220d900c0d572e648f6e2d0f5a2a472b6  qasset_sac_admin.wasm
26f684edb7e3255ac1617f1455fbfcf886a0f5b189f31974b873a5bc0f98a207  qasset_registry.wasm
```

Changing contract source, including doc comments on contract types, changes these
hashes and the recorded evidence that pins them.

## Test

```bash
# Contracts: 93 tests across the five packages
RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked --workspace

# Operator signer: 4 tests (separate Cargo workspace)
(cd tools/qasset-sac-signer && RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked)

# Python: 124 tests
.venv/bin/python -m unittest discover -s scripts -p 'test_*.py'
```

## Lint and format

```bash
RUSTUP_TOOLCHAIN=1.94.1 cargo fmt --all --check
RUSTUP_TOOLCHAIN=1.94.1 cargo clippy --locked --workspace --all-targets
```

## Verify recorded evidence

```bash
# Build the public ML-DSA verification helper used by the verifier
(cd tools/qasset-evidence-crypto && RUSTUP_TOOLCHAIN=1.94.1 cargo build --locked --release)

# Recorded consistency only (no network)
.venv/bin/python scripts/verify_qasset_evidence.py --offline

# Also recheck Testnet receipts and live configuration (read-only)
.venv/bin/python scripts/verify_qasset_evidence.py
```

Exit 0 is `SUCCESS`, 1 is `STALE` or `INVALID` (see the JSON status), and 2 is
`INCONCLUSIVE` when required live evidence is unavailable.

## Full reproduction

```bash
RUSTUP_TOOLCHAIN=1.94.1 .venv/bin/python scripts/reproduce_poc.py --offline
```

The runner builds the contracts and tools, runs the test suites, compares the
reference Wasm hashes, verifies assessment consistency and checks retained research
records. It does not submit transactions. Add `--live` for read-only Testnet
rechecks. Detailed reproduction notes are in the
[PoC evidence guide](QASSET_POC_EVIDENCE.md).

## Testnet scenarios

`scripts/qasset_poc_testnet.py` creates disposable Testnet accounts and contracts and
submits transactions. It is not needed for development and must never be used with
real funds. Operator keys are created outside the repository; `*.seed` files are
ignored by Git. Issuer locking requires an explicit environment gate and is limited
to an issuer created by the same run.

## Continuous integration

`.github/workflows/ci.yml` runs formatting, lint, contract, signer and Python tests,
the release build with the reference-hash check, and offline evidence verification.

## Contribution rules

See [contributing](../CONTRIBUTING.md) and the [security policy](../SECURITY.md).
Changes to contract interfaces, storage, authorization or cryptographic code need a
decision record in [decisions](DECISIONS.md) and adversarial tests.
