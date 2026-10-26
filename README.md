# Q-Asset — protect, assess and recover Stellar asset authority

The SAC authority PoC and its current Testnet evidence are described in the
[reproduction guide](docs/QASSET_POC_EVIDENCE.md). It uses a fresh ML-DSA-65
operator key, a fixed `set_authorized` administrator and an explicitly gated
disposable issuer lock. ML-DSA verification runs inside Wasm using unaudited
RustCrypto `ml-dsa` 0.1.1. It does not use CAP-87 or establish asset-wide safety.

Current recovery components and remaining gates: [implementation status](docs/RECOVERY_IMPLEMENTATION_STATUS.md) and [successor evidence](docs/VERIFIER_NEXT_EVIDENCE.md).

Q-Asset aims to connect post-quantum authorization, assessment of an asset's actual
control paths, and backup-compatible recovery for supported Stellar smart accounts.
The goal is to show that sensitive operations require the assessed protection and
that legitimate owners have a defined recovery path. Published signer and seed-proof
research supplies the cryptography; verified Stellar integration is the proposed
product contribution.

**Audit status:** the historical PQ testnet baseline is superseded after a
reproduced authorization-cache flaw. Old-key authority validated earlier in one
invocation tree could still be used after recovery in that same tree. The revised
candidate restricts authentication to one direct, argument-free call to its own
protected counter. It is not a general smart-wallet account. The patched candidate
has not been redeployed; old receipts do not establish its deployment or security.

## Current components

| Component | Implemented behavior | Boundary |
| --- | --- | --- |
| [Policy registry](contracts/qasset-registry/src/lib.rs) | Validates weighted declarations, calculates declared QS0–QS4, detects classical-only paths, isolates tenant administration and records revisioned snapshots. | Assessments remain `Unverified`. `quantum_security_level` and `require_min_qs` always reject; no asset authority adapter is integrated. |
| [ML-DSA recovery candidate](contracts/pq-recovery-demo/src/lib.rs) | Real ML-DSA-65 verification, enrolled-key recovery, replacement-key proof of possession and counter-scoped authorization. | Local audit fix awaiting redeployment. Prior generic-account baseline is superseded; public fixtures are unsafe for funds. This is not legacy-seed ZK recovery. |
| [Legacy-seed recovery interface](contracts/seed-recovery-verifier/src/lib.rs) | Owner-authorized immutable constructor configuration and regression tests rejecting forged credentials. | `backend_available()` is false; authorization returns `BackendUnavailable`. No seed-knowledge proof backend is integrated on-chain. |
| [Original-seed proof research](tools/seed-recovery-research) | Actual off-chain proof generation and separate-process verification for an official SEP-5 root/account relation, bound to a canonical recovery request. | Deliberately insecure reduced-round parameters, unaudited attributed backend, public fixtures only. Measured proofs are too large for a single observed Testnet transaction. No on-chain recovery is enabled. |

The backup baseline uses RustCrypto `ml-dsa` 0.1.1 and a helper that derives its
active, recovery and replacement keys from one **published** root. Anybody can
sign for them. These are not independent factors; never use this demo for funds.
Its owner address provides deployment consent and has no signing/administrator
bypass. Registry declarations do not inherit verification from this separate demo.

## Reviewer evidence

The [reviewer guide](docs/REVIEWER_GUIDE.md) explains each scenario and its limits.
[Local validation](docs/validation.json) records exact test, format/lint and WASM
results for its source hashes. The public SEP-5 relation checker has 168 checks across
5 fixture groups and 15 addresses. The registry suite also evaluates 342 bounded
quorum cases against a subset-enumeration oracle; these are cases inside a test,
not 342 additional independent tests.

The [original-seed evidence](docs/RECOVERY_EVIDENCE.md) adds a real off-chain root
proof experiment, a conditional security argument, and scalar-only signature
counterexamples across 15 public accounts. Its reduced-round proofs are insecure;
functional success is separate from quantum security and Stellar feasibility.

Further [scalar recovery experiments](docs/SCALAR_RECOVERY_EVIDENCE.md) remove
private curve multiplication and measure both leaf and root proofs, including
the upstream 438-response setting. A strict local ceremony now checks the typed
request against the actual circuit and requires real replacement-key possession
before returning a changed model state. A second
[ShorStop/Plonky3 comparator](docs/COMPACT_BACKEND_REVIEW.md) constrains the leaf
preimage and rejects a wrong witness. Both measured backends remain too large
for direct submission under the recorded transaction limit. Scalar disclosure
requires finalized classical-authority retirement beforehand; the research uses
only published fixtures and does not establish that retirement on Stellar.

Two historical testnet runs have distinct claims. The PQ run predates the audit
fix and does not establish deployment of the current candidate:

- [Metadata demo](docs/testnet-deployment.json): 17 confirmed successful transactions
  and 20 checks, including declared QS0–QS4 and unauthorized mutation rejection.
- [PQ backup recovery](docs/recovery-testnet.json): 4 confirmed successful
  transactions and 17 checks. An initial PQ key authorizes a counter action;
  recovery installs the replacement key; the replacement authorizes a second
  action. Old-key, replay, forged-signature, wrong replacement-possession and
  fee-payer bypass checks reject. Final epoch is 1, counter is 2, recovery consumed.
  These direct-call tests missed the later reproduced same-tree cache attack.
  Its WASM starts `a927b6ee` and is historical pre-audit code.

[Recovery transaction](https://stellar.expert/explorer/testnet/tx/8df78c1f40af8c00d5bedf49262e1089900621c227c9242cfbb7ca9730674cb6)
and [replacement-authorized action](https://stellar.expert/explorer/testnet/tx/f830aa32aca8a1ac6d38fbfb12705a63c6d06dba74e7313fa047299b46ac2224)
are linked to the recorded run. Negative RPC simulations are labelled separately
from committed transactions. Authentication negatives explicitly enforce auth;
a CLI recording simulation alone does not prove rejection. Testnet can reset or
archive state, so recheck the recorded hashes/network before review.

[Public verification](docs/testnet-verification.json) must be read with its status
and source hashes. The strengthened verifier rejects a patched-local/old-deployment
WASM mismatch; a historical pass cannot validate the current candidate.

## Reproduce

The reference environment is Linux x86_64, Python 3.10 and Rust 1.94.1 with
`wasm32v1-none`. Install Python's venv support if your distribution packages it
separately. All Cargo commands use lockfiles; Python dependencies include wheel
hashes for this reference environment.

```sh
python3 -m venv /tmp/qasset-poc-env
/tmp/qasset-poc-env/bin/python -m pip install --require-hashes -r scripts/requirements-poc.lock
/tmp/qasset-poc-env/bin/python scripts/reproduce_poc.py
```

Use `--offline` after Cargo dependencies are cached. Add `--live` for read-only
Testnet receipt, code, authority and revision checks. Routine reproduction builds
the five contracts and two PoC tools, checks the reference Wasm hashes, runs the
Rust and Python tests and verifies the retained public research records and proof
transport fixture. It does not deploy, retire an issuer or generate new proofs.
The relation checker is local derivation, not a ZK proof or quantum attack.

The separate proof experiment is opt-in and can take several minutes and hundreds
of MB of local working memory. It uses only published test witnesses:

```sh
python3 scripts/check_seed_recovery_evidence.py
python3 scripts/run_seed_proof_research.py --relation sep5-root --rounds 8 --output-dir /tmp/qasset-seed-proof-public
```

The first run fetches exact pinned upstream Git dependencies; add `--offline`
after caching them. The runner builds its research binary and uses the fixture
signer built by local validation. The generated proof stays in the chosen `/tmp`
directory; the report records its hashes. See the evidence guide for verification
and interpretation. Routine validation lints the research tool and runs relation
checks; it does not regenerate the expensive proof experiment.

The following are deployment commands for a later testnet run after this audit is
accepted, not read-only audit commands. No new deployment was performed after the
cache flaw was found:

```sh
python3 scripts/testnet_demo.py --wasm-dir target/wasm32v1-none/release
cargo build --manifest-path tools/pq-demo/Cargo.toml --locked --release
python3 scripts/recovery_demo.py --signer tools/pq-demo/target/release/qasset-pq-demo-tool
```

For custom validation target directories, pass the corresponding `--wasm-dir` to
both network scripts and the built helper path to `--signer`. Each network script
writes its public receipt under `docs/`. Metadata `--finish-checks` is only for
resuming a recorded run whose declared QS4 setup already completed; it is not a
substitute for deployment or the initial scenario.

## Development scope

Verified authority adapters, supported-asset scanning, signed attestations and
the original legacy-seed ZK recovery backend remain development targets.
Production recovery requires a feasible quantum-sound proof system, measured
Soroban costs and a complete account lifecycle. Current functional evidence
does not establish production approval or an independent security audit.

The [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md)
and [reference review](docs/reference-review.json) describe the technical
boundaries, prior art and remaining work.

[Cryptographic and implementation audit](docs/SECURITY_REVIEW.md) records the reproduced finding, mitigation, evidence limitations and undeployed candidate status.

The [durable local recovery experiment](docs/DURABLE_RECOVERY_EVIDENCE.md)
extends the in-memory ceremony with real-proof process races, restart replay
rejection and atomic rollback. It remains an off-chain fixture model with
insecure proof parameters. [Further backend feasibility findings](docs/COMPACT_BACKEND_NEXT_GATE.md)
include exact lossless compression measurements and the next bounded ZK
backend comparator; compact Soroban recovery remains an open gate.

A [genuine Binius ZK leaf comparator](docs/BINIUS_RECOVERY_EVIDENCE.md) now
produces a 539,888-byte canonical-request proof and completes the local durable
handoff with real ML-DSA possession. Existing parameter tradeoffs reach
432,176 bytes, still above the recorded transaction cap. The unmodified Soroban-target graph
fails on standard-library dependencies; the newer verifier-only fork now runs
in raw Wasm as described below. Quantum knowledge security remains unapproved. These measured findings keep production seed
recovery a conditional research milestone.

## Verifier portability and transport follow-up

The verifier portability and staged transport follow-up is documented in [VERIFIER_PORT_EVIDENCE.md](docs/VERIFIER_PORT_EVIDENCE.md) and [PROOF_MAILBOX_EVIDENCE.md](docs/PROOF_MAILBOX_EVIDENCE.md). The unchanged ZK leaf proof now verifies in raw Wasm. A separate Soroban mailbox stores it as sealed unverified bytes. Neither component activates legacy-seed recovery; code size, complete host costs and independent quantum-security review remain unresolved.

## Compact verifier and actual host-cost follow-up

See [current recovery status](docs/RECOVERY_IMPLEMENTATION_STATUS.md) and [successor verifier evidence](docs/VERIFIER_NEXT_EVIDENCE.md). The unchanged proof now verifies in a raw module below the refreshed byte cap with lower memory. Generic point binding is tested separately. The actual SDK wrapper remains oversized and exhausts the 400M instruction budget; recovery remains disabled.
