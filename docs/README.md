# Documentation index

Each document has one responsibility. Start with the
[project README](../README.md), then the [architecture](ARCHITECTURE.md).

## System design

| Document | Responsibility |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | The complete Q-Asset platform: components, data, workflows, security, cryptography, integration, deployment and implementation maturity |
| [Decisions](DECISIONS.md) | Architecture decision records |
| [Future work](FUTURE_WORK.md) | Engineering backlog with priorities, statuses and acceptance criteria |

## Specifications

| Document | Responsibility |
| --- | --- |
| [Contracts](CONTRACTS.md) | Implemented contract interfaces, storage, events, errors and evidence schema |
| [Clients and services](CLIENTS_AND_SERVICES.md) | Planned SDK, API, indexer and transaction state machine |
| [Operations](OPERATIONS.md) | Planned build, release, deployment, TTL and incident procedures |
| [Maintenance](MAINTENANCE.md) | Planned ownership and support responsibilities |
| [License scope](LICENSE_SCOPE.md) | Component licenses and third-party notices |

## Development

| Document | Responsibility |
| --- | --- |
| [Development](DEVELOPMENT.md) | Setup, build, test, lint, evidence verification and reproduction |
| [Reviewer guide](REVIEWER_GUIDE.md) | How to inspect and reproduce the proof of concept |

## Security

| Document | Responsibility |
| --- | --- |
| [Security policy](../SECURITY.md) | Vulnerability reporting and supported scope |
| [Threat model](THREAT_MODEL.md) | Threats and controls for the prototype contracts |
| [PoC threat model](POC_THREAT_MODEL.md) | Threats for the SAC authority demonstration |
| [PoC security findings](POC_SECURITY_FINDINGS.md) | Findings and remediation for the demonstration |
| [Security review](SECURITY_REVIEW.md) and [cryptographic review](CRYPTOGRAPHIC_REVIEW.md) | Internal reviews of contracts, cryptography and research |
| [Architecture review](ARCHITECTURE_REVIEW.md) | Documentation and architecture review findings |

## Proof of concept

| Document | Responsibility |
| --- | --- |
| [PoC evidence](QASSET_POC_EVIDENCE.md) | Evidence and reproduction for the SAC authority demonstration |
| [PoC architecture](POC_ARCHITECTURE.md) | How the demonstration is wired |
| [PoC test report](POC_TEST_REPORT.md) | Recorded test and Testnet results |
| [PoC baseline](POC_BASELINE.md) and [handoff](POC_HANDOFF.md) | Baseline and status history |
| [PoC cryptography summary](POC_CRYPTO_RESEARCH_SUMMARY.md) | Cryptographic background for the demonstration |

## Optional extension: recovery research

Recovery is optional and not required by the core platform.
[Recovery status](RECOVERY_IMPLEMENTATION_STATUS.md) is the entry point; supporting
documents cover the [recovery prototype](RECOVERY_POC.md), [evidence](RECOVERY_EVIDENCE.md),
[security argument](RECOVERY_SECURITY_ARGUMENT.md),
[durable state](DURABLE_RECOVERY_EVIDENCE.md), [scalar experiments](SCALAR_RECOVERY_EVIDENCE.md)
and [review](SCALAR_RECOVERY_REVIEW.md), [proof transport](PROOF_MAILBOX_EVIDENCE.md),
Binius [evidence](BINIUS_RECOVERY_EVIDENCE.md), [review](BINIUS_SECURITY_REVIEW.md) and
[open questions](BINIUS_A01_REVIEW_SCOPE.md), verifier [port](VERIFIER_PORT_EVIDENCE.md)
and [successor](VERIFIER_NEXT_EVIDENCE.md), compact backends
([review](COMPACT_BACKEND_REVIEW.md), [next gate](COMPACT_BACKEND_NEXT_GATE.md),
[lattice gate](COMPACT_BACKEND_LATTICE_GATE.md)) and RoKoko
([relation scope](ROKOKO_RELATION_WIRING_SCOPE.md), [hiding review](ROKOKO_ZK_HIDING_REVIEW_SCOPE.md)).

## Research records

JSON files in this directory are machine-readable research and validation records
produced by the scripts in `scripts/`. Several are inputs to the check scripts, so
they keep their current paths (`FW-REPO-04`).
