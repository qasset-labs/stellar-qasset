# Maintenance and production responsibility matrix

Status: maintenance policy, 2026-11-05; revised 2026-11-15. This is the project's
primary open-source maintenance policy. No person or organization is appointed
by it. The project has no supported production service or SLA. Each production
deployment must name an accountable owner and backup, accepted objectives,
operational funding and verified controls before the affected capability
launches. See [governance](../GOVERNANCE.md), [operations](OPERATIONS.md),
[security policy](../SECURITY.md) and [license scope](LICENSE_SCOPE.md).

**Policy versus operation.** Sections below are policy unless this table says a
mechanism is operational. Repository settings were checked on 2026-11-15.

| Mechanism | Status today |
| --- | --- |
| CI: formatting, Clippy with warnings denied, contract/signer/Python tests, reference Wasm hashes, offline evidence verification | Operational: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) on pushes to `main` and pull requests |
| Branch protection, required checks, tag protection | Not verified (`FW-REPO-07`) |
| GitHub private vulnerability reporting | Disabled (`FW-REPO-07`) |
| Scheduled dependency advisory scanning and update alerts | Not configured (`FW-REPO-06`, `FW-REPO-08`) |
| Release tags, signed artifacts, published packages | None |
| Hosted API, monitoring, storage keeper | None |

## Responsibility matrix

| Component | Required accountable role | Proposed cadence / trigger | Evidence required |
| --- | --- | --- | --- |
| Contracts and authorization | Contract/security owner | Every code/policy change; each protocol upgrade; quarterly boundary review | ABI/hash inventory, real auth/cache/rollback tests, independent review disposition |
| Cryptographic dependencies | Security owner | Weekly advisory triage; every version change and activation | Exact pins/vectors, upstream status, hostile-input/cost checks; specialist review where needed |
| Smart-account dependencies (planned) | Contract/security owner | Every upstream release and advisory; every pin change | Pinned version, advisory disposition, digest-format and route-coverage tests |
| Authority analyzer and coalition engine | Assessment owner | Every adapter, signer-kind or algorithm change | Reference configurations, oracle comparison, unchanged results for unchanged inputs |
| Evidence schemas and verifier | Assessment owner | Every schema/tool change | Historical bundles still verify; tamper regressions; version and source-hash pins |
| Recovery research | Research/security owner | Each relation/parameter/fork change; quarterly gate review | Separate source/proof/resource evidence; no production activation by elapsed time |
| SDK and bindings | Client owner | Each contract/protocol/underlying SDK release | Generated-spec diff, packed consumer examples, amount/error/credential tests |
| dApp and wallets | Client owner | Each UI/wallet change; monthly compatibility/accessibility review | Supported capability matrix, display/sign/reconnect tests, bundle inventory |
| Ingestion/API/database | Service owner | Continuous health/gaps; daily reconciliation; every schema/decoder change | Common watermark, replay equality, schema migration and unknown-event behavior |
| RPC/Horizon/history | Operations owner | Continuous tip/retention checks; before protocol/reset events | Provider capabilities, archive coverage, source disagreement handling |
| TTL and dependency retention | Operations owner | Ledger schedule derived from TTL margin; on dependency change | Complete inventory, extension/restore confirmation, job/funding caps |
| Relay/signers | Custody/operations owner | Continuous budget/status; each policy/custody change | Isolation/allowlists, sequence journal, signed intent and outcome reconciliation |
| Dependencies/supply chain | Release/security owner | Weekly advisories; monthly updates; every release | All lockfiles, current SBOM/licenses/checksums, reviewed patches |
| Backups and recovery | Operations owner | Continuous backups as configured; quarterly drills and material changes | Measured RPO/RTO, immutable artifact restore and ledger replay |
| Releases and artifact mirrors | Release owner | Every candidate; monthly mirror-integrity check | Clean builds, independent byte comparison, inventories/provenance/approvals |
| Governance/docs/security routing | Steward/security owner | Quarterly and on role/contact/support change | Actual role appointments and tested hosting/reporting controls |

The cadences are proposed defaults for a future service; network cadence,
operational risk and evidence may require tighter intervals. A daily read does
not replace TTL jobs scheduled against ledger margins. Administrative transfer
and issuer retirement are never unattended maintenance tasks. Source maintenance
(this repository) and operation of deployed infrastructure are separate
responsibilities: a merged fix does not change an immutable deployed contract or
a running service.

## Supported versions and compatibility

Current reproducibility pins: Rust 1.94.1, Soroban SDK 25.3.2/host 25.2.2/XDR 25.0.0,
Python 3.10 with `stellar-sdk` 14.0.0, `ml-dsa` 0.1.1, schema-v2/tool 2.0.0 evidence.
Research crates have independent pinned graphs. These specify historical/reference
execution, not full compatibility with the network's latest protocol.

| Network (checked 2026-11-15, read-only) | Protocol | Consequence |
| --- | --- | --- |
| Testnet | 30 | CAP-87 ML-DSA host functions available; recorded PoC evidence used protocol 29 |
| Mainnet | 29 | CAP-87 unavailable; vote scheduled 2026-11-23; re-check before relying on it |

Rules:

* **No automatic upgrades.** Soroban SDK, Stellar CLI, XDR, JavaScript and Python
  SDK, `ml-dsa` and smart-account versions change only through a reviewed change
  with a versioned build and evidence comparison. Workspace `soroban-sdk = "25"`
  is a range; `Cargo.lock` defines the build.
* **Protocol upgrades** require updated decoders (CAP-84 muxed contract
  addresses, CAP-88 metadata), re-qualified credential variants, fresh limits and a
  new evidence run on the upgraded network before live checks are trusted.
* **Authorization interfaces** (custom-account `__check_auth`, credential
  variants, smart-account digest formats) are compatibility surfaces: a change is
  breaking for signers, SDK and evidence even when contract ABI shapes match.

A future support matrix must bind SDK major version to accepted contract hashes/
ABI, service/evidence schema, underlying Stellar SDK and protocol/credential
variants, supported OS/browser/wallet versions and deployment generation.
Unknown combinations reject writes and label read limitations. Keep a documented
previous client line only where it remains safe with current deployed state;
never promise support for superseded insecure auth code.

## Cryptographic security maintenance

* **Pins.** `ml-dsa` is pinned exactly (`=0.1.1`) in the SAC administrator, signer
  and evidence helper; a version change is a security-sensitive change.
* **FIPS 204 conformance.** Every verification path runs Wycheproof and ACVP
  vectors, including malformed keys, signatures and hints
  (`contracts/qasset-sac-admin/tests/ml_dsa_vectors.rs`); a new path (CAP-87) must
  pass the same vectors before use (`FW-PQC-06`).
* **Independent verification.** Evidence credentials must also verify under a
  second implementation; the current helper shares the contract's crate
  (`FW-PQC-03`).
* **Signer keys.** Keys are created outside the repository with restrictive file
  permissions; deterministic signing is limited to test vectors; production
  signers use hedged signing and display the decoded invocation (`FW-PQC-02`,
  `FW-SEC-01`). Never commit seeds; `*.seed` is ignored.
* **Advisories.** Triage RustSec, GitHub advisories and FIPS 204 errata for
  `ml-dsa`, `sha2`, `soroban-sdk` and the Python cryptography stack; record the
  disposition even when not affected.
* **Regression.** Any cryptographic change reruns contract, vector and evidence
  suites and records measured cost.

## Smart-account maintenance

Applies to the planned OpenZeppelin integration
([ADR-009](DECISIONS.md#adr-009-compose-production-controllers-from-openzeppelin-smart-accounts));
no such dependency exists today.

* Pin an exact patched `stellar-accounts` version: at least `0.7.3` or `0.8.0`
  because of advisory GHSA-jpg9-m7w4-c7wc (delegated signers authorizing without
  keys).
* Treat the `v0.8.0` digest (`AuthDigestPreimage` binding account, payload and
  context-rule IDs) as a pinned compatibility surface for signers, SDK and
  evidence.
* On every upstream release: read breaking changes and advisories, rerun
  route-coverage, management-quorum, handover and cached-authorization tests, and
  record the disposition.
* Deployed smart accounts, verifiers and policies are versioned instances; a new
  upstream release never changes a deployed instance. Publish which deployed
  generations an advisory affects.

## Evidence and assessment maintenance

A software update must not silently change an existing security conclusion.

* Evidence carries schema version, tool version and pinned tool-source hashes;
  the verifier refuses moved or modified core scripts.
* Re-running a newer tool on old inputs produces a new versioned assessment; it
  never rewrites a published one. Historical bundles remain verifiable with their
  recorded tool versions.
* Any change to adapters, signer-kind handling, coalition search or status rules
  requires regression fixtures showing which results change and why, and a
  changelog entry stating affected assets and paths.
* Schema changes keep the previous schema verifiable (v2 bundles must keep
  verifying when v3 ships).

## SDK and API compatibility

Public interface/schema breaking changes require a new major compatibility line
or explicit versioned endpoint and migration guide. Private storage or verifier
changes still require deployment/migration review even if the API shape matches.
Generated contract clients are bound to the Wasm hashes they were generated from.
Deprecation should include replacement, exact affected versions/generations,
effective date, exit/restore steps and evidence retention. No fixed support term
or notice period is promised until owners can resource it. Security incidents
may require immediate suspension with a factual advisory.

## Release engineering

Policy for any release (none exists yet; see [operations](OPERATIONS.md)):

* Reproducible Wasm from a clean export with locked dependencies; CI already
  checks the two reference hashes, with a build-path dependency for the SAC
  administrator (`FW-DEV-03`).
* Annotated Git tag per release; release manifest with network, contract IDs,
  Wasm hashes, interfaces and dependency versions (`FW-OPS-02`).
* Build attestations (SEP-55 workflow) and, for npm packages, registry
  provenance; checksums alone are not signatures.
* Deployment uses a dedicated deployer key, compares live constructor state and
  code with the manifest before any administrative handover, and never runs from
  a developer workstation default identity.

## Dependency and supply-chain maintenance

* Every build uses `--locked`; the root `Cargo.lock`, each independent tool lock
  and the hashed Python lock (`scripts/requirements-poc.lock`) are all in scope.
* Scan all lockfiles on a schedule with a recorded advisory-database revision
  (`FW-REPO-06`); `docs/dependency-audit.json` is an October snapshot only.
* GitHub Actions are pinned by major tag (`actions/checkout@v4`,
  `actions/setup-python@v5`); pinning by commit SHA and update alerts are planned
  (`FW-REPO-08`). The workflow requests read-only `contents` permission.
* License obligations follow [license scope](LICENSE_SCOPE.md); an unresolved
  license is a release blocker for the affected artifact.

## Contribution practices

[Contributing](../CONTRIBUTING.md) defines setup, review and validation. Changes to
authorization, cryptography, evidence semantics or storage need adversarial tests
and a [decision record](DECISIONS.md); security-sensitive changes need a reviewer
other than the author. Documentation must keep implemented, prototype, planned
and research status explicit.

## Security reporting and incidents

[Security policy](../SECURITY.md) defines reporting. Incident classes specific to
Q-Asset, each requiring an advisory that names affected versions, deployed
generations and evidence:

* an assessment reported a favorable status for an exposed or unsupported path;
* a post-quantum authorization path accepted an invalid, replayed or
  out-of-scope credential;
* the evidence verifier accepted a tampered or stale bundle;
* an upstream advisory (smart accounts, `ml-dsa`, Soroban) affects a deployed
  generation.

Affected published assessments are marked superseded, never deleted.

## Operational maintenance

Applies only once services are deployed. Monitoring, ledger availability,
storage keepers, evidence archives, drift detection and database restore follow
[operations](OPERATIONS.md) and the matrix above.

### Funding, objectives and succession gates

Each owner must accept measurable service/freshness/recovery objectives and an
operating budget. Track maintenance XLM runway, hosting/history costs and custody
recovery costs separately; there is no protocol yield to fund them. Network fees,
Soroban resource fees and storage extension or restoration fees are recurring
operating costs. Set RTO below the shortest TTL/funding/retention margin and RPO
within recoverable archive/journal loss. Published release evidence needs
zero-loss retention with tested mirrors. Actual numeric availability, latency,
archive duration and incident response objectives remain open decisions requiring
infrastructure/load/drill evidence.

Transfer operational ownership only after the successor verifies manifests,
credentials, dashboards, archive/backup restore, signer constraints, funding and
release verification. Revoke outgoing access under authenticated governance;
never transfer a customer signing secret through a public issue. Unfilled roles
or absent recovery coverage block production launch; documentation is not staffing.

## Deprecation and retirement

Retirement closes new enrollment and distribution claims, communicates last
supported versions and exits, reconciles pending operations, funds any promised
restore/exit interval, then revokes unused service credentials. Do not delete
immutable history, license notices or verification artifacts. On-chain immutable
contracts can remain callable indefinitely; document key/TTL dependencies and
unavailable migrations even after the hosted UI is retired.

* **SDK deprecation:** announce the replacement major line, keep the last
  release installable and state which deployed generations it supports.
* **Contract replacement and authorization migration:** move SAC administration
  only through the guarded handover of a controller that supports it; the PoC
  administrator cannot migrate.
* **Evidence preservation:** retired assessments stay verifiable and are labelled
  historical.
* **Monitoring retirement:** stop presenting freshness for untracked assets;
  never leave a last-known status displayed as current.
