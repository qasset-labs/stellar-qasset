# Future work register

Engineering backlog for the Q-Asset platform. Each item has an identifier used in
the [architecture](ARCHITECTURE.md), a priority, a status, dependencies, a
recommended approach, measurable acceptance criteria and source references. Items
with a security impact state it explicitly.

Baseline: repository commit `77d77c5` (2026-11-07). Contract, signer and Python
test suites pass at this baseline; see [development](DEVELOPMENT.md) for commands.

**Priorities:** High (blocks a core capability or carries security impact), Medium,
Low. **Statuses:** Planned, Research, Blocked, Deferred.

| Area | Identifiers |
| --- | --- |
| [Core architecture](#core-architecture) | FW-ARCH-01 – 05 |
| [Repository organization](#repository-organization) | FW-REPO-01 – 07 |
| [Smart contracts](#smart-contracts) | FW-SC-01 – 05 |
| [Authorization and policy management](#authorization-and-policy-management) | FW-AUTH-01 – 03 |
| [Post-quantum cryptography](#post-quantum-cryptography) | FW-PQC-01 – 07 |
| [Stellar and SAC integration](#stellar-and-sac-integration) | FW-STL-01 – 04 |
| [Smart accounts and treasury infrastructure](#smart-accounts-and-treasury-infrastructure) | FW-SAT-01 – 02 |
| [Security hardening](#security-hardening) | FW-SEC-01 – 04 |
| [Testing and verification](#testing-and-verification) | FW-TEST-01 – 03 |
| [Monitoring and observability](#monitoring-and-observability) | FW-MON-01 – 02 |
| [SDKs and APIs](#sdks-and-apis) | FW-SDK-01 – 02 |
| [Developer tooling](#developer-tooling) | FW-DEV-01 – 02 |
| [Deployment and operations](#deployment-and-operations) | FW-OPS-01 – 03 |
| [Performance and scalability](#performance-and-scalability) | FW-PERF-01 – 02 |
| [Documentation and maintenance](#documentation-and-maintenance) | FW-DOC-01 – 02 |
| [Research and unresolved decisions](#research-and-unresolved-decisions) | FW-RES-01 – 02 |
| [Optional extensions: recovery](#optional-extensions-recovery) | FW-OPT-01 – 06 |

## Core architecture

**FW-ARCH-01 — Classical-coalition engine.** Priority High. Status Planned.
Compute, per protected operation, the minimal sets of classical authorities that
satisfy its rule, and whether legacy Ed25519 signers alone still meet the
threshold. Dependencies: FW-ARCH-03, FW-STL-01. Approach: implement the bounded
branch-and-bound search in [architecture](ARCHITECTURE.md#classical-coalition-algorithm)
as a library used by the analyzer. Acceptance: results match a brute-force subset
oracle on at least 1,000 generated weighted policies including nested contract
nodes; exceeded ceilings return `UNCOVERED`. Security impact: core detection
capability; false negatives would hide classical paths.

**FW-ARCH-02 — Generic issuer and SAC adapters.** Priority High. Status Planned.
The analyzer is tied to two recorded fixtures (`scripts/qasset_authority_analyzer.py`).
Dependencies: FW-ARCH-03, FW-ARCH-04. Approach: adapters for any supported issuer
and SAC configuration with explicit unsupported cases. Acceptance: reference cases
for active and retired issuer authority, unknown administrator code, disabled
clawback, changed policy, incomplete receipts and provider disagreement all produce
the documented status.

**FW-ARCH-03 — Assessment schema version 3.** Priority High. Status Planned.
Add coalition results per operation, adapter versions, signer kinds and report
receipt references to the evidence schema (current v2). Dependencies: none.
Approach: new schema with a verifier that also accepts v2 bodies for history.
Acceptance: v2 evidence still verifies; v3 round-trips with canonical hashing.

**FW-ARCH-04 — Network configuration manifest.** Priority Medium. Status Planned.
Endpoints and passphrase are embedded in several scripts (`scripts/qasset_poc_testnet.py:28`,
`scripts/verify_qasset_evidence.py:28`, `scripts/testnet_demo.py:22`). Approach:
a manifest with passphrase, network ID, generation, endpoints, protocol range,
contract IDs and code hashes, compared with live state before signing.
Acceptance: no endpoint constants outside the manifest loader; a mismatched
generation halts.

**FW-ARCH-05 — Trust model for on-chain classic-state verification.** Priority
Medium. Status Research. Verified registry gates stay disabled because contracts
cannot verify classic issuer state ([ADR-001](DECISIONS.md#adr-001-declarations-remain-separate-from-verified-authority)).
Approach: evaluate signed attestations, oracle designs and any future protocol
support. Acceptance: a reviewed decision record with threat model.

## Repository organization

**FW-REPO-01 — Repository license.** Priority High. Status Blocked (rights
holders' decision). No repository-wide license is published
([license scope](LICENSE_SCOPE.md)). Acceptance: an authorized license decision and
a root `LICENSE` consistent with component licenses.

**FW-REPO-02 — Physical separation of core, legacy and research code.** Priority
Medium. Status Deferred. `scripts/` and `tools/` mix core, legacy and research
components (now classified in their README files). Moving core files breaks
evidence verification because assessments pin tool source paths and hashes.
Dependencies: FW-ARCH-03. Approach: move with a new schema version that records new
paths, keeping archived inputs for historical evidence. Acceptance: v2 evidence
verifies offline after the move; new layout documented.

**FW-REPO-03 — Deduplicate vendored binius64.** Priority Low. Status Deferred.
`tools/binius-verifier-port/vendor/` and `tools/binius-verifier-next/vendor/` each
hold a 3.3 MB copy differing in four files. Approach: one pinned vendor tree with
per-tool patches. Acceptance: both research tools rebuild and reproduce recorded
outputs.

**FW-REPO-04 — Separate research records from documentation.** Priority Low.
Status Deferred. `docs/` holds 41 JSON research records plus logs and a patch next
to design documents. Approach: move to a research-evidence directory with updated
references in the check scripts. Acceptance: all check scripts and links pass.

**FW-REPO-05 — Treatment of two historical records.** Priority Low. Status
Deferred (owner decision). `docs/compact-loader-review/sdk-api-review.json` and
`docs/reference-review.json` contain authorship and program notes that do not fit
current documentation conventions. They are retained unchanged as historical
records. Acceptance: an owner decision to keep, annotate or supersede them without
breaking any hash or script reference.

**FW-REPO-06 — Dependency inventory and advisory scanning.** Priority Medium.
Status Planned. `docs/dependency-audit.json` is an October snapshot. Approach:
generate per-distributable inventories and scan every lockfile in CI. Acceptance:
scheduled scan covering root, tool and Python locks with recorded database
revision.

**FW-REPO-07 — Repository protections.** Priority Medium. Status Blocked
(repository administrators). Branch protection, required CI, tag protection,
release signing and private vulnerability reporting are not configured
([governance](../GOVERNANCE.md)). Acceptance: settings verified and documented.

## Smart contracts

**FW-SC-01 — Registry version 2.** Priority High. Status Planned. Current registry
keeps an unconditional setter, transfers tenancy without an expected revision and
cannot rotate its registrar (`contracts/qasset-registry/src/lib.rs`). Approach: new
deployment requiring expected revisions on every mutation, registrar rotation by a
multisignature account, issuer-consented identity linking and bounded report
receipts. Acceptance: tests for competing writes, unauthorized mutation, stale
publication and archival restoration preserving revisions. Security impact:
removes lost-update paths in shared policy state.

**FW-SC-02 — Registry TTL retention on reads.** Priority Low. Status Planned.
`get_role_quorum`, `list_weak_paths` and `declared_security_level` do not extend
role TTL. Approach: rely on `keep_alive` and a keeper, or extend in version 2.
Acceptance: keeper test shows no role entry archives while its tenant is live.

**FW-SC-03 — Production ML-DSA controller.** Priority High. Status Planned. The
prototype administrator accepts one operation and one key and cannot hand over,
rotate or migrate ([ADR-008](DECISIONS.md#adr-008-production-controllers-support-guarded-handover-and-address-bound-credentials)).
Approach: allowlist of (contract, function, argument constraints), key quorum,
per-operation rule, guarded `set_admin` handover with distinct context and
timelock, rotation with proof of possession, address-bound credentials only.
Acceptance: adversarial tests for every rejected context, rotation and handover
rehearsals on Testnet, cached-authorization tests, measured costs. Security impact:
removes key-loss lock-in and enables CAP-87 migration.

**FW-SC-04 — Registry doc-comment correction.** Priority Low. Status Deferred. The
`WeakPathReason::ThresholdMeetableClassically` doc comment
(`contracts/qasset-registry/src/lib.rs:160-161`) contains a broken sentence.
Doc comments on contract types are part of the contract specification, so the fix
changes the reference Wasm hash. Approach: bundle with FW-SC-01. Acceptance: fixed
in the next registry version.

**FW-SC-05 — Property and fuzz tests.** Priority Medium. Status Planned. Approach:
property tests for registry validation (weights, thresholds, duplicates,
revisions) and fuzzing of controller context and signature parsing. Acceptance:
tests run in CI with a fixed seed corpus.

## Authorization and policy management

**FW-AUTH-01 — Hybrid per-operation rules.** Priority Medium. Status Planned.
Approach: controller rules that require post-quantum approval alone, or classical
**and** post-quantum approval, recorded per operation and evaluated by the
coalition engine. Acceptance: tests show a classical-or-PQ rule is reported as a
classical path. Security impact: prevents hybrid rules that keep a classical route.

**FW-AUTH-02 — Guarded policy editing in clients.** Priority Medium. Status
Planned. Approach: SDK and application read the current revision and always use
revision-checked writes. Acceptance: mixed-client concurrency tests.

**FW-AUTH-03 — Treasury intent execution.** Priority Medium. Status Planned.
Approach: intents binding network, controller, token, operation, destination,
amount, epoch, nonce and expiry, with on-chain nonce consumption (Part II §6 of the
architecture). Acceptance: duplicate and stale-epoch execution rejected. Depends on
FW-SC-03.

## Post-quantum cryptography

**FW-PQC-01 — External review of the ML-DSA integration.** Priority High. Status
Planned. RustCrypto `ml-dsa` 0.1.1 and its contract integration are unaudited.
Acceptance: independent review report with findings resolved. Security impact:
signature verification correctness is the basis of enforcement.

**FW-PQC-02 — Hedged signing.** Priority Medium. Status Planned. The signer uses
deterministic signing (`tools/qasset-sac-signer/src/main.rs:155`). Approach: FIPS 204
hedged signing for production; deterministic only for test vectors. Acceptance:
production signer uses hedged mode; vector tests still deterministic.

**FW-PQC-03 — Second ML-DSA implementation for evidence.** Priority Medium. Status
Planned. `tools/qasset-evidence-crypto` uses the same crate as the contract, so a
library defect would pass both. Acceptance: evidence credentials verified by an
independent implementation in CI.

**FW-PQC-04 — CAP-87 host verification.** Priority Medium. Status Blocked
(Protocol 30 activation). CAP-87 offers pure ML-DSA with a context string, so keys,
messages and contexts carry over. Host verification traps on failure, while the
verifier pins `Contract, #3` (`scripts/verify_qasset_evidence.py:35`). Approach:
production controller version with CAP-87 back end and versioned negative
expectations. Acceptance: same vectors and negative tests pass on the host back end;
measured cost recorded. Depends on FW-SC-03.

**FW-PQC-05 — Parameter evaluation.** Priority Low. Status Research. Compare
ML-DSA-44 and ML-DSA-65 for controllers given the SHA-256 digest bound
([ADR-007](DECISIONS.md#adr-007-ml-dsa-parameters-signing-and-test-vectors)).
Acceptance: decision record with measured transaction size and cost.

**FW-PQC-06 — Vector coverage for every verification path.** Priority Medium.
Status Planned. Wycheproof and ACVP vectors now run against the administrator
(`contracts/qasset-sac-admin/tests/ml_dsa_vectors.rs`). Acceptance: every new
verification path, including CAP-87, runs the same vectors.

**FW-PQC-07 — Address-bound credentials.** Priority High. Status Planned. The
prototype runner builds legacy address credentials whose preimage omits the
authorizer address (CAP-71-02). Approach: `SOROBAN_CREDENTIALS_ADDRESS_V2` in
signers and runners; separate keys per controller. Acceptance: negative tests for
wrong authorizer and reused keys. Security impact: removes cross-account replay
where a key is shared.

## Stellar and SAC integration

**FW-STL-01 — Issuer authority classification defect.** Priority Medium. Status
Planned. Confirmed defect. The analyzer and verifier count only
`ed25519_public_key` signers against the medium threshold
(`scripts/qasset_authority_analyzer.py:125-126`,
`scripts/verify_qasset_evidence.py:417-418`). Signed-payload, pre-authorized
transaction and hash(x) signers are ignored, and `SetTrustLineFlags` is governed by
the low threshold. An issuer can be reported `UNCOVERED` instead of `EXPOSED`; the
duplicated logic means the verifier cannot catch it. Approach: classify all signer
kinds and evaluate each operation against its threshold; regenerate the assessment
with read-only queries. Fixing changes pinned tool hashes, so it ships with a new
assessment. Acceptance: regression tests for each signer kind and threshold.
Security impact: false reassurance about issuer authority.

**FW-STL-02 — Protocol 30 compatibility.** Priority Medium. Status Planned. CAP-84
muxed contract destinations and CAP-88 ledger changes require updated decoders; the
Testnet vote outcome is unconfirmed as of 2026-11-07. Acceptance: decoders and SDK
qualified against the activated protocol.

**FW-STL-03 — Network generations and production manifests.** Priority Medium.
Status Planned. Approach: generation identifiers and anchors per network; halt on
reset or mismatch. Depends on FW-ARCH-04. Acceptance: reset rehearsal invalidates
cached assessments.

**FW-STL-04 — Clawback and trustline-flag coverage.** Priority Medium. Status
Planned. `sac.clawback` is uncovered and no post-lock `SetTrustLineFlags` probe was
run. Acceptance: reference assets with clawback enabled and post-lock flag probes.

## Smart accounts and treasury infrastructure

**FW-SAT-01 — Smart-account adapter specification.** Priority Medium. Status
Research. Approach: define the adapter interface (code-hash pinning, rule
extraction, unsupported cases) against common Stellar smart-account frameworks.
Acceptance: specification and one adapter with hostile-configuration tests.

**FW-SAT-02 — Treasury authority models.** Priority Medium. Status Research.
Treasury integration is unspecified. Approach: model concrete treasury
architectures (allowances, offers, sponsorship, custody overrides) before adapters.
Acceptance: documented models and coverage rules.

## Security hardening

**FW-SEC-01 — No blind signing.** Priority Medium. Status Planned. The signer signs a
supplied digest. Approach: decode and display the invocation, recompute the
preimage, then sign. Acceptance: signer refuses digests it cannot reconstruct.
Security impact: prevents approval of unintended invocations.

**FW-SEC-02 — Custody for operator keys.** Priority Medium. Status Planned. Seeds are
stored as 0600 files outside the repository. Approach: KMS or HSM integration with
ML-DSA support. Acceptance: no plaintext seed on signer hosts.

**FW-SEC-03 — Signed attestations.** Priority Medium. Status Planned. Evidence is
hashed but not signed. Approach: attestations binding evidence hash, tool versions,
network, ledger range, scope and expiry, with an approved key and revocation policy.
Acceptance: verifier checks attestation signatures and expiry.

**FW-SEC-04 — Threat model for production components.** Priority Medium. Status
Planned. Approach: extend the threat models to the controller, services and keeper.
Acceptance: reviewed threat model linked from the architecture.

## Testing and verification

**FW-TEST-01 — Hosted CI confirmation.** Priority Medium. Status Planned. A CI
workflow is defined in `.github/workflows/ci.yml` and its commands pass locally; a
first hosted run has not been observed. Acceptance: green run on the default branch
and required checks enabled (FW-REPO-07).

**FW-TEST-02 — Coalition oracle tests.** Priority High. Status Planned. Part of
FW-ARCH-01. Acceptance: oracle comparison in CI.

**FW-TEST-03 — Scheduled read-only live verification.** Priority Low. Status
Planned. Approach: periodic `verify_qasset_evidence.py` live run with results
archived. Acceptance: stale or inconclusive results raise an alert.

## Monitoring and observability

**FW-MON-01 — Ingestion and drift detection.** Priority High. Status Planned.
Approach: ingest ledger data, detect changes to tracked authority, mark results stale
and reassess ([ADR-003](DECISIONS.md#adr-003-production-monitoring-requires-durable-indexing)).
Acceptance: drift drills for signer, administrator, code-hash and policy changes.

**FW-MON-02 — Alerts and freshness API.** Priority Medium. Status Planned.
Acceptance: every API response carries freshness state; alerts fire within an agreed
latency.

## SDKs and APIs

**FW-SDK-01 — TypeScript SDK.** Priority High. Status Planned. Modules and errors are
specified in [clients and services](CLIENTS_AND_SERVICES.md). Acceptance: packaged
SDK with bindings generated from pinned Wasm and examples run against the package.

**FW-SDK-02 — Read API.** Priority Medium. Status Planned. Acceptance: versioned
endpoints with ledger watermarks and freshness, as specified.

## Developer tooling

**FW-DEV-01 — Shared network configuration in scripts.** Priority Medium. Status
Deferred. Endpoint constants are duplicated across scripts. Changing the analyzer or
verifier changes pinned tool hashes, so this ships with FW-ARCH-03. Acceptance:
single configuration module used by all scripts.

**FW-DEV-02 — Python dependency files.** Priority Low. Status Planned.
`scripts/requirements-poc.lock` (hashed, reference), `requirements-testnet.txt` and
`requirements-crypto-demo.txt` overlap. Acceptance: documented purpose for each, or a
single lock per environment.

## Deployment and operations

**FW-OPS-01 — TTL keeper.** Priority Medium. Status Planned. Acceptance: no tracked
entry archives in a soak test; restoration preserves administrators and revisions.

**FW-OPS-02 — Release manifests and artifacts.** Priority Medium. Status Planned.
Acceptance: signed manifest with source, Wasm hashes, ABI and network
configuration, checked before deployment ([operations](OPERATIONS.md)).

**FW-OPS-03 — Accountable owners.** Priority Medium. Status Blocked (appointment).
Owners for contracts, services, operations and releases are unassigned
([governance](../GOVERNANCE.md)).

## Performance and scalability

**FW-PERF-01 — Controller cost per operation.** Priority Medium. Status Planned.
In-Wasm ML-DSA-65 costs about 102.5 million instructions per authorized call.
Acceptance: measured costs per allowlisted operation, quorum size and back end.

**FW-PERF-02 — Coalition search bounds.** Priority Low. Status Planned. Acceptance:
benchmarks for worst-case signer counts and nested nodes within agreed ceilings.

## Documentation and maintenance

**FW-DOC-01 — Historical counts in earlier reports.** Priority Low. Status Planned.
Some historical review passes cite earlier counts (for example 30 paths and 88 tests
in [PoC security findings](POC_SECURITY_FINDINGS.md)). Acceptance: each historical
figure is labelled with its phase.

**FW-DOC-02 — README and architecture overlap.** Priority Low. Status Planned.
Acceptance: README keeps an introduction and links; detailed design lives in the
architecture.

## Research and unresolved decisions

**FW-RES-01 — Wallet and custody ML-DSA capabilities.** Priority Medium. Status
Research. Acceptance: compatibility matrix of supported wallets and custody
services.

**FW-RES-02 — Service model and hosting.** Priority Low. Status Research. Hosting,
history retention and service objectives are undecided ([maintenance](MAINTENANCE.md)).
Acceptance: decision records for each.

## Optional extensions: recovery

Recovery is an optional extension; none of these items blocks core capabilities.

**FW-OPT-01 — Redeploy the patched recovery counter.** Priority Low. Status
Deferred. Testnet receipts describe the pre-fix version; the cached-authorization
fix is local only (`contracts/pq-recovery-demo`). Acceptance: fresh deployment and
receipts for the patched code.

**FW-OPT-02 — Counter lifecycle.** Priority Low. Status Research. The counter has no
TTL extension and the backup key replaces the active key without delay or veto.
Acceptance: design with timelock, cancellation and TTL maintenance, if the extension
proceeds.

**FW-OPT-03 — Seed-proof verifier feasibility.** Priority Low. Status Research. A
539,888-byte proof verifies in a 127,068-byte raw Wasm module, but the SDK wrapper
(183,090 bytes) exceeds the code limit and the 400 million instruction budget;
94–97% of cost sits in one step ([evidence](VERIFIER_NEXT_EVIDENCE.md)).
Acceptance: a complete verifier within network limits.

**FW-OPT-04 — Quantum soundness and privacy review.** Priority Low. Status Research.
Open gates A-01 and F-01 ([Binius review scope](BINIUS_A01_REVIEW_SCOPE.md)).
Acceptance: independent review of the selected proof system and parameters.

**FW-OPT-05 — Lattice relation wiring.** Priority Low. Status Research. Wiring a
SEP-5 hash-preimage relation through RoKoko is scoped but not attempted
([scope](ROKOKO_RELATION_WIRING_SCOPE.md)). Acceptance: relation with soundness tests.

**FW-OPT-06 — Proof transport consumer.** Priority Low. Status Research. The mailbox
stores unverified bytes and has no verifier consumer
([evidence](PROOF_MAILBOX_EVIDENCE.md)). Acceptance: atomic verification and
consumption design, if a verifier becomes feasible.
