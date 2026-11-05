# Operations, release and recovery specification

Baseline: 2026-11-05. Local reproduction commands exist; production hosting,
automation, signers, alerts and on-call coverage do not. Procedures below are
requirements for an operated deployment, not evidence that it exists.
[Governance](../GOVERNANCE.md) assigns decision roles only after actual appointment;
[maintenance](MAINTENANCE.md) records outstanding responsibilities.

## Build and distributable contents

Current reference: Linux x86_64, Rust 1.94.1, `wasm32v1-none`, Python3.10,
`requirements-poc.lock`, root and individual-tool Cargo lockfiles. Locked
reproduction is not hermetic: host/linker/environment and cached dependency
availability still matter. `scripts/reproduce_poc.py` writes a new report outside
the repository and does not submit transactions. `scripts/validate.py` is a wider
research runner that overwrites `docs/validation.json`; do not run it merely to
refresh a historical status. Read each runner's scope first.

```sh
RUSTUP_TOOLCHAIN=1.94.1 python3 scripts/reproduce_poc.py --offline \
  --report /tmp/qasset-release-reproduction.json
```

`--offline` requires prepopulated verified Cargo dependencies; it does not remove
Python environment requirements. Provision an isolated Python environment with
`pip install --require-hashes -r scripts/requirements-poc.lock` as described in
[reproduction](QASSET_POC_EVIDENCE.md). Do not float versions to get a hash match.
A build mismatch is a release failure requiring diagnosis and new provenance.

Target release products:

| Product | Include | Exclude |
| --- | --- | --- |
| Source archive | Tracked first-party sources/docs, lockfiles, exact vendored inputs/patches/pins, required public fixtures and every applicable license/notice | Untracked local drafts, `.git`, caches, generated `target`, identities, secrets |
| Contract bundle | Exact reviewed Wasm, extracted ABI/spec, hashes/sizes, constructor/configuration manifest, reproduction recipe and legal notices | Public-fixture credentials represented as production keys |
| Native tools | Source/build provenance, supported OS/architecture, binary hashes, usage and applicable notices | Embedded build machine paths represented as portable runtime assumptions |
| Future SDK | Explicit exports/types, runtime dependencies/lock, generated bindings, examples, notices | Source-only aliases, private logs, proving assets and secret-file tools in browser exports |
| Evidence bundle | Raw public XDR/receipts/inputs, hash map, schemas, verifier source/version and coverage limits | Claims that omitted expensive artifacts were reverified |

The signer currently embeds `CARGO_MANIFEST_DIR` to locate the build repository
and enforce its external-key boundary. A relocated standalone binary can fail if
that path is absent. Do not distribute it as a portable installed custody tool
until this behavior is deliberately redesigned/tested; source builds in the
reference checkout remain the supported demonstration path.

Validate candidate contents independently of the working directory. For a
committed candidate, export into a fresh location:

```sh
candidate_export=$(mktemp -d /tmp/qasset-release.XXXXXX)
git archive --format=tar HEAD -o "$candidate_export/source.tar"
mkdir "$candidate_export/source"
tar -xf "$candidate_export/source.tar" -C "$candidate_export/source"
```

Run checks from that export with empty build directories and isolated Python
dependencies. Shared cached registry sources are allowed only when recorded;
no local ignored proof/setup or sibling checkout may be assumed present. Export
of HEAD does not include an uncommitted candidate. Before commit, make an explicit
file manifest of tracked working-tree paths plus intended new files and export
only those bytes; exclude unrelated untracked paths. The separate review report
must state which candidate was tested. Do not stage/commit as a side effect of validation.

Current contract crates all disable publication. No root SDK/npm package exists.
Before publishing any package, inspect its actual packed file list, install that
archive into an empty consumer and execute its examples there. Verify third-party
notices against the resolved package/feature graph and binary linkage, not just
the top-level manifest. A repository-wide license is unresolved; see
[license scope](LICENSE_SCOPE.md). Documentation cannot grant missing rights.

## Release manifest and authority

Every target release manifest is immutable and versioned. Required fields:

```text
schema, release_id, source_commit/tree, dirty_state,
build_toolchain/target/profile/environment, lockfile hashes,
artifact path/size/SHA256, ABI/spec hash, binding-generator version,
network passphrase/hash, deployment generation and ledger anchors,
required/observed protocol and network settings,
contract IDs/executable kinds/code hashes, constructor/configuration hashes,
issuer/code/SAC/admin/key fingerprints, policy epochs/revisions,
upload/create/handover transaction hashes, inclusion ledger/order/results,
independent build comparison, test/review references, limitations,
release approvers, signing key fingerprint and verification instructions
```

Use exact byte definitions and schema version; avoid ambiguous concatenations.
The manifest must not claim a locally computed transaction hash was included.
Preserve original deployment JSON and content-addressed historical inputs.
Current [PoC deployment](../deployments/testnet/qasset-poc.json) and
[evidence](../evidence/qasset-authority-assessment.json) are dated reference
records, not a complete signed production manifest.

Release authority needs an appointed releaser and independent reviewer under
[governance](../GOVERNANCE.md). Contract/policy/key changes need security review;
seed-proof activation additionally needs independent cryptographic review.
Record actual approvals; a role description is not an appointment. Protected
branches/tags, mandatory review, artifact signing and CI provenance require real
hosting configuration. None is established by this document.

Build twice in independent clean environments, compare Wasm and package bytes,
explain any nondeterminism and block release on unexplained differences. Produce
checksums for every artifact, a file inventory/SBOM and provenance binding source,
builder/dependency/toolchain identities and commands. If release signing is
configured, publish verifiable signatures and a separately authenticated key
fingerprint; checksums alone do not authenticate the publisher. Retain source,
Wasm/specs, generated bindings, checksums, attestations and build/test logs in
versioned durable storage independent of short-lived CI artifacts. Mirror public
release evidence; verify restore periodically. Actual retention and access owners
must be assigned before release.

## Deployment and reset procedure

1. Verify candidate provenance, licensing scope, actual release approval and
   network identity/capabilities. Capture current resource/rent settings and
   endpoint history range with a protocol-compatible decoder.
2. Provision isolated deployer, relay and maintenance accounts, budgets and key
   custody. Production key material never enters fixtures or public manifests.
3. Upload exact code; compare included executable bytes/hash. Deploy with committed
   constructor arguments; check instances, keys, SAC binding, ABI and TTL. A
   constructor does not rerun on later code upgrade.
4. Exercise intended approvals and rejection paths before authority handover.
   Consent to deployment is distinct from SAC/tenant authority. Use explicit,
   independently reviewed migration for existing asset powers.
5. Confirm handover result and resulting state; test the replacement operation.
   Never automatically lock a production issuer. The Testnet runner's exact
   environment/same-run gates apply only to freshly generated disposable issuers.
6. Confirm fees, live entries, dependency TTL and funded keeper readiness. Archive
   included receipts, all configuration and enforced simulation transcripts with
   their different provenance labels.
7. Start ingestion from the deployment ledger. Reconcile all dependencies,
   publish manifest/API watermark, exercise a full dApp/SDK workflow and verify
   unauthorized requests fail without state change.
8. Release only after monitoring, restore drill, operational ownership and
   independent review gates pass. A successful Testnet run does not approve Mainnet.

For reset: stop writes and record last complete anchors; mark the old generation
historical. Verify the reset from trusted network/operator information and ledger
anchors; missing one RPC entry alone can also mean archival/provider outage.
Discard old pending sequences/auth approvals and index cursors. Recreate fresh
fixtures, deploy and qualify a new generation, initialize new checkpoints, and
publish new identities without overwriting earlier manifests. Passphrase may
remain identical. Cache/API paths include generation to prevent false continuity.

## TTL, restoration and funding runbook

Maintain an inventory of every instance, executable, persistent tenant/role and
external dependency. Monitor actual ledger TTL, not wall-clock guesses.
Current registry `keep_alive` is permissionless; admin renews only on valid auth.
Other dependencies may need `ExtendFootprintTTL` and archived entries restoration.
Do not assume a frequently queried contract renews in simulation.

Schedule inspection frequently enough that worst outage plus retry/restore delay
is less than the remaining TTL threshold margin. Each deployment chooses a
ledger-denominated inspection interval from its observed cadence and objectives.
Jobs acquire expiring leases, use bounded footprints and a unique generation/key/
threshold task identity, simulate, enforce per-job and rolling XLM fee caps,
submit with a serialized funded-source sequence and confirm resulting live-until
values. Competing permissionless jobs should be harmless but still cost fees.

Use `B = estimated extensions + restorations + submissions + fee headroom` over
the planned operating horizon, all in exact stroops. Record measured quantities
and an approved cap; the repository provides no universal XLM budget. Alert on
balance below the next work window and runway below the agreed outage margin.
Underfunded jobs stop safely and surface degraded liveness. They never change
keys/quorums or switch to maximum leases to bypass budgeting.

On archived state: identify original keys/code/dependencies, simulate automatic
restoration with complete restore list or compatible explicit `RestoreFootprint`,
verify fees, submit/confirm, then re-simulate intended action. Verify original
admin/key/revision/epoch/consumption after restoration. Reject missing original
state or a proposed reset/re-enrollment as an incident. Temporary proof uploads
cannot restore; reopen a new bounded session and recheck current eligibility.

## Observability and incident response

Required metrics: network/protocol/generation mismatch, source tip and common
indexed/reconciled watermark, gap interval and replay throughput, RPC latency/
errors/rate limits, stale/unknown/invalid assessment counts, policy/code/admin
changes, signer/credential failures, operation-state age, unresolved submissions,
source sequence contention, TTL minimum/dependency coverage, job leases and XLM
fee/runway. Instrument counts and bounded labels; never label metrics with secrets
or raw credentials. Log correlation IDs, versions, intent/evidence hashes and
final receipt references with sensitive capabilities redacted.

| Incident | First action | Recovery criterion |
| --- | --- | --- |
| Provider outage/disagreement | Mark unavailable; stop freshness/writes requiring missing evidence; preserve journal | Qualified provider and reconciled common ledger |
| Index gap/reset/corruption | Stop checkpoint advancement and fresh claims; preserve raw data | Exact replay or explicit incomplete-history state with reconciled current view |
| Code/admin/policy drift | Invalidate affected assessments/approvals; notify operators | Approved configuration or reviewed migration and fresh evidence |
| Unknown submitted transaction | Lookup original and fee-bump hashes/history; freeze replacement attempt | Included receipt or complete noninclusion evidence and fresh approval |
| Fee/TTL runway low | Pause discretionary sponsored submissions; escalate funding/maintenance | Budgeted restoration/extension confirmed |
| Approval-key compromise/loss | Stop affected signer/relay, assess all exposed paths; preserve evidence | Deployment-specific safe rotation/migration or explicit loss of capability |
| Release compromise | Stop distribution, revoke compromised publisher key where supported, identify affected artifacts | Independently rebuilt reviewed release and authenticated advisory |

Pausing UI/API/relay does not pause contracts. No current fixed-admin emergency
key, rotation or `set_admin` escape exists. Do not promise recovery from immutable
key loss or claw back assets as an invented operational fallback. Incident
notifications and private reports follow [security policy](../SECURITY.md).

## Backups and recovery objectives

Back up database with tested point-in-time recovery, immutable public evidence/
ledger blobs, manifests, configuration and signer-custody recovery material in
separate access domains. Secret backup handling belongs to the approved custody
system, never the public evidence archive. Hash-check restore and replay from the
last complete ledger. Never restore a stale local consumed-recovery database as
current authority; live chain state and generation anchors govern reconciliation.

Recovery objectives must be accepted per deployment before launch: database RPO
no greater than recoverable journal/archive loss; service RTO less than the
remaining TTL/funding/retention margin; historical evidence RPO zero for published
release artifacts. Numeric API availability/response and restoration objectives
are uncommitted until infrastructure, owners and load/drill results exist. Run
backup restoration, lost-response reconciliation, funding outage and provider-gap
drills before launch and on material changes; review quarterly thereafter.

## Release acceptance and rollback

Release gates: local exported reproduction, packed-content checks, current
advisory/license/SBOM review, protocol/address/auth compatibility, full resource
qualification, independent contract/security review, appointed owners, funded
maintenance, actual hosting controls, restore/drift/unknown-outcome drills and
end-to-end deployment evidence. No document alone satisfies a gate.

Web/API releases can roll back only to a version compatible with current manifests
and database schemas. Use expand/contract migrations and shadow replay; do not
roll back consumed operation journals or authority history. Immutable contracts
require an explicitly supported migration, not a file rollback. Current fixed
SAC admin cannot migrate through its exposed auth policy. Deprecation/retirement
must account for those stranded capabilities and tell operators precisely what
remains usable. Stop distribution/claims when support ends; preserve manifests,
source, notices, evidence and instructions for user exits/restoration.
