# Maintenance and production responsibility matrix

Status: target operating policy, 2026-11-05. No person or organization is appointed
by this table. The project has no supported production service or SLA. Each
production deployment must name an accountable owner and backup, accepted
objectives, funding and verified controls before the affected capability launches.
See [governance](../GOVERNANCE.md) and [operations](OPERATIONS.md).

| Component | Required accountable role | Proposed cadence / trigger | Evidence required |
| --- | --- | --- | --- |
| Contracts and authorization | Contract/security owner | Every code/policy change; each protocol upgrade; quarterly boundary review | ABI/hash inventory, real auth/cache/rollback tests, independent review disposition |
| Cryptographic dependencies | Security owner | Weekly advisory triage; every version change and activation | Exact pins/vectors, upstream status, hostile-input/cost checks; specialist review where needed |
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
and issuer retirement are never unattended maintenance tasks.

## Supported versions and compatibility

Current reproducibility pins: Rust1.94.1, Soroban SDK25.3.2/host25.2.2/XDR25.0.0,
Python3.10 with `stellar-sdk`14.0.0, `ml-dsa`0.1.1, schema-v2/tool2.0.0 evidence.
Research crates have independent pinned graphs. These specify historical/reference
execution, not full compatibility with the network's latest protocol. Protocol30
requires fresh SDK/XDR and address/credential qualification; do not update locks
without versioned build/evidence comparison.

A future support matrix must bind SDK major version to accepted contract hashes/
ABI, service/evidence schema, underlying Stellar SDK and protocol/credential
variants, supported OS/browser/wallet versions and deployment generation.
Unknown combinations reject writes and label read limitations. Keep a documented
previous client line only where it remains safe with current deployed state;
never promise support for superseded insecure auth code.

Public interface/schema breaking changes require a new major compatibility line
or explicit versioned endpoint and migration guide. Private storage or verifier
changes still require deployment/migration review even if the API shape matches.
Deprecation should include replacement, exact affected versions/generations,
effective date, exit/restore steps and evidence retention. No fixed support term
or notice period is promised until owners can resource it. Security incidents
may require immediate suspension with a factual advisory.

## Funding, objectives and succession gates

Each owner must accept measurable service/freshness/recovery objectives and a
budget. Track maintenance XLM runway, hosting/history costs and custody recovery
costs separately; there is no protocol yield to fund them. Set RTO below the
shortest TTL/funding/retention margin and RPO within recoverable archive/journal
loss. Published release evidence needs zero-loss retention with tested mirrors.
Actual numeric availability, latency, archive duration and incident response
objectives remain open decisions requiring infrastructure/load/drill evidence.

Transfer operational ownership only after the successor verifies manifests,
credentials, dashboards, archive/backup restore, signer constraints, funding and
release verification. Revoke outgoing access under authenticated governance;
never transfer a customer signing secret through a public issue. Unfilled roles
or absent recovery coverage block production launch; documentation is not staffing.

Retirement closes new enrollment and distribution claims, communicates last
supported versions and exits, reconciles pending operations, funds any promised
restore/exit interval, then revokes unused service credentials. Do not delete
immutable history, license notices or verification artifacts. On-chain immutable
contracts can remain callable indefinitely; document key/TTL dependencies and
unavailable migrations even after the hosted UI is retired.
