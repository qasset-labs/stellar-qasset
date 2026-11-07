# Architecture and documentation review report

Review date: 2026-11-05. Scope: internal architectural/documentation review of the
working-tree candidate. This is not an independent external security audit,
cryptographic theorem review or production acceptance. Existing separate reports,
including [security review](SECURITY_REVIEW.md), [cryptographic review](CRYPTOGRAPHIC_REVIEW.md)
and [PoC findings](POC_SECURITY_FINDINGS.md), remain separate and retain historical evidence.

## Scope and method

Reviewed the repository instruction inventory, all five first-party contract
implementations and manifests, authorization/storage/event/arithmetic paths,
representative adversarial tests and test inventories, analyzer, evidence verifier,
transaction runner, signer, reproduction/validation tooling, lockfile versions,
deployment and assessment records, and the owned documentation/research summaries.
Checked research conclusions against their recorded scope and implementation
status. Third-party cryptographic source is pinned evidence; it was not subjected
to a new full cryptographic audit. There are no checked-in CI workflows, public
SDK/frontend or production service deployment definitions to validate as implemented.

The evidence hierarchy is source/tests and reproducible execution for current
behavior; immutable JSON/raw transcripts for historical observations; official
Stellar specifications/docs for network semantics; explicitly labelled target
requirements for unimplemented components. Historical protocol29 deployments and
partial CLI26 resource snapshots are not current network capabilities.

Untracked files present at entry were excluded from the candidate: an ecosystem
Markdown draft, three document drafts and two proposal JSON files. They were not
edited, included as dependencies or used to establish implemented capabilities.
No contracts, implementation scripts, lockfiles, license texts or deployment/evidence
records were changed. New policy/specification files are intentional candidate
additions; no staging, commit, push, deployment, issuer lock or external message
was performed.

## Findings, severity and corrections

Severity reflects documentation-driven integration risk, not a newly demonstrated
contract exploit. "Corrected" means the owning documentation now reflects the
boundary; it does not mean the missing production feature was implemented.

| ID | Severity | Finding | Correction and remaining limit |
| --- | --- | --- | --- |
| DOC-01 | High | Primary architecture covered the earlier registry/recovery prototype and lacked a complete product design | Replaced with coherent current/target architecture and contract, client/service, operations, maintenance and decision references. Target components remain unimplemented. |
| DOC-02 | High | Fixed SAC administrator's missing rotation/handover could be mistaken for a usable production lifecycle | Exact APIs and irreversible lifecycle limitation documented; target production controller requires separate code/review and operation-time epoch checks. |
| DOC-03 | High | Native RoKoko timing/size was described as fitting the 400M Soroban instruction budget | Corrected owning wiring/lattice docs and consolidated reviewer/security summaries. Complete relation, commitment chain, envelope and metered execution remain unqualified. |
| DOC-04 | High | Selected malicious-witness tests were described as validating soundness; superseded gadget claims remained in summaries | Summaries now describe final frontend evidence and open soundness/hiding review; historical gate failure retained. No new proof-system approval. |
| DOC-05 | High | Lifecycle, classic issuer bypass and on-chain verified-gate trust could be conflated | Distinguished issuer/SAC/holder/envelope/declaration authority, cached auth/direct invoker, classic-state observation trust and disabled verified gates. |
| DOC-06 | Medium | Production dApp/SDK/indexer/relay/TTL/storage/error recovery design absent | Added proposed package/API/schema/state-machine specifications, event identity/checkpoints/gaps, exact amounts, signer isolation and budgets. No deployed API or package claimed. |
| DOC-07 | Medium | Retention/restoration/network-version assumptions could cause false freshness or failed writes | Documented automatic restore lists and explicit fallback, permanent temporary expiry, instance/code/dependency TTL, ledger-denominated RPC ranges, reset generation and protocol/address/auth compatibility gates. |
| DOC-08 | Medium | Earlier report counts and missing guarded-write statements could be read as current | Marked phase context historical, documented current guarded API and legacy unconditional behavior, corrected registrar/tenant distinction, updated entry-point links. Raw historical records preserved. |
| DOC-09 | Medium | Contribution, governance, response, licensing, release and succession policies absent | Added policies with unassigned roles, unverified private-report controls and no root license grant; inventoried actual component licenses. Actual owners, rights and hosting controls remain gates. |
| DOC-10 | Medium | Release validation could depend on ignored/untracked local artifacts | Defined exported-source/packed-artifact acceptance, explicit candidate file inventory, durable provenance, tool portability limits and independent export reproduction. |
| DOC-11 | Low | Research attribution wording violated public-documentation constraints | Removed it from owned prose while retaining explicit internal-review and no-external-audit labels. Existing third-party notices/ownership preserved. |
| DOC-12 | Low | RoKoko reproduction suggested cloning over an already tracked source tree and adding existing excludes | Updated to existing pinned manifests and current workspace layout; no research source changed or experiment rerun. |
| DOC-13 | Medium | Conservation could be overgeneralized to issuer-involved transfers or projected global supply | Qualified ordinary nonissuer conservation, issuer mint/burn classification, absent SAC total-supply API and provider-dependent native-event ingestion. |

## Stellar-specific verification

Authoritative references were opened on 2026-11-05 and linked beside claims in
owning documents. No vote schedule was treated as live activation evidence.

| Topic | Official basis and reviewed distinction |
| --- | --- |
| SAC | [CAP-46-6](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-06.md), [custom admin guide](https://developers.stellar.org/docs/build/guides/tokens/custom-sac-admin): native XLM exclusions; separate issuer and SAC admin; handover/lock consequences; [CAP-67](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0067.md) issuer-event and metadata boundaries |
| Authorization | [framework](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization), [CAP-71-01](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-01.md), [CAP-71-02](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-02.md): auth contexts/source/direct invoker, delegated/address-bound variants versus legacy manual preimages |
| Storage/resources | [state archival](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival), [CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md): automatic restore lists, explicit restore fallback, permanent temporary expiry, code/instance TTL and resource fee width |
| RPC | [simulation](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction), [submission](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/sendTransaction), [lookup](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getTransaction), [events](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents): recording/enforcement, enqueue/inclusion, bounded ledger history and opaque cursors |
| Historical data | [data-lake RPC](https://stellar.org/blog/developers/rpc-now-with-infinite-scroll): older `getLedgers` metadata depends on provider archive, not universal extension of other methods |
| Network/finality | [networks](https://developers.stellar.org/docs/networks), [SCP](https://developers.stellar.org/docs/learn/fundamentals/stellar-consensus-protocol): generation/reset identity and finality versus provider reporting |
| Compatibility | [Bell guide](https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide), [CAP-87](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md): CAP-84/88 decoder implications, proposed vote dates, actual Wasm verifier versus native primitive |
| Clients/standards | [official JS SDK](https://github.com/stellar/js-stellar-sdk), [Freighter](https://docs.freighter.app/extension-freighter-api/signing.md), [SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md), [SEP-5](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md): capability/interface/derivation boundaries |

Locked versions were read from actual lockfiles: SDK25.3.2, host25.2.2,
XDR25.0.0 and `ml-dsa`0.1.1; Python reference pins SDK14.0.0. Failed retrieval
of version-specific hosted Rust API pages was not used as evidence; local source
and official framework/specifications supply the relevant interface checks.

## Validation

Working-tree execution:

```sh
RUSTUP_TOOLCHAIN=1.94.1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  python3 scripts/reproduce_poc.py --offline \
  --report /tmp/qasset-architecture-reproduction.json
```

All 14 reproduction commands passed: 90 workspace contract tests, 4 signer tests,
124 Python tests, five-contract release build, native tool builds and retained
public evidence/relation/transport checks. The public verification helper has
zero standalone unit tests; real credentials are exercised through evidence tests.
Both reference Wasm hashes/sizes matched. Research checkers validate recorded
lineage/fixtures; they do not regenerate expensive proofs. Disabled debug info
changes host test build size, not assertions or release-Wasm settings.

The independently exported candidate also passed all 14 commands with empty
initial build directories. It contained 1,243 tracked files plus the 11 intended
new documentation files (1,254 total), excluding all six unrelated untracked
paths. It reused the installed Python interpreter and cached Cargo dependency
sources; all 18 Python lockfile package versions matched. This is independent
source-content validation, not a hermetic build or a new dependency-download
attestation. No included implementation source changed between the two runs.
Final prose corrections were synchronized into the export and rechecked after
execution; they do not alter those compilation inputs.

| Check | Result |
| --- | --- |
| Working-tree reproduction | PASS: 90 contract + 4 signer + 124 Python tests; all 14 commands |
| Fresh source-export reproduction | PASS: same 218 tests and 14 commands; five-contract build and both reference hashes match |
| Exported owned Markdown | 58 documents; 310 local file/anchor links valid; balanced code fences |
| Mermaid | Six blocks structurally checked; graphical rendering not run |
| Git whitespace / new-file whitespace | PASS; all new documents end with newline |
| Change scope | 1,185 original non-Markdown tracked files byte-identical to HEAD, including code, locks, license texts, deployment and evidence records |
| Public prose constraints | Owned-document scan passes; imported third-party source/notices preserved |
| Candidate isolation | All 1,254 manifest hashes match the export; six pre-existing untracked paths excluded |

Execution logs: `/tmp/qasset-architecture-reproduction.json` and
`/tmp/qasset-architecture-export-reproduction.json`. Candidate inventory:
`/tmp/qasset-architecture-candidate-manifest.json`. These temporary verification
aids are not new historical deployment evidence. Local-link/fence checking used
a temporary dependency-free scanner over owned Markdown, excluding imported
vendor/upstream documentation; it is a structural check, not a rendered-site test.

## Remaining production limitations

The documentation defines a complete target and identifies its gates; it does
not implement frontend/SDK/services, mutable controllers, keeper funding, hosting
controls, current protocol support or independent audits. Repository-wide licensing,
actual maintainers/releasers/responders, custody/rotation choices, service objectives,
archive retention and publishing/signing configuration remain unresolved. The
legacy recovery backend stays unavailable with A-01/F-01 and lifecycle gates open.

No live receipt/state verification, fresh network deployment, full external-link
crawl, expensive proof regeneration, full formal paper/theorem verification,
browser accessibility/rendering test or production load/restore drill is claimed
by this review. Official reference pages were checked selectively; local links
and structural Mermaid fences are checked separately from graphical rendering.

## Follow-up architecture and cryptography audit (2026-11-07)

Scope: `docs/ARCHITECTURE.md` and `docs/DECISIONS.md`, reviewed from
Stellar-integration and cryptographic perspectives. Contracts, scripts, tools and lockfiles were unchanged since
`3d2090d`. Official CAP-87, CAP-71/71-01/71-02, CAP-66 and the Bell upgrade guide
were consulted on 2026-11-07. Internal review; not an independent external audit.

| ID | Severity | Finding | Correction |
| --- | --- | --- | --- |
| ARCH-01 | High | The minimal classical-signer-combination analysis claimed in project descriptions had no architecture specification | Added §3 classical-coalition analysis: inputs, signer kinds, composition, bounds, oracle validation, current status and example diagram |
| ARCH-02 | High | No stated rationale for ML-DSA parameters or end-to-end security level; the SHA-256 authorization digest bounds the system | Added §6 cryptographic parameters and ADR-007 |
| ARCH-03 | Medium-High | Address-bound credentials described as "where supported" although CAP-71-02 is Final since protocol 27 | §9 now requires them for production controllers; ADR-008 |
| ARCH-04 | Medium | CAP-87 compatibility understated; changed failure semantics (host trap vs contract error 3) and evidence-verifier expectations unstated | §8 records pure ML-DSA with context compatibility, trap semantics, cost estimate and migration diagram |
| ARCH-05 | Medium | Production controller lifecycle did not require a guarded handover path | §6 adds guarded handover, rotation and a lifecycle diagram; ADR-008 |
| ARCH-06 | Medium | Hedged signing not required; PoC signer is deterministic | §6 and ADR-007 require hedged production signing |
| ARCH-07 | Medium | ACVP/Wycheproof vectors not required on the SAC administrator verification path | §6 and §14 require vectors on every verification path |
| ARCH-08 | Medium | "Independent implementations" overstated; evidence helper reuses the contract's ML-DSA crate | §6 and §14 require a second implementation and qualify the claim |
| ARCH-09 | Medium | Target scope not mapped to an initial release | §14 adds an initial release mapping |
| ARCH-10 | Low | Protocol 30 status text predated the Testnet vote date | §8 records that the outcome is unconfirmed as of 2026-11-07 |
| ARCH-11 | Low | Product and PoC interleaved; difficult first read | Added "Architecture at a glance" with component table, product diagram and reading guide |
| ARCH-12 | Closed | CAP-66 cited for both automatic restoration and resource fees above uint32 | Verified: CAP-66 covers both; no change |
