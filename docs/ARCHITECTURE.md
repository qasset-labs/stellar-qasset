# Q-Asset technical architecture

Design baseline: 2026-11-05. This is the primary architecture for the completed
product. **Current** describes checked-in code or dated evidence; **target**
specifies work still required. Target requirements are not deployed capabilities.
No production deployment or independent external security approval is established.

Supporting specifications: [contracts](CONTRACTS.md), [clients and services](CLIENTS_AND_SERVICES.md),
[operations and releases](OPERATIONS.md), [decisions](DECISIONS.md), and
[maintenance](MAINTENANCE.md). The [authority demonstration](POC_ARCHITECTURE.md)
explains the implemented integration; [recovery status](RECOVERY_IMPLEMENTATION_STATUS.md)
bounds the research. Findings and validation belong in the separate
[documentation review](ARCHITECTURE_REVIEW.md).

## 1. Product, requirements and economics

Q-Asset helps issuers, treasury operators, custodians and reviewers identify and
strengthen effective authority over Stellar assets. It combines declared policy
arithmetic, supported authority-path analysis, operation-specific enforcement
and reproducible assessments. Every supported path that can issue assets, move
balances or replace a stronger rule must be examined. Assessments explicitly
identify uncovered paths.

| User | Completed-product workflow | Required outcome |
| --- | --- | --- |
| Issuer administrator | Discover issuer/SAC authority, declare intent, compare and delegate supported operations | Exact identity and visible classic issuer residual powers |
| Treasury operator and approvers | Inspect custody, prepare, approve, execute and reconcile transfers | Exact amount/destination; current policy; no weaker override |
| Security reviewer | Download inputs, reproduce classifications and verify receipts | Versioned evidence, scope and freshness boundaries |
| Operations team | Monitor drift, fund fees, retain TTL and restore | Visible gaps; restoration preserves authority |
| Owner, conditional recovery extension | Enroll/revoke recovery eligibility and replace authority | Current entitlement, replacement possession and one-time consumption |

The repository defines **no Q-Asset token, staking, yield, lending, redemption
price, revenue split, per-assessment charge or protocol fee**. QEXP and QCTL are
synthetic Testnet assets. Reserve backing, beneficial ownership, legal redemption
and compliance decisions belong to issuers/custodians; these contracts do not
establish them. Commercial service pricing is unresolved.

Actual costs are network fees in XLM, classic account/trustline reserves,
Soroban resource/rent/restoration charges, infrastructure and custody. A source
pays transaction fees unless a fee-bump payer covers them; reserve sponsorship
is a different mechanism. The target service funds relay/maintenance accounts
under explicit budgets. Sponsorship gives no asset approval. Funding failure
must never weaken an approval policy.

Requirements and exclusions:

* Scope every result to network, deployment generation, asset and operation.
  Keep declarations, tested observations and unknowns distinct.
* Enumerate issuer, governance, upgrade, recovery, pause, delegation and other
  bypass paths for each supported integration. Eight role labels are not proof
  of complete coverage.
* Keep mnemonic, seed, signing secrets and private customer/compliance data off
  chain. Public evidence should be downloadable and reproducible.
* Treat consensus/host correctness, cryptographic assumptions, key custody and
  provider integrity as separate boundaries. Checksums identify bytes, not truth.
* Do not promise quantum-safe SCP/envelope signatures, arbitrary bytecode
  analysis, retroactive control of classic accounts or automatic regulatory compliance.
* Unsupported code, signer/credential variants and token semantics fail explicitly.

## 2. Implementation boundary and topology

| Component | Current | Target |
| --- | --- | --- |
| `qasset-registry` | Declaration arithmetic, guarded revision writes, events; verified gates unavailable | Preserve declarations; version any verified integration separately |
| `qasset-sac-admin` | Immutable SAC/key; ML-DSA-65 for one direct `set_authorized` auth context | Audited scoped enforcement and separately reviewed lifecycle |
| Analyzer/verifier | Python, two reference configurations, schema v2, raw evidence checks | Versioned adapters, monitoring, archive and API |
| Operator signer | Unix tool, fresh external key file, signs supplied digest | Isolated policy-aware custody service |
| dApp/public SDK | Absent | Inspection, declaration, scoped write, export and recovery flows |
| Indexer/API/relay/keeper | No production service, database or scheduler | Durable history, freshness, bounded delivery and maintenance |
| PQ recovery counter | Local restricted candidate with public fixture keys | Optional independently reviewed account integration |
| Seed verifier/mailbox | Authentication disabled; transport is unverified | Conditional research extension after all acceptance gates |

Current implementation sources: [registry](../contracts/qasset-registry/src/lib.rs),
[administrator](../contracts/qasset-sac-admin/src/lib.rs),
[analyzer](../scripts/qasset_authority_analyzer.py),
[verifier](../scripts/verify_qasset_evidence.py), and
[signer](../tools/qasset-sac-signer/src/main.rs). All five contract packages have
`publish = false`. There are no checked-in CI workflows or production hosting definitions.

```mermaid
flowchart TB
  User[Issuer or treasury reviewer] --> Web[Target dApp]
  Web --> SDK[Target SDK and bindings]
  SDK --> Wallet[Wallet or isolated signer]
  SDK --> RPC[Stellar RPC]
  SDK --> API[Target assessment API]
  API --> DB[Target projections and operation journal]
  Ingest[Target ingestion and reconciliation] --> DB
  Ingest --> Archive[Immutable evidence and ledger archive]
  Ingest --> RPC
  Ingest --> Horizon[Horizon classic state]
  Keeper[Target funded TTL worker] --> RPC
  Relay[Optional target fee relay] --> RPC
  RPC --> Ledger[Stellar ledger and SAC]
  Ledger --> Admin[Scoped authority contracts]
  Ledger --> Registry[Declaration registry]
  Issuer[Classic issuer authority] --> Ledger
```

Target initial hosting consists of a static web origin, stateless API,
independently restartable ingestion/reconciliation/maintenance workers, a
relational database and immutable blob storage. Database job leases and an outbox
suffice initially; no message broker is required. Provider, redundancy and service
objectives require deployment qualification. Isolate networks and credentials.
The API holds no user approval keys. Signer processes and optional relay envelope
keys have separate identities and funding boundaries. An API compromise may
mislead or withhold information; signing and enforcement still bind the exact action.

## 3. Identity, authority graphs and evidence

The registry's `asset: Address` is a tenant label. Issued-asset identity comprises
network, exact code bytes and issuer; derive the SAC address with the official
SDK. XLM has a native identity; contract tokens use their network and contract
ID. Tickers, domains, logos and enrollment do not establish identity or control.

Target authority graphs have typed account, contract, key, quorum and policy
nodes and directed operation/replacement edges. Each adapter pins recognized
code, ABI, protocol range, signer formats, completeness assumptions and unsupported
cases. Traverse with visited-node detection and qualified depth/node/edge ceilings;
cycles or exhausted bounds produce `UNCOVERED`, never assumed protection. Code
identity alone does not prove policy correctness or independent key custody.

Current path statuses are `DECLARED`, `TESTED_PASS`, `TESTED_REJECT`, `EXPOSED`,
`UNCOVERED`, `STALE` and `INCONCLUSIVE`. Verifier `INVALID` describes evidence
failure, not a QS level. There is no overall asset safety score. Future signed
attestations must bind evidence hash, adapter/tool versions, network/generation,
ledger range, configuration, scope and expiry, with an approved attester key and
revocation policy. They do not expand the evidence's scope or establish live authority.

Current reads span a ledger interval. Repeating a registry revision detects some
concurrent changes, not an atomic issuer/SAC/registry snapshot. Target ledger
metadata ingestion constructs views at a complete common ledger boundary and
reconciles point reads. APIs expose that watermark and disagreements. Missing or
unsupported dependencies invalidate the affected freshness claim.

## 4. Declared policy contract

The [contract reference](CONTRACTS.md#registry-api) owns exact signatures, storage,
events and errors. A constructor fixes the registrar without requiring its
consent; deployment review must independently verify that address. Enrollment
requires registrar and incoming tenant consent. Transfer requires outgoing and
incoming tenant consent, with no registrar override. No registrar rotation,
deregistration, role deletion or upgrade entry point exists.

Tenants start at revision 0. Accepted quorum writes and tenant-admin transfers
increment checked `u64` revisions, even for unchanged values.
`set_role_quorum_if_revision` rejects a stale expected revision with error 15.
The unconditional setter and admin transfer offer no compare-and-set. The eight
role entries are independently bounded. There is no global tenant enumeration/cap;
the target catalog derives membership from indexed enrollment events.

### QS0–QS4 standard

These are repository-local **declaration predicates**, not an external certification
standard. Let `C` be classical-labelled weight, `P` PQ-labelled weight, `Pmax` the
largest single PQ-labelled weight and `T` the threshold. Missing roles are weak;
present roles are weak if `C >= T`. Highest-impact roles are Treasury, Upgrade
and Governance.

| Level | Exact declared condition |
| --- | --- |
| QS0 | No PQ label anywhere |
| QS1 | A PQ label exists and a highest-impact role is weak |
| QS2 | No highest-impact role is weak, but another role is weak |
| QS3 | All eight roles exist and require PQ-labelled contribution |
| QS4 | QS3 and `C + Pmax < T` for each highest-impact role |

Classical weight 1 plus PQ weight 1 at threshold 2 is QS3 when used for all roles.
Classical weight 1 plus two PQ weights 1 at threshold 3 meets the extra QS4 rule.
Different addresses need not represent independent keys/operators. A nonexistent
authority needs adapter-validated non-applicability; omission is unknown today.

Quorums contain at most 20 unique addresses, each weight 1–255, and
`0 < T <= C + P`. Total weight is at most 5,100. Duplicate checks are quadratic
but bounded; analysis iterates eight bounded roles. These are metadata limits,
not classic Stellar signer limits or production cryptographic capacity.
`policy_assessment` requires enrollment and returns observation ledger, revision,
declared level and `Unverified`. Direct declaration reads can return QS0/missing
roles for an unknown tenant. Both verified APIs return `UnverifiedPolicy`, even
when asked for QS0.

## 5. Assets, custody and accounting

Current Q-Asset contracts hold no escrow or token balance ledger. The SAC
administrator changes holder permissions; it cannot transfer, mint, burn or claw
back. Target integrations retain balances in the token ledger and approvals in
an account/policy controller. A custody contract would require additional audited
accounting and exit rules.

The [SAC specification](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-06.md)
distinguishes holder operations from issued-asset administration. XLM's SAC has
no issuer administrator. Inspect issued-asset `AUTH_REQUIRED`, `AUTH_REVOCABLE`,
immutable flags and per-balance/trustline clawback eligibility; new flags do not
establish all historical trustlines' capabilities. Classic holders require
trustlines, authorization, capacity and reserves. Contract balances have storage
lifetimes and are not classic trustlines. For a classic trustline, SAC
`set_authorized(false)` selects authorization to maintain liabilities rather
than deleting offers/pool positions; do not label it an unconditional full freeze.

| Operation | Authority/accounting boundary |
| --- | --- |
| Transfer | Supported ordinary nonissuer holder/spender path; exact debit equals credit |
| Approve / transfer_from | Holder establishes allowance/expiry; spender may use it without fresh holder approval |
| Burn | Holder or approved spender; destroys units |
| Mint | Issued-asset SAC admin, or separate classic issuer issuance path |
| Set authorization | SAC admin; separate issuer trustline operations remain |
| Clawback | Admin/issuer authority and applicable enabled state; destroys units rather than transferring to a wallet |
| Set SAC admin | Current admin consent; independently test new address and configuration before handover |

[SEP-41](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md)
is an interface, not proof of arbitrary token economics. Allowances are spending
authority, not reservations. Outstanding approvals, native offers/liabilities,
sponsored reserves and custody overrides belong in treasury coverage. Prefer
direct transfer; allowance support needs expiration, revocation and replacement-race handling.

SAC handover leaves classic issuer powers effective unless separately retired.
The [custom-admin guide](https://developers.stellar.org/docs/build/guides/tokens/custom-sac-admin)
warns that locking an issuer before handover can make the handover impossible.
Production retirement needs a reviewed issuer-specific migration and verified
replacement operation before any irreversible step. The disposable lock runner
is not a production migration tool.

### Precision and conservation

SAC amounts have seven decimal places: one unit is `10_000_000` base units.
Use decimal strings at API boundaries and checked integer arithmetic. Reject
negative transfers, excess precision, scientific notation and implicit rounding.
The ABI is `i128`; classic balance/trustline operations also face signed `i64`
limits, liabilities and reserves. Check the destination representation, not just
the wider ABI. Other contract tokens need explicitly supported decimals and
semantics. See [Stellar's examples](https://developers.stellar.org/docs/build/guides/tokens/stellar-asset-contract).

For supported ordinary nonissuer transfers, conservation is
`debit = credit = amount`. Issuer issuance/redemption and explicit mint/burn/
clawback require separate supply-effect classification; a method name alone
does not establish conservation. The SAC has no `total_supply` method, and a
projection of tracked balances is not a global supply or reserve attestation.
[CAP-67](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0067.md)
defines issuer-related mint/burn event semantics for ingestion. Network fees affect the XLM payer
separately. No service fee may silently reduce principal. No percentage/rounding
rule exists in current economics. Reconcile token effects, allowances and fees
independently; a cached balance establishes no spending authority or redemption backing.

## 6. Enforcement and lifecycle

Current `QAssetSacAdmin` fixes a SAC and 1,952-byte ML-DSA-65 key in instance
storage. `__check_auth` admits one contract auth context: configured SAC,
`set_authorized`, two arguments. It verifies a 3,309-byte signature over the host
digest with context `qasset-sac-admin-auth-v1`. The host binds argument values;
the SAC decodes their types. There is no outgoing SAC invocation, rotation,
recovery, upgrade or other administrative method. Constructor decoding establishes
key length, not possession or SAC trustworthiness. Test configuration before handover.

Auth contexts are authorization-relevant contexts, not a view of every
unauthenticated call-stack ancestor. The guard rejects tested composite/nested
authorizations; it is not a universal call-graph verifier. Direct-invoker
authorization is distinct: a controller calling its SAC can authorize as invoker
without running its own `__check_auth`. Any such public dispatch method must
enforce policy itself. See [authorization](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization).

### Target production controller

Rotation, weighted approvals, treasury transfer and upgrade support require a
new versioned controller. Bounded configuration includes operations, independent
key identities, verifier/code pins, quorums, policy epoch and explicit governance/
recovery paths. Unsupported inputs have no permissive fallback.

A target treasury `execute` intent binds network, controller, token, operation,
destination, exact amount, expected epoch, nonce and expiry. The execution method
checks current epoch after authorization and immediately before dispatch, and
consumes an intent nonce atomically with effects. Callbacks/subsequent actions
must recheck authority across policy mutations. Governance increments checked
epochs. Batching remains disabled until the cache and execution model passes
independent validation. All direct-invoker paths require equivalent checks.

Initially retain immutable scopes for direct SAC authentication. A dynamic epoch
check only inside `__check_auth` cannot revoke already cached same-tree authority.
Mutable SAC administration requires a separately reviewed dispatch design with
operation-time checks or restrictive scopes; general mutable direct-SAC auth is
not established here. The present fixed administrator cannot hand over to a new
contract later. Selecting it forecloses rotation and software migration.

Target lifecycle is `Proposed -> Validated -> Active -> Retiring -> Retired`;
`Suspended` is an explicit enforced state. Activation needs outgoing consent and
incoming proof of possession; retirement needs usable replacement authority and
exits. Emergency paths cannot be weaker than their stated guarantee. Key counts,
timelocks and emergency procedures need deployment-specific cost/security review;
the registry's 20 metadata entries are not a signature budget.

### Verified gate boundary

Off-chain assessments do not enable `require_min_qs`. A target adapter must
establish actual policy, complete bypass coverage and freshness at the protected
operation, including verifier/upgrade identity. For supported contract state,
perform checks in the same invocation and propagate errors. RPC/Horizon responses
are not on-chain facts without an explicit authenticated bridge and threat model.
Verification of arbitrary classic issuer/signer state inside a contract remains
an unresolved integration. Until its trust model and mechanism pass review,
classic coverage stays off-chain and verified registry gates stay disabled.

## 7. Conditional recovery extension

Recovery does not block assessment/scoped-enforcement delivery. The
[contract reference](CONTRACTS.md#recovery-components) specifies actual interfaces.
The ML-DSA counter requires owner consent at construction, distinct active/backup
keys, and one-shot recovery with enrolled backup signature plus replacement
possession. Network/contract/domain, expected epoch and inclusive expiry within
1,000 ledgers are bound. Success increments epoch and consumes recovery. The owner
has no later bypass. Only its own argument-free `protected` counter is authorized.
The patched candidate's redeployment is not established by retained receipts.

`SeedRecoveryVerifier` stores immutable owner/key/path configuration and always
rejects authentication. There is no activation method. Future support requires
a new implementation. Distinguish raw 32-byte Ed25519 leaf seeds from supported
SEP-5 roots and exact `m/44'/148'/n'`, with `n < 2^31` before hardening.
[SEP-5](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md)
defines derivation compatibility, not entropy or current entitlement.

The target statement binds account-selected protected key/current policy,
network, contract, program/verifier/parameters, witness mode/path, epoch,
eligibility, action, replacement policy/key, nonce and expiry. Atomic consumption
verifies the complete proof and replacement possession, rechecks revocation and
expiry, replaces authority and consumes entitlement once. An old owner's genuine
seed is insufficient after revocation. Operation-time checks cover cached auth.

Exact backend/composition/parameters need specialist quantum proof-of-knowledge
and privacy review. Ordinary soundness for a true public key statement is not
knowledge authentication. Pairing compression cannot inherit a PQ claim.
Scalar-output experiments disclose a functioning classical signing secret:
every effective or reused classical path must be retired with ledger finality
before disclosure, including to RPC/proving services. Public retire-and-reveal
in one transaction leaves a prepublication race.

Mailbox sealing proves byte consistency only. Its consumer would need complete
proof verification and current policy checks in the atomic transition. No trusted
off-chain approval gateway silently substitutes for an infeasible verifier.
SDK-host code-size and CPU blockers remain open despite raw Wasm success. See
[successor evidence](VERIFIER_NEXT_EVIDENCE.md) and
[security argument](RECOVERY_SECURITY_ARGUMENT.md).

## 8. Network configuration and deployment provenance

Current evidence is Testnet-only. The reference locks Rust 1.94.1, Soroban SDK
25.3.2, host 25.2.2, XDR 25.0.0, Python `stellar-sdk` 14.0.0 and `ml-dsa` 0.1.1.
Workspace `soroban-sdk = "25"` is a range; `Cargo.lock` defines the build.
Research tools have separate locks. The CLI26/protocol29 limits record is explicitly
partial. Historical counts/identities live in the [evidence guide](QASSET_POC_EVIDENCE.md).

The [Bell guide](https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide)
lists Testnet/Mainnet votes for 2026-11-03/2026-11-23 and requires CAP-88-aware
ledger decoders. A scheduled vote does not prove activation. Qualify actual
network/protocol/capabilities. CAP-84 muxed contract destinations require updated
address/event decoding and role validation; older tools must reject unsupported
variants explicitly. Ledger windows do not imply fixed wall-clock durations.

[CAP-87](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md)
defines Protocol30 pure ML-DSA verification host functions. Current contracts use
Wasm RustCrypto, not those functions. A native-verifier release must preserve
message/context semantics and negative vectors, and record new artifacts/costs.
It does not migrate envelope signatures.

Target configuration contains passphrase/SHA-256 network ID, endpoints, accepted
protocol range, deployment generation, contract IDs/executable hashes, ABI/schema
versions and provenance. URL is not network identity. Compare live network,
constructor state and code with the approved release manifest before signing.
Private networks require their own passphrase/manifests.

Testnet reset clears state/history. Passphrase alone does not distinguish
generations: retain a generation ID plus ledger/deployment anchors. Halt on
backward history or missing anchors; invalidate caches, pending transactions,
checkpoints and assessments. Recreate disposable fixtures with a new manifest;
preserve old identities as historical evidence. See the
[network guide](https://developers.stellar.org/docs/networks) and
[reset procedure](OPERATIONS.md#deployment-and-reset-procedure).

## 9. Transaction and wallet protocol

The source supplies sequence/envelope authority; an operation source may differ.
A fee-bump payer supplies fee authority. Each contract authorizer supplies its
own consent subject to source-account/direct-invoker rules. A connected wallet
or sponsor is not automatically a contract approver.

```mermaid
sequenceDiagram
  participant Client
  participant RPC
  participant Approver
  participant Source
  participant Ledger
  Client->>RPC: Check identity and sequence; recording simulation
  RPC-->>Client: Auth requests, footprint and resources
  Client->>Client: Validate intent, scope, epochs and bounds
  Client->>Approver: Display and sign exact auth preimage
  Approver-->>Client: Credential
  Client->>RPC: Enforced simulation with credentials
  RPC-->>Client: Result, resources and restore requirements
  Client->>Source: Sign assembled bounded envelope
  Source-->>Client: Signed XDR
  Client->>Client: Journal XDR, hashes and intent before sending
  Client->>RPC: sendTransaction
  RPC->>Ledger: Deliver candidate
  Client->>RPC: Poll result and verify effects
  RPC-->>Client: Included result or unresolved status
```

Recording simulation discovers authorization without proving it. Enforced
simulation checks credentials and estimates resources but reserves no state,
sequence, fee or success. Use its footprint, resource data and restoration
information with qualified capped headroom. Decode contract return values as well
as transaction status. See [simulateTransaction](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction).

Build preimages from the actual credential variant with an official compatible
SDK helper. The retained PoC constructs legacy `ADDRESS` payloads and does not
support newer variants. [CAP-71-02](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-02.md)
adds address-bound credentials. Legacy payloads do not independently include the
authorizer address; do not generalize shared-key safety from them. Target signers
use address-bound forms where supported and separate keys per controller.
Delegated credentials need their own explicit compatibility tests.

Auth/invocation changes require fresh approval; sequence/fee changes require
envelope re-signing. Resimulation must preserve approved auth bytes or restart
approval. Time bounds and authorization ledger expiry are independent. Large
resource fees require checked int64 handling; CAP-66's fee-bump path is already
used by the PoC when the inner uint32 fee cannot represent the estimate.

[sendTransaction](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/sendTransaction)
queues candidates; `PENDING`/`DUPLICATE` is not inclusion. Pre-inclusion rejection
is not an included failed transaction. Fetch the final result and effects.
Ledger inclusion has finality under [SCP safety assumptions](https://developers.stellar.org/docs/learn/fundamentals/stellar-consensus-protocol);
provider honesty remains separate. Do not invent confirmation-depth requirements.

Timeout is `UNKNOWN`. Journal exact XDR, intent and inner/outer hashes before
sending; retry identical envelopes with bounded backoff. Reconcile receipt,
source sequence and business state before rebuilding. `NOT_FOUND` can mean not
yet seen or outside retention. New sequence/auth nonce can repeat a successful
economic action; database idempotency alone cannot prevent it. Target treasury
controllers consume signed intent nonces on-chain. Current APIs have no generic
business idempotency key. Never automatically resubmit an ambiguous mutation with
fresh approval. [Client/service details](CLIENTS_AND_SERVICES.md#transaction-state-machine)
define statuses and recovery.

## 10. Storage and resource lifecycle

Registry tenant/role entries are persistent; registrar is instance data.
`keep_alive` extends live tenant/roles. Several reads/writes extend tenant/instance
TTL, but role getters and score reads do not retain role TTL. Fixed admin extends
instance on construction and valid authentication. Both target
`min(120_960, max_ttl)` with a half-target threshold: approximately seven days at
five seconds per ledger, not an SLA. Counter/seed contracts have no extension
method. Mailbox uses temporary entries; logical expiry can precede deletion.

Persistent/instance entries archive and can restore; temporary entries expire
permanently. Instance and executable lifetimes both matter. Extending one
contract does not retain external dependencies. Protocol23+ invocation restore
lists can restore archived state before execution when simulation supplies the
needed entries; incomplete lists fail. Explicit `RestoreFootprint` is a fallback,
followed by fresh simulation/approval. Extension cannot revive archived state.
See [archival guidance](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival)
and [CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md).

The target dependency catalog includes instances, executables, every tenant/role
entry, external verifier/configuration, relevant token balances/allowances, and
proof preprocessing if ever enabled. Keepers inspect ledger TTL, lease bounded
jobs, simulate extension/restoration, enforce XLM budgets and confirm effects.
Others may perform permissionless maintenance. Restore original authority;
archival must not reset epochs or permit silent re-enrollment.

Refresh code/envelope/entry/event size, CPU, memory, read/write and rent settings
for every qualified deployment. Live-memory and disk/restored reads differ.
The October partial Testnet snapshot's 131,072-byte code, 132,096-byte transaction,
400M instructions and 40 MiB memory are historical values. Native tests and
overridden host limits do not establish admission. Qualify complete transactions,
including multiple credentials, restore costs, dependencies and hostile inputs.

## 11. dApp, SDK and durable services

Target dApp journeys are discovery, graph/declaration comparison, evidence export,
guarded editing, holder authorization and later supported treasury operations.
Recovery stays unavailable until its separate gates pass. Show exact issuer,
SAC, key, network, operation, amount, payer, scope and observation age before
signing. Unknown/stale data cannot carry a verified badge. Keyboard/screen-reader
access, non-color statuses and reload/reconnect recovery are release requirements.

The target SDK separates exact-value codecs, version-pinned generated bindings,
manifest validation, wallet adapters, transaction orchestration and assessment
verification. Browser packages exclude native secret-file tools and proving
backends. No published package or runnable new SDK API is claimed.
[Clients and services](CLIENTS_AND_SERVICES.md) specifies proposed interfaces,
errors, schemas and compatibility.

An indexer is required for completed monitoring/history, though the finite PoC
uses JSON/live reads. Contracts cannot enumerate all tenants and ordinary RPC
history is bounded. Index raw ledger metadata, events/classic effects, resulting
configurations and assessments; events signal changes, reconciliation establishes
state. Detect changes without Q-Asset events too. The index never signs approvals.

[getEvents](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents)
provides retained ranges and opaque cursors; default history is ledger-denominated,
not seven guaranteed days. [Data-lake-backed getLedgers](https://stellar.org/blog/developers/rpc-now-with-infinite-scroll)
can supply older metadata only where a provider retains it; that does not extend
all endpoints. Target schemas, event identity, checkpoints, replay/gaps and freshness
are specified in the client/service reference.

## 12. External integrations and confidentiality

| Integration | Supplies | Does not establish |
| --- | --- | --- |
| RPC | Simulation, entries, delivery and retained receipts/events | Honest server, perpetual history or inclusion guarantee |
| Horizon | Classic account/trustline/operation views | Atomic cross-service snapshot or arbitrary contract semantics |
| SEP-41/SAC | Token interface/native asset bridge | Honest arbitrary token economics or issuer retirement |
| Wallet | Selected envelope/auth signing capabilities | ML-DSA availability or correct dApp intent |
| SEP-5 | Supported HD derivation | Entropy, ownership or safe recovery |
| Optional SEP-1 metadata | Issuer descriptions/domains | Endorsement, reserves or verified authority |
| Optional custody/KMS | Selected supported signing boundary | Correct ML-DSA context or independent approval factors |

Fetch metadata through bounded HTTPS retrieval with redirect/private-address
protections. Sanitize text/URLs, restrict images and disallow active HTML/SVG.
Metadata cannot select executable code or change asset identity. Never fetch
assessment-supplied URLs on signer hosts. Optional web login (SEP-10/SEP-45)
requires separate versioned implementation; it grants no transaction consent.
Anchors, KYC, prices, bridges and redemption APIs are optional issuer integrations,
not current or necessary dependencies.

Only public chain state and approved public evidence enter the public archive.
Customer annotations belong in a separately encrypted, tenant-isolated service
with access logs and deletion/retention rules. Telemetry excludes credentials,
secrets, pending signed transactions and private annotations. Research scalar
proofs can themselves disclose secrets. Public-fixture workflows must not become
production witness-upload flows. Deleting logs cannot undo chain publication.

## 13. Threats and operations

| Failure/adversary | Required control | Boundary |
| --- | --- | --- |
| False labels/incomplete graphs | Explicit provenance, supported adapters, unknown edges | Operator/key independence needs separate evidence |
| Classic issuer or upgrade bypass | Enumerate alternate powers and verify migration | Scoped success is not global protection |
| Cached old-key auth | Restricted current scope; target operation-time epochs | General mutable/batched auth remains unqualified |
| Compromised API/relay | Exact intent display, signer allowlists, on-chain binding, fee caps | Availability/presentation still at risk |
| Edited evidence/dishonest provider | Raw XDR/credential/ledger-order checks; compare sources | Consistency is not validator-authenticated state |
| Replay/concurrent mutation | Host nonce/expiry; guarded revisions or target nonce consumption | Unconditional setters remain available |
| Resource/TTL abuse | Bounded input/graph/queue/footprint and budgets | Large proofs are not production inputs |
| Key loss/compromise | Approved custody, drills, explicit rotation/immutability | Current fixed admin cannot recover/rotate |
| Outage/gap/reset | Durable journal/archive, replay and generation isolation | Missing historical negatives cannot be recreated retroactively |

The [prototype threat model](THREAT_MODEL.md), [PoC threat model](POC_THREAT_MODEL.md)
and [security policy](../SECURITY.md) define concrete boundaries and reporting.
[Operations](OPERATIONS.md) defines metrics, containment, restore drills and
releases. No hidden pause key exists. Disabling a website/relay does not disable
on-chain calls. A compromised immutable operator key has no administrative
software repair; issuer-specific asset migration may be necessary.

## 14. Delivery, testing and production gates

| Stage | Required dependencies and acceptance evidence |
| --- | --- |
| Reproducible core | Exported sources, pinned builds, regressions, evidence consistency; preserve identities |
| Protocol compatibility | Updated decoder/SDK, credential/address variants, fresh limits and restored-state simulation |
| Expanded adapters | Complete explicit authority paths, supported/unknown cases, hostile configuration and drift tests |
| Read-only product | Durable ingestion/replay/gap detection, reconciled API, accessible inspection and SDK packaging |
| Scoped writes | Isolated signing, enforced simulation, outcome journal, funding caps and reconnect recovery |
| Production controller | New code, epoch/nonce enforcement, migration/incident drills, independent review |
| Production service | Assigned owners, licensing/hosting controls, measured objectives, provenance and deployment acceptance |
| Optional seed recovery | Reviewed quantum knowledge/privacy, feasible verifier and complete retirement/recovery lifecycle |

Tests must exercise actual host authorization, weighted predicates, conservation,
cache/recovery attacks, rollback, overflow, archival/restoration, nonce/expiry,
network/argument/domain binding and malformed inputs. Service coverage includes
duplicate/out-of-order ingestion, incomplete pages, retention gaps, checkpoint
crashes, database migration, reset, concurrent submission, lost responses and
browser reconnect. Independent implementations provide cross-checks but internal
execution is not an independent external audit.

Qualification records exact source/artifacts, protocol/cost model/settings and
workloads. Measure complete valid/hostile transactions, worst-case key counts,
restore costs, RPC rates, replay throughput and web latency. Select cost and
service budgets from real requirements and measurements; native research timings
are not production guarantees. Resource exhaustion is failed execution, not
cryptographic rejection.

Unresolved decisions: actual owners/release keys and repository license, supported
issuer/treasury adapters and classic-state trust, controller quorums/lifecycle,
native-verifier migration, wallet/KMS capability, hosting/history retention,
service objectives and SDK publication. Each needs an owner, decision record and
acceptance evidence before enabling the dependent capability. Assessment and
scoped enforcement can ship independently of legacy-recovery research success.
