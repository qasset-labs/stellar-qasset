# Q-Asset architecture — security revision 0.5

Current recovery components and remaining gates: [implementation status](RECOVERY_IMPLEMENTATION_STATUS.md) and [successor evidence](VERIFIER_NEXT_EVIDENCE.md).

Review date: 2026-10-19. Recovery architecture and execution costs remain unresolved.

## 1. Scope and threat model

The implemented registry analyzes **administrator-declared** role quorums. It
cannot infer arbitrary contract semantics, prove asset ownership from enrollment,
or prove that a declared algorithm is enforced. Verified authority adapters,
asset-level PQ integration, scanning, and legacy-seed ZK recovery remain future
work. A separate enrolled-key ML-DSA baseline was exercised on testnet, but a later
audit reproduced a same-invocation cached-authorization flaw. Its deployment is
historical pre-audit evidence. The revised counter-scoped candidate is local and
has not been redeployed. Neither version verifies the registry or activates the
disabled legacy-seed interface.

Stellar G-addresses encode an Ed25519 public key: exposure does not begin at first
use. Current authorization depends on the account's configured keys and thresholds.
The relevant attack is future signature forgery. SCP/network security, transport,
fee sponsorship, and per-account authorization are separate assurance boundaries.
The SDF plan discusses both migration and dormant-account recovery [R1].

## 2. Implemented registry

`QAssetRegistry` receives its registrar in `__constructor(registrar)`. There is
no public initializer. A registrar can enroll metadata tenants but cannot replace
an existing tenant or edit its quorums without the tenant administrator's consent.
Enrollment is not verification of authority over the address named by `asset`.

| API | Behavior |
| --- | --- |
| `register_asset(asset, admin)` | Requires registrar and incoming admin authorization; rejects an existing tenant. |
| `asset_admin(asset)` | Returns the tenant administrator. |
| `transfer_asset_admin(asset, admin)` | Requires outgoing and incoming administrators; registrar has no override. |
| `set_role_quorum(asset, role, quorum)` | Requires tenant admin; validates and records the declaration. |
| `get_role_quorum(asset, role)` | Reads a declaration, not the real asset's signing configuration. |
| `list_weak_paths(asset)` | Reports missing or classically satisfiable declared roles. |
| `declared_security_level(asset)` | Calculates QS0–QS4 over declared metadata. |
| `policy_assessment(asset)` | Returns declared level, revision, observation ledger, and `Unverified`. |
| `quantum_security_level(asset)` | Returns `UnverifiedPolicy`; no verified implementation is integrated. |
| `require_min_qs(asset, level)` | Returns `UnverifiedPolicy`, including when the requested level is QS0. |
| `keep_alive(asset)` | Permissionlessly extends live policy/role TTL; archived state still needs restoration. |

No arbitrary external account ABI, self-reported code hash, administrator boolean,
or unauthenticated verifier response can promote a declaration to verified status.
The enforcement API intentionally blocks use until an actual adapter is integrated.
A caller must propagate its failure; catching and ignoring an error is not enforcement.

The eight roles are Mint, Burn, Freeze, Clawback, Treasury, Upgrade, Governance,
and Recovery. Additional real authorities (pause guardians, compliance contracts,
registry administrators, code and verifier upgrades) must be covered by future
adapters. Eight named fields alone do not prove complete coverage.

### Declared-score rules

Let C be the total classical weight, T the role threshold, and Pmax the largest
single PQ-labelled weight. A declared role is weak if absent or C >= T.

| Level | Declared condition |
| --- | --- |
| QS0 | No PQ-labelled signer is recorded. |
| QS1 | A PQ label exists but Treasury, Upgrade, or Governance is weak. |
| QS2 | Those three roles are not weak, but another role is weak. |
| QS3 | All eight declared roles require a PQ-labelled contribution. |
| QS4 | QS3, and C + Pmax < T for each of the three highest-impact roles. |

QS4 now requires at least two PQ-labelled contributions even after every classical
key is assumed compromised. A classical weight-1 plus PQ weight-1 quorum at threshold
2 is QS3, not QS4. Distinct addresses still do not establish independent keys or
operators. These are declared arithmetic predicates, not verified security guarantees.
Missing roles are conservative unknowns; an intentionally absent authority will need
an independently validated non-applicability proof in a future adapter.

Individual weights are 1–255, sums/revisions use checked arithmetic, and duplicate
addresses, zero or unreachable thresholds, and more than 20 entries are rejected.
Twenty is this prototype's bounded policy limit; it is not a claim that classic
Stellar's master key plus additional signer array has exactly twenty entries.
Quorum and administrator changes emit events and increment the policy revision.
Permissionless TTL maintenance improves liveness but is not guaranteed by a keeper.
If tenant metadata is missing but role declarations remain, enrollment rejects
`OrphanedPolicy` rather than inheriting stale quorums or resetting their identity.
Restore and reconcile the original state; this is a defensive consistency check,
not an assertion that ordinary archival deletes persistent entries.

## 3. Recovery boundary

`SeedRecoveryVerifier` is a reserved custom-account interface, not an operational
recovery mechanism. It has owner-authorized atomic construction with
`(owner, protected_pubkey, derivation_index)` and immutable configuration. The index
is the unhardened account index n, less than 2^31, for m/44'/148'/n'.

`RecoveryProof { binding, proof: Bytes }` is only a transport placeholder.
`backend_available()` returns false and `__check_auth` always returns
`BackendUnavailable`. There is no activation, reconfiguration, or upgrade function.
The former constant pairing, ignored proof points, and unauthenticated initializer
are removed. A public payload equality check never established seed knowledge or
cryptographic binding. No disabled recovery entry is classified as post-quantum.

A future recovery feature can only help previously enrolled compatible Soroban
accounts. It cannot acquire authority over arbitrary dormant G-accounts. Enrollment,
revocation, ownership changes, classical fallback retirement, and the ability to
change verifiers or remove recovery must be explicit. An original participant who
has been removed must not regain authority merely by showing an old seed.

### Required proof relation and feasibility gate

A candidate must prove knowledge of an accepted high-entropy preimage that derives
the enrolled key using the exact supported wallet derivation [R21, R22]. The proof
must bind the Soroban auth payload, network, account/contract, configuration epoch,
path, recovery action, replacement authority, and expiry. Host nonce replay checks
complement rather than replace cryptographic statement binding.

Post-quantum soundness must hold for the complete proof system, including any
recursive compression. Groth16/BN254 is excluded from the PQ recovery claim [R1].
Witness secrecy by itself is insufficient. Mnemonic length does not prove entropy;
24 words is standard BIP39's maximum, not a minimum that permits arbitrary longer
phrases. A circuit starting from a raw BIP39 seed cannot enforce mnemonic word count.
Raw Stellar secret seeds and SEP-5 HD wallets also need distinct support policies.

Before activation: specify the relation and parameters; validate SEP-5 vectors;
implement actual negative proof tests; measure exact proof size, verifier cost,
fees, memory, and hostile inputs against live Soroban limits [R23]; obtain independent
cryptographic review; verify authorization lifecycle and fresh deployments. An
infeasible backend leaves recovery unavailable and requires a revised technical scope.

## 4. Reference review and originality

Six original external technical references were opened. Six public code repositories were downloaded at recorded commits and their
relevant authentication/derivation files inspected. Third-party builds, deployments,
and benchmarks were not independently rerun. `reference-review.json` preserves the
link inventory, pinned source evidence and access limits.

ZKPoSP is a preprint. Its accessible abstract conditions quantum security on the
NIZK; QBIP32 is a different derivation construction. The full PDF returned access
errors, so its detailed theorem was not independently inspected [R2]. Author
technical notes identify RISC Zero succinct receipts and Plonky3 hiding-FRI
implementations as candidates [R24, R25]. The mobile note repeats server signing-proof
timings of 12–13 seconds and 9–10 ms verification; these are author reports, not
reproduced results or full SEP-5-on-Soroban measurements. Derivation and per-message
proofs are different workloads.

ZKBoo has relevant SLIP-0010/Ed25519 circuit code, but its README reports very large
proofs and unfinished unaudited lifting details [R3]. Its LGPL license must be
respected before reuse. Roasbeef's Bitcoin implementation uses a different statement;
its reduced variants reveal different public data and its current claim is not
transaction-bound [R5, R11]. Neither establishes Soroban SEP-5 feasibility.
Optech is corroboration [R4]; CoinDesk is secondary background [R6].

Soundness implements a Falcon smart account and explicitly plans proof-of-seed
signers; there is direct planned recovery overlap [R7]. Latticework has actual ML-DSA verification, but the reviewed account wrapper's
initializer can overwrite its key without authorization [R8]. Qstellar's reviewed
verifier checks formatting rather than a signature over its message [R9]. Neither
wrapper is imported into this revision. devnWisdom's token authority checks are
scheme-agnostic Address authorization, not necessarily classical-only [R10].
OpenZeppelin provides existing policy primitives [R17]. Quorum publishes mandatory
PQ approval thresholds on Solana, although linked source was unavailable to this
review [R18]. Universal first-ever/no-overlap claims are withdrawn. Baldimtsi et al.'s EdDSA seed-witness research is identified [R26], and Strongpoint
is adjacent institutional custody work [R27], with production and Stellar scope
unverified here. The defensible
proposed contribution is Stellar asset-role coverage bound to actual configuration
and enforced sensitive operations, building on existing primitives.

## 6. Validation, migration and remaining work

Regression coverage includes real Soroban require_auth rejection of forged recovery
credentials with correctly computed public hashes and fresh nonces; constructor
owner authorization; rejection of old initializers; tenant isolation/admin transfer;
forged declared QS4 failing a cross-contract gate; weighted PQ fault tolerance;
validation, policy revisions, event behavior and TTL maintenance. See test sources
and the validation commands in README. Tests are not an independent audit.

This is a breaking pre-release ABI/storage revision. Old initialize, recovery proof
point fields and success counters are removed. Rename score consumers to
`declared_security_level` and display Unverified prominently. Deploy fresh contracts
with constructor arguments; do not upgrade old instances expecting constructors to
run. Before migrating any real integration, independently establish its current
control and compatible quorum configuration. Reviewer scripts submit explicitly
scoped testnet demonstrations; no mainnet deployment is claimed.

The security repairs close unsafe code paths, but do not complete the proposed product.
Production hardening, verified authority adapters, legacy-seed ZK recovery,
scanner/SDK, signed attestations, partner integrations and independent audits remain
explicit work. Current local and testnet receipts are reviewer evidence, not
production approval. No claim of full originality or production approval is made.

## 7. PQ backup recovery audit and deployment boundary

An adversarial regression demonstrated that old-key authorization validated and
cached by the host before recovery could authorize a later protected action after
recovery in the same invocation tree. Separate direct calls with fresh nonces did
not test this case. Replacing stored keys does not invalidate host authorization
already cached for the current tree.

The local mitigation restricts `__check_auth` to exactly one context: its own
`protected` counter method, with no arguments. Aggregator roots, unrelated methods
and multiple contexts reject. Generic wallet or batched asset authorization needs
a separately designed epoch-aware execution policy. This changed WASM has not
been deployed after the finding; old testnet evidence is historical and superseded.


`contracts/pq-recovery-demo` is a separate ML-DSA-65 custom account. Its constructor
requires owner consent and distinct active/recovery keys; the owner has no later
bypass. `protected` verifies the host authorization payload with the active key and
increments a counter. `recover` requires an enrolled recovery-key signature plus
replacement-key proof of possession over a canonical XDR statement containing the
domain, network ID, contract, expected epoch, replacement key and expiry. Normal
and recovery signature contexts differ. Expiry must be current and within 1,000
ledgers; replacement differs from both stored keys. Success replaces active
identity, increments epoch and permanently consumes recovery. No initializer,
upgrade, recovery-key replacement or repeated recovery is exposed.

`tools/pq-demo` derives three role-separated ML-DSA keys with HKDF-SHA512 from a
published root. All secrets are public and share that root: these are not independent
factors or production keys. RustCrypto `ml-dsa` 0.1.1 and this account are unaudited.
The account verifies signatures, not a historical Ed25519/SEP-5 seed proof. The
historical generic-auth version and patched counter-only candidate are different
artifacts; successful old direct-call receipts cannot establish patched deployment.

[Historical recovery receipts](recovery-testnet.json) record four confirmed successful
transactions and 17 checks: deployment, initial-key action, one-time recovery and
replacement-key action. Final epoch is 1, counter 2 and recovery consumed. Forged
recovery, wrong replacement possession, replay, old-key fresh-nonce and fee-payer
bypass checks reject. Negative cases are enforced-auth RPC simulations, not committed
transactions. Recorded simulation costs are 204,473,156 instructions for recovery
and about 102.86 million for an action: this exact fixture, not a production or ZK
benchmark.

[Metadata receipts](testnet-deployment.json) separately record 17 confirmed
transactions and 20 checks. The asset is only a metadata identity; no token is
issued. The legacy verifier remains disabled. The historical
[public verification](testnet-verification.json) covered old deployment receipts
and state. The strengthened verifier must reject the patched-local/old-deployment
WASM mismatch; no old pass establishes deployment of the audited candidate.

[Local validation](validation.json) records results for its exact source hashes.
The separate compatibility checker has 168 public SEP-5 relation checks across five groups and
15 addresses. A registry oracle additionally exercises 342 quorum cases inside a
test. See [reviewer guide](REVIEWER_GUIDE.md) for reproduction. These delivered
baselines are evidence; remaining legacy-seed ZK and asset-adapter work must
be scoped separately.

## References

Reference IDs, primary URLs and inspection scope appear in `reference-review.json`.

## Verifier portability and transport follow-up

A separate research-only [proof mailbox](PROOF_MAILBOX_EVIDENCE.md) accepts authenticated ordered temporary chunks, seals an immutable byte commitment and offers bounded reads. Its uploader is a transport sponsor, not a recovery authorizer; every verified gate rejects. The [verifier port](VERIFIER_PORT_EVIDENCE.md) is an isolated raw Wasm fixture, not a contract connected to registry or recovery authority.

## Compact verifier and actual host-cost follow-up

The [successor verifier](VERIFIER_NEXT_EVIDENCE.md) introduces strict compact immutable preprocessing, owned padded constraints, an external raw input ABI and equivalent table-free arithmetic. The [generic point-binding library](../tools/recovery-key-binding/README.md) checks mathematical scalar/key equality with a trusted-key prerequisite. The actual SDK measurement wrapper hashes the same immutable host Bytes before private decoding and has no recovery authority. Neither raw module size fit nor a sealed mailbox establishes a successful integrated account operation. See [component diagram and gate matrix](RECOVERY_IMPLEMENTATION_STATUS.md).
