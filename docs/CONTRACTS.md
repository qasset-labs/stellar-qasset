# Contract and evidence interface reference

Baseline: 2026-11-05. This reference describes current source. Proposed controller,
SDK and service interfaces are specified separately in [architecture](ARCHITECTURE.md)
and [clients/services](CLIENTS_AND_SERVICES.md). Contract methods are Rust signatures;
clients must use the exact release's contract specification/XDR, not inferred JSON.
All five packages are pre-release, `publish = false`, and expose no upgrade method.

## Registry API

Source: [implementation](../contracts/qasset-registry/src/lib.rs) and
[tests](../contracts/qasset-registry/src/test.rs). `Result` errors propagate as
contract failures; generated test clients expose `try_*` helpers. Host decoding,
authentication, resource and missing archived-footprint failures may occur before
a contract error is returned.

| Method (excluding `Env`) | Return | Authorization and semantics |
| --- | --- | --- |
| `__constructor(admin: Address)` | `()` | Fixed registrar; no `require_auth` in constructor |
| `register_asset(asset: Address, admin: Address)` | `Result<(), Error>` | Registrar plus incoming admin if distinct; reject duplicates/orphaned roles; revision 0 |
| `asset_admin(asset: Address)` | `Result<Address, Error>` | Public tenant lookup |
| `transfer_asset_admin(asset: Address, admin: Address)` | `Result<(), Error>` | Stored outgoing and incoming admin if distinct; revision +1, even self-transfer |
| `set_role_quorum(asset, role: Role, quorum: Quorum)` | `Result<(), Error>` | Tenant admin; unconditional last successful writer |
| `set_role_quorum_if_revision(asset, role, quorum, expected_revision: u64)` | `Result<(), Error>` | Tenant admin; compare revision before setter; error 15 on conflict |
| `get_role_quorum(asset, role)` | `Option<Quorum>` | No tenant/auth check, no TTL renewal |
| `list_weak_paths(asset)` | `Vec<WeakPath>` | Eight roles; missing roles reported conservatively |
| `declared_security_level(asset)` | `QsLevel` | Declaration only; unknown label can return QS0 |
| `policy_assessment(asset)` | `Result<PolicyAssessment, Error>` | Requires tenant; observation ledger, current revision, declared level, `Unverified` |
| `quantum_security_level(asset)` | `Result<QsLevel, Error>` | Always `UnverifiedPolicy` |
| `require_min_qs(asset, min_level: QsLevel)` | `Result<(), Error>` | Always `UnverifiedPolicy`, even QS0 |
| `keep_alive(asset)` | `Result<(), Error>` | Public; retains live tenant/instance and present role entries |

`Quorum { signers: Vec<Signer>, threshold: u32 }`;
`Signer { address: Address, algo: SignerAlgo, weight: u32 }`.
Algorithms are `Ed25519`, `Secp256r1`, `MlDsa44`, `MlDsa65`, `MlDsa87` labels.
Roles are Mint, Burn, Freeze, Clawback, Treasury, Upgrade, Governance and Recovery.
`PolicyAssessment` fields are `asset`, `declared_level`, `policy_revision: u64`,
`ledger_sequence: u32`, and `verification: VerificationStatus` (only `Unverified`).
`WeakPath` includes role, reason (`Unregistered` or
`ThresholdMeetableClassically`), classical/PQ weights and threshold.
The [QS rules](ARCHITECTURE.md#qs0qs4-standard) define the exact calculation.

### Storage, events and errors

| Key/location | Value | Lifecycle |
| --- | --- | --- |
| Instance `ADMIN` | Registrar `Address` | Fixed for deployment lifetime |
| Persistent `(ASSET, asset)` | Private `AssetPolicy { admin, revision }` | Register, transfer, quorum mutation; no delete |
| Persistent `(ROLE, asset, role)` | `Quorum` | Replace whole value; no role-delete API |

`load_policy` renews tenant and instance; writes renew written entries.
`get_role_quorum`, `list_weak_paths`, and `declared_security_level` do not renew
roles. `keep_alive` checks each of eight roles. All renewals use target
`min(120_960, storage.max_ttl())`, threshold half-target. Instance extension also
covers executable according to SDK/host semantics; dependency entries still need
separate maintenance. Simulation does not persist renewal.

Current SDK contract events use the generated spec's topic/data encoding:

| Event | Indexed fields | Data fields | Trigger |
| --- | --- | --- | --- |
| `AssetAdminChanged` | `asset` | `admin`, `revision` | Registration at 0, or transfer at incremented revision |
| `QuorumSet` | `asset`, `role` | `threshold`, full `signers`, `revision` | Each successful setter |

There is no recovery/transfer event from this registry. A failed invocation
commits neither policy changes nor its contract events; diagnostic simulation
output is not a committed event stream. Index from the generated event schema,
not guessed human-readable event topics.

| Code | Registry error | Code | Registry error |
| ---: | --- | ---: | --- |
| 1 | NotAdmin (reserved; actual auth is host-enforced) | 2 | ThresholdUnreachable |
| 3 | ZeroThreshold | 4 | AssetNotRegistered |
| 5 | QsLevelTooLow (reserved) | 6 | ZeroSignerWeight |
| 7 | AssetAlreadyRegistered | 8 | DuplicateSigner |
| 9 | TooManySigners | 10 | UnverifiedPolicy |
| 11 | SignerWeightTooHigh | 12 | WeightOverflow |
| 13 | RevisionOverflow | 14 | OrphanedPolicy |
| 15 | RevisionConflict | | |

Validation: at most 20 unique addresses, weights 1–255, reachable nonzero
threshold. Revisions use checked addition. No token arithmetic is performed.
`OrphanedPolicy` prevents silent inheritance/reset when metadata is absent but
roles remain; restoration is the normal response to archival, not re-registration.
Guarded conflict tests verify unchanged revision, quorum and events. The legacy
unconditional setter remains callable; a client-only preference cannot disable it.

## Fixed SAC administrator

Source: [implementation](../contracts/qasset-sac-admin/src/lib.rs),
[adversarial tests](../contracts/qasset-sac-admin/src/test.rs).

| Method | Effect |
| --- | --- |
| `__constructor(sac: Address, operator_key: Bytes) -> Result<(), Error>` | Decode exactly 1,952-byte ML-DSA-65 key; store immutable SAC/key; renew instance; no owner authorization/possession proof |
| `sac() -> Address` | Configured SAC |
| `operator_key() -> Bytes` | Public key bytes |
| `protected_function() -> Symbol` | `set_authorized` |
| Host `__check_auth(payload: Hash<32>, signature: Bytes, contexts: Vec<Context>)` | Check allowed scope, then verify key/signature and renew instance |

Signature is exactly 3,309 bytes, pure ML-DSA over the host's 32-byte digest with
context `qasset-sac-admin-auth-v1`, using pinned RustCrypto `ml-dsa` 0.1.1 inside
Wasm. This implementation is unaudited. It does not use CAP-87.
Instance enum keys are `Sac` and `OperatorKey`. No custom events are emitted.
SAC emits its own state-change events. TTL uses the same bounded target/threshold
as registry. Rejected auth must not persist renewal or change SAC authorization.

Errors: 1 `BadKeyLength`, 2 `BadSignatureLength`, 3 `InvalidSignature`,
4 `UnsupportedAuthContext`. Scope is one `Context::Contract` for configured SAC,
function `set_authorized`, exactly two arguments. Argument values are host-signed;
types are SAC-validated. Classic trustline deauthorization uses the SAC
maintain-liabilities semantics; the registry role name `Freeze` does not change them. Other methods, SACs, create-contract contexts and composite
auth scopes reject before signature verification. No public dispatch entry point
calls the SAC as this contract. There is no mint/clawback/burn/rotation/recovery/
set-admin authorization path, no registrar lookup and no dynamic registry gate.

Constructor does not verify that the address is a SAC. Permission to deploy is
not permission to administer the asset. `set_admin` on the actual SAC requires its
current administrator. After handover, the current fixed policy cannot hand over
again, even with a genuine operator signature. Key loss or compromise is therefore
a deployment-lifecycle blocker for production use.

## Recovery components

### Enrolled ML-DSA counter

Source: [implementation](../contracts/pq-recovery-demo/src/lib.rs),
[tests](../contracts/pq-recovery-demo/src/test.rs).

`__constructor(owner, initial_key, recovery_key)` requires owner consent, decodes
two 1,952-byte keys and rejects equality. Instance keys: `ActiveKey`, `RecoveryKey`,
`Epoch = 0u64`, `Consumed = false`, `Counter = 0u64`. No TTL extension or events.
Public reads: `active_key()`, `epoch()`, `recovery_enabled()`, `counter()`.
`protected() -> Result<u64, Error>` requires this account's authorization and
increments the checked counter. Its auth guard accepts only one context for its
own argument-free `protected` method; normal signing context is `qasset-pq-auth-v1`.

`recovery_digest(expected_epoch, replacement_key, valid_until_ledger)` returns
SHA-256 of canonical Soroban XDR tuple:

```text
("qassetrecoverv1", network_id, current_contract_address,
 expected_epoch: u64, replacement_key: Bytes, valid_until_ledger: u32)
```

`recover(expected_epoch, replacement_key, valid_until_ledger,
recovery_signature, replacement_signature)` requires unconsumed recovery, exact
epoch, expiry `now <= expiry <= now + 1000`, a different replacement from both
stored keys, enrolled-backup signature and replacement possession over this digest
with context `qasset-recover-v1`. Success replaces active key, increments checked
epoch and permanently consumes recovery. It does not reset counter. The owner
has no later bypass; recovery key has no replacement/re-enrollment API.

Errors 1–11: `BadKeyLength`, `BadSignatureLength`, `InvalidSignature`,
`RecoveryConsumed`, `WrongEpoch`, `Expired`, `ExpiryTooFar`, `KeyReuse`,
`CounterOverflow`, `EpochOverflow`, `UnsupportedAuthContext`.
Failure rolls back all mutation. Public fixture secrets make this demo unsuitable
for funds. Old Testnet receipts are for pre-fix code; source tests cover the
same-invocation cached-authorization finding, not a generalized wallet.

### Disabled seed account

Source: [implementation](../contracts/seed-recovery-verifier/src/lib.rs).
Constructor `(owner, protected_pubkey: BytesN<32>, derivation_index: u32)` requires
owner auth and `index < 2^31`. Instance `Config` stores immutable `RecoveryConfig`.
`config()` reads it; `backend_available()` is false. Host signature type is
`RecoveryProof { binding: BytesN<32>, proof: Bytes }`. `__check_auth` returns
`BackendUnavailable` (1), or `NotInitialized` (2) without config. Constructor error
3 is `InvalidDerivationIndex`. Public binding equality is not seed knowledge.
No activation/upgrade, proof acceptance, event or TTL maintenance is implemented.

### Unverified proof mailbox

Source: [implementation](../contracts/recovery-proof-mailbox/src/lib.rs),
[tests](../contracts/recovery-proof-mailbox/src/test.rs).
`UploadHeader` holds uploader, 32-byte nonce, 64-byte statement, 32-byte verifier
and parameter IDs, length and exclusive expiry. Session ID is SHA-256 of a typed
XDR vector binding domain `qasset-proof-upload-v1`, network, contract and every
header field plus chunk size. `expected` commitment is fixed at first opening,
though not included in that ID. Session nonce/header must be unique while live.

| Method | Semantics |
| --- | --- |
| `open(header, expected: BytesN<32>) -> Result<BytesN<32>, Error>` | Uploader auth; length 1..1 MiB; `now < expires <= now + 1000`; create session |
| `append(id, index: u32, data: Bytes) -> Result<u32, Error>` | Uploader auth; next index only; exact 32 KiB chunk except final remainder; return received chunk count |
| `seal(id) -> Result<UploadMetadata, Error>` | Permissionless; all chunks and final rolling hash must match; mark `sealed_unverified` |
| `metadata(id)` | Public live metadata; fails at logical expiry |
| `read_slice(id, index, offset, length)` | Public sealed data; positive length <=8 KiB and within one chunk |
| `backend_available()` / `require_verified(id)` | False / always `BackendUnavailable` |

Temporary keys are `Session(id)` and `Chunk(id,index)`. Persist/append extends
TTL using `expires - now + 1`; logical checks reject at `now >= expires` even
if minimum network TTL retains bytes. No restore of deleted temporary state.
Maximum chunks: 32. Rolling start is SHA-256 of `qasset-upload-start-v1 || id`;
advance hashes `qasset-upload-chunk-v1 || rolling || u32BE(index) || u32BE(len) || data`.
`UploadOpened` topics include ID, data length; `UploadSealedUnverified` topics
include ID, data commitment. There are no append/approval/recovery events.

Errors 1–13: `InvalidSize`, `InvalidExpiry`, `AlreadyExists`, `NotFound`, `Expired`,
`AlreadySealed`, `InvalidIndex`, `InvalidChunk`, `Incomplete`, `CommitmentMismatch`,
`Unsealed`, `BackendUnavailable`, `InvalidRange`. Any invalid attempt preserves
state. Sealing grants no recovery authority; all bytes and labels are public.

## Evidence and compatibility

Schema `qasset-authority-assessment-v2`, tool 2.0.0, binds input byte hashes/sizes,
network, ledger range, tool source hashes, issuer state, SAC/admin identity,
mechanism and policy revisions. Source fingerprint matching is strict; changing
an included implementation can require a newly versioned assessment. Exact
historical schema-v1 bodies alone receive compatibility treatment.
The verifier separately decodes XDR and checks credentials, mutations, error
causes, post-lock order and live configuration. It is a separate implementation,
not an independent external audit. Negative simulations remain RPC transcripts.

CLI exit 0: `SUCCESS` within mode/scope. Exit 1: `STALE` or `INVALID`, distinguished
by JSON. Exit 2: `INCONCLUSIVE`. Offline mode is recorded consistency only.
[Reproduction](QASSET_POC_EVIDENCE.md) is the executable current usage reference.
ABI/storage changes require new versioned deployments; constructors do not rerun
on upgrade. Never modify historical manifests/inputs to disguise incompatibility.
