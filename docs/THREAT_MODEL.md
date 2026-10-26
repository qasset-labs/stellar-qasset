# Q-Asset prototype threat model

Scope: the current declaration registry and disabled legacy-seed recovery account
interface, plus the separately implemented PQ backup recovery baseline described
below. Each has its own security boundary and receipts.
Review this alongside the exact source/artifact hashes in
[validation](validation.json), any [testnet receipts](testnet-deployment.json),
and the [reviewer scenarios](REVIEWER_GUIDE.md). This is a design and regression
test model, not an independent security audit.

## Assets and trust boundaries

| Asset or boundary | Current assurance |
| --- | --- |
| Registry registrar | Chosen at deployment; authorizes metadata tenant enrollment. No override of an existing tenant's administrator. |
| Tenant administrator | Can change that tenant's declarations; transfer requires outgoing and incoming consent. Correct labels are not assumed. |
| Asset label | An address naming a tenant. Enrollment does not establish control of the real asset. |
| Role declarations | Bounded weighted metadata used for arithmetic analysis. No real signer implementation is inspected. |
| Policy assessment | A point-in-time declared score, mutation revision and observation ledger, explicitly `Unverified`. |
| Verified security gate | Always rejects `UnverifiedPolicy`; it currently authorizes no operations. |
| Legacy-seed recovery configuration | Owner-authorized constructor stores immutable key/path configuration. It proves consent, not seed knowledge. |
| Legacy-seed recovery authorization | Unavailable: initialized instances always return `BackendUnavailable`. |
| External asset/account/prover | Outside the implemented security boundary. No funds or actual asset authorities are managed by this registry. |

The implementation relies on Soroban host authorization, transaction rollback,
storage/restoration semantics and constructor dispatch. It does not establish
network consensus security, fee-payer quantum resistance or wallet key custody.
Addresses must be interpreted on the intended network. Identical source names or
algorithm labels are insufficient to establish the identity of deployed code.

## Adversaries

An unauthenticated caller may submit malformed quorums, forge algorithm labels in
their own authorized tenant, copy public payload hashes, supply arbitrary recovery
bytes, reuse known addresses or call any exported method. A malicious registrar
may enroll misleading asset labels but must obtain the declared tenant's consent.
A compromised tenant administrator may lie about that tenant's entire policy.
Consumers may also misuse a declared score as a security certificate or ignore a
failed gate. These behaviors must not be confused with verified asset protection.

The proposed future quantum adversary can forge classical signatures after
recovering signing scalars from public keys. Current administrative authorization
is supplied by the configured Soroban address and is not certified quantum-safe by
this prototype. The implementation therefore does not promise that tenant
declarations remain honest or unchanged after classical administrator compromise.

## STRIDE analysis and regression evidence

The analysis covers spoofing, tampering, repudiation, information disclosure,
denial of service and elevation of privilege within the boundaries above.

| Threat | Control and regression evidence | Residual limit |
| --- | --- | --- |
| Spoof tenant administrator | Quorum mutations require the stored tenant's authorization. Exact-invocation tests reject absent authority and registrar-only attempts. | Compromise of the actual administrator permits metadata changes. |
| Claim an initialized instance or replace another tenant | Constructor configuration, no public initializer, duplicate enrollment rejection, two-party administrator transfer. | A deployer can choose an unusable registrar; enrollment is not proof of real asset ownership. |
| Inflate declared signing weight | Reject duplicate addresses, zero weights, weights above 255, zero/unreachable thresholds and more than 20 signers. | Different addresses can have the same underlying controller or keys. Twenty is a prototype bound, not a complete protocol signer-count claim. |
| Overstate PQ resilience | Classical-weight analysis and stronger QS4 predicate; all assessments remain `Unverified`; verified APIs always fail. | Algorithm labels can be false. The eight listed roles may omit real authority paths. |
| Forged recovery or copied public hash | No proof backend; no pairing shortcut; all authorization rejected. Native host test uses correctly computed public hashes and fresh nonces without authorization mocks. | Availability is intentionally zero. No valid-proof acceptance or recovery security is established. |
| Hide or repudiate declaration changes | Quorum/admin changes increment checked revisions and emit events; snapshot reports observation ledger. | No signed attestation, complete event archive or independent indexer is provided. Ledger number is observation time, not proof of last mutation. |
| Disclose private recovery material | Current configuration contains a public key, owner address and index; no seed is stored or accepted as a witness. | Declarations are public. A future local prover and wallet need their own secret-handling analysis; this contract establishes no seed-privacy guarantee for them. |
| Resource exhaustion | Per-quorum signer/weight bounds and fixed eight-role iteration. Input validation occurs before storing invalid quorums. | Host/network limits still apply; enrollment has no global tenant cap. Actual multi-contract PQ transaction costs remain unmeasured. |
| Expired or inconsistent storage | Permissionless `keep_alive` extends live policy/role state; re-enrollment rejects surviving orphaned role declarations. | Different entries can archive at different times; restoration, fees and keeper availability remain operational requirements. Archival is not deletion. |
| Ignore enforcement failure | A protected test contract propagates the registry error and shows no state change. | Arbitrary external callers can catch or ignore errors; the registry cannot enforce another contract's behavior. |

For the declared score, let `C` be total classical weight, `T` the threshold and
`Pmax` the largest PQ-labelled weight. A role is weak if missing or `C >= T`.
QS4 additionally requires `C + Pmax < T` for Treasury, Upgrade and Governance,
after QS3 has established required PQ-labelled weight for all eight roles. This
models compromise of all classical signers plus any one PQ-labelled signer. It
does not model shared operators, algorithm breaks or complete actual authority.

Unknown tenants cannot produce a policy assessment. Direct declared reads can
return conservative QS0/missing-role results; verified gates still reject.
Invalid typed arguments may fail at host decoding before a contract error is
returned. Availability failures must not be interpreted as stronger security.

## Deployment and operational assumptions

This revision changes ABI and storage. Deploy fresh instances with constructor
arguments; an upgrade does not rerun a constructor. Compare deployed WASM hashes
and network identifiers to the reviewed evidence. Testnet deployment demonstrates
execution on that network, not safe production use or current mainnet adoption.

Configuration and declarations are public. No mnemonic or real private seed is
needed for this demo. Recovery proof bytes have no secret witness semantics today.
No deployment or reviewer script should require entering an existing funded wallet's
mnemonic. Demo credentials and any future prover must have an explicit custody
and privacy model before production use.

Restoration and TTL maintenance can require additional transaction resources.
The registry offers a maintenance method; it does not run a service that guarantees
state liveness. Old receipts remain historical evidence after testnet resets or
configuration changes and must not be presented as a current security attestation.

## Requirements outside the current claim

The separate `pq-recovery-demo` / `tools/pq-demo` baseline verifies actual ML-DSA-65
signatures. [Its historical receipt](recovery-testnet.json) records successful
direct recovery and replacement-key actions, but a later audit reproduced an
authorization-cache revocation flaw. That deployment is superseded; the patched
local candidate has not been redeployed. The recovery key
must be enrolled in advance; the contract does not prove knowledge of a historical
Ed25519/SEP-5 seed. The existing registry and disabled legacy verifier retain the
boundaries described above.

The attack pre-authorized an old key under an aggregator invocation, performed
recovery, then invoked the protected counter using host-cached authorization in
the same tree. Changing the stored key was insufficient to revoke that cache.
Fresh-nonce old-key tests in separate transactions did not establish same-tree
revocation. The mitigation accepts exactly one auth context: this account's own
argument-free `protected` counter. Aggregator roots, unrelated calls and multiple
contexts reject. General smart-wallet/batch support remains outside the candidate
and needs an explicit epoch-aware execution design. Review the local regression
and candidate hash separately; old successful receipts do not validate this fix.

The baseline constructor requires owner consent and distinct active/recovery keys.
Owner consent gives no later administrative or signing bypass. Recovery requires
both the enrolled key's signature and replacement-key proof of possession, bound
to domain, network, contract, epoch, replacement key and expiry. It accepts expiry
from the current ledger through 1,000 ledgers ahead. Success increments epoch,
installs replacement authority and consumes recovery permanently. Normal host
payload signatures use a different context. Tests cover replay, altered/forged
credentials, wrong contract/network/context, expiry boundaries, old-key rejection
and unchanged state on failure.

Residual risks are explicit: RustCrypto `ml-dsa` 0.1.1 and this contract are
unaudited; fixture keys derive from one public root, so anybody can sign and their
custody offers no protection. Distinct role derivations are not independent security
factors. There is no repeated recovery, backup-key replacement, upgrade or full
wallet lifecycle. The protected counter is a test action, not a token/treasury
integration. Host auth and ML-DSA verification do not make the fee-payer envelope
or SCP quantum-safe. Instance archival still requires restoration; this account
does not guarantee keeper liveness. No funds should use this public-fixture demo.

The ordinary public SEP-5 checker separately validates derivation compatibility.
It is not zero knowledge and does not recover a scalar using a quantum attack.

The proposed recovery system must demonstrate an end-to-end quantum-sound proof
system, exact supported witness/derivation formats and parameters, transaction and
replacement-key binding, replay handling, prior enrollment, revocation, ownership
changes, and retirement of classical paths before an attacker can drain or rebind
the account. Historical seed knowledge alone must not restore a removed owner's
authority. No wrapper can retroactively gain control over an unrelated classic
account. A 24-word phrase does not by itself prove sufficient random entropy.

Published seed-lifting work supplies relevant methods, not completed Soroban
feasibility or production approval. Hash-based witness secrecy cannot compensate
for a quantum-vulnerable pairing proof. Full proof size, hostile-input costs,
memory and transport need measurement on the target network and independent
cryptographic review.

The proposed verified registry needs supported, versioned adapters that establish
real signer algorithms and configuration, complete asset authority coverage,
and the administrators/upgrades/verifier changes that can bypass those policies.
Unsupported or missing evidence must remain unknown. No self-reported code hash,
algorithm string or tenant approval can establish that trust boundary alone.

Those are future acceptance requirements. The current safety property is narrower:
unverified declarations and unsupported recovery bytes cannot satisfy this
prototype's reserved verified-authorization interfaces.

## Scalar disclosure in research variants

The new scalar-output experiments retain a private seed/root witness but expose
the full clamped Ed25519 signing scalar. An ordinary attacker can then sign for
any still-active or reused classical key. Retirement must be independently
authenticated and finalized before disclosure to any untrusted party, including
RPC/fee-payer services. Combining retirement and publication in one public
transaction does not remove the prepublication race. A fixture flag is not
observed retirement. See [scalar review](SCALAR_RECOVERY_REVIEW.md).

The strict local ceremony demonstrates native proof/signature verification and
a sequential model transition. It does not cover durable storage, concurrent
consumption, actual external approvals or cached Stellar authorization. The
separate compact STARK primitive binds only its public scalar and dummy action
digest; its masking, proximity-gap and quantum knowledge assumptions remain
unapproved. See [compact review](COMPACT_BACKEND_REVIEW.md).

## Verifier portability and transport follow-up

The proof mailbox commits only public upload bytes. Sponsor authentication, verifier/statement labels and successful sealing are not evidence of seed knowledge or current recovery authority. A future consumer must verify the complete pinned relation and current account policy atomically. Raw Wasm fixture guards cover only the published key; a generic integration must validate scalar-to-protected-key identity. Preserve finalized classical-authority retirement before any real scalar disclosure. See [port](VERIFIER_PORT_EVIDENCE.md) and [transport](PROOF_MAILBOX_EVIDENCE.md).

## Compact verifier and actual host-cost follow-up

Additional boundaries: compact preprocessing must expand to the pinned original relation, retain every padded constraint and reject noncanonical ULEB/EOF. Metadata-only circuit state must never export as a full unpadded circuit. Generic point validity does not attest who selected the protected key. CPU/memory exhaustion is failed execution, not proof rejection. Explicitly overridden registration or expanded diagnostic budgets never establish network feasibility. See [successor evidence](VERIFIER_NEXT_EVIDENCE.md).
