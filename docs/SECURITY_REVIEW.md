# Q-Asset cryptographic and implementation review

Date: 2026-10-19. First-party adversarial review with internal cross-checks. This is not an independent external audit,
FIPS certification, or a proof of end-to-end quantum security.

## Decision

The proposed original-seed recovery mechanism is conditionally plausible. Its
proof backend, concrete parameters and Soroban feasibility remain unestablished.
Production and original-seed recovery approval are withheld.

Follow-up evidence now includes an actual off-chain SEP-5 root proof and a
separate-process verifier, using deliberately insecure reduced-round research
parameters. This closes the lack of an executable functional experiment; it does
not close A-01, validate quantum extraction/zero knowledge, or enable recovery.
Measured proof size excludes this backend as a direct single-transaction candidate
under the observed limits. See [recovery evidence](RECOVERY_EVIDENCE.md).

A concrete authorization-composition defect was reproduced in the separate
ML-DSA counter demonstration and fixed locally. Its previously deployed testnet
revision is superseded. The patched candidate has not been redeployed. No further
deployment or transaction submission occurred after the user's audit instruction.

## Findings and disposition

| ID | Severity in reviewed scope | Finding | Disposition |
| --- | --- | --- | --- |
| C-01 | Medium for the counter; potentially High for custody reuse | Old-key authorization remains cached across recovery within one authorization tree. | Fixed locally: only one self/protected/no-argument context is accepted. Historical testnet code superseded. |
| T-01 | Medium | Successful receipts were not bound to claimed operations. | Fixed: envelope/network hashes, fee signatures, exact calls/arguments, authorization roots, order and uniqueness verified. |
| T-02 | Medium | On-chain WASM was compared only to mutable JSON hashes. | Fixed: current validation inputs and local artifacts must match recorded source/build/deployment evidence. Superseded baseline rejects current verification. |
| T-03 | Low | Interrupted validation could leave an older passed file. | Fixed: save in-progress before tools, record exceptions, pin inputs before checks and reject changes during execution. |
| T-04 | Low | Build provenance incomplete. | Improved: tool/package versions and build-environment fingerprints recorded. Hermetic reproduction and transitive Python hash locks remain outside this evidence. |
| T-05 | Low | CLI log changes could omit required receipts without failing. | Fixed: unique receipt hashes, every contract creation and exact ordered mutation coverage required; offline removal/reordering tests added. |
| A-01 | Release-blocking assurance gap | No validated quantum-secure original-seed proof backend or complete asset-authority lifecycle. | Open. Legacy verifier remains disabled. This is missing assurance, not a demonstrated mathematical break. |
| R-01 | Low in the isolated research scope | Initial compact proof decoder accepted trailing encoded bytes. | Fixed with strict remaining-byte rejection and input-size bounds; actual positive and trailing-data negatives rerun on the final verifier. AIR unchanged; original generation provenance retained. |
| V-01 | Verifier portability defect | Native usize transcript encoding differs on Wasm32. | Fixed fork uses explicit u64LE; unchanged proof and original transition vector pass. |
| V-02 | Resource/representation defect | Duplicate constraint vector and oversized fixed preprocessing. | Successor moves exact constraints, retains metadata, rejects invalid export and uses lossless canonical encoding. |
| V-03 | Integration gap | Point guard supported only a public fixture. | Generic no_std binding component implemented/tested; trusted current account-key integration remains open. |
| E-01 | Evidence-quality issue | Python optimization disabled new assertion-based evidence checks. | Explicit checks and optimized-mode mutation regressions added. |
| F-01 | Release-blocking feasibility gap | Actual SDK code is oversized and canonical verification exhausts local CPU budgets. | Open: raw successor size/memory pass does not close SDK code/CPU or full transaction feasibility. |
| R-02 | Evidence-quality issue | A ceremony negative could count an unrelated `ValueError` as native proof rejection. | Fixed: a distinct exact-response proof-rejection type and independently checked valid replacement signature are required for that result. |

No additional critical/high implementation defect was demonstrated within the
counter/metadata scope. This is not assurance that none exists. Public fixture
keys deliberately provide no custody protection.

## C-01 reproduction and mitigation

The failing regression used actual ML-DSA signatures and a real Soroban
authorization entry, without authorization mocks after construction:

1. A batch contract requests the account's authorization under its old active key.
2. It invokes recovery with valid backup and replacement-key signatures.
3. It invokes the protected counter under that previously authorized tree.

The old implementation returned `Ok(Ok(1))` after the active key changed. The host
had already validated the old authority and reused it. The prerequisite is old-key
signing ability plus a valid recovery intent that can be relayed; this does not
forge an ML-DSA signature from its public key.

The patch inspects the complete authorization context before signature verification.
Empty/external/composite contexts, other methods/arguments and contract creation
reject. Only one invocation of this account's own argument-free counter is allowed.
The counter cannot call recovery internally. The regression now rejects with
unchanged state; direct recovery and replacement-key authorization still pass.

This is a deliberately narrow mitigation, not a general wallet solution. Future
asset integrations need epoch-aware operation checks, recovery ordering, delegation
and coverage of external approvals/cached authorities. Do not remove the restriction
and infer immediate revocation from updating a key in storage.

## Cryptographic approach

Let `k` be the Ed25519 leaf seed, `a = LE(clamp(SHA512(k)[0:32]))`, and `A = [a]B`.
Shor reveals `a mod l`, not automatically `k` or the HD root. A correctly bound
quantum-secure proof of knowledge of `k` could distinguish retained backups from
scalar-only forgery. Proving knowledge of `a` would not.

A Stellar `S...` secret encodes the leaf seed. Stealing it gives the leaf-recovery
witness. Root-only recovery can distinguish isolated leaf theft only if the root
remains secret and no classical bypass survives. Neither relation restores a lost
backup or establishes current ownership after legitimate revocation.

The proof system needs quantum knowledge/extraction, quantum zero knowledge and
justified Fiat–Shamir/QROM parameters. Ordinary soundness of an already true
key-generation statement is insufficient ownership authentication. Bind network,
parent account, program/parameters, current eligibility epoch, protected identity,
exact replacement authority, action and expiry. Pairing-based Groth16 compression
cannot preserve the promised PQ soundness; arithmetic over a BN254 field alone
does not imply pairing-based security.

Backup entropy and hash composition require explicit claims. Random 12-word BIP39
entropy is 128 bits, not 128 bits of generic quantum search resistance. Word count
does not prove randomness. An idealized reviewer derivation gives about 2^125.5
Grover queries for any-seed search against a legitimate clamped Ed25519 public key;
this is not a practical attack, lower-bound proof or certification metric. Full
HD proving does not automatically remove that anchor limit.

ML-DSA-65 does not give the whole system category-3 security automatically: SHA256
action/host binding, backup entropy, key generation and protocol composition need
their own analysis. Shared-root role keys are not independent factors. Key decoding
and possession do not certify honest generation or entropy.

Any surviving classical spending, upgrade, cancellation or policy-change authority
can bypass recovery after quantum compromise. Enforce classical retirement, current
entitlement and revocation. A deployed contract cannot retrofit rights over arbitrary
unenrolled classic accounts.

## Evidence and remaining gates

The exact final source, tool versions, tests and artifacts appear in
[validation.json](validation.json). Historical deployments retain original hashes
and an explicit superseded disposition in [recovery-testnet.json](recovery-testnet.json).
Their direct-call success did not establish safety of arbitrary composite calls.

Follow-up [scalar benchmarks and strict ceremony](SCALAR_RECOVERY_EVIDENCE.md)
and the [compact backend comparator](COMPACT_BACKEND_REVIEW.md) add actual native
proof experiments. Neither backend satisfies the recorded transaction-size bound
or closes A-01. The ceremony's consumed flag is a sequential in-memory guard;
callers must retain returned state, and durable/concurrent consumption is absent.
Scalar disclosure changes the classical threat boundary and requires previously
finalized retirement across every effective and reused-key authority path.

Eight pinned public NIST ACVP/Wycheproof fixtures add independent valid/invalid
expectations, including repeated hints, malformed ordering/padding, norm boundaries
and nonempty contexts. Selected vectors are not ACVP validation or FIPS certification.

[dependency-audit.json](dependency-audit.json) records the exact fresh RustSec revision:
no known vulnerabilities were reported; the workspace has unmaintained advisories
for `derivative` and `paste`. The separate signer lockfile has no reported warnings.
The later off-chain research lockfile reports the unmaintained `atomic-polyfill`
advisory and no known vulnerabilities. It is an unaudited research dependency tree,
not a production verifier candidate or an approval of upstream cryptography.
The scalar variant also reports unmaintained `atomic-polyfill`; the compact
comparator reports unmaintained `atomic-polyfill` and `paste`. The recorded
database scan reports no known vulnerabilities in either added lockfile, without
approving the AIR, proof parameters or upstream implementations.
Yanked-package checks were disabled. This scan is not a full dependency audit.

The registry remains a declaration analyzer and its verified gates reject. The
legacy verifier rejects every proof. Independent review, production custody,
archival/restoration, a full asset adapter and the flagship proof backend remain
separate requirements. See [detailed cryptographic review](CRYPTOGRAPHIC_REVIEW.md),
[threat model](THREAT_MODEL.md) and [baseline scope](RECOVERY_POC.md).

The later [durable local experiment](DURABLE_RECOVERY_EVIDENCE.md) adds atomic
state and receipt persistence, revision comparison and controlled actual-proof
process races. This closes reuse of discarded in-memory state only within the
trusted local database model. It does not close A-01 or establish network
retirement, filesystem anti-rollback, proof security or on-chain consumption.

The [Binius follow-up](BINIUS_RECOVERY_EVIDENCE.md) narrows A-01 with an actual
539,888-byte canonical leaf proof, parameter experiments and a failed no_std
build. It does not close the backend/lifecycle release block. Separate-agent
review caught two local evidence/adapter issues, both corrected before the
final experiment: proof-process memory/thread bounds were incompletely applied,
and contradictory approval flags needed explicit rejection. Native verification
now applies the reported limits and checks exact response/backend identity;
research record loading rejects production-approval claims. The final canonical
experiment was rerun after these changes. Wrong-seed prover aborts are explicitly
classified separately from cryptographic verifier rejection.

## Verifier portability and transport follow-up

The verifier portability audit found target-width-dependent Fiat-Shamir sampler serialization and corrected the fork to the original native64 u64LE protocol. The unchanged real proof and transition vector now pass native/Wasm checks. Exact preprocessing identity and capacity optimizations retain constraints and parameters. The [raw Wasm evidence](VERIFIER_PORT_EVIDENCE.md) remains conditional on code size, full host metering and external review. The [proof mailbox](PROOF_MAILBOX_EVIDENCE.md) has no recovery authority; its sealed state is unverified.

## Compact verifier and actual host-cost follow-up

The [current gate matrix](RECOVERY_IMPLEMENTATION_STATUS.md) records duplicate-constraint removal, strict compact decoding, closed metadata-export misuse, generic scalar/key validation and optimized-Python evidence checks. Exact proof and constraint identity remain unchanged. Raw size/memory blockers improved; actual SDK code size and CPU remain open, with 400M and 12B diagnostic exhaustion. Independent quantum knowledge/ZK and complete authority-lifecycle assurance remain A-01 blockers.

## Lattice-proof, relation-reframing and primary-source follow-up

[The lattice gate](COMPACT_BACKEND_LATTICE_GATE.md) retains the dated literature,
source and experiment trail. Its Binius64 and RoKoko proof-system conclusions
remain proposed specialist-review obligations, not security approval. See the
[Binius review scope](BINIUS_A01_REVIEW_SCOPE.md) and
[RoKoko soundness/hiding scope](ROKOKO_ZK_HIDING_REVIEW_SCOPE.md).

The canonical RoKoko gadget experiment supersedes an earlier gate that accepted
a malicious ignored coefficient. Its replacement exercises five honest 64-bit
additions and eight malicious witnesses through the frontend, with a written
argument still requiring independent review. It does not exercise the full
commitment chain, complete SHA-512 relation, Soroban ABI or metered network
execution. Native proof size/time does not establish transaction or CPU fit.
[Wiring scope](ROKOKO_RELATION_WIRING_SCOPE.md) and
[canonical evidence](rokoko-canonical-gadget-research.json) own the details.

Binius64's actual SDK wrapper remains oversized and exhausts the measured CPU
budgets. Native profiling narrows hotspots without demonstrating a completed
Soroban verifier. [Successor evidence](VERIFIER_NEXT_EVIDENCE.md) retains sizes,
costs and reproduction scope. A-01, F-01 and full account-policy integration
remain open. No cryptographic experiment was rerun by this documentation update.
