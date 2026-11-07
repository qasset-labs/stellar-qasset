# Review the Q-Asset prototype

> **Scope:** This document covers the current Q-Asset proof-of-concept (PoC) and
> research contracts: limited Testnet implementations that demonstrate core
> mechanisms. They are not the full Q-Asset product. The complete product design is
> described in the [architecture](ARCHITECTURE.md).

Current recovery components and remaining gates: [implementation status](RECOVERY_IMPLEMENTATION_STATUS.md) and [successor evidence](VERIFIER_NEXT_EVIDENCE.md).

This demo demonstrates weighted policy analysis, tenant authorization, and rejection
of unsupported security claims. The registry analyzes declarations; the legacy-seed
ZK verifier stays disabled. A historical ML-DSA-65 testnet run demonstrated direct
recovery from an enrolled PQ backup key, but later audit found a same-tree cached
authorization flaw. The patched counter-only candidate is local and awaits
redeployment. Neither the old run nor the candidate demonstrates legacy-seed ZK
recovery or security of an external asset.

Use the [contract reference](CONTRACTS.md) for the current API and
[architecture](ARCHITECTURE.md) for the completed product design and the
[threat model](THREAT_MODEL.md) for assumptions and residual risks. Recovery feasibility remains unresolved.

## Evidence and reproduction

Run these commands from the repository root:

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked --target wasm32v1-none --release
```

The Rust toolchain needs the `wasm32v1-none` target. Cargo needs access to locked
dependencies or a populated local cache. 

[Local validation](validation.json) records commands, results and source/artifact
hashes. [Public testnet evidence](testnet-deployment.json) records deployment
identifiers, transaction hashes and demo observations when a deployment run has
completed. If that file is absent or reports an incomplete run, testnet deployment
has not been established by this evidence pack. Check its recorded network and
status before treating an identifier as a successful deployment.

For the testnet evidence, inspect the deployment and mutation transaction results,
match the recorded WASM hashes to the built artifacts, and distinguish submitted
transactions from RPC simulations. A rejected simulation is a useful negative
check; it is not a committed failed transaction. Testnet data can later expire or
be reset, so retain the receipts and the exact source revision.

The source tests are in
[registry tests](../contracts/qasset-registry/src/test.rs) and
[recovery tests](../contracts/seed-recovery-verifier/src/test.rs). Some arithmetic
fixtures use `mock_all_auths`; they test declared policy calculations. Separate
authorization tests use exact invocation mocks, and the recovery rejection test
uses actual host authorization entries without authorization mocks. None of
these two contracts' fixtures is a valid ML-DSA signature or a valid seed-knowledge
proof. A separate backup-key demo has a different scope, described below.

To run the metadata testnet deployment with the Stellar CLI installed and testnet
access available:

```sh
python3 scripts/testnet_demo.py --wasm-dir target/wasm32v1-none/release --output docs/testnet-deployment.json
```

The script uses its dedicated reviewer configuration directory by default;
`--config-dir PATH` selects another. This command deploys and changes testnet demo
state. Its output receipt is the evidence for its actual results, not a claim
about a separate recovery deployment.

The local compatibility check uses the public SEP-5 fixtures and pinned PyNaCl:

```sh
python3 -m pip install -r scripts/requirements-crypto-demo.txt
python3 scripts/check_recovery_relation.py
```

It checks derivation and public-key relations, including wrong inputs and the
distinction between a leaf seed and its expanded/reduced signing scalar. It does
not recover a scalar from a public key, run a quantum attack, generate a ZK proof
or measure an on-chain verifier. Published test-vector keys must not hold funds.

## Scenario 1: presence differs from required participation

Deploy the registry with its registrar as a constructor argument. Enroll a sample
asset label with consent from the registrar and tenant administrator. This records
a metadata tenant; it does not prove ownership of the named asset.

Use `set_role_quorum` to declare signers and thresholds, then read
`list_weak_paths`, `declared_security_level` and `policy_assessment`.
Let `C` be total classical weight and `T` the threshold. A present role is weak
when `C >= T`; a missing role is also reported as weak.

| Treasury declaration | Result for this role |
| --- | --- |
| Classical weight 3, ML-DSA-labelled weight 1; threshold 3 | Weak: classical weight alone reaches the threshold. |
| The same signers; threshold 4 | The declaration requires a PQ-labelled contribution. Actual cryptography remains unverified. |

The other seven roles affect the asset's declared level. To isolate Treasury in
this example, declare the other roles as requiring a PQ-labelled contribution.
The declared levels are:

| Level | Predicate over stored declarations |
| --- | --- |
| QS0 | No PQ-labelled signer anywhere. |
| QS1 | A PQ label exists, but Treasury, Upgrade or Governance is weak. |
| QS2 | Those three roles require PQ-labelled weight, but another role is weak. |
| QS3 | All eight roles require PQ-labelled weight. |
| QS4 | QS3, and `C + largest_PQ_weight < T` for each of Treasury, Upgrade and Governance. |

QS4 therefore requires at least two PQ-labelled addresses even after every
classical signer is assumed compromised. A classical weight 1 and PQ-labelled
weight 1 at threshold 2 is QS3, not QS4. For a high-impact role with classical
weight 2 and PQ-labelled weights 3 and 1, threshold 6 meets the QS4 arithmetic;
threshold 5 does not. Distinct addresses do not establish distinct keys or people.

Focused local reproduction:

```sh
cargo test -p qasset-registry --locked role_is_weak_when_a_single_high_weight_classical_signer_alone_meets_the_threshold
cargo test -p qasset-registry --locked qs4_requires_two_pq_addresses_even_after_all_classical_signers_are_compromised
```

## Scenario 2: forged QS4 labels never become verified security

Declare two ordinary addresses as ML-DSA signers, each weight 1, with threshold 2
for all eight roles. The expected declared score is QS4. This deliberately shows
that an administrator controls labels: those addresses do not become PQ signers.

Expected results:

| Read or action | Expected result |
| --- | --- |
| `declared_security_level(asset)` | QS4 for this fixture. |
| `policy_assessment(asset)` | Declared QS4, current revision/observation ledger, `Unverified`. |
| `quantum_security_level(asset)` | `UnverifiedPolicy`. |
| `require_min_qs(asset, any_level)` | `UnverifiedPolicy`, including a QS0 minimum. |
| Protected test contract calling the gate | Reverts before its execution flag changes. |

The gate rejects every policy in this release. There is no administrator switch
that promotes metadata to verified evidence. This is a regression demonstration
of rejection, not an integration that accepts authentic PQ authorization.

```sh
cargo test -p qasset-registry --locked forged_algorithm_metadata_cannot_satisfy_verified_gate
cargo test -p qasset-registry --locked cross_contract_gate_blocks_state_change_despite_declared_qs4
```

For an unknown tenant, `policy_assessment` returns `AssetNotRegistered`. Declared
reads conservatively report QS0 and missing roles; they do not verify an asset.
The verified gate rejects unknown tenants as well.

## Scenario 3: administrators cannot silently take another tenant

Review the tests for these outcomes:

| Attempt | Expected behavior |
| --- | --- |
| Enroll without registrar or incoming administrator consent | Authorization fails. |
| Enroll an already registered asset label | `AssetAlreadyRegistered`; original administrator remains. |
| Registrar changes another tenant's quorum | Authorization fails. |
| Transfer with only the old or only the new administrator | Authorization fails. |
| Transfer with both parties | Administrator changes and revision increments; the old administrator loses mutation authority. |
| Invoke the old public `initialize` function | No such entry point. |
| Re-enroll missing tenant metadata while role declarations survive | `OrphanedPolicy`; original declarations are retained. |

`set_role_quorum` and administrator changes emit events with the mutation revision.
`policy_assessment` records the current observation ledger; it is not a signed
attestation. Reads and `keep_alive` do not create a new policy revision.
Permissionless TTL maintenance extends live entries, subject to network limits;
archived entries require restoration. No keeper availability is guaranteed.

```sh
cargo test -p qasset-registry --locked tenant_updates_require_the_exact_asset_admin_authorization
cargo test -p qasset-registry --locked tenant_transfer_requires_both_parties_and_revokes_the_old_admin
cargo test -p qasset-registry --locked reenrollment_rejects_orphaned_role_declarations_without_resetting_them
```

## Scenario 4: recovery rejects plausible-looking forged credentials

The recovery constructor requires owner authorization and stores the protected
public key and unhardened account index `n < 2^31`. There is no public initializer,
configuration update, upgrade or activation switch. `backend_available()` is false.

The host authorization regression constructs the correct public Soroban payload
hash, fresh nonces and arbitrary proof bytes, then calls a protected operation
that invokes `require_auth` for the recovery account. Authorization fails and the
protected state remains unchanged. Direct custom-account checks return
`BackendUnavailable` on initialized instances, regardless of proof content.

```sh
cargo test -p seed-recovery-verifier --locked forged_credentials_fail_through_real_require_auth_without_auth_mocks
cargo test -p seed-recovery-verifier --locked matching_or_modified_bindings_never_authorize_placeholder_proofs
```

This demonstrates that the former public-hash/pairing placeholder cannot authorize
an action. It does not demonstrate a valid proof being accepted. The reserved
`RecoveryProof` envelope is not an implemented proof format. Do not install this
disabled account as required authorization for funds.

## PQ backup recovery: historical testnet run and local audit fix

**The old baseline is superseded.** A later audit reproduced stale authorization
within a single invocation tree: an aggregator could validate old-key authority,
recover the account, then use already cached old authority on a protected action.
The direct before/after transactions below did not cover that execution pattern.

The patched candidate accepts exactly one authorization context for its own
argument-free `protected` counter. It rejects aggregator/unrelated/multi-context
roots. This is a constrained counter demo, not generic wallet authorization. The
patched WASM has not been redeployed. Keep the old receipts as historical evidence,
not a security or deployment claim for the candidate. Local regression results and
new artifact hashes belong to the separate audit validation.


[The ML-DSA account](../contracts/pq-recovery-demo/src/lib.rs) and
[public-fixture helper](../tools/pq-demo/src/main.rs) implement real ML-DSA-65
verification. The owner authorizes deployment and receives no later bypass. An
active key authorizes a counter action; an enrolled recovery key then signs a
one-time transition to a different replacement key. The replacement also signs
the recovery intent as proof of possession. Both signatures cover the network,
contract, epoch, replacement key and bounded expiry, under the recovery context.
The account then accepts the replacement key and rejects the old key, even with
a fresh nonce. Recovery is consumed permanently.

[Historical recovery evidence](recovery-testnet.json) records four
confirmed successful transactions and 17 checks. Final state is epoch 1, counter 2,
recovery disabled and active key matching replacement. Forged recovery signatures,
wrong replacement possession, repeated recovery and fee-payer bypass fail. Negative
cases are RPC simulations with authentication enforced, not committed failures.
The normal action costs about 102.86 million simulated instructions; recovery costs
204,473,156 for this exact fixture. These are not legacy-seed ZK verifier costs.

```sh
cargo build --manifest-path tools/pq-demo/Cargo.toml --locked --release
python3 scripts/recovery_demo.py --signer tools/pq-demo/target/release/qasset-pq-demo-tool
python3 scripts/verify_testnet.py
```

Install `scripts/requirements-testnet.txt` for the network scripts and Stellar CLI.
The last command reads public receipts, deployed WASM and state without signing or
sending. It must now reject a mismatch between the patched local candidate and old
deployment. [Historical verification evidence](testnet-verification.json) cannot
establish a new audited deployment. Do not run the deployment command during this
audit-only review. For the current local source/evidence reproduction, use
`python3 scripts/reproduce_poc.py --offline --report /tmp/qasset-review-reproduction.json`
and the pinned environment in [the evidence guide](QASSET_POC_EVIDENCE.md). The
wider research runner `scripts/validate.py` overwrites `docs/validation.json` and
does not establish local Markdown-link validity or fresh proof generation.

The helper's active, recovery and replacement keys derive from one published root.
Anyone can sign for them, and they are not independent factors. Never use these
fixture keys with funds. The RustCrypto `ml-dsa` 0.1.1 dependency and account are
unaudited. This counter demonstration has no asset/treasury adapter or general
wallet/key-loss lifecycle.

The historical run established direct-call PQ verification but missed the cached
authorization flaw. The patched candidate narrows its scope to the counter. Neither
version demonstrates arbitrary batch revocation or general wallet safety. It does not
activate `SeedRecoveryVerifier`, change registry verification status, or prove
knowledge of a legacy SEP-5 seed in zero knowledge. It requires prior PQ-key
enrollment. This completed work is functional evidence within the stated scope.

## What remains for the proposed product

A useful recovery product could still be a significant Stellar contribution.
Seed-preimage proofs already have academic and implementation prior art, including
Soundness's PQChain and its published Stellar recovery direction. Exact SEP-5
compatibility, a measured Soroban verifier and a complete account lifecycle are
the proposed engineering contribution; see [reference review](reference-review.json).

Before claiming working legacy-seed ZK recovery, demonstrate a quantum-sound proof backend,
valid and invalid proofs, exact proof transport/verifier costs, prior enrollment,
revocation, retirement of classical bypasses and authorization of a specified new
PQ authority. Groth16/BN254 does not satisfy the proposed quantum threat model.
Before claiming verified asset security, demonstrate adapters bound to actual
code/configuration and every relevant authority path. Scanner, SDK, signed
attestations, partner integrations and independent review are further deliverables.

This evidence pack is intended to let reviewers assess concrete engineering work.
It supplies no invented team credentials, independent audit, partner commitment,
external endorsement or completed feasibility result. Responsibility for the
implementation, testing and documentation remains with the maintainers.

[Cryptographic and implementation audit](SECURITY_REVIEW.md) records the reproduced finding, mitigation, evidence limitations and undeployed candidate status.

## Original-seed evidence follow-up

Read [RECOVERY_EVIDENCE.md](RECOVERY_EVIDENCE.md) for the actual off-chain SEP-5 root proof and reproduction commands. It uses deliberately insecure reduced-round parameters, publicly known witnesses and an unaudited attributed backend. A separate verifier checks it without the root as an input. This functional experiment and the scalar-only signature counterexamples strengthen the evidence package but do not activate the on-chain seed verifier, prove quantum security or establish a feasible Soroban recovery operation.

## Additional measured research

[Scalar proof comparisons](SCALAR_RECOVERY_EVIDENCE.md) distinguish leaf/root and
eight/438-response workloads, and document finalized retirement before scalar
disclosure. The strict local ceremony requires a real root proof and real
replacement signature, then returns a new model state. It is not durable
consumption or on-chain retirement. The [compact backend review](COMPACT_BACKEND_REVIEW.md)
records an independently attributed leaf-preimage STARK, a wrong-witness test,
decoder correction and final verification provenance. No result activates the
legacy seed verifier or establishes production quantum security.

### Durable local consumption and backend fit

The separate [durable recovery experiment](DURABLE_RECOVERY_EVIDENCE.md) uses the actual original-root proof and replacement possession to test duplicate-process consumption, restart replay, revocation/retirement/expiry races, ABA changes and transaction rollback. This extends the in-memory ceremony; it is local trusted-database research with insecure proof parameters and fixture policy inputs. The on-chain seed verifier remains disabled.

The [next backend gate](COMPACT_BACKEND_NEXT_GATE.md) records measured lossless compression and distinguishes existing WHIR/recursion/Binius capabilities from unproven fit/security claims. The 86 KB non-ZK benchmark is not evidence of a usable zero-knowledge recovery proof.

### Genuine compact ZK comparator

[Binius recovery evidence](BINIUS_RECOVERY_EVIDENCE.md) adds a canonical-request
leaf proof, thirteen actual functional checks, a real replacement-possession
handoff, exact hypothetical invocation size and a retained failed Soroban build.
A separately reproduced existing-parameter study keeps the upstream96-bit
query calculation and does not reach transaction fit. Source provenance,
proofs and strict negative-test classification distinguish what was measured
from unestablished security and deployment properties.

## Verifier portability and transport follow-up

Read [verifier portability](VERIFIER_PORT_EVIDENCE.md) for the native64/Wasm transcript correction and actual bounded raw Wasm execution, and [staged transport](PROOF_MAILBOX_EVIDENCE.md) for the actual Soroban Wasm mailbox round trip. These supersede the earlier raw compilation blocker, without establishing a deployable verifier. Upload sealing is never proof approval. No post-audit deployment was performed.

## Compact verifier and actual host-cost follow-up

Start with [current implementation status](RECOVERY_IMPLEMENTATION_STATUS.md). [Successor evidence](VERIFIER_NEXT_EVIDENCE.md) supersedes the raw-module size blocker while retaining the actual SDK size/CPU failures. The generic point helper has independent RFC/SEP5 vectors and actual Wasm checks. All are local research; no post-audit deployment or approved original-seed recovery is claimed.

## Lattice-proof and relation-reframing follow-up

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
