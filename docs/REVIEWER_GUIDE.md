# Review the Q-Asset prototype

Current recovery components and remaining gates: [implementation status](RECOVERY_IMPLEMENTATION_STATUS.md) and [successor evidence](VERIFIER_NEXT_EVIDENCE.md).

This demo demonstrates weighted policy analysis, tenant authorization, and rejection
of unsupported security claims. The registry analyzes declarations; the legacy-seed
ZK verifier stays disabled. A historical ML-DSA-65 testnet run demonstrated direct
recovery from an enrolled PQ backup key, but later audit found a same-tree cached
authorization flaw. The patched counter-only candidate is local and awaits
redeployment. Neither the old run nor the candidate demonstrates legacy-seed ZK
recovery or security of an external asset.

Use the [architecture](ARCHITECTURE.md) for the full API and the
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
audit-only review. For complete local reproduction,
`python3 scripts/validate.py --offline` runs the workspace, helper, public SEP-5
checker and document checks; omit `--offline` if dependencies are not cached.

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

[Compact backend lattice gate](COMPACT_BACKEND_LATTICE_GATE.md) is external literature review plus a direct source check and two new measured circuits. A disclosed Fiat-Shamir transcript-binding defect in Binius64 (OtterSec, 2026-03) was checked against this project's pinned commit by reading the vendored verifier source, which already contains the exact reported fix. [`tools/binius-commit-prove-research`](../tools/binius-commit-prove-research) (SHA-256 preimage) and [`tools/binius-commit-prove-blake3-research`](../tools/binius-commit-prove-blake3-research) (BLAKE3 preimage) then measured proving only a hash-preimage statement instead of the full SHA-512/clamp/scalar-mult relation, against the identical pinned backend: even crossing a trace-padding bucket boundary only shrank proof size 4.4% (539,888 → 515,984 bytes) while prove/verify/setup time dropped substantially — see [binius-commit-prove-research.json](binius-commit-prove-research.json) and [binius-commit-prove-blake3-research.json](binius-commit-prove-blake3-research.json). This pins down the mechanism (proof size here scales with query count times log(trace size), not trace size) and redirects the next step toward a lattice-compression backend rather than a smaller circuit. That step was then attempted directly, not just planned: LaBinius has no declared license anywhere in its repository and a hard, fallback-free AVX-512 dependency confirmed by a failed build on this evaluation machine, which would also block any `wasm32v1-none` port on any hardware — closed as blocked, not merely unevaluated. RoKoko, built separately, is Apache-2.0 licensed with a genuine portable fallback and measured a real 95-107 KB proof verifying in 0.39s with no SIMD acceleration at all, though that benchmarks its core argument machinery on a synthetic witness, not yet a wired hash-preimage relation — see [COMPACT_BACKEND_LATTICE_GATE.md](COMPACT_BACKEND_LATTICE_GATE.md) section 3b. A full read of the canonical Binius64 specification found it proves classical ROM soundness/knowledge-soundness explicitly, with quantified error terms, while its post-quantum claim is an unsupported hedge repeated twice with zero QROM treatment — and separately admits Binius64 verification "is not yet succinct," confirming the measured CPU cost from the primary source, not just this project's own port. It also surveys unreproduced 2026 lattice-SNARK proof-size claims, and checks the academic literature directly for a path to close A-01: a standing theorem (Chiesa-Manohar-Spooner 2019) would give Binius64's family QROM security if round-by-round soundness were shown for its LIOP (not yet shown; a 2025 attempt to ease that requirement was withdrawn for a proof bug), while a differently-shaped, more directly applicable standing theorem (Lai-Malavolta-Spooner 2022) already targets the lattice/Bulletproofs family RoKoko and LaBinius belong to. A full-text follow-up read of all four papers (CMS19, LMS22, RoKoko, RoK and Roll) then confirmed both lattice papers' proofs use only classical rewinding, never cite LMS22 despite sharing an author (Russell Lai) with it, and that LMS22's theorem is proven for plain-SIS Bulletproofs only — not vSIS, which RoKoko and RoK and Roll actually use — so the lattice-family task is extending LMS22's framework to vSIS, not confirming an existing theorem already applies. A further full-text read (section 0e of the lattice gate doc) of Håböck's BaseFold list-decoding-regime paper (IACR ePrint 2024/1571) found it proves round-by-round soundness directly for FRI-Binius — the exact construction this project's own prior `BINIUS_SECURITY_REVIEW.md` already identified, independently, as Binius64's underlying PCS (same ePrint ID cited in both). This closes the specific open precondition on the Binius64 side of A-01; the remaining step is confirming Iron Spartan's sumcheck constraint-reduction layer composes with it under the standard round-by-round-soundness composition rule before CMS19 applies directly — verification work against already-published proofs, not open research. Section 0f then checked this directly against the pinned Binius64 source (not inference) and found the favorable composition case: `crates/spartan-verifier/src/lib.rs:343-375` runs the mulcheck sumcheck to completion with zero oracle interaction before `lib.rs:224-237` hands evaluation claims to a separate BaseFold opening phase (backed by real FRI-Binius BaseFold, `lib.rs:280-301`) — standard sequential composition, not the harder interleaved pattern Håböck's own Protocol 2/3 uses. Two narrow, citation-checkable items remained (ZK masking and BaseFold's ZK-hiding wrapper both preserving round-by-round soundness); a further check against Justin Thaler's standard reference "Proofs, Arguments, and Zero-Knowledge" (downloaded and searched directly, 329 pages) resolved the first with a named theorem (any sum-check-based protocol satisfies round-by-round soundness, citing Canetti et al.) and found the book's own direct discussion of the Libra-style masking technique Binius64 uses, stating it "plausibly preserv[es] post-quantum soundness" — an expert assessment, not a proof, but the most on-point source found; only BaseFold's own ZK-hiding wrapper remains genuinely unaddressed by anything checked. A further scoping pass on RoKoko found its "wire a real hash-preimage relation" task is substantial circuit-gadget engineering (authors-labeled "EXPERIMENTAL" SNARK frontend, no existing hash gadgets in the repository), not quick wiring. Every open item now has a specific, correctly-scoped owner — see section 5 of `COMPACT_BACKEND_LATTICE_GATE.md`: Binius64's A-01 is ready for, and this project recommends commissioning, a scoped independent cryptographic review now; both F-01 paths and the vSIS/RoKoko A-01 side remain separately-scoped engineering/research work, not further self-directed research. A-01 (the Binius64 side now a scoped verification task, not open research; the vSIS/RoKoko side still needing a framework extension) and F-01 (CPU cost measurably improved on Binius64 but still unsolved there; proof-size mechanism now understood and independently corroborated upstream; RoKoko's size looks solved pending relation wiring) remain open. A follow-up timing pass against Binius64's own unmodified `tracing::info_span!` instrumentation (8 native runs) then located F-01's hotspot directly against source (`crates/verifier/src/zk_config.rs:153-170`): the real Spartan verification plus the actual BaseFold/FRI opening, run second and currently unspanned upstream, dominates at 94-97% of wall time, not the structural IOP's bit-operation reduction phases measured in the cheap recording pass that runs first (3-5%, despite one of its sub-spans being named "PCS Opening") — see [verifier-profile-research.json](verifier-profile-research.json). This narrows where F-01 reduction work should focus without closing it. A section-size breakdown of the 183,090-byte SDK wrapper against the 127,068-byte raw module then ruled out Cargo profile flags and avoidable `soroban-sdk` features as quick fixes for the 56,022-byte gap; both are already maximal, so the gap is inherent SDK contract-ABI glue — see [sdk-code-size-breakdown.json](sdk-code-size-breakdown.json). A follow-up pure-userspace sampling profile (`pprof`, no `sudo`) then decomposed that undecomposed step directly: roughly 71% of samples fall inside `binius_spartan_verifier::wiring`'s MLE-evaluation functions, not the BaseFold/FRI Merkle/hash machinery (under 5% combined) — see [verifier-wiring-hotspot-research.json](verifier-wiring-hotspot-research.json). This narrows the hotspot to function granularity without closing F-01, and no change was made to the pinned verifier. A fresh RoKoko clone (commit `c3f8206`) was then scoped directly against its own source for the F-01 RoKoko side, and tested against the live library rather than left as a reading exercise: a calibration test confirmed the documented binariness recipe accepts a malicious non-binary witness unless the caller separately checks the shipped value's own structure, and a further bisection found a more serious blocker — multiplying two independently-committed secret values (needed for every AND/XOR between different values) costs degree 4 and is rejected unconditionally, with or without weighting, because two different regions always need two distinct selectors. This is not resolved; see [ROKOKO_RELATION_WIRING_SCOPE.md](ROKOKO_RELATION_WIRING_SCOPE.md), updated same-day, for the full finding. F-01's RoKoko side is now blocked on this question, not merely "substantial engineering." A follow-up probe of the ring's internal structure then resolved this, not just found a lead: packing two secret bits into one ring element's two coefficients (confirmed, empirically and robustly across six varied inputs, to behave as a controllable quadratic-extension slot) and squaring that one region against itself yields `2*a*b` as a side effect, for free; tying this to a freshly committed `p_ab` region, and deriving XOR from the same packed value, both validated end to end -- honest witnesses accepted, two independently-malicious witnesses (wrong AND, wrong XOR) both correctly rejected. What remains genuinely open is not soundness (validated directly) but whether the sumcheck protocol underlying these claims is zero-knowledge-hiding, not merely sound -- a question this project cannot resolve by itself and now scopes for independent review, same as Binius64's own open A-01 question. A full 1-bit adder (sum and carry-out, needed six times per SHA-512 round) was then built from that same AND+XOR construction alone -- no digit decomposition, no shipped value -- and validated against all 8 input combinations plus six independently-malicious witnesses, each rejected. A scoped review request for the one remaining open question (zero-knowledge hiding, not soundness) is ready to send: [ROKOKO_ZK_HIDING_REVIEW_SCOPE.md](ROKOKO_ZK_HIDING_REVIEW_SCOPE.md). A separate, untested assumption in that scope document -- that rotation and carry-chaining get a "free" shift via a documented copy-claim recipe -- was then checked directly and found wrong (that recipe only ties same-index entries); what actually works, confirmed both accepting a correct shift and rejecting a corrupted one, is one individual length-1-region tie per shifted position, not one batched claim. See [ROKOKO_RELATION_WIRING_SCOPE.md](ROKOKO_RELATION_WIRING_SCOPE.md) for the full construction. **Correction, same day:** that AND/XOR gate and the full adder built on it were then found unsound -- their malicious tests only flipped the coefficient each gate gives meaning to, and an adversary putting junk in an ignored coefficient (with true AND = 0) was accepted by the live library while the gate read AND = 1. Both are superseded by a canonical design (every wire a pure scalar bit; primary inputs checked; gate outputs forced exact by the ties), which rejected that attack and now includes a 64-bit ripple-carry adder: 5 honest cases matching native `u64` addition accepted, 8 malicious witnesses rejected, 77 claims, ~80-210 ms prove, ~14-22 ms verify, front-end proof only. The same pass found the documented binariness recipe leaks the Hamming weight of secret bits through its shipped value, fixed with complement padding -- see [rokoko-canonical-gadget-research.json](rokoko-canonical-gadget-research.json).
