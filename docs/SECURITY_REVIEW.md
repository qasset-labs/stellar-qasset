# Q-Asset cryptographic and implementation review

Date: 2026-10-19. First-party, AI-assisted adversarial review with three parallel
review passes and root verification. This is not an independent external audit,
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

[Compact backend lattice gate](COMPACT_BACKEND_LATTICE_GATE.md) checked the pinned Binius64 commit against a disclosed Fiat-Shamir transcript-binding defect (resolved: the pin already contains the fix) and read the canonical Binius64 specification in full. The spec proves classical random-oracle-model soundness and knowledge-soundness explicitly, with quantified error terms via the BCS transform and Fiat-Shamir; its post-quantum security is an unsupported one-line hedge, repeated twice, with zero QROM, round-by-round, or Chiesa-Manohar-Spooner treatment anywhere in 55 pages. This makes A-01 a precisely named gap — a specific missing QROM knowledge-extraction proof, not a vaguely unestablished one. The same read found Binius64's own admission that its verification "is not yet succinct," corroborating from the primary source (not just this project's port) why F-01's CPU cost is structural. Two new measured circuits (SHA-256 and BLAKE3 preimage relations, in place of the full SHA-512/clamp/scalar-mult relation) confirmed relation-shrinking helps CPU time but cannot deliver the order-of-magnitude proof-size cut F-01 needs on this backend, because its proof size scales with query count times log(trace size). Both findings redirect further work toward an independent QROM proof or a lattice-compression backend rather than further tuning the current one. That redirection was then tested directly: LaBinius, the leading lattice candidate by reported proof size, has no declared license anywhere in its repository and a hard, fallback-free AVX-512 dependency confirmed by an actual failed build attempt — a dependency that would also block any `wasm32v1-none` port regardless of hardware, so it is closed as blocked rather than left unevaluated. RoKoko, a second lattice candidate, is properly licensed, built and ran successfully on hardware without AVX-512 (degrading gracefully rather than failing), and measured a real 95-107 KB proof verifying in 0.39s — but that benchmarks its core argument machinery on a synthetic witness, not yet the hash-preimage relation this project would need wired through it. A direct literature check then asked whether an existing theorem already closes A-01: Chiesa-Manohar-Spooner (2019, standing) gives QROM security for any round-by-round-sound IOP-based SNARG, which would apply to Binius64 if that property were shown for its LIOP (sumcheck + BaseFold) — it has not been, a 2025 attempt to relax this to ordinary soundness was withdrawn by its own author for a genuine bug in its core lemma, and BaseFold's own round-by-round soundness in the practical regime was called ongoing work by its original authors as recently as 2024. A differently-shaped theorem (Lai-Malavolta-Spooner 2022, also standing) is explicitly stated to cover "Bulletproofs-like protocols based on lattices" — the construction family RoKoko and LaBinius belong to — though whether RoKoko's own construction satisfies it is unverified here. A follow-up full-text read of all four papers (CMS19, LMS22, RoKoko, RoK and Roll, supplied directly rather than fetched) confirms neither RoKoko's nor RoK and Roll's own security proofs mention "collapsing," QROM, or cite LMS22 anywhere — both use only classical rewinding extractors, despite Russell Lai co-authoring all three papers — and sharpens the gap: LMS22's theorem is proven only for plain-SIS Bulletproofs (BLNS20/AL21/ACK21), not for vSIS, the commitment RoKoko and RoK and Roll actually use, so closing A-01 for the lattice family means extending LMS22's framework to vSIS, not merely confirming its hypotheses already hold. A further full-text read (section 0e) of Håböck's BaseFold list-decoding-regime paper (IACR ePrint 2024/1571) found it proves round-by-round soundness directly for FRI-Binius — the exact construction this project's own prior `BINIUS_SECURITY_REVIEW.md` already identified, independently, as Binius64's underlying PCS. This closes the specific open precondition on the Binius64 side of A-01; the remaining step is confirming Iron Spartan's sumcheck constraint-reduction layer composes with it under the standard round-by-round-soundness composition rule before CMS19 applies directly — verification work against already-published proofs, not open research. A direct check against the pinned Binius64 source (section 0f) confirmed the favorable case: the mulcheck sumcheck runs to full completion with no oracle interaction (`crates/spartan-verifier/src/lib.rs:343-375`) before handing off to a separate BaseFold opening phase (`lib.rs:224-237`, backed by real FRI-Binius-style BaseFold, `lib.rs:280-301`) — standard sequential composition, not the harder interleaved pattern, so the composition argument goes through directly. Two narrow, citation-checkable items remain (does Libra-style ZK masking preserve round-by-round soundness; does BaseFold's ZK-hiding wrapper preserve it) rather than open research. A-01 for Binius64 is now a scoped, time-boxed verification task; F-01 on that same backend remains unsolved (measured oversized, exceeds the 400M instruction budget). A further check against Justin Thaler's standard reference "Proofs, Arguments, and Zero-Knowledge" (downloaded and searched directly, 329 pages) independently confirmed, via a named citation to Canetti et al., that any sum-check-based interactive proof satisfies round-by-round soundness — covering Binius64's Phase 1 sumcheck directly — and found the book's own discussion of exactly the Libra-style masking-polynomial ZK technique Binius64 uses, stating it "plausibly preserv[es] post-quantum soundness" for sum-check-based protocols. That is an expert assessment, not a proof, but it is the most directly on-point source found; only BaseFold's own ZK-hiding wrapper remains genuinely unaddressed by any source checked. Neither closes A-01 or F-01 outright, but each now has a named theorem and a specific, checkable precondition standing between here and closure, rather than an open-ended "needs review" — and the Binius64 path in particular is now materially closer to closeable on the security side, while RoKoko remains the stronger path on the size side. A follow-up scoping pass found RoKoko's "wire a real hash-preimage relation" task is substantial circuit-gadget engineering (its SNARK frontend is authors-labeled "EXPERIMENTAL" with no existing hash gadgets), not quick wiring — so every open item in `COMPACT_BACKEND_LATTICE_GATE.md` now has a specific, correctly-scoped owner (section 5): Binius64's A-01 is ready for a scoped independent cryptographic review (recommended as the next action); the vSIS/RoKoko A-01 side is open research out of scope for this project; both F-01 paths are ordinary engineering work, separate from and able to proceed in parallel with that review. A follow-up timing pass on Binius64's own `tracing::info_span!` instrumentation (unmodified, 8 native runs) then located F-01's hotspot directly against source (`crates/verifier/src/zk_config.rs:153-170`): a cheap inner recording pass (3-5% of wall time, despite one of its sub-spans being literally named "PCS Opening") runs first, then the real outer Spartan verification plus the actual BaseFold/FRI opening — currently unspanned and so not further decomposable without touching pinned source — dominates at 94-97%; see [verifier-profile-research.json](verifier-profile-research.json). This narrows where SDK-size/CPU reduction work should focus; it does not itself close F-01. A follow-up section-size breakdown of the actual 183,090-byte SDK wrapper against the 127,068-byte raw module ruled out Cargo profile flags and avoidable `soroban-sdk` features as quick fixes for the 56,022-byte gap (both already maximal); the gap is inherent SDK contract-ABI glue, not a tuning oversight — see [sdk-code-size-breakdown.json](sdk-code-size-breakdown.json). F-01 remains open on both the code-size and CPU-instruction axes. A follow-up pure-userspace sampling profile (`pprof`, no `sudo`) then decomposed that undecomposed step directly: roughly 71% of samples fall inside `binius_spartan_verifier::wiring`'s MLE-evaluation functions, not the BaseFold/FRI Merkle/hash machinery (under 5% combined) — see [verifier-wiring-hotspot-research.json](verifier-wiring-hotspot-research.json). F-01 remains open; this narrows the hotspot to function granularity without closing it, and no change was made to the pinned verifier. A fresh RoKoko clone (commit `c3f8206`) was then scoped against its own source for the F-01 RoKoko side, and tested directly against the live library rather than left as a reading exercise: a calibration test confirmed the documented binariness recipe accepts a malicious non-binary witness unless the caller separately checks the shipped value's own structure, and a further bisection found a more serious blocker — multiplying two independently-committed secret values (needed for every AND/XOR between different values, not just the addition gadget) costs degree 4 and is rejected unconditionally, with or without weighting, because two different regions always need two distinct selectors. This is not resolved; see [ROKOKO_RELATION_WIRING_SCOPE.md](ROKOKO_RELATION_WIRING_SCOPE.md), updated same-day, for the full finding. F-01's RoKoko side is now blocked on this question, not merely "substantial engineering." A follow-up probe of the ring's internal structure then resolved this, not just found a lead: packing two secret bits into one ring element's two coefficients (confirmed, empirically and robustly across six varied inputs, to behave as a controllable quadratic-extension slot) and squaring that one region against itself yields `2*a*b` as a side effect, for free; tying this to a freshly committed `p_ab` region, and deriving XOR from the same packed value, both validated end to end -- honest witnesses accepted, two independently-malicious witnesses (wrong AND, wrong XOR) both correctly rejected. What remains genuinely open is not soundness (validated directly) but whether the sumcheck protocol underlying these claims is zero-knowledge-hiding, not merely sound -- a question this project cannot resolve by itself and now scopes for independent review, same as Binius64's own open A-01 question. A full 1-bit adder (sum and carry-out, needed six times per SHA-512 round) was then built from that same AND+XOR construction alone -- no digit decomposition, no shipped value -- and validated against all 8 input combinations plus six independently-malicious witnesses, each rejected. A scoped review request for the one remaining open question (zero-knowledge hiding, not soundness) is ready to send: [ROKOKO_ZK_HIDING_REVIEW_SCOPE.md](ROKOKO_ZK_HIDING_REVIEW_SCOPE.md). A separate, untested assumption in that scope document -- that rotation and carry-chaining get a "free" shift via a documented copy-claim recipe -- was then checked directly and found wrong (that recipe only ties same-index entries); what actually works, confirmed both accepting a correct shift and rejecting a corrupted one, is one individual length-1-region tie per shifted position, not one batched claim. See [ROKOKO_RELATION_WIRING_SCOPE.md](ROKOKO_RELATION_WIRING_SCOPE.md) for the full construction. **Correction, same day:** that AND/XOR gate and the full adder built on it were then found unsound -- their malicious tests only flipped the coefficient each gate gives meaning to, and an adversary putting junk in an ignored coefficient (with true AND = 0) was accepted by the live library while the gate read AND = 1. Both are superseded by a canonical design (every wire a pure scalar bit; primary inputs checked; gate outputs forced exact by the ties), which rejected that attack and now includes a 64-bit ripple-carry adder: 5 honest cases matching native `u64` addition accepted, 8 malicious witnesses rejected, 77 claims, ~80-210 ms prove, ~14-22 ms verify, front-end proof only. The same pass found the documented binariness recipe leaks the Hamming weight of secret bits through its shipped value, fixed with complement padding -- see [rokoko-canonical-gadget-research.json](rokoko-canonical-gadget-research.json).
