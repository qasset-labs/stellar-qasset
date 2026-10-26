# Review: publishing the clamped scalar to shrink original-seed proofs

Initial review 2026-10-19; integration and test-label corrections verified 2026-10-20. Internal research review for Q-Asset. No transactions or deployments. This evaluates a proposed relation transformation, not the security of a production proof implementation.

## Decision

**The transformation is mathematically valid for genuine, canonically encoded RFC8032 Ed25519 anchors and the existing threat model that already gives the attacker the discrete logarithm.** It removes fixed-base curve multiplication from the private-witness circuit. It does not prove a scalar witness: the private witness must still be the leaf seed, or the SEP-5 root used to derive it.

**Publishing the scalar creates an immediate classical signing compromise.** Therefore this optimization is only suitable after a separately established retirement boundary, and after considering every other system sharing this key. Never release such a proof, its public scalar, or the scalar-bearing proving request for a live classical account. Sending it to a fee payer, RPC operator, proving service, public mempool or telemetry system counts as publication to an adversary.

## Exact equivalence

Write `C(k) = LE(clamp(SHA512(k)[0:32]))`, `l = 2^252 + 27742317777372353535851937790883648493`, and `E(a) = canonical_edwards_encoding([a mod l]B)`. Valid clamps have `a = 2^254 + 8r`, `0 <= r < 2^251`.

The original leaf relation is `R(A,k) := E(C(k)) = A`. The decomposed verifier checks the public scalar shape, `E(a)=A`, and a knowledge proof for `R'(a,k) := C(k)=a`. For a valid clamped scalar, these predicates have **exactly the same accepted witnesses**, since reduction modulo `l` is injective on this clamp set. Proof: equality implies `8(r1-r2)=0 mod l`; `8` is invertible and `|r1-r2| < 2^251 < l`, so `r1=r2`.

For root mode replace `k` by `D(S,n)` for the exact SEP-5 hardened `m/44'/148'/n'` derivation. Witness length, account-index range and child derivation must remain constrained. The public scalar does not remove SHA512/HMAC derivation costs from root mode. It only removes the final private curve multiplication.

An attacker with reduced discrete log `a0` can already recover the full scalar: `r=((a0-2^254)*8^-1) mod l`, then `a=2^254+8r`. Thus exposing `a` adds no secret information **in that declared quantum threat model**. This is not equivalent in the ordinary classical threat model, where computing the discrete log was intended to be difficult.

The equivalence requires the verifier to receive the expected anchor from authoritative wallet state. Letting the prover choose both `a` and `A` authenticates an arbitrary attacker-owned key. An action digest is not a substitute for enforcing that digest's fields against the circuit and current state.

## Encoding and external curve checks

1. The public scalar must be exactly 32 little-endian bytes. Require `(a[0]&7)==0` and `(a[31]&0xc0)==0x40`. These checks express the RFC8032 clamp: low three bits zero, bit 254 one, bit 255 zero. Equality inside the proof must bind all 32 bytes of the clamped SHA512 result, rather than comparing reduced scalars or truncating a digest.
2. A full clamped integer is larger than `l`. A library constructor that only accepts canonical reduced scalars will reject it. Reduce modulo `l` only in the external group multiplication, using a reviewed reduction function. Never reduce the proof's expected full-clamp output in place.
3. Compute `[a mod l]B` using the exact standard Ed25519 prime-order base point, canonically encode the computed point, and compare all 32 bytes with the pinned anchor. This byte equality automatically rejects a pinned encoding that is noncanonical, off-curve, torsion-bearing or otherwise not the exact derived prime-order point. An explicit canonical decode/prime-order/nonidentity guard is useful for clarity when a decoder is used. Do not accept cofactor-cleared equality, an Ed25519 signature-verification predicate, Ristretto encodings, or an attacker-selected generator as substitutes.
4. Nonidentity follows for genuine clamped scalars: no multiple of `l` in `[2^254,2^255)` is divisible by 8. Explicit rejection is still appropriate defensive validation.
5. Public bytes should be typed/versioned, with no alternate integer encodings or endian coercions. The proof statement, binding transcript and external anchor check must all use the same bytes. Test little/big-endian confusion, 31/33-byte scalars, every forced clamp bit, wrong valid clamp, reduced-vs-full scalar confusion, noncanonical point encodings and unexpected root path/index.

## Retirement before disclosure

There is a feasible prospective architecture: while classical authorization is still trusted and before disclosing the scalar, migrate the controlled asset/authority into an independently authenticated policy that disables the old Ed25519 key as an effective spend, upgrade, admin, cancel, enrollment and recovery-replacement authority. Pin the old public key solely as a seed-recovery anchor. Confirm this retirement in finalized authoritative state. Subsequent scalar disclosure then attacks only a retired classical capability, while the seed proof can authorize a tightly specified recovery through the new policy.

This is a migration/preparation workflow, not retroactive rescue of arbitrary classic accounts. A Soroban verifier does not alter native classic-account signer rules by itself. Specific asset adapters and every native-account authority path must be separately designed and tested.

The retirement transaction may itself use the old signature **only during a preparation phase that still assumes its classical authenticity**. If the adversary already has the scalar, old-key consent alone cannot distinguish the owner from that adversary, so first-time enrollment/retirement requires another previously enrolled uncompromised factor or an external trust/governance assumption. There is no cryptographic bootstrap around this limitation.

Submitting retirement and a scalar-bearing proof in the same public transaction does not solve prepublication exposure. Before that transaction is committed, an observer can use the now-public scalar to race a conflicting classical spend or control change. A private submission service merely adds that service as a trusted party unless a separately analyzed confidentiality-and-ordering mechanism prevents disclosure and front-running. The simple defensible rule is two phases: retire and confirm first, publish second.

After retirement, a successful scalar-only attack must not be able to re-enable itself through a cancellation, upgrade, admin, threshold signer, delegated spender, pending transaction, stale authorization cache, governance path or TTL/reinitialization path. Every sensitive operation must check the current authority epoch. A status flag called `retired` does not establish these invariants.

Retirement also has a cross-system condition: the same public key may still control another account, chain, application, asset-issuer authority or off-chain signature protocol. Publishing its scalar compromises those uses. The research CLI should stay public-fixture-only; a future user-facing product must treat key reuse and completed migration as explicit enrollment prerequisites. An application cannot generally prove that no key reuse exists anywhere.

## Remaining proof obligations

* The hard problem remains finding any accepted seed/root preimage given the full public scalar and permitted side information. Under an idealized uniform map with 251 variable output bits, generic quantum preimage search has scale about `2^125.5` queries; source entropy or multiple targets may reduce this. This is an ideal attack estimate, not a lower bound or certified security level.
* Ordinary NP soundness is insufficient because an honest anchor already has a witness. Recovery authentication needs a proof/signature-of-knowledge with extraction against the specified quantum adversary. If honest proofs are available, formulate adaptive chosen-action queries and the necessary simulation/extraction guarantee. Quantum zero knowledge addresses witness secrecy separately.
* State the exact Fiat-Shamir/QROM or standard-model theorem applicable to the selected backend, its setup, transcript commitments, challenge derivation, hash outputs, domain separation, repetition count and extraction loss. Hash-based implementation alone does not establish quantum security. Existing eight-round ZKBoo experiments are functional tests only, regardless of the optimized relation.
* The canonical recovery action must bind network, protected authority, old anchor, public scalar/relation, path/index, verifier/program/parameters, current epoch and eligibility, replacement key/policy, exact operation, nonce and expiry. Using a reviewed signature-of-knowledge message-binding construction is preferable to assuming an otherwise unused digest is bound. If a transcript binding API is used, audit exactly how that message influences challenges and commitments.
* A zero-knowledge property must hold relative to the **new public statement**, which explicitly reveals the scalar. It cannot promise continued classical secrecy of that scalar. Do not output the SHA512 second half, leaf seed, root seed, chain code, unopened/all-party secret shares, secret prover randomness or memory snapshots in reports. A legitimate MPC-in-the-head transcript includes specifically opened party seeds/shares; serialize only the material permitted by that exact proof protocol, never all views or the master entropy. A public-fixture demonstration cannot establish absence of side-channel leakage for real witnesses.
* Replacement-key possession and full policy retirement are independent contract obligations. Correct knowledge-proof verification does not establish current owner eligibility or make a weak replacement policy safe.

## Scope of the demonstrated result

Suggested wording: “We are testing a scalar-exposed recovery relation that can remove elliptic-curve arithmetic from the private proof circuit. It preserves the seed-preimage authentication goal against an attacker already assumed to know the Ed25519 discrete logarithm. Because disclosure also enables ordinary Ed25519 signatures, this option applies only to keys whose classical authority has already been retired through a verified migration. Current proofs use public fixtures and insufficient research parameters; compact quantum-secure proofs, production security analysis and Soroban verification remain unresolved feasibility work.”

Do not claim this is a new cryptographic primitive, a proof that preimages are quantum-hard, safe recovery of still-live classic accounts, or evidence that the entire root derivation becomes cheap. Measure optimized leaf and optimized root modes separately against the existing full-point circuit, with identical fixtures, binding, repetitions, randomness policy and build configuration.

## Primary sources consulted

* [RFC8032](https://www.rfc-editor.org/rfc/rfc8032), especially key expansion, point encoding and signing equations. These justify the exact clamp and scalar-only forgery consequences. The decomposition and injectivity proof above are direct mathematical analysis, not a quoted RFC theorem.
* [Don–Fehr–Majenz–Schaffner, Fiat–Shamir in the QROM](https://arxiv.org/abs/1902.07556). The abstract states theorem-dependent quantum soundness/knowledge preservation; it does not certify this backend or parameter set.
* [ZKPoSP](https://eprint.iacr.org/2026/1508), abstract. Its explicit quantum NIZK and extraction assumptions motivate the obligations; the full theorem was not independently verified in this review.

## Peer review of the research tool

Inspected `/tmp/qasset-scalar-research-tool/src/main.rs` after the relation change. The circuit derives the fixed SEP-5 path when requested, SHA512-hashes the actual private seed, clears the low three bits and forces the high clamp bits, and exposes exactly the resulting 32 bytes as proof outputs. The native check first rejects incorrect clamp shape, then uses Dalek's standard base-point clamped multiplication and exact canonical bytes against independently pinned fixture anchors. The standalone verifier has only dummy private inputs and the pinned public scalar; it does not need either witness.

Initial peer review identified two evidence-label defects, both corrected before the final canonical experiments: appending the mode after the digest means the existing last-byte `changed_action` mutation changes the mode string, not the action digest. Mutate a byte inside the digest explicitly and test mode separately. Also rename `wrong_public_key_rejected` and `wrong_assertion_rejected`, because those mutations now change a public scalar byte and a forced clamp bit respectively; the full-point circuit's labels no longer describe them. The independent pinned-key rejection is correctly covered by the existing native unit test.

This inspection found no replacement of the seed witness by a scalar witness. It does not establish quantum knowledge security, production-safe proving, or general user input handling: the CLI remains deliberately public-fixture-only and the statement digest is opaque to its Rust verifier.


## Final disposition

The staged tool mutates a byte inside the action digest and separately tests mode binding. Scalar and clamp mutations now use accurate labels. Native point-anchor tests cover forced clamp bits, malformed widths, reversed/reduced scalar encodings and invalid point encodings. Canonical-request runs at 8 and 438 repetitions are recorded separately. The latter remains an upstream repetition count, not established quantum knowledge security. See [SCALAR_RECOVERY_EVIDENCE.md](SCALAR_RECOVERY_EVIDENCE.md). No classical key was retired on-chain and no live scalar was disclosed.
