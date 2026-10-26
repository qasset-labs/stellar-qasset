# Conditional security argument for Q-Asset original-seed recovery

2026-10-19. First-party research notes for review. This is a handwritten conditional argument and executable-evidence plan, **not a computer-checked theorem, implementation of a ZK backend, proof of quantum hardness, independent audit, or production approval**. No network transactions were performed.

## What can actually be established now

1. The proposed leaf and SEP-5 root relations match published Stellar derivation examples; the repository already checks 15 public addresses and 168 compatibility/negative conditions.
2. Scalar exposure and seed possession are different properties. We can exhibit a valid ordinary Ed25519 signature produced from the scalar alone, while treating that same scalar as an Ed25519 seed derives a different key. This is concrete evidence that classical authorization can be broken without a seed witness.
3. Mathematical lemmas about the clamp can be proved directly, below.
4. Protocol authorization and replay properties can be exercised in an explicit state model. A finite model is evidence about that model only, particularly when a proof-verification result is idealized.
5. Resistance of SHA-512 seed-preimage inversion and a real quantum-secure proof backend remain assumptions and unmet implementation milestones. Tests cannot establish either hardness claim.

## Exact objects and threat boundary

Let `k` be a 32-byte Ed25519 seed, `H = SHA-512`, `a = LE(clamp(H(k)[0:32]))`, and `A = [a]B`, canonically encoded. Let `l = 2^252 + 27742317777372353535851937790883648493`. The clamp implies

`a = 2^254 + 8r`, with `0 <= r < 2^251`.

For root mode let `S` be the raw HD seed and `k = D(S,n)`, where `D` is **the exact SEP-5 / SLIP-0010 hardened path `m/44'/148'/n'`**. Fix supported witness length and permitted account-index domain; do not silently accept arbitrary derivation rules. A raw BIP39-derived root is not proof of a mnemonic checksum, historical wallet provenance, or any entropy level.

A quantum attacker receives `A`, the reduced discrete logarithm `a0 = a mod l`, all public protocol state, and transcripts. Giving `a0` explicitly avoids relying on elliptic-curve hardness anywhere in the recovery argument. Additional exposed sibling keys, signatures, multiple targets and HD metadata must be included in the security experiment if the implementation exposes them. The attacker does **not** receive a valid seed witness. Theft of the witness lies outside this protection claim.

The attacker may submit, front-run, reorder and relay recoveries. A copied valid intent may legitimately install its intended replacement key. The desired property is prevention of a different unauthorized replacement or action, not prevention of permissionless delivery of an already authorized action.

## Lemma 1: the complete clamped scalar is also revealed

Reduction modulo `l` is injective on valid clamped scalars. If `a1 = a2 mod l`, then `8(r1-r2) = 0 mod l`. Because `l` is odd, 8 is invertible, and because `|r1-r2| < 2^251 < l`, `r1=r2`.

Indeed, from `a0` compute

`r = ((a0 - 2^254) * inverse_mod(8,l)) mod l`.

For a genuine RFC8032 key `r < 2^251`, and `a = 2^254+8r` recovers the full clamped integer. **Do not claim that Shor leaves the full expanded scalar hidden. The remaining secret is a hash preimage such as `k`, not `a`.** The second half of `H(k)` is also not necessary to forge a signature once `a0` is known.

## Lemma 2: scalar possession suffices for an ordinary signature

Given `a0` and `A`, choose nonzero nonce `t mod l`, compute `R = [t]B`, `h = LE(SHA512(ENC(R)||ENC(A)||m)) mod l`, and `s = (t+h*a0) mod l`. The signature `ENC(R)||LE32(s)` satisfies `[s]B = R+[h]A`, so it passes ordinary Ed25519 verification without knowing `k` or the deterministic signing nonce prefix.

Executed on all 15 selected public SEP-5 accounts with PyNaCl verification: PASS; see seed-recovery-evidence.json. Nonce derived solely from the supplied scalar, a fixed public audit domain, and the message; no original seed or SHA512 prefix was passed to the scalar-only construction. Also PASS: interpreting `LE32(a0)` as a leaf seed yields a different public key; reconstructing the full clamp from `a0` succeeds. No private or witness bytes were printed.

This is a classical supplied-scalar counterexample, **not a quantum implementation or a seed-inversion attack**. It proves why a still-enabled classical spend/upgrade/policy authority defeats the recovery protection, even if the seed-proof system itself is perfect.

## The authorization relation must bind an exact action

Use a single canonical action `m` committing to at least: protocol/version, network, protected contract/account, verifier program and parameters, recovery mode, pinned old `A`, permitted root path/index, current entitlement/eligibility epoch, exact operation, replacement key and full replacement policy, session/nonce, expiry. Delegated signer identity belongs here when relevant. The contract derives expected fields from current state instead of trusting them from the prover.

One explicit candidate consistent with the current design notes is

`R_leaf((A,m,z),k) := EdPublic(k)=A AND z=H_tag(domain || len(m) || m || k)`.

`R_root((A,n,m,z),S) := EdPublic(D(S,n))=A AND z=H_tag(domain || len(m) || m || S)`.

`H_tag`, lengths and encodings must be fixed and independently justified. A reviewed signature-of-knowledge transformation may instead bind `m` directly; replacing that step with an informal claim about a ZK library is insufficient. Merely including an unused `m` as a public input to `R(A,k) := EdPublic(k)=A` does not establish action binding: the relation remains true for every message, and a proof implementation may ignore the unused input. An explicit binding construction and transcript review are necessary.

The public tag is not a new enrolled security anchor: a forger who finds any matching seed can produce the tag. It must not be presented as raising the seed anchor's security level.

## Conditional authorization proposition

Consider an eligible wallet whose pinned public anchor is `A`, with no remaining independently effective classical or administrator bypass. At recovery consumption it atomically checks current eligibility/revocation, epoch, nonce, expiry, exact action, backend/version, and any replacement-key possession requirement. It atomically consumes the recovery permission and changes authority; every sensitive operation after the defined retirement boundary checks the currently applicable epoch and authority. Pending and cached authorization cannot override those operation-level checks.

Assume all of the following:

- **Seed-preimage resistance with auxiliary information:** no efficient quantum algorithm finds **any** accepted witness for `A` in the relevant leaf/root relation, given `a0` and all declared side information and simulated legitimate transcripts. This is a specifically stated assumption; it does not follow from the difficulty of discrete logarithms, from SHA512's output length alone, or from the examples passing.
- **Proof security:** the chosen proof/signature-of-knowledge construction provides quantum zero knowledge and the extraction/simulation-extractability properties required for fresh, adaptively chosen action statements, under its exact setup and QROM/standard-model assumptions. Completeness and ordinary NP soundness alone are insufficient.
- **Binding:** action encoding is unambiguous and the employed hashes/commitments provide the security needed for the exact chosen-action threat model. The reviewed verifier actually enforces the whole relation and pinned program/parameters.
- **State enforcement:** the on-chain transition implements the stated guards and preserves them through authorization caching, batching, callbacks, upgrades and delegation. There is no unmodeled spend, governance, admin, cancel, threshold or migration bypass.

Then a fresh, unauthorized recovery by a quantum attacker would imply either a failure of a binding/state assumption or extraction of a valid seed preimage, contradicting the relevant proof-security and seed-preimage assumptions.

### Reduction sketch, and its limits

A reduction receives the target anchor and scalar and uses the proof system's permitted simulator to answer allowed honest transcript/action queries. It runs the adversary. On a fresh accepted unauthorized action, state enforcement excludes stale/revoked/replayed/other-account acceptance; binding identifies one exact fresh statement. The backend's quantum extractor returns a witness satisfying `R`. The reduction verifies it and outputs it as a seed-preimage solution.

For a complete proof, the exact simulator/extractor experiment must be written, including concurrent sessions, adaptive statements, challenge-target selection, auxiliary input and allowed oracle access. One cannot simply assign a generic additive `2^-128` loss. If the backend supplies extraction success `g(epsilon)` at the specified adversary success and a transcript simulation loss `delta`, the bound must use that actual function and runtime, e.g. `g(epsilon-delta-other_failure_terms) <= Adv_seed_inversion(T')`. **Neither `g` nor concrete parameters are established in this repository.** This argument is therefore a precise conditional proof obligation, not a finished cryptographic reduction for a selected backend.

Zero knowledge addresses witness leakage, separately from knowledge extraction. Ordinary proof soundness about false statements is not enough: a genuine owner's public key already has a seed witness, so the statement is true even when an attacker lacks it.

## Claims that must be rejected

- **Historical uniqueness:** the proof establishes some accepted preimage, not that it is uniquely the seed generated years ago. Hash-to-clamped-scalar mapping cannot give that uniqueness.
- **Scalar as witness:** `A=[a]B` is satisfied by the assumed quantum attacker. A scalar witness cannot authenticate against that attacker.
- **Leaf-seed theft protection:** a leaked Stellar `S...` value normally exposes the 32-byte seed. A leaf proof cannot distinguish its thief from its owner.
- **Root-only theft claim without retirement:** requiring root `S` can exclude a thief of only `k`, conditional on root-preimage hardness and independently disabling the still-usable classical signature path.
- **Current ownership from old seed:** a revoked participant may still know its genuine old root. Current entitlement must be checked outside and at final consumption of the proof.
- **Trusting prover-selected `A`:** an attacker can prove its own seed relation and replace the purported protected anchor unless the actual wallet state pins `A`.
- **Seed entropy from format:** a 64-byte BIP39 root or 24 words is not evidence of random generation. Random 12-word mnemonic entropy is 128 bits, giving approximately `2^64` ideal Grover queries under the simplest distribution model.
- **Certified 128-bit or category-3 end-to-end security:** clamped RFC8032 outputs have `2^251` possibilities. Under ideal hash/PRF modeling, arbitrary matching-seed search has scale about `2^125.5` ideal quantum queries. This is a generic upper attack estimate, not a security lower bound, implementation cost, practical attack, or proof of the exact security level. Source entropy, multiple targets and side information can reduce it.
- **Retroactive classic-account rescue:** deploying a Soroban verifier does not change classic account authorization. The protected wallet/asset authority must already route through an authorized rule permitting this recovery.

## Reproducible negative cases worth adding immediately

1. A scalar-only signature passes ordinary Ed25519 verification, while that scalar fails as a seed witness under the original `A`.
2. Correct leaf/root witnesses satisfy ordinary relation evaluation; wrong witness/path/account index/coin type fails. Clearly label the evaluator as revealing the witness to the local process, not ZK.
3. Start from an authorized action and change each network/account/backend/old-key/path/epoch/new-policy/nonce/expiry field individually. A proposed proof statement or binding digest must change; a copied old certificate cannot be consumed for the mutation.
4. Revoke eligibility after proof preparation; consumption fails. Likewise expire the proof, increment epoch, consume nonce and rotate anchor.
5. An old owner's otherwise valid seed proof fails after revocation. An attacker's valid proof under its own `A` fails against the wallet-pinned anchor.
6. A supplied valid certificate may be relayed unchanged once; altered replacement, second consumption and cross-account reuse fail. This defines the permitted front-running boundary.
7. Demonstrate an intentionally insecure classical bypass in the model, then remove it. The bypass counterexample must fail the invariant before the repaired model passes.
8. Treat proof-verifier output as an explicit **ideal predicate** in a protocol model. Never let such a model or stub return true in production or count it as evidence of a real PQ proof.

## Primary references checked for this note

- [RFC8032, keys/sign/verify](https://www.rfc-editor.org/rfc/rfc8032): the seed expansion and signature equations support the scalar-only counterexample.
- [Baldimtsi et al., Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368): abstract reports seed-witness migration and a game-based argument. Full theorem not independently verified here; published benchmarks are not Soroban measurements. This is prior art, not Q-Asset's original theorem.
- [ZKPoSP](https://eprint.iacr.org/2026/1508): abstract explicitly states quantum-random-oracle security conditional on NIZK zero knowledge and simulation extractability. Full theorem not independently verified here.
- [Don, Fehr, Majenz, Schaffner, Security of the Fiat-Shamir Transformation in the Quantum Random-Oracle Model](https://arxiv.org/abs/1902.07556): abstract gives conditions for quantum soundness/knowledge preservation and signature security. It is not blanket certification for an arbitrary hash-based backend.

These sources motivate the proof obligations. None supplies a completed Q-Asset-specific on-chain security or performance proof.

## Current executable evidence

The public-fixture checker now adds 195 relation/counterexample checks across 15 addresses, 11 draft-statement binding mutations and five policy-precondition rejections. Its policy checks do not implement a state transition or prove replay/cached-authorization invariants. The separate original-seed research tool constructs actual reduced-round off-chain proof transcripts; its deliberately insufficient round count establishes functional behavior only. The precise run and limitations are recorded in `seed-proof-research.json` and `RECOVERY_EVIDENCE.md`. No approved on-chain seed-proof backend is enabled.
