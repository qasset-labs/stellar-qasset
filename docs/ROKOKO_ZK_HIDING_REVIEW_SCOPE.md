# Scoped review request: is RoKoko's canonical gate sound, and does its sumcheck hide the witness? — F-01 RoKoko side

Prepared 2026-10-23 for an independent cryptographic reviewer, following
the same pattern as `BINIUS_A01_REVIEW_SCOPE.md`. This is a scope-of-work
brief, not a review itself, and not a security approval. It is a separate,
narrower request than that document: a different backend (RoKoko, lattice-
based, not Binius64), a different open question (zero-knowledge hiding, not
QROM soundness), and explicitly out of scope for that other review.

## What this is and is not

**Is:** a request to confirm (or refute) that a specific, concrete
construction — the "canonical" AND/XOR gate and the 64-bit ripple-carry
adder built from it inside RoKoko's SNARK frontend — is sound and
zero-knowledge hiding. This project tested soundness by corrupting
witnesses and confirming rejection, including the junk-coefficient attack
that broke its previous construction, and wrote a soundness argument; but
its previous construction also passed every test this project wrote for
it, so the argument needs outside checking. Hiding was not, and cannot be,
validated by testing at all.

**Is not:** a request to review RoKoko's cryptography from scratch, to
approve RoKoko as this project's production backend, or to design a
different construction. It is scoped to one question about one
construction.

## Background

`docs/ROKOKO_RELATION_WIRING_SCOPE.md` (section "Canonical design: a sound
gate, and a validated 64-bit adder") and
`docs/rokoko-canonical-gadget-research.json` record the construction under
review and its full research trail. **An earlier version of this brief
described a different gate that this project later found unsound** (a
junk-coefficient adversary was accepted); that gate is superseded and is
not what this review is about. In brief:

- RoKoko (`github.com/lattice-arguments/rokoko`, pinned at commit
  `c3f8206465f4b4cf34b8aafa378af5b081608944`) is a lattice-based SNARK
  whose frontend commits one vector of ring elements and proves
  `sum over index i of weight(i) * witness(i) * ... = value` claims via an
  interactive (Fiat-Shamir'd) sumcheck protocol.
- The ring is `Z_q[X]/(X^128+1)`, `q = 1125899906839937`, conjugation
  `X → X⁻¹` (confirmed directly against `ring_arithmetic.rs` and by
  computation; an earlier "quadratic slots, ω=0" description in this
  project's notes was wrong).
- **The construction.** Every wire is a pure scalar bit (constant
  polynomial in `{0,1}`). Primary inputs are committed as
  `[c, 1−c]` and checked by two shipped-value claims (binariness:
  constant term of `Σ r·conj(r) − conj(ones)·r`; scalar-ness: constant
  term of `Σ (conj(ones) − 1)·r`; both must be zero) plus an eq-batched
  complement tie `c + (1−c) = 1`. A gate over canonical inputs `A`, `B`
  uses one packed region `ab` and outputs `C` (AND), `D` (XOR), with three
  eq-batched `sums_to_zero` ties: `ab = A + B·X²`; `ab·ab = A + B·X⁴ +
  2C·X²`; `D = A + B − 2C`. A 64-bit ripple-carry adder chains two gates
  per bit, a linear carry-out tie, and one length-1 tie per carry link.
- **What was validated, directly against the live library**
  (`tools/rokoko-gadget-research/src/main.rs`): five honest 64-bit
  additions accepted and matching native `u64` addition; eight malicious
  witnesses rejected, including junk coefficients in the packed region
  (the attack that broke the superseded gate); primary-input tampering
  rejected by the caller-side constant-term checks.
- **A leak this project found and fixed, which the reviewer should
  confirm is fully fixed**: the documented binariness recipe, applied to
  secret bits alone, ships a value revealing their Hamming weight (two
  patterns of different weight shipped different values). The complement
  padding makes the shipped values identical across bit patterns (tested).
- **What was not, and cannot be, validated by this project**: whether the
  *transcript* (round polynomials, Fiat-Shamir challenges, the final
  proof, the `witness_eval`/`conj_witness_eval` openings) reveals anything
  about the secret bits beyond what each claim asserts; and the soundness
  of the commitment chain the binariness argument relies on for its
  no-wraparound assumption — only the front end (`prove_claims`/
  `verify_claims`) was exercised.

## The question, precisely

**Does RoKoko's sumcheck protocol, as implemented, hide the witness beyond
what the stated claims reveal — for the canonical gate's `sums_to_zero`
ties and the primary-input checks' shipped values, batched in one
`prove_claims` call — and is the written soundness argument for the
canonical gate correct?**

Sub-questions a complete answer should address:

1. Does RoKoko's sumcheck/PCS layer implement any zero-knowledge-hiding
   mechanism at all (e.g. masking polynomials, random blinding of round
   polynomials), or is it a sound-but-not-hiding IOP, with zero-knowledge
   (if any) expected to come from a different layer this project has not
   identified? `docs/snark.md`'s own text does not use the phrase
   "zero-knowledge" anywhere the research for this project found; this
   should be confirmed or corrected directly against source, not assumed
   either way.
2. If a hiding mechanism exists, does it apply uniformly to every claim
   shape, or only to specific ones (e.g. only to `sums_to(expr, value)`
   claims where `value` is shipped, not to `sums_to_zero` claims)? The
   gates use `sums_to_zero` exclusively; the primary-input checks
   necessarily ship two values each, which are fully exposed to the
   verifier and are made bit-independent only by the complement padding.
   Is that padding sufficient, or do other coefficients of the shipped
   values carry information the constant-term reasoning does not cover?
3. Does batching multiple claims into one `prove_claims` call (all gate
   ties, the shipped-value checks, and the carry-chain ties together, as
   the 64-bit adder does — 77 claims) change the hiding
   analysis relative to a single claim — e.g. via shared randomness, or
   via the `witness_eval`/`conj_witness_eval` fields of
   `InitialSumcheckProof` (`src/protocol/snark/lowering.rs:497-502`)
   potentially correlating information across claims?
4. Given the answer to the above, does the specific construction in
   "Background" leak anything about the secret bits beyond what the claims
   assert (that `C = A∧B`, `D = A⊕B`, and that the primary inputs are
   canonical bits)? If it does leak more, what, specifically, and does
   that leakage matter for this project's actual use case (a seed-recovery
   relation where intermediate SHA-512 state must stay secret)?
5. **Soundness, not only hiding.** Is the canonical gate's written
   soundness argument correct — `ab = A + B·X²` pins `ab`; with `A, B`
   canonical, `ab·ab = A + B·X⁴ + 2C·X²` forces `C = AB` because `2X²` is
   invertible in `Z_q[X]/(X^128+1)` — and does the ripple-carry adder's
   induction over bit positions hold given that gate ties are eq-batched
   (random point) while carry links are individual exact ties? The
   superseded gate passed every test this project wrote and was still
   unsound; this item asks for the adversaries this project did not think
   of.
6. Does the binariness argument's "no wraparound mod q" assumption, which
   RoKoko's docs attribute to the commitment chain's certified ℓ2 bound,
   actually hold for these witnesses once the chain is run — and if not,
   what bound or additional check would restore it?

## What a complete answer looks like

For each sub-question: a clear verdict grounded in the actual source
(`crates` under `src/protocol/snark/` and `src/protocol/parties/`, not the
documentation alone, which this project's own research found to be
incomplete on exactly this point), with file:line citations where
possible. If the construction does leak information, identify precisely
what and whether a modification (e.g. a masking term, a different claim
shape) would close the gap, and at what cost (extra claims, extra proof
size).

## What this review does NOT need to cover

- Binius64's A-01 question (QROM soundness) — separate backend, separate
  review, already scoped in `BINIUS_A01_REVIEW_SCOPE.md`.
- (Superseded: an earlier version of this brief put soundness out of
  scope. It is now explicitly in scope — sub-question 5 — because the
  previous construction, which this project had "validated directly",
  turned out to be unsound.)
- Whether RoKoko should be selected as this project's production backend,
  proof-size/performance measurement, or the remaining engineering work
  (the two-limb addition gadget, the full 80-round SHA-512 circuit) — all
  separate, ordinary engineering tasks tracked in
  `ROKOKO_RELATION_WIRING_SCOPE.md`.
- vSIS/RoKoko's own A-01 question (whether RoKoko's lattice assumptions are
  post-quantum sound) — a different, larger, already-identified open
  research question (`COMPACT_BACKEND_LATTICE_GATE.md` section 0d), out of
  scope here.

## Source materials for the reviewer

- `docs/ROKOKO_RELATION_WIRING_SCOPE.md` — the full research trail,
  including what was and was not independently verified at each step.
- `tools/rokoko-gadget-research/src/main.rs` — the actual test code that
  validated this construction's soundness; re-clonable and re-runnable
  (`cargo +nightly run --release`, after adding the crate to a workspace
  `exclude` list per that file's own instructions).
- Pinned source: `github.com/lattice-arguments/rokoko` at commit
  `c3f8206465f4b4cf34b8aafa378af5b081608944`.
- RoKoko's own documentation: `docs/snark.md` in that pinned checkout.
- The underlying paper referenced in RoKoko's README: "RoKoko:
  Lattice-based Succinct Arguments, a Committed Refinement" (title as
  given in the repository; this project did not locate or read the paper
  itself, only the implementation).
