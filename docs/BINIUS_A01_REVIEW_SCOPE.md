# Scoped review request: Binius64 post-quantum (QROM) soundness — A-01

Prepared 2026-10-22 for an independent cryptographic reviewer. This is a
scope-of-work brief, not a review itself, and not a security approval. It
assembles everything a reviewer needs to answer three narrow, named
technical questions, with exact citations and source locations, rather than
asking for an open-ended audit.

## What this is and is not

**Is:** a request to confirm (or refute, or supply a missing short proof
for) three specific, bounded claims that — if they hold — give an actual
proven QROM (post-quantum) knowledge-soundness result for the Binius64
backend's zero-knowledge argument, via an existing published theorem
(Chiesa-Manohar-Spooner 2019), rather than the unsupported "post-quantum"
hedge currently in Binius64's own specification.

**Is not:** a request to design a new proof from scratch, to review the
whole Q-Asset codebase, or to approve deployment. Binius64's Soroban
verification path independently exceeds the Soroban instruction budget
(F-01, unrelated to this review — see `VERIFIER_NEXT_EVIDENCE.md`), so a
favorable answer here does not by itself make this backend deployable. This
review is scoped to the security-proof question only.

## Background: why these three questions, and only these

`docs/COMPACT_BACKEND_LATTICE_GATE.md` records the full research trail
(sections 0b through 0g) that produced this scope; it is the source of every
claim below and should be read by the reviewer for full context and to
confirm nothing was mis-transcribed here. In brief:

- Binius64's own specification (`binius.xyz/spec.pdf`) proves classical
  random-oracle-model soundness explicitly, but states "post-quantum
  security" as an unsupported one-line hedge, repeated twice, with zero QROM
  treatment anywhere in the document.
- Chiesa-Manohar-Spooner, "Succinct Arguments in the Quantum Random Oracle
  Model" (IACR ePrint 2019/834, TCC 2019; "CMS19" below), Theorem 8.6
  (informal Theorem 3), proves: a BCS-compiled non-interactive argument built
  from a public-coin IOP with **round-by-round soundness** error ε has
  quantum soundness error O(t²ε + t³/2^λ) against t-query quantum attackers,
  and inherits argument-of-knowledge / zero-knowledge from the IOP's
  corresponding properties. "Round-by-round soundness" (Definitions 8.3-8.4,
  adapted from Canetti-Chen-Holmgren-Lombardi-Rothblum-Rothblum, "CCH+18"/
  "CCH+19") is a specific, checkable object: a state function
  `state(x, transcript) ∈ {0,1}` over partial transcripts such that the
  empty transcript starts at 0, no prover message can flip 0→1, and any full
  transcript still at 0 is rejected by the verifier; round-by-round
  soundness error ε bounds, for every non-doomed (state=0) transcript, the
  probability a single fresh verifier challenge flips state to 1.
- Ulrich Håböck, "Basefold in the List Decoding Regime" (IACR ePrint
  2024/1571, rev. 2025-09-04; "Håböck24" below) proves round-by-round
  soundness, in the practical list-decoding regime (up to the
  Guruswami-Sudan-Johnson bound), for Basefold (Theorem 1) and specifically
  for **FRI-Binius** (Theorem 6) — the binary-field, packed-multilinear
  Basefold variant from Diamond-Posen, "Polylogarithmic proofs for
  multilinears over binary towers" (IACR ePrint 2024/504; "DP24" below).
  This project's own prior, independent source review
  (`docs/BINIUS_SECURITY_REVIEW.md`) already identified DP24 as Binius64's
  underlying "BaseFold/ring-switching source" — confirmed from two separate
  readings, not inferred by family resemblance.
- Direct inspection of the pinned Binius64 source (commit
  `115108d5a661d95c0b474b6ab02558bfe6c6bec7`,
  `github.com/IrreducibleOSS/binius64`) found Binius64's LIOP is a clean
  two-phase **sequential** composition (the favorable case for
  round-by-round-soundness composition, not the harder interleaved case):
  - Phase 1: `crates/spartan-verifier/src/lib.rs:343-375`,
    `fn verify_mulcheck<F, C>(... C: IPVerifierChannel<F>)` — note the trait
    bound `IPVerifierChannel`, not `IOPVerifierChannel`: this function has no
    oracle-query capability. It runs `mlecheck::verify_zk`, a degree-2
    zerocheck/sumcheck for the `A*B=C` constraint with Libra-style masking
    for zero knowledge, and returns evaluation claims.
  - Phase 2: `lib.rs:224-237` packages the Phase 1 output into
    `OracleLinearRelation` structs (`{oracle, transparent, claim}`, each
    asserting `⟨oracle_poly, transparent_poly⟩ = claim`), then calls
    `channel.verify_oracle_relations([...])` (`lib.rs:233`). The channel
    trait's doc comment (`crates/iop/src/channel.rs:95-101`) states this step
    "runs the opening protocol (e.g., BaseFold)." `Verifier::setup`
    (`lib.rs:280-301`) confirms the channel is backed by
    `BaseFoldZKVerifierCompiler` — the **zero-knowledge** variant of real
    FRI-Binius-style BaseFold, not the plain variant Håböck's Theorem 6
    directly analyzes.
  - The `OracleLinearRelation` claim form matches Håböck's §6.1 generalized
    inner-product kernel case exactly (his equation 33,
    `⟨Gk, R⟩_{Hn} = vk` for arbitrary succinct-evaluable `R`, not merely a
    single Lagrangian-kernel query) — confirmed by the `mask_transparent`
    closure at `lib.rs:378-390`, which is itself a non-Lagrangian
    quadratic-composition closure.
- Justin Thaler's standard reference, "Proofs, Arguments, and
  Zero-Knowledge" (draft manuscript,
  `https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf`; "Thaler"
  below), independently confirms, citing CCH+19 by name (Chapter 5, pages
  77-78): "any ... interactive proof based on the sum-check protocol"
  satisfies round-by-round soundness. The same book's Chapter 13, §13.3
  "Zero-Knowledge via Masking Polynomials" (pages 203-207), discusses
  exactly the Libra-style masking-polynomial technique used in
  `mlecheck::verify_zk`, applied to sum-check-based protocols, and states it
  "has the dual benefits of **plausibly preserving post-quantum soundness**,
  and typically adding less overhead than the commit-and-prove-based
  transformation." This is a direct, on-point, named-expert assessment — but
  explicitly hedged ("plausibly"), not a proof given in that passage.

Two items this chain needs are therefore an **expert assessment** rather
than a **proof**, and one item is **unaddressed by every source checked** in
this project's own research. Nothing found contradicts any of the three; the
gap is absence of a located/constructed rigorous argument, not evidence
against the claims.

## The three questions, precisely

**Q1 (unaddressed — the most open item).** Does `BaseFoldZKVerifierCompiler`
— the zero-knowledge-hiding variant of BaseFold that Binius64 actually uses
(`crates/*/src/lib.rs:280-301`) — preserve the round-by-round soundness
Håböck24's Theorem 6 establishes for the plain (non-hiding) FRI-Binius
construction? If yes, cite or construct the argument. If the hiding
transformation changes the protocol's round structure, degree bounds, or
challenge-response pattern in a way that breaks the round-by-round argument,
say so precisely and identify what, if anything, would restore it (e.g. a
modified state function, additional error term).

**Q2 (expert-asserted, not proof-backed).** Does the specific masking
construction implemented in `mlecheck::verify_zk`
(`crates/spartan-verifier/src/lib.rs:343-375` and its call into the
`mlecheck` module) match the Libra-style masking-polynomial technique Thaler
describes closely enough that his "plausibly preserving post-quantum
soundness" assessment transfers rigorously — i.e., does adding this specific
random masking polynomial to the `A*B=C` zerocheck preserve round-by-round
soundness (not merely ordinary soundness) of Phase 1? A short direct
argument is plausible here (masking adds a random low-degree term without
changing the round structure, degree bounds, or challenge-sampling that the
unmasked sum-check's round-by-round argument already covers) but has not
been constructed or located by this project.

**Q3 (structural match confirmed; composition needs sign-off).** Given Q1
and Q2 resolve favorably: does the sequential composition of Phase 1
(masked mulcheck, round-by-round sound per Q2) and Phase 2
(`BaseFoldZKVerifierCompiler` opening, round-by-round sound per Q1), as
actually implemented (`lib.rs:149-253`, with the Phase 1→Phase 2 handoff at
`lib.rs:224-237`), satisfy the standard round-by-round-soundness composition
rule — a chain of round-by-round-sound reductions is itself round-by-round
sound, with error equal to the max of the per-phase errors (this
composition principle is used throughout both CCH+18/CMS19 and Håböck24
§2.2, which frames IOPs explicitly as "a chain of randomized reductions") —
cleanly enough to invoke CMS19 Theorem 8.6 directly on the assembled LIOP?
If so, state the resulting concrete quantum soundness error bound
`O(t²ε + t³/2^λ)` using Binius64's actual pinned parameters
(`SECURITY_BITS=96`, `log_inv_rate=1`, 232 test queries, per
`docs/BINIUS_SECURITY_REVIEW.md`) and assess whether that concrete number is
an acceptable security level for a seed-recovery authorization feature —
this project has not independently evaluated the resulting bits of security
against t-query quantum adversaries at these specific parameters.

## What a complete answer looks like

For each of Q1-Q3: a clear verdict (holds / does not hold / holds with a
stated modification), the argument or citation supporting it, and for Q3
specifically, the resulting concrete numerical soundness bound at Binius64's
pinned parameters. If any item does not hold as stated, identify precisely
what would need to change (in the construction, the parameters, or the
claimed theorem) to restore it.

## What this review does NOT need to cover

- F-01 (Binius64's Soroban SDK verification path exceeding the 400M
  instruction budget) — separate, ordinary engineering problem, not a
  security question.
- The vSIS/RoKoko lattice family's own A-01 gap (§0d of the lattice gate
  document) — that is open research (extending Lai-Malavolta-Spooner 2022's
  framework to vSIS), a different and larger commitment than this review.
- General code-quality or implementation-bug review of Binius64 or this
  project's wrapper code — see `docs/BINIUS_SECURITY_REVIEW.md` and
  `docs/VERIFIER_PORT_EVIDENCE.md` for prior, separate findings in that
  category.

## Source materials for the reviewer

- `docs/COMPACT_BACKEND_LATTICE_GATE.md` sections 0b, 0c, 0d, 0e, 0f, 0g —
  the full research trail behind every claim above, including what was and
  was not independently verified at each step.
- `docs/BINIUS_SECURITY_REVIEW.md` — this project's prior, separate source
  review of Binius64's pinned implementation (parameters, hash choices,
  transcript handling).
- Pinned source: `github.com/IrreducibleOSS/binius64` at commit
  `115108d5a661d95c0b474b6ab02558bfe6c6bec7`.
- CMS19: `https://eprint.iacr.org/2019/834` (direct PDF fetch returns HTTP
  403 from automated tooling in this project's environment; the reviewer's
  own access may differ).
- Håböck24: `https://eprint.iacr.org/2024/1571`.
- DP24: `https://eprint.iacr.org/2024/504`.
- Thaler: `https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf`.
- Binius64 canonical spec: `https://www.binius.xyz/spec.pdf`.
