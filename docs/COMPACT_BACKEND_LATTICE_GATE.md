# Compact recovery backend: lattice-proof and architecture follow-up

2026-10-22. External research, a full read of the canonical Binius64
specification, two new local circuit measurements, and two attempted
third-party builds, triggered by a reviewer question about closing A-01 (no
validated quantum-secure proof backend) and F-01 (the compact ZK verifier's
SDK code size/CPU exceed Soroban's budget) from
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). Section 0 is a direct source-code
check; section 0b is a full read of the primary Binius64 spec (not a
secondary summary) that found an explicit classical-ROM soundness proof and
an upstream admission that its verifier is not succinct; section 0c checks
the actual academic literature for a path to QROM security and finds a
standing, applicable theorem for Binius64's family with an unmet precondition,
a 2025 attempt to ease that precondition withdrawn for a proof bug, and a
differently-shaped, more directly on-point standing theorem for the
lattice/Bulletproofs family RoKoko and LaBinius belong to; section 0d reads
the full text (not abstracts) of all four papers named in section 0c — CMS19,
the withdrawn 2025 follow-up's replacement theorem (LMS22), and RoKoko/RoK
and Roll's own papers — supplied directly by the user, confirms both papers'
security proofs use only classical rewinding with zero mention of
"collapsing," QROM, or LMS22's own framework despite shared authorship, and
narrows §0c's optimistic framing: LMS22's Theorem 4 is proven only for
plain-SIS Bulletproofs, not vSIS, so closing A-01 for the lattice family needs
extending LMS22's framework to vSIS, not merely confirming its hypotheses
already hold; section 0e reads Håböck's BaseFold list-decoding-regime paper
(also user-supplied) in full and finds it proves round-by-round soundness for
exactly the FRI-Binius/BaseFold construction this project's own prior review
already identified as Binius64's underlying PCS — closing the specific open
precondition §0c flagged for the Binius64 side of A-01, leaving only a
verification/assembly step (not open research) before CMS19 can be invoked
directly; section 1 is
literature review; sections 2b and 2c each add a new, isolated research
circuit
([`tools/binius-commit-prove-research`](../tools/binius-commit-prove-research),
[`tools/binius-commit-prove-blake3-research`](../tools/binius-commit-prove-blake3-research))
and a native measurement against the existing Binius64 pin; section 3b
clones and attempts to build two external lattice-SNARK repositories outside
this repository's own tree (evaluation only, nothing vendored or committed —
see §3b for why). No change to any existing circuit, no deployment and no
crypto security approval. Figures in section 1 are third-party authors' own
reported numbers, not reproduced by this project; figures in sections 0, 2b,
2c and 3b are measured directly, with exact hashes recorded where the
evidence is this project's own pinned dependency; section 0b's quotes and
occurrence counts are from the primary specification PDF, extracted and
searched directly, not from a secondary summary.

## 0. Checked: the pinned Binius64 commit is not the disclosed-vulnerable revision

OtterSec's "Unfaithful Claims: Breaking 6 zkVMs" (published 2026-03-03,
researchers Himanshu Sheoran and Valter Wik;
<https://osec.io/blog/2026-03-03-zkvms-unfaithful-claims>) reported a
Fiat-Shamir transcript-binding defect across six systems **including Binius64**:
in the shift-protocol verifier, `public: &[Word]` was "NEVER ABSORBED" into the
transcript before challenges (`r_j`, `r_s`, `inout_eval_point`) were sampled, so
`public_eval = MLE(public, r_j, inout_eval_point)` was computed from an unbound
public slice — "a single 128-bit linear constraint over hundreds of bits" that
"admits many alternative witnesses," i.e. an attacker-controlled public
statement could still satisfy the fixed challenges. Reported fixed 2026-12-29
via commit `86a515f0632d2acdf547ed82780dfe7f9f39358f` (PR #1355, "Observe
public inputs to the execution," fixing upstream issue #1350), touching
`crates/prover/src/prove.rs`, `crates/spartan-prover/src/lib.rs`,
`crates/spartan-verifier/src/lib.rs` and `crates/verifier/src/verify.rs`, each
adding a `transcript.observe().write_slice(...)` call with the comment
"observes the public input (includes it in Fiat-Shamir)."

**This has now been checked directly against this repository's vendored source,
not inferred from commit ordering.** This project pins Binius64 at
`115108d5a661d95c0b474b6ab02558bfe6c6bec7` everywhere it is used
(`tools/binius-seed-research`, `tools/binius-verifier-port`,
`tools/binius-verifier-next` — identical `verify.rs` across the two vendored
copies, confirmed with `diff -q`). Reading the vendored
`tools/binius-verifier-next/vendor/binius64/crates/verifier/src/verify.rs` at
lines 122-123 of `IOPVerifier::verify` shows:

```rust
// Verifier observes the public input (includes it in Fiat-Shamir).
let public_elems = channel.observe_many(&encode_public(public));
```

placed before `channel.recv_oracle()` and every challenge-sampling call in the
function (`verify_intmul_reduction`, `verify_bitand_reduction`, `shift::verify`,
all downstream of this line). The identical pattern, with the identical
comment wording, appears again in the vendored
`crates/spartan-verifier/src/lib.rs:341-342`
(`transcript.observe().write_slice(public)`). This is the exact fix text and
fix location reported for commit `86a515f`, present verbatim in the pinned
revision. Cross-referencing GitHub directly: commit `115108d5...` is PR #1465
("`compute_public_value`: trade in challenges for plain field eval"), which
postdates PR #1355/commit `86a515f` (both by PR-number ordering and by the fix
text already being present). **Conclusion: the pinned commit postdates and
includes this fix. The OtterSec-disclosed forgery does not apply to this
project's Binius-based evidence.** No re-generation of
`BINIUS_RECOVERY_EVIDENCE.md`, `VERIFIER_PORT_EVIDENCE.md` or
`VERIFIER_NEXT_EVIDENCE.md` is needed on this account.

This narrows, but does not close, reference R33's caution in
the recorded technical reference review ("ROM knowledge compilation and plausible PQ language do
not establish QROM extraction for the older pinned implementation"): the
specific publicly disclosed implementation bug is absent from the pinned
revision, but R33's deeper point — that Binius64's spec does not itself carry a
QROM knowledge-extraction theorem for this exact IOP — is a separate, still-open
question that an implementation fix cannot answer. Treat A-01 as still open on
that narrower, harder ground, not on this specific (now-resolved) forgery risk.

A related check: the ShorStop/Plonky3 SHA-512 AIR comparator
(`tools/compact-seed-research`) pins `p3-challenger = 0.5.2`, nominally inside
the vulnerable range of a different, confirmed CVE (CVE-2026-46654 /
GHSA-vj64-rjf3-w3v7, "MultiField32Challenger: transcript malleability and
challenge entropy loss," patched in 0.4.3/0.5.3). Reading
`tools/compact-seed-research/vendor/shorstop/src/lib.rs:32,111` shows the
adapter instantiates `SerializingChallenger32<Val, HashChallenger<u8, ByteHash,
32>>` — a plain byte-hash challenger, not `MultiField32Challenger`, which is the
only struct the advisory names as affected (its root cause is specific to
`MultiField32Challenger::duplexing`'s base-2^64-to-base-2^31 field-switching
between an outer BN254-style field and an inner field; `HashChallenger` has no
such field-switching step). This usage is very likely unaffected, though the
advisory text does not explicitly say other challengers are safe, so this is a
reasoned inference from the described mechanism, not a vendor confirmation.

## 0b. Read: the canonical Binius64 spec, cover to cover, for what it actually proves

R33 in the recorded technical reference review already flagged that "ROM knowledge compilation and
plausible PQ language do not establish QROM extraction for the older pinned
implementation." That was reasoned from a review-note summary, not from reading
the primary source. The canonical spec — "Binius64 Blueprint," dated 2026-10-07,
<https://www.binius.xyz/spec.pdf>, 55 pages — has now been read in full (text
extracted locally; exact page/line citations below) to settle what it actually
contains, rather than continue to infer from secondary commentary.

**It is more rigorous than a first pass suggested, and the gap is narrower and
more precise than "no soundness proof exists."** The spec gives an explicit,
quantified soundness and knowledge-soundness analysis for the full compiled
SNARK (§5.5, "The Binius64 SNARK"):

> "Combining the soundness errors of the LIOP, BaseFold, and BCS gives an
> overall soundness error of `O(ℓ_words + ℓ_cons)/|K| + 2^-λ` in the random
> oracle model... Knowledge soundness follows from the same compilation chain
> with knowledge extraction at each stage."

This composes three cited results: the LIOP's own Schwartz–Zippel/sumcheck
error terms (§4.3-4.9), BaseFold's soundness (Zeilberger-Chen-Fisch, tightened
by Håböck [Hab24]), and the Ben-Sasson–Chiesa–Spooner (BCS16) oracle-to-IP
transform, of which the spec says: "In the random oracle model, this
transformation preserves soundness up to a tight multiplicative loss in the
adversary's query budget." §7.3 repeats the same structure for the
zero-knowledge-compiled variant this project's tooling actually uses:
"Knowledge soundness and the soundness error are inherited from the inner
LIOP, IronSpartan, and the compiler, increased only by the `O(1)/|K|` terms of
the masking and composition steps."

**Every one of these results is stated and proved in the classical random
oracle model (ROM) only.** An exact text search of the full 55 pages finds:
`QROM` — 0 occurrences; `round-by-round` — 0 occurrences; any form of
`Chiesa, Manohar` (the citation for the actual QROM-extraction framework a BCS
+ Fiat–Shamir construction would need, per §0's earlier literature search) —
0 occurrences; `quantum` — exactly 2 occurrences, both of them this same
one-clause hedge, word for word identical in spirit: "the scheme is plausibly
secure against quantum adversaries" (§1.1) and "plausibly post-quantum secure"
(Abstract). Neither instance cites a proof, a reduction, or even a reference
for the quantum claim — the paragraph immediately following the §1.1 instance
moves on to a different topic (succinctness) without returning to it, and
nothing elsewhere in the document does either.

**This sharpens A-01 from "unestablished" to a specific, named, textually-confirmed
gap**: Binius64's classical ROM soundness is real, cited, and quantified;
its post-quantum security is an unsupported adjective, repeated twice,
in a document that is otherwise careful to prove everything else it asserts.
Closing this gap for real means either (a) an independent QROM
knowledge-extraction proof for this exact BCS-transformed, Fiat-Shamir-compiled
LIOP composition — the Chiesa-Manohar-Spooner round-by-round framework is the
established tool for this, and nothing in this spec applies it — or (b) a
backend whose PQ soundness argument is already published and reviewed for the
general construction family, which is the standing argument for evaluating a
lattice-based backend (Module-SIS; §3) rather than continuing to assume
Binius64's hedge will eventually be filled in.

**The same read also sharpens F-01, independent of A-01.** §1.1 states plainly,
about Binius64 generally, not about this project's Soroban port specifically:
"At present, Binius64 is succinct in proof size... Verification is **not yet
succinct**—the verifier reads the circuit description in the course of
checking a proof—**and reducing verification cost is ongoing work**." That is
an admission, in the upstream construction's own canonical specification, that
non-succinct (at least linear-in-circuit-size) verification cost is a known,
currently-unsolved property of Binius64 itself — not an artifact introduced by
this project's `wasm32v1-none` port, Soroban's metering, or the SDK wrapper.
It is independent evidence, from the primary source rather than from this
project's own measurements, for why §2b/§2c found CPU time improving with
circuit size while proof bytes barely moved, and for why the SDK verifier
exhausts even a 12B-instruction diagnostic budget: the verifier was never
designed to be succinct in the first place. This is a second, independent
reason — not just LaBinius's own reported proof size — to prefer evaluating a
backend engineered for succinct verification over further tuning of Binius64's
current verifier.

## 0c. Checked the actual academic literature for a path to close A-01, not just for its absence

§0b established that A-01 is a precisely named gap: Binius64's QROM security is
an unsupported hedge, not a theorem. That leaves an obvious next question —
does a general theorem already exist in the literature that would close this
gap if applied, or is this a genuinely open research problem with no known
route at all? Both standing papers below were read at the abstract level
(their IACR ePrint PDFs returned HTTP 403 to automated fetches; only their
HTML abstract pages, CC-BY licensed, loaded) — conclusions below are
abstract-level and explicitly flagged wherever full-text confirmation would
be needed before relying on them further.

**There is a standing, applicable theorem for Binius64's construction
family — but it needs an ingredient that is not yet established for the
specific component Binius64 uses.** Chiesa, Manohar, and Spooner, "Succinct
Arguments in the Quantum Random Oracle Model" (IACR ePrint 2019/834, a major
revision of a TCC 2019 publication, not withdrawn, CC BY), state in their own
abstract: "We additionally use our techniques to prove that SNARGs based on
interactive oracle proofs (IOPs) with **round-by-round soundness** are
unconditionally secure in the quantum random oracle model." This is exactly
the shape of Binius64: an IOP (sumcheck + BaseFold), compiled via BCS and
Fiat-Shamir, into an RO-based SNARG. If Binius64's LIOP has round-by-round
soundness (a classical, non-quantum property — a stronger refinement of the
plain soundness the spec already proves), CMS19 already gives QROM security
for the compiled construction, off the shelf.

**That "if" is live, not a formality — and recent attempts to relax it
collapsed.** A 2025 follow-up aiming to generalize this to any IOP satisfying
only *ordinary* (not round-by-round) soundness, "Quantum Rewinding for
IOP-Based Succinct Arguments" (arXiv 2411.05360, Chiesa, Dall'Agnol, Di, Guan,
Spooner), **was withdrawn by one of its own authors on 2025-10-20**, with the
withdrawal note identifying a specific flaw: "There is a mistake in the proof
of Lemma 3.2 ... the adversary sends `Q_u` determined by all verifier
randomnesses, but it only has the first `l-1` verifier randomnesses," and the
two candidate fixes either lose generality or are "incompatible with [the]
collapsing definition." This is not a minor erratum — it is the paper's core
rewinding lemma. **The practical upshot: as of this review, there is no
standing result that lets Binius64 get QROM security merely from the ordinary
soundness its own spec already proves; CMS19's stronger round-by-round
requirement is still the only applicable door, and it has not been shown
open for Binius64's LIOP.**

Whether that door *can* be opened depends on a component-level question that
is itself unsettled for the practical regime Binius64 uses. Round-by-round
soundness is established in the literature for plain FRI (a 2025/2026
preprint reports "a significantly simpler security analysis of FRI, in
particular its round-by-round soundness," per search-indexed summaries not
yet read in full). **BaseFold — what Binius64 actually uses, not plain
FRI — is explicitly a different proof problem**: a widely cited summary notes
that "because the protocol is different from FRI, its security cannot be
reduced to that of FRI in a black-box way... the verifier additionally needs
to check that this polynomial is consistent with the sum-check message, which
defeats the original proof technique that works for FRI," and that, per the
original authors' own 2024 conference slides, proving knowledge soundness
when the verifier operates within the (practical) list-decoding radius was
listed as **ongoing work**, not yet complete, at that time. Binius64's own
spec (§0b) cites Håböck's 2024 paper ([Hab24], "BaseFold in the List Decoding
Regime") for a "tightened" classical soundness bound and states a concrete
overall error formula, which suggests this specific gap may have since been
closed in the cited literature by the time the Oct-2026 spec was written —
but this review has not read [Hab24] itself to confirm, and in any case that
paper, like everything else here, addresses classical (not quantum)
soundness. The honest state: Binius64's classical soundness looks
well-founded and improving; its round-by-round soundness — the specific
property CMS19 would need to deliver QROM security — has not been shown
established for BaseFold anywhere this review has found, independent of the
quantum question entirely.

**Checked directly, still inconclusive.** Håböck's paper itself (IACR ePrint
2024/1571, "Basefold in the List Decoding Regime," received 2024-10-05, last
revised 2025-09-04) was located and its abstract read directly: it
generalizes the correlated-agreement theorem to linear subcodes of
Reed-Solomon codes to analyze Basefold soundness up to the Johnson
list-decoding bound. The abstract names no soundness notion explicitly — no
"round-by-round," no "knowledge soundness" — so it neither confirms nor rules
out that this is the paper that closes CMS19's precondition. The full PDF
returned HTTP 403 to automated fetch, the same wall hit by every other
ePrint paper in this investigation; only user-supplied full text (as was done
for CMS19, LMS22, RoKoko, and RoK and Roll in §0d) could resolve this
specific sub-question further.

**The lattice/Bulletproofs-style family (RoKoko, LaBinius) has a
differently-shaped, more directly on-point standing result.** Lai, Malavolta,
and Spooner, "Quantum Rewinding for Many-Round Protocols" (IACR ePrint
2022/889, preprint status per its ePrint page, not withdrawn, CC BY), state in
their own abstract: "This technique applies to any protocol satisfying
natural multi-round generalizations of special soundness and collapsing,"
and, as their stated main result, "we show that **recent Bulletproofs-like
protocols based on lattices satisfy these properties, and are hence sound
against quantum adversaries**." This is exactly RoKoko's and LaBinius's
construction shape (recursive split-and-fold, Ajtai/lattice commitments) —
markedly closer to an existing positive result than Binius64's FRI/BaseFold
shape is. Two caveats keep this from being read as "RoKoko is already proven
quantum-sound": the 2022 paper necessarily predates RoKoko (2026) and LaBinius
(2026) by several years, so neither is literally one of the "recent" protocols
it analyzed, and this review could not fetch either paper's full text to
check whether RoKoko's own security section (unread; its ePrint PDF also
returned 403) explicitly verifies and cites this framework for its own
construction. The gap this leaves is narrower and more tractable than
Binius64's, though: it is "confirm an already-existing theorem's hypotheses
hold for this specific construction," not "wait for a round-by-round
soundness proof of an underlying component that conference slides called
ongoing work."

**Net effect on A-01**: still open, but now for a reason specific enough to
act on. For Binius64's family, closing it needs either (a) an independent
proof that Binius64's LIOP (sumcheck + BaseFold) has round-by-round soundness,
which would let CMS19 apply directly, or (b) a repaired version of the
withdrawn 2025 generalization, or (c) switching families. For the lattice
family, closing it needs checking whether RoKoko's (or a similar) construction
already satisfies the LMS22 hypotheses — plausible given the stated
closeness of fit, but unverified here. Neither is a "wait for a review"
problem alone; both have a concrete, identifiable mathematical task attached,
which is more than could be said before this literature check.

## 0d. Read: the full text of CMS19, LMS22, RoKoko, and RoK and Roll — not abstracts

§0c's conclusions were abstract-level, because every direct ePrint PDF fetch
from this environment returned HTTP 403. The user supplied all four full
papers directly (PDF text). This section replaces the abstract-level reading
with a full-text one and corrects one point of over-optimism in §0c.

**CMS19, precisely.** The applicable result is Theorem 8.6 (formal; informal
Theorem 3): a BCS-compiled non-interactive argument built from a public-coin
IOP with round-by-round soundness error ε has quantum soundness error
O(t²ε + t³/2^λ) against t-query quantum attackers, and inherits
argument-of-knowledge / zero-knowledge if the IOP has round-by-round
proof-of-knowledge / is honest-verifier zero-knowledge. "Round-by-round
soundness" is a specific, checkable object (Definitions 8.3-8.4, adapted from
Canetti-Chen-Holmgren-Lombardi-Rothblum-Rothblum 2018): a state function
state(x,tr) ∈ {0,1} over partial transcripts, required to start at 0 on the
empty transcript, never be flipped 0→1 by a prover message, and force verifier
rejection on any full transcript still at 0 — with round-by-round soundness
error ε meaning no non-doomed (state=0) transcript has more than ε probability
of a random next verifier message flipping it to 1. This confirms §0c's
reading exactly and adds the precise definitional target: establishing
round-by-round soundness for Binius64's actual LIOP (sumcheck +
BitAnd/IntMul/BinMul/Shift reductions through BaseFold) is the concrete,
well-defined mathematical task — not yet done, as §0b already found the spec
proves only plain soundness.

**LMS22, precisely — and this corrects §0c.** The formal result (Theorem 4) is
not a general statement about "Bulletproofs-like lattice protocols." It is
proven for one specific, concretely written-out protocol: Fig. 3's recursive
fold-split argument for the *plain* SIS relation `Ax = y mod q`, where `A` is
sampled **uniformly at random** — the construction lineage of
BLNS20/AL21/ACK21, confirmed by the paper's own closing line ("The
lattice-based Bulletproofs protocols family described in the fashion of
Fig. 3 can be seen as the result of applying Corollary 1 to lattice-based
Bulletproofs in the fashion those described in the literature
[BLNS20, AL21, ACK21]"). The two abstract hypotheses the authors introduce and
then discharge by hand only for that protocol:
- *Recursive special soundness* (Def. 5): per-round extractors Ei that peel
  one folding round off a k-ary tree of transcripts, via the same
  Vandermonde-based extraction technique AL21/ACK21 already use classically.
- *Last-round collapsing* (Def. 6): the linear hash `Hash_A(x) = Ax mod q`
  stays collapsing (the quantum analogue of collision-resistance) even after
  the key `A` is repeatedly "folded" (linear-combined with short unit
  coefficients) across rounds — proved via somewhere-statistically-binding
  (SSB), built in turn from an (ℓ,β)-bounded linearly homomorphic encryption
  scheme instantiable from plain LWE (Regev) or NTRU.

RoKoko and RoK and Roll use **vSIS** (Cini-Lai-Malavolta, CLM23), not plain
SIS: vSIS commitment keys are tensor-structured
(`A_{n,2^μ} = B_{n,0} • B_{n,1} • ⋯`, a Kronecker/row-tensor product), not
LMS22's uniformly-random `A`. Neither the fold-collapsing proof (which is
specific to the plain-SIS hash's algebraic structure) nor the recursive
special-soundness framework (built for Fig. 3's single-step fold, not
RoKoko's considerably richer composed RoK sequence —
Πsplit-⊗/Πsplit-⊗̄, Π⊗RP/ΠRP for structured+unstructured random projection,
Πfold-split with sumcheck-based linearization, recursive commitments, Πjoin,
Πbatch, Πnorm) has been shown to transfer to vSIS or to RoKoko's actual
construction. §0c's framing — "this is exactly RoKoko's and LaBinius's
construction shape" — was too strong: it is the same *family* in spirit
(recursive split-and-fold, Ajtai-style lattice commitments) but not literally
the protocol LMS22 proves anything about, and the gap between "same family in
spirit" and "satisfies the stated hypotheses" is exactly where unproven
security claims usually hide.

**RoKoko's and RoK and Roll's own security sections: checked directly, not
inferred.** Full-text search of both papers (not just their abstracts) finds:
zero occurrences of "collapsing" in either paper; "quantum" appears only in
framing boilerplate (Shor's algorithm motivating lattice cryptography,
lattice assumptions "believed to remain secure against quantum attacks");
every knowledge-soundness proof in both papers is written as explicit
*classical* rewinding ("the extractor rewinds A and repeats the process to
obtain a second witness-statement pair... except with the failure
probability... by Lemma 5 and the union bound") — i.e. a standard
special-soundness extractor, never adapted to or even acknowledged as
insufficient for a quantum prover. Neither paper's reference list cites
Lai-Malavolta-Spooner's quantum-rewinding paper, despite **Russell Lai being a
co-author of all three papers** (RoKoko, RoK and Roll, and LMS22 itself) — the
author who proved the relevant quantum-rewinding tool exists does not invoke
it in his own later lattice-SNARK papers. This is not evidence the
constructions are quantum-insecure; it is evidence that "post-quantum" in
their abstracts is an **assumption-level** claim (vSIS conjectured
quantum-hard) with no accompanying **proof-level** quantum-rewinding
treatment — the identical shape of hedge already found in Binius64's spec in
§0b, minus even Binius64's two one-line QROM mentions.

**Net effect on A-01, revised.** Both families now have a textually-confirmed
absence of quantum-rewinding treatment in their primary sources, and a
precisely identified theorem that could close the gap if its hypotheses were
checked and held:
- Binius64 family: needs round-by-round soundness shown for its LIOP
  (sumcheck + BaseFold), which would let CMS19 Theorem 8.6 apply directly.
- vSIS/RoKoko family: needs (a) a fold-collapsing proof for vSIS's
  tensor-structured hash (not merely the plain-SIS hash LMS22 already
  covers), and (b) recursive-special-soundness verified for RoKoko's full
  composed RoK sequence, not just a single fold-split step — i.e. an
  extension of LMS22's framework to a materially more complex protocol, not
  a direct application of its Theorem 4.

Neither task is complete. The lattice family's task is still narrower in
scope than re-deriving a soundness notion for an unrelated hash construction,
but it is "extend and re-verify a framework," not "confirm an existing
theorem's hypotheses already hold," which is a step more work than §0c
suggested before the full text was available.

## 0e. Read: Håböck's BaseFold paper in full — this is the result CMS19 needed

§0c and §0d left one live unknown open for the Binius64 family: whether
round-by-round soundness had ever been shown for BaseFold in the practical
(list-decoding) regime. The user supplied the full text of Ulrich Håböck,
"Basefold in the List Decoding Regime" (IACR ePrint 2024/1571, received
2024-10-05, last revised 2025-09-04, StarkWare Industries). This closes the
question, and the answer is yes, with a precise scope.

**The paper exists specifically to supply this precondition.** Its own
footnote on page 1 states: "This is a revision of the preprint [Hab24]...
The present version clarifies the soundness analysis in terms of
round-by-round soundness [and] discusses soundness of WHIR as a polynomial
commitment scheme." The introduction is explicit: "the present document is a
revision of the previous preprint [Hab24]. Besides clarifying that the
analysis therein is not merely in a round-wise manner, but proves
**round-by-round soundness [CCH+18, CMS19]**." CCH+18 and CMS19 are cited by
name as the target framework — this paper was written to plug directly into
Chiesa-Manohar-Spooner's QROM theorem.

**Theorem 1 (Basefold soundness, §3.1):** "Protocol 2 as an interactive
oracle proof for R satisfies round-by-round soundness, with round-by-round
soundness error ε ≤ max{ε(C₀,M,1,θ), 1/|F|+ε(C₁,1,B₁,θ), ...,
1/|F|+ε(Cₙ,1,Bₙ,θ), (1-θ)ˢ}" — proven, for the proximity parameter θ taken
explicitly "in the list decoding regime," up to the Guruswami-Sudan-Johnson
bound 1-√ρ (not merely the easier unique-decoding regime). The proof (§5,
Lemmas 1-3) is a full round-by-round-soundness argument in the
Canetti-Chen-Holmgren-Lombardi-Rothblum-Rothblum (CCH+18) state-function
sense — the exact definitional target identified in §0c/§0d.

**Theorem 6 (FRI-Binius soundness, §6.3):** extends Theorem 1 to FRI-Binius
[DP24] specifically — binary-field, packed-multilinear Basefold, the
construction Binius-family systems use — stating "Protocol 3 is a
round-by-round sound interactive oracle proof for the language R, with
round-by-round soundness error ε = max{ε', ε_BF(C,M,θ,s)}." This is the
construction this project's own earlier source review already identified as
Binius64's underlying PCS: `docs/BINIUS_SECURITY_REVIEW.md` states
"`crates/verifier/src/zk_config.rs` wraps the inner protocol with GF(2^128)
Iron Spartan and BaseFoldZK" and cites "Underlying binary BaseFold/
ring-switching source: https://eprint.iacr.org/2024/504" — that ePrint ID is
DP24, the exact paper Håböck's Theorem 6 analyzes. This is a confirmed
structural match against this project's own prior independent source
inspection, not an inferred family resemblance.

**What this changes for A-01, precisely.** CMS19's Theorem 8.6 needs
round-by-round soundness of Binius64's *complete* LIOP (the Iron Spartan
sumcheck reduction for BitAnd/IntMul/BinMul/Shift constraints, intertwined
with the BaseFold/FRI-Binius commitment and folding rounds) before it can be
cited directly. Håböck's paper proves round-by-round soundness for the
BaseFold/FRI-Binius proximity-and-evaluation layer itself — exactly the
"wait for a round-by-round soundness proof of an underlying component" gap
§0c flagged as the blocking open question, now closed by a published,
reviewed-looking theorem rather than conference slides calling it "ongoing
work." Two pieces remain to literally complete the chain, both narrower in
scope than what was open before this read:
1. Confirm Iron Spartan's own sumcheck-based constraint reduction (R1CS/
   AND-gate satisfaction, reduced to the evaluation claim that Basefold then
   opens) is itself round-by-round sound. This is expected to hold — sumcheck
   is a standard example of a round-by-round-sound protocol in the
   foundational CCH+18 paper itself, and Håböck's own Protocol 2 already
   proves round-by-round soundness for a sumcheck *intertwined with* FRI-style
   folding sharing verifier challenges, which is structurally the same
   composition pattern Iron Spartan + BaseFold uses — but this has not been
   checked line-by-line against Binius64's actual LIOP pseudocode here.
2. Apply the standard round-by-round-soundness composition fact (a chain of
   round-by-round-sound reductions is itself round-by-round sound — this is
   literally how Håböck frames IOPs throughout §2.2, as "a chain of randomized
   reductions") to stitch the Iron Spartan sumcheck layer and the
   Basefold/FRI-Binius layer into one round-by-round-sound statement about the
   complete LIOP, then invoke CMS19 Theorem 8.6 on the result.

Neither remaining step is open research. Both are verification/assembly work
against already-published, already-proven results — a materially different,
and substantially more tractable, position than §0c's "has not been shown
established for BaseFold anywhere this review has found." **A-01 for the
Binius64 family has moved from "needs an unpublished proof" to "needs a
careful assembly-and-match verification of existing proofs against the
actual pinned LIOP" — a task suited to focused independent cryptographic
review, not to indefinite research.** The vSIS/RoKoko family's gap (§0d) is
unaffected by this finding and remains the more open of the two.

## 0f. Checked directly against pinned source: which composition case actually applies

§0e left one step open: does Binius64's actual LIOP interleave sumcheck with
BaseFold folding the way Håböck's Protocol 2/3 does (requiring a direct
structural match to his proof), or does it compose the two as separate
sequential phases (requiring only the standard, well-established
round-by-round-soundness composition fact)? This was checked directly against
the pinned source (commit `115108d5a661d95c0b474b6ab02558bfe6c6bec7`), not
inferred, with exact file:line citations.

**Result: the favorable case.** Binius64's LIOP is a clean two-phase
sequential protocol, not an interleaved one.

- **Phase 1 — mulcheck sumcheck runs to full completion first, with no oracle
  interaction.** `crates/spartan-verifier/src/lib.rs:343-375`,
  `fn verify_mulcheck<F, C>(... C: IPVerifierChannel<F>)`. The trait bound is
  `IPVerifierChannel`, not `IOPVerifierChannel` — this function has no
  oracle-query capability at all. It runs `mlecheck::verify_zk` (a degree-2
  zerocheck/sumcheck for the `A*B=C` constraint with Libra-style masking for
  zero knowledge), binds a challenge point, and returns evaluation claims.
  This is a standard multilinear sumcheck instance — the canonical example of
  a round-by-round-sound protocol in the foundational literature (CCH+18).
- **Phase 2 — BaseFold opens the resulting evaluation claims strictly after
  Phase 1 ends.** `lib.rs:224-237` packages the mulcheck output into
  `OracleLinearRelation` structs (`{oracle, transparent, claim}`, each
  asserting `⟨oracle_poly, transparent_poly⟩ = claim`), then calls
  `channel.verify_oracle_relations([...])` (`lib.rs:233`). The channel trait's
  doc comment (`crates/iop/src/channel.rs:95-101`) states this step "runs the
  opening protocol (e.g., BaseFold)." `Verifier::setup` (`lib.rs:280-301`)
  confirms the channel is backed by `BaseFoldZKVerifierCompiler` — real
  FRI-Binius-style BaseFold.
- **Why this is specifically Håböck's covered case:** the
  `OracleLinearRelation` claim form (`⟨oracle_poly, transparent_poly⟩ = claim`
  for a general, non-Lagrangian "transparent" closure) is exactly the
  generalized inner-product form Håböck's §6.1 covers (his equation 33), whose
  round-by-round soundness is established via his non-linear correlated
  agreement Theorem 4, extended to binary-field packed multilinears by §6.3's
  Theorem 6 (FRI-Binius) — Binius64's exact setting. The `mask_transparent`
  closure (`lib.rs:378-390`) is itself a non-Lagrangian quadratic-composition
  closure, confirming this is the generalized-kernel case, not the simpler
  single-query case.

**What this gets, precisely.** Standard round-by-round-soundness composition
(sequential chaining — both CCH+18 and Håböck's own §2.2 framing of IOPs as
"a chain of randomized reductions" use exactly this) applies directly: Phase 1
(standard sumcheck, round-by-round sound by well-established fact) hands off
an evaluation-claim language that is literally Phase 2's input language;
Phase 2 is round-by-round sound by Håböck's Theorem 6. The composed LIOP is
round-by-round sound with error equal to the max of the two phases' errors.
No bespoke interleaved-protocol comparison — the harder case this project's
own earlier framing worried about — is needed.

**Two residual items remain, both narrow and citation-checkable rather than
open research:**
1. Does Libra-style sumcheck *masking* (used for zero knowledge, not plain
   sumcheck) preserve round-by-round soundness? Masking for ZK is a standard,
   generally soundness-preserving transform; this is very likely true but has
   not been checked against a specific citation here.
2. Does `BaseFoldZKVerifierCompiler` — the *zero-knowledge* variant of
   BaseFold Binius64 actually uses — preserve the round-by-round soundness
   Håböck proved for plain (non-ZK) BaseFold/FRI-Binius? Same situation:
   standard expectation, not yet confirmed against a citation.
3. The canonical spec PDF (binius.xyz/spec.pdf) was not re-fetched to
   cross-check this source-level finding against the formal specification
   text; the source code is authoritative and gives exact file:line evidence,
   but a reviewer should still reconcile this against §5-7 of the spec.

**Net effect: A-01 for the Binius64 family is now a scoped, time-boxed
verification task — confirm two standard soundness-preservation claims
(masking, ZK-hiding) and assemble the composition — not an open research
problem.** This is a materially stronger position than any point earlier in
this document. F-01 is unaffected: the Soroban port of this same backend
remains measured oversized (exceeds the 400M instruction budget per
`VERIFIER_NEXT_EVIDENCE.md`), so CPU/code-size reduction is still required on
this backend regardless of A-01's improved outlook. The vSIS/RoKoko family
(§0d) is unaffected and remains the more open path on the A-01 side, while
being the stronger path on the F-01 side (95-107 KB, fits budget, pending
relation wiring) — an asymmetry between the two backends that is now the
project's central remaining architecture decision.

## 0g. Checked directly: Thaler's textbook on sumcheck round-by-round soundness and ZK masking

§0f left two narrow items as "standard but not citation-confirmed": does ZK
masking preserve round-by-round soundness, and does BaseFold's ZK-hiding
wrapper preserve it. Justin Thaler's standard reference, "Proofs, Arguments,
and Zero-Knowledge" (draft manuscript, https://people.cs.georgetown.edu/
jthaler/ProofsArgsAndZK.pdf, technical content stabilized mid-2022), was
fetched successfully (a prior attempt in this investigation got only
unreadable raw PDF bytes from this same host; this one downloaded cleanly and
was extracted locally with PyMuPDF — 329 pages, 1.1M characters, searched
directly rather than summarized by an intermediary). Two passages directly
answer the open items.

**Item 1 (plain sumcheck round-by-round soundness) is now independently
confirmed by a second, different source, not just Håböck.** Chapter 5
(Fiat-Shamir), pages 77-78, states the general theorem plainly: "Canetti et
al. [CCH+19] showed that the GKR protocol (and **any other interactive proof
based on the sum-check protocol**) satisfy round-by-round soundness, and
hence applying the Fiat-Shamir transformation to it yields a non-interactive
proof that is secure in the random oracle model." This is a direct, named
citation (Canetti-Chen-Holmgren-Lombardi-Rothblum-Rothblum, the same paper
Håböck cites as [CCH+18]) for exactly the claim needed about Binius64's Phase
1 (the mulcheck sumcheck, before ZK masking is applied).

**Item 2 (does ZK masking preserve this) is now directly, though not
fully rigorously, addressed.** Chapter 13 ("Zero-Knowledge via Commit-and-
Prove and Masking Polynomials"), §13.3 "Zero-Knowledge via Masking
Polynomials" (pages 203-207), discusses exactly the Libra-style
masking-polynomial technique Binius64's `mlecheck::verify_zk` implements, and
states: **"If Q is based on the sum-check protocol..., then the second
transformation of this chapter, based on masking-polynomials (Section 13.3)
can be applied. This has the dual benefits of plausibly preserving
post-quantum soundness, and typically adding less overhead than the
commit-and-prove-based transformation."** In this book's own established
framework (set out two chapters earlier, in the Fiat-Shamir chapter just
cited), "post-quantum soundness" of a Fiat-Shamir-compiled sum-check-based
protocol is precisely what round-by-round soundness is *for* — the two are
the same claim in this author's terms. The word "plausibly" is the author's
own hedge: this is an expert assessment in a widely-used graduate reference,
not a theorem-with-proof in this specific passage. It is the closest,
most directly on-point source found across this entire investigation for
this exact question, and it is a real, citable, and positive signal — not
confirmation at the rigor level of Håböck's Theorem 1/6 or the
CCH+19-via-Thaler citation above.

**What remains, precisely.** Three items, narrower than before:
1. The masking-polynomial transformation's round-by-round-soundness
   preservation is expert-asserted ("plausibly"), not proof-backed, in the
   most authoritative source checked. A rigorous proof (if one exists) has
   not been located; a reviewer may need to either find one or supply a short
   independent argument, which — given that masking only adds a random
   low-degree term without changing the round structure, degree bounds, or
   challenge-sampling that the round-by-round argument for plain sumcheck
   already covers — looks like a tractable, bounded proof task rather than
   deep new research.
2. BaseFold's ZK-hiding wrapper (`BaseFoldZKVerifierCompiler`) specifically
   is still unaddressed by any source found; the general masking-polynomial
   discussion above is about ZK-ifying sumcheck, not about ZK variants of
   FRI/BaseFold-style polynomial commitment schemes, which is a related but
   distinct question.
3. Neither item has been checked against Binius64's actual masking
   implementation in source (only confirmed that the function is named
   `verify_zk` and uses "Libra-style masking" per §0f) to confirm it matches
   the standard construction these sources describe, rather than a variant.

**Revised net effect: A-01 for Binius64 is now narrower still** — one
textbook-cited theorem fully closes the plain-sumcheck piece; the
ZK-masking piece has a direct, positive, named-expert signal rather than
silence, with a plausible short completing argument rather than a proof gap
of unknown size; only the BaseFold-ZK-wrapper piece remains genuinely
unaddressed by anything found. This is the kind of residual gap a scoped
independent cryptographic review is built for — confirm or supply one short
proof, confirm one BaseFold-ZK-specific soundness claim, check the
masking construction against the pinned implementation, then assemble.

## 1. Two external groups solved the identical problem; their architecture is the lesson, not just their numbers

Both papers below target precisely Q-Asset's original-seed recovery statement —
prove knowledge of an EdDSA/Ed25519 HD seed to authorize a new key under the same
address, without exposing the seed — for other EdDSA chains. Neither is Stellar-
specific and neither has been reproduced here, but their published architecture
choices are directly transferable.

- **ZKPoSP** (Botta, Pospieszalski, Ragnoli, Ranvier; IACR ePrint 2026/1508,
  <https://eprint.iacr.org/2026/1508>, AmericanFortress, last updated 2026-08-04).
  Targets BIP32-Ed25519. Its central architectural move: split proving into a
  **one-time derivation proof** per key pair and a **separate, per-message
  signing proof** whose cost does not grow with derivation depth. Built on RISC
  Zero (a hash-based STARK zkVM) with KMAC256 for its internal hash. States that
  post-quantum security is *conjectured*, not proven: every step of the security
  argument depends only on hash-function hardness and NIZK soundness in the
  QROM, explicitly avoiding any discrete-log-based step. A secondary source
  (not the paper itself) reports ~12-13s proving and ~9-10ms verification on
  server hardware for the per-message proof; this project's own
  the recorded technical reference review already cites this secondary figure under R24/R25 and
  flags it as unreproduced.
- **Baldimtsi, Chalkias, Roy, Sedaghat, "Post-Quantum Readiness in EdDSA Chains"**
  (IACR ePrint 2025/1368, <https://eprint.iacr.org/2025/1368>, Mysten
  Labs/George Mason/KU Leuven; full version in FC 2026 proceedings). Targets
  Sui/Solana/Near-style EdDSA chains with the same "prove seed knowledge, keep
  the address, authorize a new PQ key" statement as this project's Recovery
  role. Proof-of-concept uses the Ligetron zkVM (also hash-based/STARK-style).
  Reported figures: 6.2s proving, 2.3s verification, **5.4 MB proof size**.

Neither figure has been independently reproduced in this repository. But the
comparison is still informative: this project's own already-executed Binius64
Iron Spartan leaf comparator produces a **539,888-byte** genuine ZK proof (see
[BINIUS_RECOVERY_EVIDENCE.md](BINIUS_RECOVERY_EVIDENCE.md)) — roughly **10x
smaller** than the Sui-affiliated paper's reported 5.4 MB for a materially
similar statement. The existing internal direction is not behind the published
field on proof size; it is specifically short of *Soroban's* transaction/code
limits, which are far tighter than what either external paper targets (neither
targets an embedded, metered Wasm verifier).

The reusable lesson from both papers, independent of their chosen backend, is
the **split between a one-time (or off-chain, pre-enrollment) expensive proof
and a small, repeatable on-chain proof** — see §2.

## 2. Reframe the relation: commit at enrollment, prove only the commitment preimage at recovery

Every backend this project has measured so far (ZKBoo/BIP32 lifting, the
scalar-exposure variant, the ShorStop/Plonky3 SHA-512 AIR, the Binius64 Iron
Spartan leaf comparator) proves some form of the **full** relation: SHA-512
expansion, clamping, and/or Ed25519 scalar multiplication, directly, inside the
circuit, at *recovery time*. That relation is inherently circuit-unfriendly
(SHA-512's bit-oriented round function and modular EC scalar multiplication both
require many constraints in essentially every proof system), which is the
proximate reason every measured proof has been megabytes before compression and
still hundreds of kilobytes after heavy optimization.

Both external systems in §1 sidestep exactly this by not re-proving the whole
derivation relation every time:

- ZKPoSP separates a one-time **derivation proof** from the cheap recurring
  proof.
- A commitment/attestation made once, while the classical key is still trusted
  (i.e. *before* any quantum compromise and before recovery is ever needed), does
  not itself need to be a zero-knowledge proof — it can be checked **in the
  clear**, classically, at enrollment time, exactly as this project's
  `pq-recovery-demo` already checks an enrolled recovery key's bytes directly
  with no proof system at all.

Concretely: at enrollment (while the owner still controls their classical
Ed25519 key and the account is not yet under threat), have the owner compute
locally `k` → SHA-512/clamp/scalar `a` → `A = [a]B` (today's relation, performed
*outside* any circuit, exactly as `recovery-key-binding`'s generic point-binding
helper already validates), and additionally compute `C = H_zk(k)` for some
**ZK-and-lattice-friendly** hash `H_zk` (not SHA-512). The account registers
`C` alongside its normal SEP-5-derived public key, using a conventional,
non-ZK, classically-verified transaction. At recovery time, after a quantum
compromise of `a`/`A` is assumed, the proof obligation shrinks to exactly: "I
know `k'` such that `H_zk(k') = C`, and I am binding this proof to the current
network/contract/epoch/replacement-key/expiry statement" — a single
hash-preimage-knowledge circuit, not a SHA-512-plus-scalar-multiplication
circuit. This is the same "commit now, prove cheaply later" shape as both
external papers, applied at the relation level instead of only the proof-system
level, and it composes with whichever backend is chosen next.

Caveats, stated at the same rigor this project holds itself to elsewhere:

- This requires an **additional enrollment-time step** (registering `C`) and
  changes what "previously enrolled" means for this feature; it does not help
  an account that only ever registered its plain SEP-5 public key. That is an
  acceptable cost here because recovery already requires prior enrollment in
  every version of this design (see `RECOVERY_SECURITY_ARGUMENT.md`).
- `H_zk` must itself be chosen for defensible generic (Grover-only) preimage
  resistance at an adequate security level — committing through a weak or
  novel hash would trade a measurement problem for a cryptanalysis problem.
  Candidates and their current caveats:
  - **Vision Mark-32** (Ashur, Mahzoun, Posen, Šijačić; IACR ePrint 2024/633,
    <https://eprint.iacr.org/2024/633>) is defined directly over binary tower
    fields and is already vendored in this repository's Binius64 dependency
    tree (`crates/hash/src/vision*.rs`) — but only as Binius's *internal*
    Merkle/transcript hash, never yet as the *statement* being proven. Its
    ePrint listing itself carries an "Update security arguments" note; treat
    its margins as provisional pending that update, not as settled.
  - **Poseidon2 over binary fields ("Poseidon_b")** has a 2025 revision
    (IACR ePrint 2025/1893) explicitly re-examining its security against recent
    algebraic/subspace-trail cryptanalysis — active scrutiny is a healthy sign
    for a ZK-friendly hash, but it means the margin has moved recently and
    should be re-checked against the latest revision before pinning a version.
  - A conservative fallback is to commit via the **already-audited, already-
    used SHA-256** (the host-accelerated hash this registry and the mailbox
    already call via `env.crypto().sha256`), accepting a larger-but-still-far-
    smaller-than-SHA-512-plus-EC circuit than today's relation, in exchange for
    not introducing a new, less-analyzed primitive onto the critical path.
    §2b below measures this trade rather than assuming it.

## 2b. Measured: the SHA-256 version of this change, and why it mostly didn't help proof size

This section originally predicted "roughly one to two orders of magnitude"
smaller proofs from this reframing. That prediction has now been measured
against the existing Binius64 Iron Spartan backend and is **mostly wrong for
proof size, right for CPU time** — reported here rather than left standing
uncorrected.

[`tools/binius-commit-prove-research`](../tools/binius-commit-prove-research)
reuses the exact pinned Binius64 commit, the identical `ZKProver`/`ZKVerifier`
configuration, the same public RFC8032 fixture seed and the same dummy action
digest as `tools/binius-seed-research`, but proves `SHA256(seed) = commitment`
instead of `clamp(SHA512(seed))[0:32] = scalar AND [scalar]B = point`. Exact
numbers and hashes are in
[binius-commit-prove-research.json](binius-commit-prove-research.json); summary:

| Metric | SHA-512+clamp+scalar-mult (existing) | SHA-256 preimage (new) | Change |
| --- | --- | --- | --- |
| AND constraints | 1,155 | 912 | -21% |
| Padded trace (`committed_total_len`) | 2,048 words | 2,048 words | **unchanged** |
| Proof bytes | 539,888 | 539,856 | -0.006% |
| Prove time | 1.086 s | 0.748 s | -31% |
| Verify time (incl. setup) | 0.601 s | 0.351 s | -42% |

**Proof size barely moved because both relations' AND-constraint counts land in
the identical power-of-two padded-trace bucket.** A synthetic sweep (same
file) built trivial chains of `N` AND gates and found the padding is not a
fixed floor — a 1-constraint circuit pads to 4 words — but the bucket this
particular pair of relations falls into jumps from 1,024 to 2,048 words
somewhere between roughly 256 and 512 raw AND gates. Removing the
scalar-multiplication gadget cut constraint count by 21%, which was not enough
to cross that boundary; SHA-256's own compression function still costs ~900
AND constraints.

This **sharpens rather than removes** the case made above for a true algebraic
ZK-friendly hash over binary fields (Vision/Poseidon) instead of a merely
smaller classical hash: the sweep shows real headroom exists one bucket down,
but reaching it needs a commitment circuit substantially smaller than SHA-256,
which a bit-sliced classical hash cannot provide — only a primitive designed
to need few multiplication gates per output bit plausibly can. The reframing
is still the right first move for *CPU time* (measured, not assumed, -31%/-42%
here) and remains a precondition for any backend change to make sense at all;
it just does not by itself close F-01's proof-size side under this specific
backend's parameters. It is the first thing re-measured per §4, with the
existing Binius64 adapter (confirmed patched per §0) — the result above *is*
that re-measurement, and it redirects §4's next step toward backends/hashes
that can actually leave this padded-trace bucket, not away from the reframing
itself.

## 2c. Measured: crossing the bucket boundary with an already-vetted smaller hash, and why that still isn't enough

§2b's sweep showed the padding bucket does shrink for smaller circuits, with a
boundary between roughly 256 and 512 raw AND gates, and predicted that reaching
it would need something smaller than SHA-256's ~900 AND constraints rather
than a from-scratch algebraic hash necessarily. Before attempting any new,
unreviewed primitive, a cheaper check: do any of the hash gadgets *already
implemented and tested* in the pinned `binius-circuits` crate (BLAKE2s, BLAKE3,
Keccak — all independently specified, widely used, not written by this
project) already cross that boundary for a 32-byte input?

BLAKE3 does: 626 AND constraints versus SHA-256's 912, landing in a
**1,024-word bucket, half of SHA-256's 2,048**.
[`tools/binius-commit-prove-blake3-research`](../tools/binius-commit-prove-blake3-research)
measured what that actually produces, against the identical pinned backend,
action-binding discipline and fixture seed as the other two comparators. Exact
numbers and hashes are in
[binius-commit-prove-blake3-research.json](binius-commit-prove-blake3-research.json):

| Metric | SHA-512+clamp+scalar-mult | SHA-256 preimage | BLAKE3 preimage |
| --- | --- | --- | --- |
| AND constraints | 1,155 | 912 | 626 |
| Padded trace (`committed_total_len`) | 2,048 | 2,048 | **1,024** |
| Proof bytes | 539,888 | 539,856 | **515,984** (-4.4%) |
| Setup time | 0.752 s | 0.851 s | 0.408 s (-52%) |
| Prove time | 1.086 s | 0.748 s | 0.533 s (-29%) |
| Verify time | 0.601 s | 0.351 s | 0.275 s (-22%) |

**Crossing the bucket boundary only shrank the proof by 4.4%, not the ~50% a
halved trace length would naively suggest — but it halved setup time, almost
exactly.** That split is the signature of a FRI/BaseFold-style argument: setup
cost scales with the trace itself (`O(n)`, so halving `n` halves it), while
proof bytes scale with the fixed query count (232, per `pins.json`) times the
Merkle-authentication-path length, which only scales with `log(n)` — dropping
`log2(committed_total_len)` from 11 to 10 removes one Merkle-tree level per
query, a small constant saving across a *fixed* number of queries, not a share
proportional to the circuit-size reduction.

This changes what §2b could only hedge about into a specific, measured
mechanism, and it changes the recommendation: **relation-size reduction, even
when it successfully crosses a padding-bucket boundary with a real, vetted,
properly swapped-in hash, cannot deliver the order-of-magnitude proof-size
reduction F-01 needs under this backend's FRI/BaseFold construction.** The
reframing remains clearly worthwhile for CPU time (now measured at three
points, consistently 20-50% faster per halving of trace size) and remains a
precondition worth keeping for any future backend. But closing F-01's size
side requires a backend whose proof size does not scale as
`O(queries × log(n))` — which is exactly the property a lattice-based
construction like LaBinius+LaBRADOR is designed to have (§3), not a smaller
circuit on the current backend. This is now the load-bearing reason to prefer
evaluating LaBinius next, not merely "it reports a smaller number in its own
paper."

## 3. Backend alternatives whose soundness rests on a better-studied assumption

Everything measured in this project to date (ZKBoo, Plonky3/WHIR, Binius64 Iron
Spartan) is a hash-based Fiat-Shamir STARK-family construction, whose
"post-quantum" status rests on a QROM Fiat-Shamir transform heuristic that, per
§0, has had a real implementation-level break found in a sibling system this
year. An independent family worth comparing — **lattice-based** succinct
arguments, whose soundness instead reduces to Module-SIS/Module-LWE, assumptions
with a much longer and more conservative cryptanalytic track record — has had
several 2026 results specifically aimed at small proof sizes:

| Construction | Source | Reported proof size | Reported prove/verify time | Notes |
| --- | --- | --- | --- | --- |
| LaBinius + LaBRADOR | Osadnik & Seiler, IACR 2026/2103, <https://eprint.iacr.org/2026/2103> | ~96.4 KiB | 3.07s / 0.73s | SNARK for "standard hash evaluations"; explicitly connects to **Binius and Flock front ends** — i.e. designed to sit under the same binary-field circuit front end already used here, swapping only the polynomial-commitment/compression backend. Author's own blog benchmark (<https://www.osdnk.me/blog/labinius>), not independently reproduced. |
| RoKoko | IACR 2026/575, <https://eprint.iacr.org/2026/575> | ~200 KB ("practical") | not reviewed in depth here | Successor to "RoK and Roll" (ASIACRYPT 2025, first post-quantum SNARK with quasi-linear proof size); reports ~100x faster verification than Greyhound at competitive size. |
| Cyclo | IACR 2026/359, <https://eprint.iacr.org/2026/359> | ~30 KB ("practical") | not reviewed in depth here | Lattice folding scheme, successor to LatticeFold+; proof size is the headline result. |
| Greyhound | IACR 2024/1293 | ~53 KB (at degree 2^30) | not reviewed in depth here | Polynomial commitment only (Module-SIS), not a full SNARK; a building block other entries above build on. |

All four rows are **unverified by this project**: preprint or author-blog
figures, not independently reproduced, not ported to `wasm32v1-none`, and not
measured against Soroban's CPU-instruction metering model. The LaBinius row is
the most directly relevant because its stated design goal — a compact proof of
a hash evaluation, over binary-field arithmetic compatible with an existing
Binius-style circuit front end — is exactly the statement shape this project
would need after the §2 reframing, and its reported 96.4 KiB is already under
Soroban's recorded 132,096-byte whole-transaction limit by itself, which would
remove the need for the chunked mailbox staging workaround entirely if it holds
up under an actual Soroban port. Its 0.73s native verification time is
promising relative to the 11.8s native verification this project already
measured for the (since-abandoned) ZKBoo backend, but native wall-clock time is
not a reliable predictor of Soroban's metered-instruction cost — lattice/NTT
arithmetic without AVX-512 (the reference implementation's own acceleration)
inside a metered wasm32 interpreter could still be expensive, and this must be
measured directly, the same way this project already measured Binius64's
Soroban port cost rather than assuming it from native numbers.

## 3b. Attempted: building LaBinius and RoKoko, not just reading their papers

Per §4's prior ordering, the next step was to pin an exact LaBinius revision
and reproduce its native benchmark before any Soroban-specific work. That was
attempted, not merely planned.

**LaBinius is blocked on two independent grounds, before performance even
enters into it.** Cloning `github.com/osdnk/labinius` at `96b57f7` (2026-09-18)
found no `LICENSE` file and no `license` field anywhere in its workspace
`Cargo.toml` — only its vendored third-party LaBRADOR C library
(`crates/pcs/labrador`, Apache-2.0, IBM Corp., properly attributed with
upstream provenance in its own `VENDORED.md`) is licensed; the `labinius`
Rust code itself, the actual research contribution, is not. Under default
copyright that means no one has permission to reuse it, independent of any
technical merit — the same bar this project has applied to every other
dependency (ZKBoo LGPL-3.0, ShorStop/Binius64 MIT/Apache, this section's own
RoKoko check below), so it is applied here too rather than waived because the
numbers looked good. Separately, and independent of licensing: `crates/pcs`'s
build script unconditionally runs `make -C labrador` with no feature gate
before compiling anything else, and that Makefile hard-requires AVX-512
(`chihuahua.c` calls `_mm512_*` intrinsics directly, no scalar fallback). On
this evaluation machine (no AVX-512; confirmed via `/proc/cpuinfo`), that
`make` step fails at the first file with "inlining failed in call to
'always_inline' ... target specific option mismatch," which fails the whole
build before any Rust code compiles — there is no reduced-feature or
clear-opening mode that avoids it, because the C library is linked
unconditionally regardless of which `Opening` variant is used at the Rust
level. **This second point generalizes beyond this one sandbox**: Soroban's
`wasm32v1-none` target has no AVX-512 and never will, so a construction with a
hard, fallback-free AVX-512 dependency in its reference implementation cannot
currently be ported to Soroban at all, regardless of what hardware evaluates
it natively — the blocker is not "this machine is too weak," it is "this
code path cannot exist in a wasm32 target as published." Both findings stand
independent of LaBinius's reported 96.4 KiB figure, which remains unverified
by this project for an unrelated, better reason now: it cannot currently be
built, at all, by anyone without AVX-512 hardware and without contacting the
authors for an explicit license grant.

**RoKoko, by contrast, builds and runs.** `github.com/lattice-arguments/rokoko`
at `c3f8206` (2026-10-20) has a proper root `LICENSE` (Apache-2.0, "RoKoko
authors") and the same for its `incomplete-rexl` ring-arithmetic sub-crate.
Its README states explicitly that `incomplete-rexl` "runs on any
Rust-supported platform (with degraded performance)" when AVX-512 is absent —
a real portable fallback, not a hard dependency — which this evaluation
confirmed directly: `cargo +nightly build --release` succeeds on this
non-AVX-512 machine with no C toolchain involved at all (pure Rust), and
running the resulting binary prints explicit, honest feature detection
(`✗ AVX-512F is NOT available on this CPU`, `✗ AVX-512DQ`, `✗ AVX-512VBMI2`)
and proceeds anyway rather than failing. This is a materially different
engineering posture from LaBinius's, and the more promising candidate for an
eventual wasm32 attempt specifically because it has already demonstrated it
degrades rather than breaks in the absence of vector-SIMD hardware — which is
exactly wasm32v1-none's situation.

The README documents that its first run only populates an allocation cache
(printing "a number of warnings about an unpopulated cache") and that a
second run is required for representative timing; measured directly, the
first run's CRS-generation step alone took 17.96s of wall-reported internal
time inside a 15m21s wall-clock run (1m59s user, 5m19s sys — consistent with
one-time allocation/cache-population overhead, not steady-state computation),
and the second run's CRS generation dropped to 2.09s, confirming the cache
behavior as documented.

Both the first and second runs, at the binary's default `P28` parameter
class, were killed by the kernel OOM killer (confirmed in `dmesg`/`journalctl`:
`Out of memory: Killed process ... (rokoko) ... anon-rss:4900496kB` and
`anon-rss:5114200kB` respectively) — this evaluation machine has 5.8 GiB of
RAM total, and `P28`'s resident footprint exceeded that even with no
parallelism enabled. This is an environment resource limit, not a defect in
RoKoko: dropping to the smallest shipped parameter class, `P22`
(`./target/release/rokoko p-22`), completed cleanly in 15.9s wall time with no
memory pressure, printing:

```
TOTAL CRS gen time: 144383865 ns
TOTAL Commit time: 1445614438 ns
TOTAL Prover time: 13507023868 ns
Total proof size: 95.27685546875 KB
Wire proof size: 106.5556640625 KB (serialise 1.699 ms, deserialise 1.226 ms)
TOTAL Verifier time: 387293315 ns
```

**This is a real, independently-reproduced measurement, not an author-reported
figure** — but it needs the same caveat applied to every other number in this
document: read the actual code path before treating it as comparable to this
project's own circuit measurements. `main.rs`'s default `execute()` path (the
one just run) calls `check_prover_claims_match_witness`, which checks the
prover's claims against `claim(witness, inner, outer)` computed directly from
an **in-memory synthetic witness** sampled by the harness — this benchmarks
RoKoko's core committed-witness evaluation-argument machinery in isolation,
not a proof of any specific hash-preimage relation (there is a separate
`execute_snark`/`snark` feature path for "user-supplied sumcheck claims about
a committed witness," which could in principle carry a real circuit, but
wiring an actual SHA-256/BLAKE3-preimage relation through it — the way
LaBinius explicitly does via its Binius/Flock front-end integration — has not
been done, here or upstream, and is itself nontrivial work). So: ~95-107 KB
and ~0.39s verification, with **no SIMD acceleration at all**, for the
argument system's own overhead at this parameter class — comfortably under
Soroban's 132,096-byte transaction cap and a promising floor, but not yet a
measurement of "proving BLAKE3(seed)=commitment," which is the actual
statement this project would need. Wiring that relation through is the
concrete next step if this backend is pursued further, not a repeat of this
measurement.

### Scoped directly: what "wiring the relation through" actually requires

A follow-up pass inspected RoKoko's actual `snark` module and its own
documentation (`docs/snark.md`) to scope this "concrete next step" precisely,
rather than estimate it from the paper. The finding changes the estimate
materially.

RoKoko's SNARK front end is explicitly labeled by its own authors:
**"The SNARK front end (EXPERIMENTAL)"** (`docs/snark.md`, title line). Its
own "mental model" section states the claim language's actual expressiveness
plainly: "There is no other multiplication: factors combine *pointwise, at
the same index*. Relations between entries at different positions are a
layout problem — put the data where the claim needs it (commit a rearranged
copy and tie it back with a copy claim)." Concretely, the supported
primitives are: weighted sums/dot-products over a committed witness region
(`witness_in(region)`), public weight factors (`table`, `eq`, `powers`,
`combination`), and `Claim::sums_to` / `Claim::sums_to_zero` batched into one
sumcheck. This is a lookup-argument/inner-product claim system, not a
general-purpose boolean/arithmetic circuit (R1CS/Plonkish gate) system.

A repository-wide search for existing hash-function circuit gadgets
(`blake|sha256|sha512|xor|rotat|bit_decomp|bitwise`, case-insensitive, across
`src/`) found no hits that are hash-preimage circuit code — the only
`blake3`/hash-related matches are `src/common/hash.rs`, which is the
Fiat-Shamir **transcript** hash (BLAKE3 used to derive challenges), unrelated
to proving a hash function's preimage. There is no pre-built BLAKE3, SHA-256,
or any other hash gadget anywhere in this repository, unlike Binius64's
`binius-circuits` crate (which supplied the already-tested SHA-256 and
BLAKE3 gadgets `tools/binius-commit-prove-research` and
`tools/binius-commit-prove-blake3-research` wired against directly) or
LaBinius's documented Binius/Flock front-end integration.

**What this means concretely.** Proving `BLAKE3(seed) = commitment` through
RoKoko is not a wiring task against an existing gadget — it requires
building a boolean-circuit gadget layer from scratch inside an
authors-labeled-experimental frontend: bit-decomposing 32-bit words into
committed boolean witness entries (`src/common/decomposition.rs` provides
generic digit decomposition, which helps but is not a boolean-circuit
gadget), encoding XOR and modular-addition-with-carry as polynomial
identities over those bits, and chaining this correctly across BLAKE3's
seven compression rounds with copy-constraints tying state between rounds —
genuine multi-day cryptographic circuit engineering with real correctness
risk if rushed, not a bounded afternoon task. This project's own discipline
throughout this document has been to measure the real thing rather than
approximate it; hand-rolling an untested hash gadget under time pressure and
reporting its output as a measurement would violate that discipline, not
extend it.

**Revised status.** RoKoko's proof-size and verification-time numbers remain
genuinely promising (§3b above) and the licensing/portability posture remains
the strongest of any candidate evaluated. But "wire a real hash-preimage
relation through RoKoko" is now known to be a substantial, separately-scoped
engineering effort — comparable in magnitude to building a new circuit
frontend component, not an incremental addition to existing tooling — and
should be budgeted and planned as such rather than attempted inside a
single research session.

## 4. Recommended next gate

In order of expected information gained per unit of effort, matching this
project's own existing methodology (read-only source inspection before any
build; native measurement before any Wasm port; Wasm port before any SDK/ABI
integration):

1. **§0 is resolved**: the pinned Binius64 commit includes the disclosed
   transcript-binding fix, confirmed by direct source inspection against the
   exact reported fix text, not merely commit-number ordering. No action item
   remains here beyond keeping the pin where it is and re-checking it on any
   future re-pin. **§0b is also resolved, as a literature check**: the
   canonical Binius64 spec has been read cover to cover; it proves classical
   ROM soundness/knowledge-soundness explicitly and with quantified error
   terms, and states its post-quantum security as an unsupported hedge
   repeated twice with zero QROM treatment. A-01 is now a precisely named
   gap — a QROM knowledge-extraction proof that does not exist in the primary
   source, not a vaguely "unestablished" one — and remains exactly as open as
   before, because reading the spec cannot supply the missing proof itself.
   §0b also found the spec's own admission that Binius64 verification "is
   not yet succinct," independent evidence for why §2b/§2c's CPU numbers
   improved with circuit size while proof bytes barely moved. **§0c checked
   whether the literature already has a path to close A-01 rather than
   stopping at "unestablished"**: CMS19 gives QROM security for any
   round-by-round-sound IOP-based SNARG, which would apply to Binius64
   directly if round-by-round soundness were shown for its LIOP — but that is
   not yet shown, a 2025 attempt to relax the requirement to ordinary
   soundness was withdrawn for a genuine proof bug, and BaseFold's own
   round-by-round soundness in the practical list-decoding regime was, per
   the original authors' 2024 slides, called ongoing work rather than
   complete. The same check found a more directly applicable standing theorem
   (LMS22) for the lattice/Bulletproofs family RoKoko and LaBinius belong to,
   whose own abstract claims coverage of "recent Bulletproofs-like protocols
   based on lattices" — unverified against RoKoko's own (unread) security
   section, but a narrower, more tractable gap than Binius64's.
2. **§2b is measured**: re-running the existing Binius64 leaf comparator under
   the §2 reframing (SHA-256 preimage instead of the full SHA-512+clamp+scalar-mult
   relation) cut constraint count 21% and CPU time 31-42%, but left proof size
   unchanged (539,856 vs 539,888 bytes) because both relations pad to the same
   2,048-word trace bucket. The isolation this step was meant to provide is
   now a specific, quantified number, not an open question — and it redirects
   step 3 rather than validating it as originally framed.
3. **§2c is measured, and it redirects this step again.** BLAKE3 (already
   vetted, already implemented, no new primitive) crossed the predicted
   bucket boundary — 626 AND constraints, 1,024-word bucket, half of
   SHA-256's — and still only shrank the proof 4.4%, because this backend's
   proof size scales with `queries × log(trace size)`, not trace size. A
   Vision/Poseidon-sized circuit would very likely cross *another* bucket
   boundary or two, but by this same mechanism that would still only buy a
   few more percent per halving, not an order of magnitude — so **do not
   spend effort implementing a novel algebraic hash gadget expecting a large
   proof-size win from trace-length reduction alone on this backend.** The
   reframing (any of the three measured relations) remains worth keeping for
   its real, measured CPU-time benefit and as the natural circuit to port to
   whichever backend comes next.
4. **§3b attempted this, and the answer split in two.** LaBinius (ePrint
   2026/2103) is blocked on two independent grounds that have nothing to do
   with its reported numbers: no declared license anywhere in its repository,
   and a hard, fallback-free AVX-512 dependency in its reference
   implementation's C bridge (confirmed by an actual failed build on this
   evaluation machine) that would block a `wasm32v1-none` port regardless of
   what hardware evaluates it natively. **Do not pursue LaBinius further
   without first securing an explicit license from its authors** — the
   AVX-512 dependency might be removable by someone with the time to rewrite
   its FFI'd C kernels in portable Rust, but the license gap cannot be
   engineered around. RoKoko (ePrint 2026/575) is not blocked the same way:
   it is Apache-2.0 licensed, has a genuine portable fallback (confirmed: it
   builds and runs correctly on this non-AVX-512 machine, with explicit,
   honest runtime feature detection rather than a silent crash), and measured
   directly at its smallest parameter class produced a 95-107 KB proof
   verifying in 0.39s with **no SIMD acceleration at all** — comfortably
   under Soroban's transaction cap. The real next step, if this family is
   pursued further, is wiring an actual hash-preimage relation (BLAKE3,
   matching §2c) through RoKoko's `execute_snark`/committed-witness-claim
   interface, since the measurement just obtained benchmarks its core
   argument machinery on a synthetic witness, not that specific statement —
   this is nontrivial integration work, not a configuration flag, and has
   not been done here or upstream. Only after that would a native →
   wasm32v1-none → Soroban-SDK-ABI pipeline (mirroring Binius64's) be the
   next gate, with the same negative/malicious-witness tests and exact-byte
   provenance discipline used throughout `BINIUS_RECOVERY_EVIDENCE.md` and
   `VERIFIER_NEXT_EVIDENCE.md`.
5. **Independent cryptographic review remains a separate, non-skippable gate**
   regardless of which backend/relation step 4 selects — Module-SIS-based
   soundness is better-studied than ad hoc STARK Fiat-Shamir, but
   "better-studied" is not "reviewed for this specific composition," and §0's
   now-resolved finding was still a real, disclosed, exploitable bug in a
   sibling system a few months before this review — exactly the class of
   defect independent review exists to catch, and exactly why it cannot be
   waived for whichever family is chosen. §0c adds a concrete, assignable
   version of this gate rather than just repeating that review is needed:
   for Binius64, the open mathematical question is specifically whether its
   LIOP (sumcheck + BaseFold) has round-by-round soundness, which a
   repaired form of CMS19 could then turn into QROM security directly; for
   the lattice family, §0d's full-text read sharpens this further: LMS22's
   Theorem 4 is proven only for plain-SIS Bulletproofs (BLNS20/AL21/ACK21),
   not vSIS, so the task is extending LMS22's fold-collapsing and
   recursive-special-soundness framework to vSIS's tensor-structured
   commitment and to RoKoko's full composed RoK sequence — more work than
   confirming an existing theorem's hypotheses already hold, though still a
   named extension of a named framework, not open-ended research. Neither is
   "ask a cryptographer to look at this generally" — both are a named
   theorem and a named precondition to check.

Steps 1, 2 and 3 are now closed, with measured evidence — including evidence
that corrected this document's own initial prediction. Step 4 was attempted,
not merely planned: LaBinius is now closed too, as blocked (license and a
hard AVX-512 dependency that generalizes to blocking any `wasm32v1-none`
port), and RoKoko is open and partially measured (licensed, portable,
95-107 KB proof of its core argument machinery, with wiring an actual
hash-preimage relation through it as the defined remaining work). Step 5 is
the same release-blocking gate this project has held constant throughout.
This document adds a researched, cited, and now substantially measured path
forward — it does not claim either gap is closed.

## 5. Where this leaves the project, and the actual next action

§§0d-0g pushed A-01's Binius64 side substantially further than a literature
check can: full-text reads of CMS19, LMS22, Håböck's BaseFold paper, and
Thaler's standard reference (all user-supplied or directly downloaded and
searched, not summarized secondhand), cross-checked against the pinned
source at file:line precision, found that Binius64's LIOP composes as the
favorable sequential case, that plain sum-check-based protocols are
round-by-round sound by a named theorem (independently confirmed by two
sources), and that the specific ZK-masking technique Binius64 uses is
expert-assessed in a standard reference as "plausibly preserving
post-quantum soundness." **One item remains genuinely open on this specific
question: whether BaseFold's own ZK-hiding wrapper preserves round-by-round
soundness** — nothing found addresses this directly, for either Binius64's
`BaseFoldZKVerifierCompiler` or the general case. This is not a gap further
solo literature search is likely to close efficiently; it is the kind of
narrow, well-posed technical question a scoped independent cryptographic
review exists to answer, and the honest, responsible next step **is to
hand it to one, rather than continue searching alone.**

Separately, §3b's RoKoko follow-up found that "wire a real hash-preimage
relation through RoKoko" — previously estimated as integration work — is
actually substantial, separately-scoped circuit-gadget engineering (building
boolean-circuit primitives from scratch inside an authors-labeled
"EXPERIMENTAL" frontend with no existing hash gadgets), not something to
attempt inside a research session without the correctness-verification
budget that kind of code demands. Binius64's own F-01 (the Soroban SDK
verification path still measured exceeding the 400M instruction budget) has
no newly identified next lever either; it remains a CPU/code-size
engineering problem on its own terms.

**Taken together, every open item in this document now has a specific,
correctly-scoped owner, and none of them is "more unaided research by this
project":**

- **A-01, Binius64 side** — ready for a scoped independent cryptographic
  review. The review's actual deliverable is narrow and checkable: confirm
  (a) that `BaseFoldZKVerifierCompiler`'s hiding transformation preserves the
  round-by-round soundness Håböck's Theorem 6 established for plain BaseFold,
  (b) that Binius64's Libra-style masking implementation matches the standard
  construction Thaler's book describes closely enough for its "plausibly
  preserving" assessment to transfer, and (c) the composition assembly
  itself — then CMS19 Theorem 8.6 applies and gives an actual QROM proof, not
  a conjectured-hardness hedge. This is the single highest-value action
  available to the project right now.
- **A-01, vSIS/RoKoko side** — genuinely open research (extending LMS22's
  framework to vSIS and to RoKoko's full composed RoK sequence); not a task
  for this project to attempt or for a bounded review to resolve quickly.
  Out of scope until the field publishes it or the project commissions
  original research, which is a materially different, larger commitment than
  a review.
- **F-01, Binius64 side** — unsolved CPU/code-size engineering, but no longer
  lever-less: `sdk-code-size-breakdown.json` ruled out quick code-size fixes
  (the 56,022-byte SDK-wrapper gap is inherent `soroban-sdk` glue), and
  `verifier-wiring-hotspot-research.json` found, via a pure-userspace
  sampling profiler, that ~71% of verification cost sits specifically in
  `binius_spartan_verifier::wiring`'s MLE-evaluation functions, not the
  BaseFold/FRI hashing machinery a shallower guess would target. Neither
  finding closes F-01; both give a dedicated optimization effort (not
  research, and not attempted here — no change was made to the pinned
  verifier) a concrete target instead of a diffuse one.
- **F-01, RoKoko side** — the cross-region-multiplication blocker found
  directly against the live library (two independently-committed secret
  regions cannot be multiplied together: degree 4, rejected unconditionally,
  with or without weighting, because two different regions always need two
  distinct selectors) is now resolved, not just scoped. A follow-up probe of
  the ring's internal structure (`ROKOKO_RELATION_WIRING_SCOPE.md`) found
  that packing two secret bits into one ring element's two coefficients
  (confirmed, empirically and robustly across six varied inputs, to behave
  as a controllable quadratic-extension slot) and squaring that *one*
  region against itself yields `2*a*b` as a free side effect — no
  cross-region product needed at all. Tying this to a freshly committed
  `p_ab` region, and deriving XOR from the same packed value, were both
  validated end to end against the live library: honest witnesses accepted,
  two independently-malicious witnesses (a wrong AND tie, a wrong XOR tie)
  both correctly rejected, including larger and edge-case bit patterns.
  Combined with the already-validated binariness, rotation, and two-limb
  addition primitives, this removes F-01-RoKoko's "blocked on an open
  question" status: it is engineering work again, not research, with one
  caveat carried forward rather than resolved — this validated soundness,
  not zero-knowledge-hiding, which this project cannot verify by itself and
  now scopes for independent review (`ROKOKO_ZK_HIDING_REVIEW_SCOPE.md`,
  ready to send), the same way Binius64's own open question already is. A
  full 1-bit adder was then built from the same construction alone (no
  digit decomposition, no shipped value) and validated against all 8 input
  combinations plus six independently-malicious witnesses, each rejected —
  the two concrete building blocks SHA-512 needs (bitwise gates, addition)
  are both validated now, ahead of, not blocked on, that review. A separate,
  untested assumption in that scope document — that rotation and
  carry-chaining get a "free" shift via a documented copy-claim recipe —
  was then checked directly and found wrong (that recipe only ties
  same-index entries, not shifted ones); what actually works, confirmed
  both accepting a correct shift and rejecting a corrupted one, is one
  individual length-1-region tie per shifted position, not one batched
  claim — a real, now-corrected cost, not a free one. **Correction, same
  day:** that AND/XOR gate and the full adder were then found unsound — an
  adversary putting junk in a coefficient the gate ignores was accepted by
  the live library with AND reading 1 when the truth was 0 — and are
  superseded by a canonical design (every wire a pure scalar bit, primary
  inputs checked, gate outputs forced exact), which rejected that attack
  and now includes a validated 64-bit ripple-carry adder (5 honest cases
  accepted, 8 malicious rejected, 77 claims, front-end only); see
  `rokoko-canonical-gadget-research.json`. F-01-RoKoko is still
  engineering work, but the review now has to cover soundness too, not
  only hiding.

**Recommendation:** commission the scoped independent cryptographic review
for Binius64's A-01 now — it is the one gap where this project's own further
effort has reached genuine diminishing returns and where external expertise
is specifically what closes it, while the engineering gaps (both F-01 paths)
are ordinary, plannable work that does not block starting that review in
parallel. [`BINIUS_A01_REVIEW_SCOPE.md`](BINIUS_A01_REVIEW_SCOPE.md) is the
self-contained scope-of-work brief for that review — three named questions,
every citation and file:line reference a reviewer needs, ready to send.
