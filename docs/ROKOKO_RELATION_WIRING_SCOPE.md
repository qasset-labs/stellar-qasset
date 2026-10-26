# Scoping: wiring a SEP-5 hash-preimage relation into RoKoko

Prepared 2026-10-23 against a fresh clone of `github.com/lattice-arguments/rokoko`
at commit `c3f8206465f4b4cf34b8aafa378af5b081608944` (`tools/rokoko-relation-research/`,
disposable, not security-reviewed, not committed to this project's own history
beyond `pins.json`). This is an engineering scope, not a security review, and
not a claim that this work has started being implemented.

**Fourth update, same day — read this first.** The AND/XOR gate and the
full adder described in "Resolved: a working AND+XOR construction" and
"Validated: a full adder from AND+XOR alone" below are **unsound and
superseded**. Their malicious-witness tests only flipped the coefficient
each gate gives meaning to; an adversary that instead puts junk in a
coefficient the gate ignores was tested against the live library and
**accepted**: with true AND = 0, the proof verified while the gate read
AND = 1. They are replaced by the canonical design in "Canonical design: a
sound gate, and a validated 64-bit adder" below, which pins every wire to a
pure scalar bit, was tested against that same attack (rejected), and comes
with a written soundness argument rather than only test results. The same
pass also corrected the ring model (it is the negacyclic polynomial ring
`Z_q[X]/(X^128+1)`, not "quadratic slots with ω=0") and found that the
documented binariness recipe, applied to secret bits, leaks their Hamming
weight through its shipped value. Evidence:
[rokoko-canonical-gadget-research.json](rokoko-canonical-gadget-research.json).
The earlier sections are kept, marked superseded, because the reasons they
fail are what shaped the replacement.

**Updated 2026-10-23, same day, three times.** First: empirical testing
found that multiplying two independently-committed secret values directly
(`witness_in(a_region) * witness_in(b_region)` for different regions) is
rejected unconditionally — see "Confirmed blocker" below. Second: that
blocker is resolved with a validated AND+XOR construction, and a full
adder built from it alone — see "Resolved: a working AND+XOR construction"
and "Validated: a full adder from AND+XOR alone" below. Third: a separate
assumption this document had made without testing — that rotation and
carry-chaining get a "free" shift via the documented "tie two regions
together" recipe — was checked directly and found wrong; that recipe only
ties same-index entries. What actually works for a shift, confirmed by
testing, is covered in primitive 4's correction below. Each correction is
kept in place, in the order found, rather than silently rewritten, because
each one's analysis remains relevant to why the next attempt was shaped the
way it was. The construction for AND/XOR does not multiply two different
regions at all; it packs the two values into one region from the start and
uses the ring's own quadratic slot structure to recover their product as a
byproduct of a same-region self-square, which was already known to be cheap.
The blocker's analysis (why direct cross-region multiplication fails) is exactly
what motivated the resolution's design and remains correct on its own terms.

## Why this task exists

RoKoko is the strongest candidate on proof size/speed for F-01: a prior
measurement (`COMPACT_BACKEND_LATTICE_GATE.md` section 3b) found a real
95-107 KB proof verifying in 0.39s with no SIMD, comfortably inside Stellar's
132,096-byte transaction cap and the 400M-instruction CPU budget, in sharp
contrast to Binius64's 183,090-byte/400M-instruction-exhausting measured
state (see `verifier-profile-research.json`, `verifier-wiring-hotspot-research.json`,
`sdk-code-size-breakdown.json`). That measurement was on RoKoko's own
synthetic benchmark witness, not the project's actual SEP-5 relation. This
document scopes what wiring the real relation would take.

## The relation to target

Matching the scope this project already adopted for every other backend
comparator (Binius64's "leaf" relation, the Plonky3/ShorStop SHA-512 AIR
comparator, the scalar-exposure STARK variant — see `SCALAR_RECOVERY_EVIDENCE.md`,
`README.md`): prove knowledge of a 32-byte seed `k` such that the clamped
scalar `a = clamp(SHA512(k)[0:32])` equals a publicly revealed value, bound to
the canonical recovery request (action, epoch, replacement key). The Ed25519
scalar multiplication `A = [a]B` is checked natively, outside the proof,
against the revealed `a` — not in-circuit. This keeps the in-circuit relation
to exactly one SHA-512 compression-function evaluation over a short, fixed-
length message, which is the tractable sub-problem; full HD derivation or
in-circuit scalar multiplication is explicitly out of scope here, as it has
been for every other backend this project measured.

## RoKoko's primitive set (confirmed against source, not inferred from the docs alone)

`docs/snark.md` in the clone describes the frontend as: commit one vector of
ring elements, then prove `sum over index i of weight(i) * witness(i) * ... = value`.
Five primitives matter for this task, each confirmed directly in source:

1. **Bit decomposition into individually-committable, binary-constrained ring
   elements already exists**: `decompose_bits` (`src/common/decomposition.rs:158-198`)
   takes a slice of ring elements and returns, for each one, `radix` new ring
   elements — one per bit position — where ring element `b`'s coefficient `c`
   holds bit `b` of input ring element `c`'s coefficient value. This is a
   first-class, already-SIMD-optimized (AVX-512 fast path included) function,
   not something that needs to be built from scratch.
2. **Binariness is a documented, existing claim recipe** (`docs/snark.md:245-248`):
   `witness_in(r) * witness_in(r).conjugate() - table(ones_conj).on(r.vars()) * witness_in(r)`
   summed to a shipped value whose constant coefficient must be zero. Applying
   this to every `decompose_bits` output proves those outputs are genuinely
   binary, not merely claimed.
3. **Witness-times-witness products are a first-class operation, but only
   within one region** — a correction made after empirical testing (see
   "Confirmed blocker" below), not assumed here. `impl std::ops::Mul for
   ClaimExpr` (`src/protocol/snark/lowering.rs:460`) and the usage in
   `examples/claims.rs:31` and `src/protocol/parties/executor.rs:267`
   (`witness_in(segment) * witness_in(segment)`) all multiply a region by
   *itself* (optionally conjugated), which shares one selector and stays at
   degree 2. Multiplying two genuinely *different* regions together directly
   — what a naive reading of AND (`a_i*b_i`) between two independent secret
   values would need — was tested directly and found to cost degree 4 (two
   distinct selectors plus two witness reads), unconditionally over the
   degree-3 ceiling (`docs/snark.md:153-158`). See "Confirmed blocker"
   below for that finding, and "Canonical design: a sound gate, and a validated 64-bit adder"
   for how AND and XOR are actually obtained instead — by packing both
   values into one region from the start, not by multiplying two regions
   together.
4. **Fixed-offset bit permutation (rotation/carry-chaining) needs
   individual length-1 ties, not the batched "tie two regions" recipe** —
   a correction, caught by testing before relying on it: the documented
   "tie two regions together" recipe (`docs/snark.md:202-207`,
   `eq(&point).on(original.vars()) * (witness_in(original) -
   witness_in(mirror))`) compares `original` and `mirror` at the *same*
   index on both sides; it is a same-index equality check ("the alignment
   tool"), not a shift. Tested directly: batching a genuine shift (`mirror[i]
   = original[(i-1) mod n]`) through that exact recipe is **rejected**, even
   for an honest, correctly-shifted witness — confirming the recipe cannot
   express a shift as written. What does work, tested and confirmed (both
   accepting a correct shift and rejecting a corrupted one): **one
   individual `sums_to_zero(witness_in(b_i) - witness_in(a_{i-1}))` claim
   per position**, using length-1 `Region::new(offset, 1, witness_len)`
   reads (length 1 has no alignment constraint, and a one-point "cube" needs
   no `eq` weight — there is nothing to average over that could hide a
   mismatch). A 64-bit rotation or a 64-position carry chain needs roughly
   63 such individual claims, not one batched claim; still cheap per claim,
   but a real, uncollapsed count, corrected here rather than left as an
   unvalidated "free" assumption.
5. **64-bit modular addition does NOT use the digit/value recipe after
   all** — an approach sketched in an earlier draft of this document (split
   each word into two 32-bit limbs under `MOD_Q`'s ~50-bit range, decompose
   each limb's sum via `decompose_bits` to read off the carry) was found,
   on closer inspection before writing any such code, to have a secrecy
   problem: the documented digit/value recipe's target (`Claim::sums_to(expr,
   value)`) is a value the prover *ships in the clear*, which the
   project's own calibration testing confirmed is genuinely exposed to the
   verifier (see "Calibration test run against the live library" below).
   For a SHA-512 relation, intermediate sums must stay secret — shipping
   them would leak information about the seed. **Addition is instead built
   from the canonical AND/XOR gate alone** (see "Canonical design: a sound gate, and a validated 64-bit adder"
   below; the earlier gate this paragraph first pointed to was unsound): a standard 1-bit full adder, `sum = a xor b xor cin`,
   `carry_out = (a and b) xor ((a xor b) and cin)`, built from three
   applications of the one validated AND+XOR gate, chained bit by bit for a
   ripple-carry 64-bit adder. This needs no `decompose_bits`, no limb
   splitting, and ships nothing — every intermediate value stays inside a
   freshly committed region tied by a `sums_to_zero` claim, exactly like
   the AND/XOR construction itself. `decompose_bits`/binariness remain
   useful primitives for other purposes (e.g. applying the clamp step to
   the final hash output, where revealing structure is the point), but are
   not the mechanism this project uses for addition.

**Build constraint confirmed by actually running it**: the crate uses unstable
Rust features (`#![feature(coerce_unsized, unsize)]`, `src/lib.rs:1`) and
fails on the stable toolchain with `E0554`; it builds and the documented
`examples/claims.rs` runs correctly under `cargo +nightly`, confirmed
end-to-end in this pass (prover/verifier accepted all four batched claims,
including the witness-energy norm claim). The project's other pinned
dependencies (Binius64) build on stable; any RoKoko-based work would need a
pinned nightly toolchain as an additional, new build requirement.

**Confirmed absent**: no existing hash-preimage gadget of any kind. The only
`sha256`/`sha512`/`blake3` hits in the whole repository are Fiat-Shamir
transcript hashing and internal seed derivation (`src/common/hash.rs`,
`src/common/sampling.rs`, `src/common/short_challenge.rs`,
`src/common/projection_matrix.rs`) — unrelated to proving a hash preimage.
The repository's own docs label the whole SNARK front end "EXPERIMENTAL."

**Capacity is not a constraint**: the ring is degree-128
(`src/protocol/params.rs:126-134`'s test: `DEGREE.ilog2()` contributes to a
"p-28" set meaning 2^13 x 2^8 ring elements x 128 coefficients = 2^28
committable Zq scalars). A single SHA-512 compression-function evaluation
needs on the order of a few hundred thousand bit-witness entries (80 rounds x
~8 64-bit words x a small constant factor for intermediate Ch/Maj/Σ/σ
values) — several orders of magnitude under 2^28. Capacity was not the risk
in this scoping pass; claim count and resulting proof size/time are the real
open questions, and this pass did not estimate those numerically (see
Open Questions below).

## What actually needs to be built

Composing the above primitives into a full SHA-512 compression function:
80 rounds, each needing the message-schedule word (rotation/shift/XOR,
operating entirely at the bit level — no limb splitting, since every word
is represented as 64 individually committed bits throughout, not packed
into `MOD_Q`-sized limbs), the `Ch`/`Maj` bitwise functions (AND/XOR/NOT
compositions, each AND/XOR an application of the validated gate), the
`Σ0`/`Σ1`/`σ0`/`σ1` functions (rotation via individual length-1 shift
ties, confirmed as the working mechanism — not the originally assumed
batched copy-claim, see primitive 4's correction above — plus XOR
bit-products), and six 64-bit modular additions (64 chained full adders
each, see "Canonical design: a sound gate, and a validated 64-bit adder" below — no digit
decomposition, no shipped value, with the carry chain itself needing the
same individual length-1 shift ties as rotation). The bit-products (every
AND and XOR between two independently committed secret bits) have a
validated construction — see "Canonical design: a sound gate, and a validated 64-bit adder"
below — one auxiliary packed region and three eq-weighted tie claims per
gate over canonical scalar-bit inputs, not a single direct multiplication. None of it would be generated
from a circuit-DSL or gate library either way, since RoKoko has none;
every claim this project would need is written explicitly. At the scale of
80 rounds this means writing out, by hand, on the order of a few thousand
region commitments and tie claims (roughly 2 per AND/XOR gate, 6 per
full-adder bit position, and one individual claim per shifted/rotated bit
or carry-chain link, across 8 words x 64 bits x 80 rounds' worth of gates),
not a few dozen — a concrete, now-boundable number, not an open-ended one.
This matches, and now confirms with source-level specificity, the standing
assessment that this is "substantial circuit-gadget engineering," not
quick wiring — substantial in claim count, not in unresolved design
questions.

## Recommended staged approach (revised a fourth time: canonical design)

This list is revised a fourth time. The earlier AND/XOR gate and full adder
were found unsound (junk-coefficient attack, accepted by the live library)
and are replaced by the canonical design (see "Canonical design: a sound
gate, and a validated 64-bit adder" below), which now includes a full
64-bit ripple-carry adder validated against honest and malicious witnesses.

1. **Independent review**, scoped in
   [ROKOKO_ZK_HIDING_REVIEW_SCOPE.md](ROKOKO_ZK_HIDING_REVIEW_SCOPE.md) —
   now covering the canonical gate (not the superseded one), the
   Hamming-weight leak in the documented binariness recipe and its
   complement-padding fix, and a request to check the written soundness
   argument, not only zero-knowledge. Ready to send, not yet commissioned.
2. ~~Addition gadget~~ — done, at full 64-bit width: 77 claims, 80–210 ms
   prove, 14–22 ms verify, front-end claims proof ~1.3 KB.
3. **Exercise the commitment chain** on the adder's witness (`commit`,
   `prover_round`, `verifier_round`), which supplies the ℓ2 bound the
   binariness argument assumes and the opening that dominates proof size.
   Not done yet; needed before any size or soundness number covers the
   full proof rather than the front end.
4. **One full SHA-512 round**, then **the full 80-round compression** for
   the fixed-length SEP-5 message. Remaining pieces are the message
   schedule, `Ch`/`Maj` (each a few canonical gates), and `Σ`/`σ`
   rotations (length-1 ties, like the carry chain).
5. **Measure and compare** proof size, prove time, verify time, against the
   same Soroban budget this project checks every other backend against.
   Only at this point does this become a genuine F-01 candidate rather than
   a scoping exercise.

Each stage is independently measurable and should be evaluated before
committing to the next, consistent with this project's standing rule against
rushing security-relevant proof/circuit work. This revision is itself the
reason review stays first: the previous construction passed every test this
project wrote for it and was still unsound, because the tests only covered
the adversaries this project thought of. An outside reviewer's adversaries
are the ones this project did not.

## Calibration test run against the live library (not yet the addition gadget)

Before attempting the addition gadget, a small, separate tool crate
(`tools/rokoko-gadget-research/`, path-dependent on the pristine clone, never
modifying it) implemented and ran the documented binariness recipe exactly
(`docs/snark.md:245-248`) over a 4-entry witness, both with a genuine 0/1
witness and with a deliberately malicious witness containing a non-binary
entry (`2`). Result, confirmed by actually running both cases: `verify_claims`
**accepted in both cases**. The sumcheck only checks that the prover's shipped
value is *consistent with* the committed witness, not that the shipped value
has the required structure. The documented "two duties stay yours" line
(`docs/snark.md:177-182`) is not a minor caveat — it is load-bearing: a caller
that checks only `verify_claims(...).is_ok()` would wrongly accept a non-binary
witness. A correct integration must also check the shipped value's constant
coefficient is zero as a separate, explicit step after `verify_claims`
succeeds. This applies to every "case 3" (prover-ships-the-value) claim this
scoping document relies on, including the addition gadget's carry/sum values,
not just binariness — a real implementation needs this check wired in
everywhere a value is shipped, or it silently accepts malicious witnesses.

## Confirmed blocker: multiplying two different secret regions together

The calibration pass above was extended to directly test the degree-budget
question this document originally left open, and found something more
serious than an open question: **a product term can reference at most one
distinct sub-region via `witness_in(...)`; multiplying two different
sub-regions together costs degree 4 and is rejected unconditionally, with or
without any `eq` weight.**

Confirmed by bisection against the live library (same `tools/rokoko-gadget-research/`
crate): `witness_in(a_region) * witness_in(b_region)`, for two genuinely
different regions `a_region != b_region`, panics with the same "degree at
most three" error even with **no** `eq` factor at all. A single sub-region
read alone, or `eq(point) * witness_in(one_sub_region)`, both succeed.

Confirmed by reading the exact mechanism in `lowering.rs:1086-1113`:
`witness_in(region)` for a true sub-region lowers to a `WitnessSegment` that
decomposes into a *selector* (keyed by `(prefix, length)`) plus a plain
witness-read factor. `push_selector` (`lowering.rs:1086-1090`) deduplicates
by exact `(prefix, length)` match — **so two reads of the same region share
one selector** (matching `docs/snark.md:88-89`: "witness_in(r) * witness_in(r)
costs the same selectors as one"), **but two different regions always push
two distinct selectors**, each counted in the degree-3 budget alongside the
two witness-read factors: 2 selectors + 2 reads = degree 4, over the cap,
unconditionally — not something a cleverer choice of offsets or an added
`eq` weight can route around. `Region::whole(witness_len)` is the one
exception (no selector at all, confirmed via `witness()`'s documented
equivalence to it), but a region spanning the entire witness leaves no room
for anything else to be committed alongside it in the same proof.

This directly undermines primitive 3 and the auxiliary-pairwise-product-wire
design sketched above and in "What actually needs to be built": AND, and
the cubic XOR/majority formulas built from it, both need `a_i * b_i` for
two independently-placed secret quantities. No documented RoKoko recipe —
checked again against this finding — multiplies two *different* witness
regions together; every example is either a self-product (the norm/
binariness recipes) or a witness-times-public-weight product. That absence,
in hindsight, was itself a signal this document underweighted on first
read.

**This is now the primary open blocker for this task, not a secondary
open question.** Two directions remain genuinely unexplored: (a) whether
some packing scheme (e.g. using the ring's 128 coefficients to co-locate
otherwise-independent quantities under one logical region, if that is even
semantically available for this purpose) could bring `a` and `b` under one
shared selector without collapsing them into the same value, or (b)
concluding that RoKoko's current frontend, as documented and as it
actually behaves, is not well-suited to general bitwise circuits between
independent secret values, regardless of circuit-writing effort. Neither
was resolved in this pass. The staged plan below is accordingly revised:
stage 1 is now this exact question, not the addition gadget itself.

## Resolved: a working AND+XOR construction between independent secret bits

> **SUPERSEDED — unsound.** This construction was later attacked with junk
> in a coefficient it gives no meaning to (`ab = 1 + √2·X` for inputs
> `a=1, b=0`), and the live library accepted a proof in which AND reads as
> 1. Its "validated" status below held only against adversaries that flip
> the meaningful coefficient. The ring explanation in the next subsection
> (quadratic slots, `ω=0`) is also wrong: the ring is `Z_q[X]/(X^128+1)`,
> strided `v[1]` is the `X²` coefficient, and `b²` lands at `X⁴`. See
> "Canonical design: a sound gate, and a validated 64-bit adder" below.
> Kept for the record of why the replacement is shaped the way it is.

Direction (a) from the blocker above is resolved, not just explored, with a
construction validated end to end against the live library — both accepting
a correct witness and, independently, rejecting two different malicious
witnesses (a wrong AND tie, a wrong XOR tie), in `tools/rokoko-gadget-research/`.

### The ring structure that makes this possible

`DEGREE=128` is not 128 independent scalar lanes; it is `NUM_SLOTS=64`
independent **slots**, each `SLOT_DEGREE=2` — a small quadratic-extension
sub-ring, confirmed by `incomplete_ntt_multiplication_inner`'s dedicated
`slot_mult` call ("5 mults + 2 adds", `src/common/ring_arithmetic.rs:1009-1016`)
and by the project's own README ("parameters are selected such that the ring
splits into factors of degree 2... incomplete NTT for efficient
multiplication"). Multiplying two ring elements is genuine quadratic-extension
multiplication *within* each slot: `(a0 + a1·X) * (b0 + b1·X) mod (X^2 - ω)`
for some slot-specific constant `ω`.

For the first slot (coefficients `v[0]`, `v[1]`), `ω = 0` was determined
empirically (squaring `(a,b)` gives `(a^2, 2ab)`, not `(a^2+ωb^2, 2ab)` for
nonzero `ω`) and confirmed robust across six varied inputs including edge
cases (`probe_pattern_generality` in `tools/rokoko-gadget-research/src/main.rs`):
`a=b=6` gives `(36,72)`; `a=0,b=1` gives `(0,0)`; all matched `(a^2, 2ab)`
exactly. **This means squaring a ring element with `a_i` in `v[0]` and `b_i`
in `v[1]` reliably yields `2*a_i*b_i` in `v[1]` of the result, for free, as
a side effect of a same-region self-product — which was already validated
as cheap (degree 2, one selector) before the blocker was ever found.**

A second coefficient pair (`v[2]`, `v[3]`) was tried and gave an
unexplained `(0, 0)` result that does not fit this model — `StridedCoefficients`
is a pre-NTT coefficient ordering (confirmed by reading
`from_coefficients_to_strided_coefficients`, `ring_arithmetic.rs:191-200`),
and `to_representation(IncompleteNTT)` runs a genuine global NTT
(`SLOT_RING.ntt_forward`), not a simple per-pair relabeling, so there is no
guarantee every raw coefficient pair maps to one controllable slot the way
`(v[0], v[1])` empirically does. **This construction is validated only for
the `(v[0], v[1])` pair.** It does not need more than that: each witness
*index* already gets its own full ring element, so packing `a_i` into
`v[0]` and `b_i` into `v[1]` *for every index i in a region* gives one
AND/XOR gate per bit position across an entire SHA-512 word (or more) using
only this one validated coefficient pair, which is exactly what the actual
relation needs — not 64 independent gates packed into one ring element.

### The construction, validated step by step

1. **Pack**: for each bit position `i`, build one ring element with
   `v[0] = a_i`, `v[1] = b_i` (`StridedCoefficients`, then converted).
   Commit all of them as one region, `ab_region`.
2. **Square and commit the AND tie**: off-circuit, compute the full
   self-square of each `ab_region` entry (`v[0] = a_i^2 = a_i`, `v[1] =
   2*a_i*b_i`, for bits), and commit this as a *fresh*, separate region,
   `p_ab_region`. Tie it with one eq-weighted claim:
   `Claim::sums_to_zero(eq(point).on(ab_region.vars()) * (witness_in(p_ab_region)
   - witness_in(ab_region) * witness_in(ab_region)))`. **Confirmed accepted
   for a correct `p_ab_region`, and confirmed rejected (genuine sumcheck
   mismatch, not a degree panic) when `p_ab_region` is corrupted at one
   position** (`run_tie_fresh_region_case`, both the honest and malicious
   cases). The earlier blocker's selector-counting analysis was not wrong
   about cross-region products — it is simply not what this claim does:
   `p_ab_region` and `ab_region` are two different regions, but the claim
   only ever multiplies `ab_region` by *itself*; `p_ab_region` appears only
   as a single, unmultiplied witness read.
3. **Derive and commit the XOR tie**: `a_i + b_i - 2*a_i*b_i` is recovered
   from already-committed quantities via `witness_in(ab_region) +
   witness_in(ab_region).scale(&X) - witness_in(p_ab_region)`, where `X` is
   the ring element `(0,1)` (same slot, `v[1]=1`). Working through the slot
   algebra with `ω=0`: `(a,b) + (a,b)*X - (a,2ab) = (a,b) + (0,a) - (a,2ab)
   = (0, a+b-2ab)` — the desired value lands in `v[1]`, so `xor_region` is
   committed with `v[1] = a_i xor b_i` (not `v[0]`) to match. Tied with a
   second eq-weighted `sums_to_zero` claim, batched in the same
   `prove_claims` call as the AND tie. **Confirmed accepted for a correct
   `xor_region`, and confirmed rejected when `xor_region` is corrupted at
   one position, independently of the AND tie's own correctness**
   (`run_and_xor_gate_case`, both malicious variants rejected separately).
4. **Confirmed robust**: four honest-witness variations (the original
   4-bit pattern, an 8-bit pattern, all-zero bits, all-one bits) all
   accepted; `.scale(&RingElement)` (`lowering.rs:449`) is genuine ring
   multiplication by a public constant and adds no degree, confirmed via
   the same test runs completing without a degree panic.

### What this resolves, and what it does not

This resolves the primitive-3 blocker for the one operation the SHA-512
relation actually needs repeatedly: AND and XOR between two independently
committed secret bits, each landing in its own freshly committed region
usable by later gates. Combined with the already-validated primitives
(binariness, copy-claims for rotation, the two-limb addition recipe), this
removes the "primary open blocker" status from F-01's RoKoko side: the
staged plan below returns to an engineering effort, not an open research
question.

It does **not** resolve two things, which remain genuinely open:

- **Zero-knowledge, not soundness.** Every test here checked soundness
  (does a malicious witness get rejected) by actually corrupting a witness
  and confirming rejection — not whether the sumcheck protocol itself hides
  the committed values from the verifier beyond what the claims assert.
  This is a property (or non-property) of RoKoko's whole sumcheck/PCS
  layer, not specific to this construction; it was not independently
  verified anywhere in this project's research and applies equally to
  every other claim in this document, old and new.
- **Why it works, beyond "confirmed by testing."** The degree-budget
  arithmetic for the tie claims above was not independently hand-verified
  against `expr_degree`/`validate_claims` with full confidence — this
  project's own attempts to hand-trace that logic were wrong more than
  once earlier in this same investigation. The claims are known to work
  because they were run against the live library and both accepted correct
  witnesses and rejected incorrect ones, which is the standard this whole
  project holds every other backend to; it is not a substitute for an
  independent cryptographic review's own derivation, which this
  construction would still need before being trusted for production use,
  exactly as Binius64's A-01 path already has one scoped.

## Validated: a full adder from AND+XOR alone

> **SUPERSEDED — unsound.** Built on the gate above, so it inherits the
> junk-coefficient gap. It also never tied one gate's outputs to the next
> gate's inputs: each gate's witness was computed off-circuit, so the tests
> checked each gate's internal consistency, not the wiring between them. The
> replacement below adds both. Its mutual-exclusivity observation (`c1`,
> `c2` never both 1) remains correct and is reused.

Addition (needed six times per SHA-512 round) is built entirely from the
AND+XOR construction above, with no new primitive and no shipped value:

```
s1 = a xor b;       c1 = a and b          (gate 1, on a and b)
sum = s1 xor cin;   c2 = s1 and cin       (gate 2, on s1 and cin)
carry_out = c1 xor c2                     (gate 3, on c1 and c2)
```

`carry_out = c1 xor c2` equals the true majority-of-three/carry only
because `c1` and `c2` are mutually exclusive in a valid full adder (`c1=1`
forces `a=b=1`, which forces `s1=0`, which forces `c2=0`); this was checked
by brute force over all 8 `(a,b,cin)` combinations before trusting it, not
assumed from the standard full-adder identity alone (`run_full_adder_case`,
the `assert_eq!(c1 & c2, 0, ...)` check run against every input
combination tested).

Validated end to end, against the live library, in
`tools/rokoko-gadget-research/src/main.rs`'s `run_full_adder_case`: all 8
possible `(a, b, cin)` input combinations, batched into one proof,
**accepted**; six independent malicious witnesses — one corrupting each of
the three gates' AND tie or XOR tie individually — **all six correctly
rejected**. A 64-bit ripple-carry adder is 64 chained copies of this full
adder, with `carry_out` of position `i` feeding in as `cin` of position
`i+1`. That chaining step was tested directly (not assumed): the
documented "tie two regions together" recipe, tried first, **does not**
express this shift (see primitive 4's correction above); what does work,
confirmed both accepting a correct chain and rejecting a corrupted one, is
one individual length-1-region `sums_to_zero` tie per consecutive pair of
positions (`probe_shift_via_individual_length1_ties`,
`tools/rokoko-gadget-research/src/main.rs`). Building the full 64-position
chain (not attempted in this pass) needs 63 such individual ties in
addition to the three-gate pattern repeated 64 times — not a new
primitive, but a real, now-corrected claim count rather than the "free"
one this document originally, and wrongly, assumed.

## Canonical design: a sound gate, and a validated 64-bit adder

This replaces the two superseded sections above. Evidence, source hashes,
and every result below:
[rokoko-canonical-gadget-research.json](rokoko-canonical-gadget-research.json).

### The ring, confirmed

`Z_q[X]/(X^128+1)`, `q = 1125899906839937` (prime, `q ≡ 1 mod 8`).
`StridedCoefficients` is a permutation of the true coefficient basis
(`strided[i + part·64] = coeff[2i + part]`, `ring_arithmetic.rs`
`from_coefficients_to_strided_coefficients`), and conjugation is the Galois
map `X → X⁻¹` (`conjugate_in_place_ref`). Confirmed directly:
`(3 + 5X²)² = 9 + 30X² + 25X⁴`; `X¹²⁷·X = −1`; `ct(u·conj(u)) = Σ u_c²`.

### Why the earlier gate failed

A committed value has 128 coefficients. The earlier gate gave meaning to
two of them (`X⁰`, `X²`) and constrained nothing else, so a prover could
add junk elsewhere. With inputs `a=1, b=0`, packing `ab = 1 + √2·X`
(`√2 ≡ 1063640708289491 mod q`) makes `ab² = 1 + 2√2·X + 2X²`; the `X²`
coefficient read as "2·AND" is 2. The live library accepted this proof.

### The canonical invariant

**Every wire is a pure scalar bit**: a constant polynomial in `{0,1}`, the
other 127 coefficients zero. Only the circuit's primary inputs need an
explicit check; every gate output is forced canonical by the gate's own
ties, so gates compose without per-wire checks.

**Primary inputs** are committed as `[c₀..c_{n−1}, 1−c₀..1−c_{n−1}]`, with:
binariness (shipped value; constant term = Σ over all coefficients of
`x(x−1)`, zero iff all are bits, given no wraparound mod q); scalar-ness
(shipped value, weight `conj(ones) − 1`; constant term = Σ of all
non-constant coefficients, zero iff all are zero, given they are bits); and
a complement tie `bits + comp = 1` (eq-batched, target `eq_weighted_sum`
from public data). The caller must check both shipped constant terms are
zero after `verify_claims` succeeds. Tested: honest accepted; `bit = 1+X²,
comp = −X²` (complement tie still holds) rejected by the caller check
(constant term 2); `bit = 2, comp = −1` rejected (constant term 4).

**The complement half is not optional.** The documented binariness recipe,
applied to secret bits alone, ships a value that reveals their Hamming
weight — tested: weight-4 and weight-7 patterns shipped different values.
With complement padding they ship byte-identical values (`n·(1 − conj(ones))`,
independent of the bits).

**The gate**, over canonical inputs `A`, `B`, with one auxiliary packed
region `ab` and outputs `C` (AND), `D` (XOR), three eq-batched
`sums_to_zero` ties:

```
t1: ab      = A + B·X²
t2: ab·ab   = A + B·X⁴ + 2·C·X²
t3: D       = A + B − 2C
```

`t1` pins `ab` exactly, so junk is impossible. Since `(A + BX²)² = A² +
2AB·X² + B²·X⁴` with `A² = A`, `B² = B` for bits, and `2X²` is invertible
in the ring, `t2` forces `C = AB`; `t3` forces `D = A ⊕ B`. No separate
`p_ab` region is needed (the self-product sits directly inside `t2`, which
the library accepts within its degree budget).

### The 64-bit ripple-carry adder

Per bit: `gate1(A, B) → C1, S1`; `gate2(S1, Cin) → C2, Sum`; `Cout = C1 +
C2` (one linear eq-batched tie; `C1`, `C2` mutually exclusive, asserted at
every position). Carry chain: `Cin[0] = 0`, `Cin[i] = Cout[i−1]`, one
length-1 tie per link. Soundness by induction over bit positions: if
`Cin[i]` is canonical, gate2's inputs are canonical, so `C2[i]`, `Sum[i]`,
`Cout[i]` are forced correct and canonical, so `Cin[i+1]` is.

Validated against the live library: five honest cases, each asserted equal
to native `u64` `wrapping_add` before proving — including
`0xffffffffffffffff + 1 = 0` (a carry through all 64 positions) and
`0x8000000000000000 + 0x8000000000000000 = 0` — all **accepted**, at 77
claims, 80–210 ms prove, 14–22 ms verify, ~1.1–1.3 KB front-end claims
proof. Eight malicious witnesses, all **rejected**: a broken carry link
with everything downstream self-consistent, a broken carry-out tie, junk
`X¹` coefficients in either gate's packing (the attack that broke the old
gate), and a wrong AND, XOR, or sum bit in either gate.

### What this does not establish

- **Front end only.** `prove_claims`/`verify_claims` were exercised; the
  commitment chain (`commit`, `prover_round`, `verifier_round`) was not.
  The binariness argument relies on no wraparound mod q, which RoKoko's
  docs attribute to the chain's certified ℓ2 bound — not exercised here,
  so wraparound-exploiting adversaries are out of these tests' scope.
- **Proof size.** The ~1.3 KB is the front-end sumcheck proof only; the
  commitment opening, which dominates RoKoko's measured 95–107 KB, is not
  included.
- **Soundness is argued and tested, not proven or reviewed**, and
  zero-knowledge hiding of the transcript remains with
  [ROKOKO_ZK_HIDING_REVIEW_SCOPE.md](ROKOKO_ZK_HIDING_REVIEW_SCOPE.md).

## Open questions this scoping pass did not resolve

- No numerical estimate of total claim count, proof size, or prove/verify
  time for the full 80-round circuit was produced. Given RoKoko's claims batch
  into one shared sumcheck (`docs/snark.md:149-151`), cost likely scales with
  total claim/variable count rather than claim count alone, but this was not
  measured.
- Resolved, not left open: `eq(point)` does count toward the degree-3
  budget (confirmed), and two different witness regions cannot be
  multiplied directly at all, with or without `eq` (confirmed) — but the
  resolution found this is not the real constraint on the task, since the
  working construction never multiplies two different regions; see
  "Canonical design: a sound gate, and a validated 64-bit adder" above.
- **Resolved**: the unexplained `(v[2], v[3]) → (0, 0)` result. Strided
  `v[2]`, `v[3]` are the `X⁴`, `X⁶` coefficients, so their square lands at
  `X⁸..X¹²` (strided `v[4]..v[6]`), which the probe never printed. The ring
  is the ordinary negacyclic polynomial ring; there are no "controllable
  coefficient pairs", only polynomial multiplication, and the canonical
  design relies on nothing more than that.
- **New**: the commitment chain (`commit`, `prover_round`,
  `verifier_round`) has not been run on any of these witnesses. It supplies
  the ℓ2 bound the binariness argument assumes (no wraparound mod q) and
  the opening that dominates proof size. Every soundness and size claim in
  this document currently covers the front end only.
- **New, from the resolution, the most important remaining gap**: whether
  the sumcheck protocol underlying these claims is zero-knowledge-hiding,
  not merely sound. This project validated soundness directly (malicious
  witnesses rejected); it did not and cannot validate hiding by itself.
  This applies to every claim in this document, not just the new
  construction, and is now the single most important open item — see the
  staged approach above, which puts an independent review of exactly this
  first.
- Whether multiple SHA-512 evaluations could be packed across the ring's 128
  coefficient "lanes" for amortized cost (the way `decompose_bits` already
  processes all coefficients of an input in parallel) was not investigated;
  this project needs only one evaluation per recovery request, so this may
  not matter, but it is a real feature of this backend's design worth noting.
- No numerical estimate of total claim count, proof size, or prove/verify
  time for the full 80-round circuit was produced (also listed above); this
  remains true after the resolution and is now stage 2's job to measure.

## What this document is not

Not a decision to proceed with implementation, not an estimate of calendar
time, and not a claim that RoKoko is selected as the production backend. It
is the grounding needed to make that decision with specifics instead of the
prior general assessment alone.

## Reproduce

```sh
git clone https://github.com/lattice-arguments/rokoko.git tools/rokoko-relation-research
cd tools/rokoko-relation-research && git checkout c3f8206465f4b4cf34b8aafa378af5b081608944
cargo +nightly run --release --example claims   # confirms the frontend's documented API surface runs as described
```

Also requires adding `tools/rokoko-relation-research` to this project's root
`Cargo.toml` under `[workspace] exclude`, since the pristine upstream clone
has no `[workspace]` table of its own (left unmodified deliberately) and
would otherwise conflict with this project's existing workspace.

All calibration, bisection, and the AND+XOR construction tests (binariness
positive/negative; the degree-budget probes; the slot-pairing and
pattern-generality probes; the fresh-region tie claims; the AND+XOR
capstone, honest and both malicious variants) are a separate crate, also
excluded from the root workspace, and all run together from one binary:

```sh
cd tools/rokoko-gadget-research && cargo +nightly run --release
```
