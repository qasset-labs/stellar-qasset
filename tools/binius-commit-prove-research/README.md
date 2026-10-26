# Binius commit-then-prove relation comparator

Public RFC8032 fixture only. Not an approved production or quantum-security backend.

This isolated tool measures the relation-reframing hypothesis from
[docs/COMPACT_BACKEND_LATTICE_GATE.md](../../docs/COMPACT_BACKEND_LATTICE_GATE.md)
section 2: instead of proving `clamp(SHA512(seed))[0:32] = scalar AND [scalar]B = point`
(the existing [`binius-seed-research`](../binius-seed-research) comparator), this
circuit proves only `SHA256(seed) = commitment` — a hash-preimage statement with
no elliptic-curve scalar multiplication at all. It reuses the exact same pinned
Binius64 commit `115108d5a661d95c0b474b6ab02558bfe6c6bec7`, the same Iron Spartan
`ZKProver`/`ZKVerifier` configuration (`log_inv_rate=1`, `SECURITY_BITS=96`), the
same canonical action-binding transcript discipline, the same public RFC8032
test1 fixture seed as witness, and the same dummy action digest as
`binius-seed-research`, so the two measured proofs are directly comparable.

**This is NOT a proposal that SHA-256-of-the-raw-seed is the production
enrollment commitment.** A real design needs its own domain-separated
enrollment statement and a reviewed choice of commitment function. This tool
answers one narrower, measurable question: how much of the existing backend's
proof size and verifier cost comes from the *relation* (SHA-512 + clamp +
scalar-mult) versus the backend itself.

`cargo build --release --locked --manifest-path Cargo.toml`

`qasset-binius-commit-prove-research prove ACTION64HEX PROOF REPORT [wrong-witness]`

`qasset-binius-commit-prove-research verify PROOF COMMITMENT32HEX ACTION64HEX`

## Measured result

See [docs/binius-commit-prove-research.json](../../docs/binius-commit-prove-research.json)
for exact numbers, hashes and the padding-bucket sweep. Summary: proof size
barely changed (539,856 vs 539,888 bytes) because both relations' AND-constraint
counts (912 vs 1155) pad up to the identical 2048-word trace bucket in this
backend's power-of-two padding rule — removing the scalar-multiplication
gadget was not enough to cross down into a smaller bucket. Prove time dropped
31% and verify time dropped 42%. A synthetic sweep of trivial AND-gate chains
confirms the padding rule does shrink for genuinely smaller circuits (a
crossover between roughly 256 and 512 raw AND gates), which is evidence for,
not against, evaluating a true algebraic ZK-friendly hash (Vision/Poseidon
over binary fields) rather than a merely smaller classical hash like SHA-256 —
SHA-256's own ~900 AND constraints just is not small enough to reach the next
bucket down.

This does not close A-01 or F-01. No backend other than Binius64 Iron Spartan
is measured here, and a smaller proof under a different relation still needs
independent quantum-knowledge/ZK review before any security claim.

Only the included public fixture is supported; no arbitrary private-seed input
exists. Publishing the clamped-scalar comparator's scalar, or this circuit's
raw seed, permits classical forging: retirement must precede disclosure to any
untrusted party, including RPC submission.
