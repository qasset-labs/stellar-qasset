# Binius commit-then-prove relation comparator — BLAKE3 variant

Public RFC8032 fixture only. Not an approved production or quantum-security backend.

Follow-up to [`tools/binius-commit-prove-research`](../binius-commit-prove-research),
which measured that proving `SHA256(seed) = commitment` instead of the full
`clamp(SHA512(seed))[0:32] = scalar AND [scalar]B = point` relation barely
shrank the Binius64 Iron Spartan proof, because both relations' AND-constraint
counts (912 and 1,155) padded to the identical 2,048-word trace bucket. A
probe over already-vetted 32-byte hash gadgets in the pinned `binius-circuits`
crate found BLAKE3 needs only 626 AND constraints for the same input size —
landing in a 1,024-word bucket, half of SHA-256's. This tool measures what
that actually does to proof size and time, proving `BLAKE3(seed) = commitment`
against the identical pinned Binius64 commit, Iron Spartan configuration,
action-binding discipline and RFC8032 fixture seed as the other two tools.

**BLAKE3 is not proposed as the production enrollment commitment function.**
It is an already-implemented, independently specified, widely used hash —
chosen here only because it is the smallest already-vetted circuit gadget
available in this pinned dependency, to test the padding-bucket hypothesis
without writing any new cryptographic primitive.

`cargo build --release --locked --manifest-path Cargo.toml`

`qasset-binius-commit-prove-blake3-research prove ACTION64HEX PROOF REPORT [wrong-witness]`

`qasset-binius-commit-prove-blake3-research verify PROOF COMMITMENT32HEX ACTION64HEX`

## Measured result

See [docs/binius-commit-prove-blake3-research.json](../../docs/binius-commit-prove-blake3-research.json)
for exact numbers and hashes. Summary: proof size dropped only 4.4% (515,984
vs ~539,872 bytes average of the other two) despite the trace bucket halving,
while prove/verify/setup time dropped substantially (-29%/-22%/-52% relative
to the SHA-256 comparator). This matches the expected shape for a FRI/BaseFold
argument: setup cost scales with trace size itself, but proof bytes scale with
query count times Merkle-path length, i.e. with `log(trace size)`, not trace
size — so even successfully crossing a padding-bucket boundary only removes
one Merkle-tree level per query, not a share proportional to the circuit-size
reduction.

**This means relation-size reduction alone cannot deliver the order-of-magnitude
proof-size cut F-01 needs under this backend's construction.** It confirms —
with a direct measurement against this exact pinned dependency — that closing
F-01's size side needs a backend whose proof size does not scale with
`O(queries × log(n))`, such as a lattice-based construction (see
docs/COMPACT_BACKEND_LATTICE_GATE.md section 3), not further relation
shrinking on the current Binius64 Iron Spartan backend.

This does not close A-01 or F-01. Only the included public fixture is
supported; no arbitrary private-seed input exists. Publishing this circuit's
raw seed permits classical forging: retirement must precede disclosure to any
untrusted party, including RPC submission.
