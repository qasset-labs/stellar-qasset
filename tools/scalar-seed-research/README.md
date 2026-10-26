# Public-scalar seed-preimage research benchmark

This isolated off-chain research tool complements the existing hidden-scalar
`seed-recovery-research` tool. It does not replace that tool or its evidence.
It uses the same attributed, revision-pinned upstream ZKBoo implementation and
its SHA-512 and SLIP-0010 circuits; it introduces no new proof protocol.

The circuit output is the **public clamped Ed25519 scalar**, rather than the
public key. Verification independently checks that this exact, correctly clamped
scalar maps to the pinned official public key, using curve25519-dalek outside
the circuit. Both scalar and point are fixed official public fixtures. Arbitrary
secret input is intentionally unsupported. The verifier does not receive the
seed. The two supported relations are:

- `leaf`: RFC 8032 section 7.1 TEST 1 leaf seed -> SHA-512 -> clamped scalar.
- `sep5-root`: SEP-0005 test 1 root -> SLIP-0010 m/44'/148'/0' -> SHA-512 -> clamped scalar.

The expected scalar constants were independently computed using Python hashlib,
not the proof circuit; pinned public keys come from the official fixtures.

**Disclosing this scalar gives classical Ed25519 signing authority.** This
variant is unsuitable for any account where that key still controls spending,
upgrades, recovery cancellation or another authority. Merely showing this proof
does not retire that authority. No such retirement is implemented by this tool.
Retirement must be independently finalized **before** disclosing the scalar or
submitting any scalar-bearing proof; doing both in one public transaction permits
an observer to race the retirement. Disclosure also compromises every other
system that reuses this key. This is a prepared-migration experiment, not rescue
of arbitrary still-live classical accounts.

Build offline from an environment with the pinned dependencies cached:

```
cargo build --release --locked --offline
```

Usage (the digest is an exact 64-byte recovery request digest, represented as 128
hexadecimal characters):

```
qasset-scalar-seed-research prove DIGEST_HEX PROOF_FILE REPORT_FILE 8 leaf
qasset-scalar-seed-research verify DIGEST_HEX PROOF_FILE 8 leaf
qasset-scalar-seed-research prove DIGEST_HEX PROOF_FILE REPORT_FILE 438 sep5-root
qasset-scalar-seed-research verify DIGEST_HEX PROOF_FILE 438 sep5-root
```

Only 8 and 438 rounds are accepted, with an explicit verifier-required round
count. Eight rounds are deliberately insecure. The value 438 reproduces the
upstream advertised parameter count; using that number is **not a validation of
quantum knowledge extraction, quantum zero knowledge, Fiat-Shamir/QROM
assumptions, this adapter, or the upstream implementation**. The program reports
functional test results, not a security level. The Fiat-Shamir binding includes
a distinct variant domain, the supplied digest, and the relation mode.

Proof randomness comes from `/dev/urandom`; the entropy buffer is explicitly
zeroized. The Blake3 adapter implements a `Drop` which actually calls the
upstream zeroize implementation. All witnesses are public fixtures regardless.

Proof files are experimental postcard serializations. Do not use for funds or
accept untrusted files in a production service. The verifier caps files at
256 MiB and rejects trailing bytes, malformed encodings, missing responses and
wrong statement bindings. This benchmark neither parses a live recovery request
nor checks on-chain state, transaction fees, epoch freshness or expiry.

License: LGPL-3.0-or-later. Upstream revisions and attribution are preserved in
`upstream-pins.json`. No deployment, transaction submission, Soroban verification
or production security approval is performed.
