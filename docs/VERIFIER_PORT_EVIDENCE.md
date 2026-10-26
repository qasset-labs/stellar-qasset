# Native-to-Wasm recovery verifier evidence

The exact retained 539,888-byte Binius leaf proof now verifies in an actual
`wasm32v1-none` module. This closes the earlier raw-Wasm portability gap. It does
not supply a Soroban recovery contract or approve the backend's quantum security.
The existing legacy-seed account continues to reject every authorization.

## What ran

The [research package](../tools/binius-verifier-port/README.md) retains a pinned,
attributed verifier-only `core`/`alloc` port, its upstream patch, source hashes,
licenses, frozen public preprocessing, actual execution reports and a reproducer.
It vendors 292 files from eleven verifier dependency crates; 174 differ from the
pinned upstream. This substantial fork needs independent review.

Six native cases and nine actual Wasm cases passed, including the unchanged
canonical proof, action mutation, corruption, strict trailing-data rejection,
truncation and empty input. Wasm also checks the exact padded-constraint identity
and rejects changed/unclamped scalars through a **public fixture guard**. None of
these executions trapped. The guard is restricted to the published RFC8032 key;
it is not a generic scalar-to-account relation. A future integrating caller must
independently check the exact protected public key and complete recovery request.

The preprocessed circuit is 2,714,051 bytes, pinned by SHA256 before nested decode.
Two original native exports matched byte for byte. The port preserves all 131,072
padded constraints and the original proof. Its full constraint fingerprint is
`0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938`.
The [preprocessing reference](../tools/binius-preprocessing-reference/README.md)
retains the original native export/loader source, patch and historical evidence
without duplicating the full upstream repository.

## Findings and corrections

The upstream sampler transition serialized a `usize` index using its target
width. Native64 hashed eight bytes while Wasm32 hashed four, changing Fiat-Shamir
challenges and rejecting the valid proof. The port explicitly serializes `u64`
little endian, preserving the original native64 protocol. A native/Wasm golden
transition vector and the unchanged real proof cover this correction.

Initial padded-constraint copying triggered an unnecessary allocation growth.
The port reserves the exact padded capacity, reserves outer decoded vectors and
uses direct small-vector construction. These changes preserve values, ordering,
masking and proof parameters. An earlier 40 MiB allocation failure is superseded
by the bounded successful runs; it was not evidence of fundamental impossibility.
The reproduction script invalidates stale success before tools run and records
failure on build, process or parse errors.

## Measurements and remaining gates

| Measurement | Result |
| --- | --- |
| Raw module | 3,604,811 bytes, including embedded public proof and setup |
| Executable code section | 229,052 bytes |
| Embedded data section | 3,333,580 bytes |
| Canonical Wasm linear memory | 39,911,424 bytes |
| Largest tested linear memory (trailing-data rejection) | 41,549,824 bytes |
| Enforced module memory maximum | 41,943,040 bytes (40 MiB) |
| Imports / floating-point operators | zero / zero |

These measurements are from raw Node/V8 execution, not Soroban host metering.
The code section alone exceeds the recorded 131,072-byte contract limit, even
before the embedded data is externalized. A separate embedded-Binaryen optimization
probe reduced executable code to 197,877 bytes and retained all nine passing
Wasm cases; it is still 66,805 bytes above that recorded cap. The
[optimization record](verifier-port-optimization/report.json) preserves this
measurement separately from the frozen port baseline. The host adds memory and instruction
costs; passing a raw 40 MiB cap does not prove the complete call fits that cap.
The module has a fixture ABI, not the Soroban contract ABI. No live RPC call or
transaction submission was made for these experiments.

Production needs a bounded immutable preprocessing architecture, smaller guest
code, real contract ABI and full host metering across adverse inputs, generic
scalar-to-key validation, canonical request binding and an atomic current-policy
account transition. Loading a setup blob from callers and trusting their chosen
hash is not acceptable. The original 96-bit query-phase parameter is unchanged;
it does not establish 96-bit overall security or 128-bit quantum knowledge/ZK
security. Independent cryptographic and implementation review remain gates.

Finalized retirement of **every effective classical authority must precede any
scalar disclosure**, including publication to RPC, fee payer or reused-key systems.
These experiments use only already-public fixtures. They do not rescue an
unenrolled classic account or restore legitimately revoked governance rights.

## Reproduce locally

From the repository root, with populated locked Cargo caches and Rust 1.94.1:

```sh
python3 scripts/check_verifier_port_evidence.py
python3 tools/binius-verifier-port/scripts/run.py \
  --setup tools/binius-verifier-port/target/fixtures/fixed-setup.bin \
  --proof target/binius-seed-research/proof.bin
```

The first command checks source/report lineage and any retained artifact hashes;
it does not rerun verification. The second actually builds and executes native
and Wasm checks without Stellar RPC. Ignored binary fixtures must be regenerated
or obtained with their exact recorded hashes on a fresh checkout. Source and
record hashes are reproducibility controls, not an external security attestation.

## Compact verifier and actual host-cost follow-up

The earlier fixture measurements above remain historical. The [successor](VERIFIER_NEXT_EVIDENCE.md) now fits the complete raw module under the refreshed byte cap and reduces memory, with unchanged proof/constraints. A separate actual SDK wrapper remains oversized and fails the 400M CPU budget. Refer to [current implementation status](RECOVERY_IMPLEMENTATION_STATUS.md) for what is implemented and still gated.
