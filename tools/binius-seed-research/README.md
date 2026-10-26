# Binius leaf-seed research comparator

Public RFC8032 fixture only. Not an approved production or quantum-security backend.

This isolated tool reuses the existing Binius64 fixed SHA512 circuit and Iron Spartan ZKProver/ZKVerifier at exact commit 115108d5a661d95c0b474b6ab02558bfe6c6bec7, following the MIT ShorStop adapter e7692712c601814d03acc5b638e0a15962f50452. Both projects retain attribution and included licenses.

The witness is exactly the public RFC8032 test1 32-byte seed. The circuit constrains SHA512, RFC8032 clamp of the first 32 bytes, and equality to four public scalar words. The SHA512 second half and unclamped first-half discarded bits stay private. The native wrapper independently checks that the exact clamped scalar gives the pinned RFC8032 public point. A domain, scalar bytes and caller-supplied canonical recovery SHA512 action digest are observed in the existing transcript before protocol messages/challenges. The wrapper does not parse or validate Stellar policy itself.

`cargo build --release --locked --manifest-path Cargo.toml`

`qasset-binius-seed-research prove ACTION64HEX PROOF REPORT [wrong-witness]`

`qasset-binius-seed-research verify PROOF SCALAR32HEX ACTION64HEX`

Only the included public fixture is supported; no arbitrary private-seed input exists. No secret-erasure assertion is made. The optional wrong-witness experiment changes one fixture seed byte while retaining the independently fixed public scalar/action and passes the unsatisfied evaluated assignment to the real prover. Depending on the existing prover this may error or generate a rejecting proof; record which actually occurs.

The upstream configured SECURITY_BITS constant is 96; log_inv_rate=1 reproduces the pinned adapter default. This is not a 128-bit or quantum-knowledge/ZK security certification. No parameter is lowered for proof-size reporting. Transcript finalization rejects trailing bytes; proof file reads are bounded to 256MiB+1 before allocation can exceed the fixed limit significantly. Native verifier use does not establish a Soroban port or cost feasibility. Publishing the clamped scalar permits classical forging: retirement must precede disclosure to any untrusted party, including RPC submission.
