# Evidence for original-seed recovery

Date: 2026-10-19. First-party, AI-assisted research with parallel review. **A working off-chain proof experiment now exists. It is deliberately insecure at the exercised round count and does not implement on-chain recovery.**

## What was executed

The attributed, exact-revision-pinned ZKBoo ecosystem generates an actual noninteractive proof transcript for this complete relation:

```
private 64-byte SEP-5 root S
  -> HMAC-SHA512("ed25519 seed", S)
  -> SLIP-0010 hardened children 44', 148', 0'
  -> 32-byte RFC8032 leaf seed k
  -> SHA512, clamp, Ed25519 fixed-base multiplication
  -> official Stellar public key A
```

The fixture is official SEP-5 test case 1, account 0, public address `GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6`. Root derivation, chain codes, leaf expansion and public-key multiplication run **inside the circuit**. It is not a scalar-only proof or the separate preregistered ML-DSA backup-key demo. The affine point advice is constrained, and the verifier requires assertion flag 1.

The public proof message is a SHA512 digest of a typed canonical Soroban XDR statement. It includes network, parent contract, pinned public identity, root/leaf mode and path index, policy epoch/hash, exact rotation operation, replacement algorithm/key, expiry, and source/parameter identifiers. Those identifiers fingerprint the research adapter and parameters; they are not approved production verifier IDs. The proof library binds this digest through its transcript API. A separate verifier process receives the proof and public digest, supplies dummy witness values, and accepts it. The same proof rejects a changed policy epoch in a second process.

The prototype is restricted to published witnesses and fixed fixture relations. It accepts no user mnemonic, seed or private-key argument. Root mode proves one raw-root/account relation at `m/44'/148'/0'`; it does not prove BIP39 PBKDF2, mnemonic checksum/entropy or historical wallet provenance. Leaf mode is an additional RFC8032 fixture experiment, not the recorded root run.

## Measured final root run

| Measurement | Observed result |
| --- | ---: |
| Repetitions | 8 — intentionally insecure |
| Raw upstream proof bytes | 70,591,687 |
| Postcard-serialized proof bytes | 83,779,038 |
| Proving time | 33.208 seconds |
| First verification time | 11.803 seconds |
| In-tool functional checks | 8 passed |

The checks cover the valid statement and rejection of changed public key, assertion flag, action digest, commitment, truncated/empty proof, and increased required response count. Separate-process acceptance and changed-epoch rejection are recorded additionally. Times are native local measurements, not Soroban instruction costs. Fresh randomness means future proof bytes, hashes and timings can differ.

See [seed-proof-research.json](seed-proof-research.json) for exact source/lock hashes, statement XDR, parameters, proof hashes, compiler versions and separate-verifier results. The generated binary proof remains outside Git at the report's artifact directory. Anyone reviewing the computation can regenerate it; this JSON is an execution record, not an independently signed attestation.

The current Testnet read-only snapshot reports `132,096` bytes as maximum transaction size. Even the raw reduced-round proof is about 534.4 times that whole-transaction limit, before adding a transaction envelope. **This backend is unsuitable for direct single-transaction submission in its measured form.** The snapshot preserves a CLI26/protocol29 compatibility warning, so it is not claimed to be the complete protocol29 configuration. No verifier was run on Soroban. The result does not rule out a different backend or a separately reviewed architecture.

Upstream calls 438 rounds its 128-bit PQ setting. That claim is not independently established here, and eight rounds provide no meaningful security. A naive linear response-size projection is about 3.86 GB raw at 438 rounds; that full proof was **not** generated. Increasing the round count alone would not establish quantum knowledge extraction, zero knowledge, QROM security, hash composition, implementation safety or adequate seed entropy. A proof at reduced rounds can accept mutations by chance; the runner records failures and does not search for a favorable changed message.

## Mathematical argument and counterexamples

[RECOVERY_SECURITY_ARGUMENT.md](RECOVERY_SECURITY_ARGUMENT.md) gives a handwritten conditional argument and two direct mathematical lemmas. It is not computer checked or a completed security reduction for this backend.

* A reduced Ed25519 scalar uniquely determines its complete clamped scalar. The protected secret is a hash preimage such as the leaf or root seed, not hidden clamped-scalar bits.
* A supplied scalar alone can forge an ordinary Ed25519 signature, without the seed or original deterministic nonce prefix. The fixture script verifies such signatures over unsubmitted Stellar transaction hashes on 15 public accounts.

The new [public-fixture evidence](seed-recovery-evidence.json) contains 195 relation/counterexample checks, 11 draft-statement mutation checks and five policy-precondition rejections. Ten new adversarial unit tests exercise malformed statements, point encodings, signature/message substitution, clamp boundaries, root/leaf confusion, current-policy mismatch and expiry. Existing SEP-5 compatibility checks remain separately recorded at 168 checks.

A Stellar `S...` secret supplies the leaf-seed witness. Leaf recovery cannot distinguish its thief from its owner. Root-only recovery can exclude a thief of only the leaf, conditional on root secrecy and retirement of classical authority. Trying scalar bytes as a seed and getting a different key does not prove seed inversion hard. Finite fixture tests cannot establish a quantum-hardness claim.

The Python policy object checks preconditions only. It does not implement a consuming state machine or prove replay, authority-retirement or cached-authorization invariants. The proof experiment does not verify current eligibility on-chain or establish replacement-key possession. The Rust verifier takes an opaque digest and a fixed fixture relation; it does not parse the XDR. The wrapper chooses matching key/path fields. A production adapter must also ensure the statement's key/path and relation actually match the circuit inputs and verifier, rather than merely accepting a prover-supplied digest. It must derive the exact public statement from authoritative state, verify an approved proof and replacement possession, then atomically rotate and consume the epoch. All spend, upgrade, admin and cached authorization paths must respect the retirement boundary.

## Reproduction

Install the pinned Python requirements and run the repository's local validation first; it builds the public-fixture ML-DSA signer. Rust Git dependencies are pinned by exact revision and fetched on the first build. All ZKBoo packages are attributed LGPL-3.0-or-later; source links and revisions are in [upstream-pins.json](../tools/seed-recovery-research/upstream-pins.json).

```sh
python3 scripts/check_seed_recovery_evidence.py
python3 scripts/run_seed_proof_research.py --relation sep5-root --rounds 8 --output-dir /tmp/qasset-seed-proof-public
```

Add `--offline` after caching the research dependencies. Optional `--target-dir` and `--fixture-signer` locate custom build directories. The generated statement and proof are in the chosen output directory. For standalone verification, pass its `statement.json` field `digest_sha512_hex` to:

```sh
tools/seed-recovery-research/target/release/qasset-zk-seed-research verify DIGEST_64_BYTES_HEX /tmp/qasset-seed-proof-public/proof.postcard 8 sep5-root
```

A separate-process verifier does not consume the backup seed as an input; the use of public fixtures and weak parameters does not demonstrate privacy for real user secrets. The BLAKE3 adapter now uses actual zeroization and drop cleanup, without claiming complete witness-memory erasure. The research lockfile's known-advisory scan has an unmaintained `atomic-polyfill` warning and no reported vulnerabilities; it is not a cryptographic audit.

## Reviewer claim and remaining gate

The demonstrated result is: “We reproduced a complete SEP-5 original-root proof off-chain using attributed code and measured its costs. This experimental backend is too large for direct Soroban submission. We have precise security assumptions, counterexamples and test evidence; compact, reviewed on-chain verification and the authority lifecycle remain unresolved.”

This is functional and feasibility evidence for one research comparator, not a new cryptographic primitive or production-ready recovery. The on-chain `SeedRecoveryVerifier` remains disabled, and no deployment or recovery transaction was submitted during this work.
