# Experimental Q-Asset leaf-seed STARK probe

Public test fixtures only. **Do not enter real seeds. Do not deploy this code.**

This tool reuses the MIT-licensed [LimeChain/ShorStop Plonky3 adapter](https://github.com/LimeChain/ShorStop/tree/e7692712c601814d03acc5b638e0a15962f50452/libs/mopro/plonky3-adapter), pinned to commit `e7692712c601814d03acc5b638e0a15962f50452`, and Plonky3 0.5.2. Vendor changes are the Q-Asset wrapper module/export, MIT license copy, and removal of its nested workspace declaration. Upstream SHA512 AIR is unchanged. Cargo.lock pins all resolved packages.

The proof relation is a private 32-byte Ed25519 leaf seed whose SHA512 hash clamps to a public scalar. Fixed protocol domain bytes and a public 64-byte action digest are observed in the Fiat-Shamir transcript. The action digest is a dummy fixture in this harness. The AIR does not compute Ed25519 multiplication, Stellar account/root derivation, or a recovery transaction. A verifier must independently authenticate those public inputs and retired authority state.

The original 1-row draft was rejected because 78 queries can exhaust tiny-trace hiding entropy. This version uses 128 repeated valid rows, fresh OS-seeded ChaCha masking streams, and the upstream hiding PCS/MMCS. **This is not an independently reviewed ZK or quantum signature-of-knowledge construction.** Upstream parameters have an acknowledged low-degree proximity-gap security term; no 128-bit PQ claim is made.

Build and run:

```sh
cargo build --release --locked
./target/release/qasset-compact-seed-research /tmp/qasset-compact-seed-proof
```

The tool writes proof.postcard, checkpoint.json, result.json and tests valid acceptance, changed scalar/action rejection, a malicious changed witness with unchanged public statement, corruption, truncation and trailing data. The proof exposes the clamped scalar, which enables classical signing for an active Ed25519 key; this is safe only for the explicit public RFC8032 fixture used here.

Verify without providing a seed (use values from result.json):

```sh
./target/release/qasset-compact-seed-research verify PROOF_FILE CLAMP_HEX ACTION_SHA512_HEX
```

Exit 0 means accepted; exit 2 means rejected. The CLI checks a 256 MiB proof cap before reading, and the API rejects trailing bytes and oversized proof encodings. Native verifier parsing is not a hardened service. Proof size and native runtime do not establish Soroban feasibility. See `evidence/` for measurements and separate generation/final-verification source records; run `python3 verify_provenance.py` to check the recorded local source hashes. The recorded proof was generated before strict trailing-data rejection was added to the decoder; the proof protocol/AIR/configuration did not change, and the final verifier is tested against that same artifact.
