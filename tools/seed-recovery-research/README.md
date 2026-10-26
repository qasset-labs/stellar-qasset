# Original seed recovery proof experiment

**Published fixtures only. Reduced rounds are insecure. No contract authorization or deployment.**

This isolated tool calls the attributed upstream ZKBoo/ZKB++ implementation and exact RFC8032 seed-to-Ed25519 public-key circuit. It does not implement a new proof protocol. The fixed witness is either the public RFC8032 section 7.1 TEST1 leaf seed (`leaf` mode), or the official SEP5 testcase1 64-byte BIP39 root with path `m/44'/148'/0'` (`sep5-root` mode). The root mode computes SLIP0010 HMAC-SHA512 master and three hardened child steps inside the circuit, then applies the same RFC8032 relation. It does not prove PBKDF2 or mnemonic provenance. The expected public key is independently fixed from the RFC or official SEP-5 address, and the verifier demands assertion flag 1. SHA512, clamping, fixed-base Edwards multiplication and constrained compressed-point advice run inside the upstream circuit. The signing scalar remains private inside this circuit.

The prover uses fresh OS randomness, never exports it, and binds a 64-byte message digest using a dedicated transcript domain. The `verify` command supplies dummy witness/advice inputs and only the expected public output and message. There is intentionally no real-seed input interface. No mnemonic/PBKDF2 derivation is proved here. The BLAKE3 adapter uses its zeroize feature and wipes its state on drop; this does not establish erasure of all witness or working-memory copies.

Build from this directory:

```sh
cargo build --release --locked
# Subsequent builds can use --offline after all pinned Git and registry dependencies are cached.
```

Generate the 64-byte message digest using the repository draft `RecoveryStatement` encoder and pass its hexadecimal encoding:

```sh
cargo run --release --locked -- prove DIGEST_64_BYTES_HEX /tmp/qasset-seed-proof.postcard /tmp/qasset-seed-proof-result.json 8 sep5-root
cargo run --release --locked -- verify DIGEST_64_BYTES_HEX /tmp/qasset-seed-proof.postcard 8 sep5-root
```

`prove` checks the public RFC result against clear execution, generates an actual proof, serializes/deserializes it, verifies it through a dummy-witness verifier, and tests changed public key, assertion flag, message digest, commitment, response count, and missing responses. It records every boolean and returns failure if any functional check fails. It does not retry/search changed messages to obtain desired rejection. `verify` rejects invalid serialized data, trailing bytes, proof files over 256 MiB, incorrect count, or a failed replay, and returns exit code 1 for rejection. A failed negative check at weak round counts is evidence of the deliberately insufficient soundness, not grounds to present the result as secure.

Default 8 rounds; allowed 1..16 only. The upstream repetition helper calls 438 rounds its 128-bit post-quantum setting; that claim has not been independently established here. Neither 8-round nor 16-round results support a cryptographic security claim. A message change can happen to match the same challenge vector, especially at very low repetition counts. Fresh randomness supports the intended proof construction but running tests does not prove zero knowledge, quantum knowledge soundness, or secrecy under implementation attacks. The code and upstream libraries are unaudited.

A preliminary two-round run measured raw proof size 17,238,356 bytes, postcard serialization 20,458,510 bytes, proving 10.844 seconds, and verification 3.492 seconds on this environment. These are functional timings from a deliberately insecure experiment. Full security-parameter execution, Soroban verification, proof aggregation, production lifecycle, and retirement of classical authority are not implemented or demonstrated. Do not commit generated proof files; retain their hashes and measurements in the evidence JSON.

All ZKBoo ecosystem sources are pinned by exact Git revisions in Cargo.toml and Cargo.lock, listed in upstream-pins.json, and licensed LGPL-3.0-or-later. See LICENSE. The small BLAKE3 Hasher adapter and circuit wiring follow upstream API/test examples. Primary sources: https://github.com/zkboo/zkboo and https://github.com/zkboo/zkboo-bip32 . This experiment does not establish novelty of seed lifting.
