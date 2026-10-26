# Compact external-input Binius64 research verifier

This successor experiment preserves the existing public RFC8032 leaf-seed relation and original proof, with the same Binius64 revision `115108d5a661d95c0b474b6ab02558bfe6c6bec7`, upstream 96-bit setting, 232 FRI queries and transcript. It is a raw Wasm fixture experiment, not a Soroban contract or approved quantum backend. The earlier `binius-verifier-port` remains unchanged.

The optimized raw module receives bounded setup/proof/scalar/action bytes through a one-time input buffer. It contains no embedded setup or proof. The loader accepts only compiled setup SHA256 `0d1a3b775ce006e07df6af3aa1491d2d7c29202e11985fd6045ef398cb3be424`, before decoding. This experiment supports only the independently pinned RFC8032 public-key fixture; generic exact point binding, account eligibility, retirement and replacement authority remain outside this ABI.

Three changes reduce representation and code size without reducing any proof parameter:

- Canonical bounded ULEB32 operand lengths and packed wire indices recode the exact setup from 2,714,051 to 1,286,664 bytes. `transcode.py` verifies the original immutable hash, new immutable hash, and byte-exact expansion back to the original. Bases, oracle layout, FRI queries, constraints and blinding remain identical.
- An explicit verifier-only constructor moves the existing unpadded constraint vector into the final padded vector, avoiding a second retained copy. It records the original 82,373 unpadded count and preserves the complete 131,072-constraint fingerprint `0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938`. The retained-original getter returns `None` for this owned mode; old export routines fail explicitly rather than treating padded data as unpadded data.
- Optional field feature `compact-inversion` retains the original inversion addition-chain schedule but computes each Frobenius operation with repeated calls to the existing squaring routine instead of a 49,152-byte lookup table. Zero inversion and the out-of-range helper convention remain unchanged. This is an arithmetic time/space tradeoff, requiring independent review and actual Soroban CPU measurement. It introduces no new cryptographic assumption. Loader and upstream verification share the same locked SHA-256 implementation, avoiding a duplicate dependency. The source header hash is precomputed as the exact original source SHA256, avoiding embedded source text and its runtime hashing.

The original `u64LE` sampler-index compatibility fix is retained. Actual verification still calls the complete `ZKVerifier::verify` and rejects unread proof data with `finalize`. Scalar public words are derived from the same scalar observed by the transcript.

Measured raw Wasm size and memory are research evidence only. The module's raw ABI has no Soroban SDK wrapper, ledger transport, contract authorization, transaction envelope or host accounting. Fitting a standalone module below the recorded 131,072-byte code cap does not establish a deployable recovery contract or that combined host/guest resources fit. Quantum knowledge, Fiat-Shamir/QROM and zero-knowledge assumptions remain unapproved. No Stellar RPC, transaction or deployment is used.

## Reproduce

Rust 1.94.1 with `wasm32v1-none`, Node 22, Stellar CLI 26's embedded optimizer, Python 3 and cached locked dependencies are required. The script records failures before running tools, persists command results, removes inherited Rust flags, and rejects source changes during a run. It is not a hermetic build.

```sh
python3 scripts/run_next.py --setup /path/to/compact-fixed-setup.bin --proof /path/to/original-proof.bin
```

Alternatively use `--original-setup /path/to/original-fixed-setup.bin` to reproduce the lossless recoding. Generated fixtures, modules and reports stay under `target`. Compiler settings are explicit in `external-input/Cargo.toml`: opt level `z`, fat LTO, one codegen unit, panic abort, stripped symbols and 40 MiB maximum linear memory. The optimizer command is deprecated by CLI26 but retained here to reproduce the measured invocation.

The run checks native proof acceptance and negatives, twelve raw Wasm proof/setup cases, five ABI bounds, the original-native transcript golden vector and all padded constraints. It also compares 646 deterministic field vectors across unchanged original-native reference outputs, the original Wasm table branch and the optional Wasm squaring branch, including zero, one, high bits, every basis bit and 512 hash-derived inputs. These functional checks are not a formal security proof. Timing is Node/V8 execution, not Soroban metering.

Original licenses and upstream instructions remain in `vendor/binius64`. `provenance.json` records current sources and patch lineage; `evidence` records this successor experiment, rather than relabeling the original port's reports.
