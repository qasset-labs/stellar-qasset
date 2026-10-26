# Binius64 Soroban target compile probe

This isolated check asks whether the unmodified Binius64 verifier at exact revision `115108d5a661d95c0b474b6ab02558bfe6c6bec7` can be consumed by a `#![no_std]` library compiled for Soroban's `wasm32v1-none` target. It is not a deployed verifier or a proof-security assessment.

Reproduce with the Rust 1.94.1 toolchain and installed `wasm32v1-none` target:

```sh
cargo +1.94.1 check --locked --lib --target wasm32v1-none
```

The recorded invocation uses `--offline` after dependencies were fetched. `Cargo.lock` pins the dependency versions. The source dependency has `default-features = false`; Cargo nevertheless enables `rand/std` through explicit upstream workspace rand features. Disabling defaults on this one dependency does not provide an upstream no_std implementation. The expected observed result is exit 101, error E0463 at `rand_core` 0.9.5 `extern crate std`.

The small local library re-exports the verifier's config module to establish that this is a genuine dependency compilation, with no cryptographic stub or bypass. A failed check is not proof that a reviewed port is impossible. It establishes that the existing native verifier cannot be plugged into the present Soroban target unchanged.

## Concrete port work identified in the exact source

- The verifier and its ten local dependency crates have no `#![no_std]` mode. Replacing std paths needs actual `core` / `alloc` imports and dependency features, plus a bounded allocator and panic-abort behavior.
- `crates/transcript/src/transcript.rs` combines proof reading with prover-only filesystem / environment / thread debug-dump hooks. Guest builds need to separate those hooks from the transcript logic without changing transcript semantics.
- `crates/verifier/src/zk_config.rs` `ZKVerifier::setup` symbolically runs the inner verifier, compiles an outer Spartan constraint system, constructs padded constraint systems, and calculates FRI parameters. Its frontend dependencies use HashMap and Backtrace. Moving this work off chain requires a reviewed fixed verifier representation and immutable circuit/parameter binding; accepting prover-supplied preprocessing would change the trust model.
- `crates/iop/src/fri/common.rs` `calculate_n_test_queries` uses floating-point math and explicitly documents that its estimate covers only FRI query-phase error. A fixed parameter configuration must preserve the intended protocol and avoid floating-point Wasm instructions; this setting alone is not complete quantum security.
- `crates/field/src/arch/mod.rs` and `arch/wasm32/mod.rs` already select portable arithmetic when simd128 is absent. `crates/utils/src/rayon/mod.rs` already runs synchronously on Wasm without atomics. Therefore x86 intrinsics and multithreading are not established fundamental blockers.
- `ZKVerifier::verify` does not consume `VerifierTranscript`; callers must call `finalize()` after verification to reject trailing unread proof data.
- Only a successfully built, instantiated and metered Soroban contract running real valid and invalid proofs could establish actual instruction, memory, code-size and ledger-entry feasibility. This probe supplies none of those measurements.

## Primary sources

- [Exact Binius64 source](https://github.com/IrreducibleOSS/binius64/tree/115108d5a661d95c0b474b6ab02558bfe6c6bec7)
- [Stellar Rust dialect](https://developers.stellar.org/docs/learn/fundamentals/contract-development/rust-dialect): no standard OS I/O, threads or floating-point instructions; use the `wasm32v1-none` target, which has no std library.

The machine-readable report, exact build stderr, feature tree and source hashes are adjacent. No Stellar transaction was signed, submitted or deployed for this check.
