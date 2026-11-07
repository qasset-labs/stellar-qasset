# Contracts

Rust Soroban contracts in the Cargo workspace. Interfaces, storage, events and
errors are specified in the [contract reference](../docs/CONTRACTS.md); their place
in the system is described in the [architecture](../docs/ARCHITECTURE.md).

| Contract | Area | Status | Tests |
| --- | --- | --- | --- |
| [`qasset-registry`](qasset-registry) | Core: declared policy registry | Implemented; deployed on Testnet | `src/test.rs` (36) |
| [`qasset-sac-admin`](qasset-sac-admin) | Core: post-quantum SAC administration | Prototype controller; fixed key and single operation | `src/test.rs` (21), `tests/ml_dsa_vectors.rs` (3) |
| [`pq-recovery-demo`](pq-recovery-demo) | Optional extension: enrolled-key recovery | Prototype; public fixture keys | `src/test.rs` (14) |
| [`recovery-proof-mailbox`](recovery-proof-mailbox) | Optional extension: proof transport | Research; stores unverified bytes | `src/test.rs` (13) |
| [`seed-recovery-verifier`](seed-recovery-verifier) | Optional extension: seed recovery interface | Research; authentication always disabled | `src/test.rs` (6) |

None of the contracts exposes an upgrade method. Changes ship as new versioned
deployments. Editing contract source, including doc comments on contract types,
changes the reference Wasm hashes recorded in the evidence; see
[development](../docs/DEVELOPMENT.md#build).

Build and test:

```bash
RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked --workspace
RUSTUP_TOOLCHAIN=1.94.1 cargo build --locked --workspace --target wasm32v1-none --release
```
