# Tools

Each tool is an isolated Cargo project with its own lockfile; none is a member of
the root workspace. Core tools support authority assessment and enforcement;
research tools belong to the optional recovery extension.

## Core

| Tool | Purpose |
| --- | --- |
| [`qasset-sac-signer`](qasset-sac-signer) | Creates a fresh ML-DSA-65 operator key outside the repository and signs Soroban authorization digests. Prototype: deterministic signing over a supplied digest |
| [`qasset-evidence-crypto`](qasset-evidence-crypto) | Public ML-DSA credential verification used by the evidence verifier |

## Optional extension: recovery research

| Tool | Purpose |
| --- | --- |
| `pq-demo` | Public-fixture helper for the enrolled-key recovery counter; keys are known to everyone |
| `seed-recovery-research`, `compact-seed-research`, `scalar-seed-research` | Seed-knowledge proof experiments with reduced-round or otherwise unvalidated parameters |
| `binius-seed-research`, `binius-soroban-research`, `binius-commit-prove-research`, `binius-commit-prove-blake3-research`, `binius-preprocessing-reference`, `binius-verifier-port`, `binius-verifier-next`, `binius-verifier-profile-research` | Binius64 proof, verifier porting and Soroban cost experiments |
| `recovery-key-binding` | Public scalar and key binding experiment |
| `rokoko-relation-research`, `rokoko-gadget-research` | Lattice-proof relation scoping and gadget experiments |

`binius-verifier-port` and `binius-verifier-next` each vendor a pinned binius64
tree, and `rokoko-relation-research` is an unmodified upstream clone excluded from
the workspace. Their license texts are preserved; see
[license scope](../docs/LICENSE_SCOPE.md). Tracked build logs under research
`evidence/` directories are recorded outputs, not build artifacts.

Build and test the core tools:

```bash
(cd tools/qasset-sac-signer && RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked)
(cd tools/qasset-evidence-crypto && RUSTUP_TOOLCHAIN=1.94.1 cargo build --locked --release)
```
