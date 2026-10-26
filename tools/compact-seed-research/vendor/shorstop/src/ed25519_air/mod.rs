//! Ed25519 fixed-base scalar-multiplication AIR over BabyBear.
//!
//! Proves $A = [s] B$ where $B$ is the Ed25519 generator and $s$ is a
//! clamped 256-bit scalar. See `docs/ed25519-spec.md` for the full design,
//! constraint inventory, and soundness analysis.
//!
//! Trace shape: 256 rows, one per scalar bit. Transition constraints link
//! the running accumulator $(X_t, Y_t, Z_t, T_t)$ in extended Edwards
//! coordinates to row $t+1$ via the HWCD mixed-addition formula against
//! the precomputed constant $R_t = [2^t] B$.

pub mod air;
pub mod columns;
pub mod constants;
pub mod field;
pub mod generation;
pub mod mul_witness;
pub mod point;
pub mod precomputed_base_multiples;
/// Helpers for the batched (Ed25519 + RangeCheckU16) prove/verify path.
/// Used both by integration tests and by the production
/// [`crate::bip39_to_solana::prove`] entry point — exposed
/// crate-wide (not gated to `cfg(test)`) so the chain proof can
/// reuse the Ed25519+RangeCheck witness builder.
pub(crate) mod prove_verify_helpers;

#[cfg(test)]
mod coverage_tests;
#[cfg(test)]
mod nist_tests;
#[cfg(test)]
pub(crate) mod prove_verify_tests;
#[cfg(test)]
mod soundness_tests;
#[cfg(test)]
mod test_helpers;
