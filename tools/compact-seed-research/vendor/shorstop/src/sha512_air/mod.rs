//! SHA-512 compression function as a Plonky3 AIR over BabyBear.
//!
//! Single-row-per-compression design, modeled on Plonky3 PR #1563
//! (`p3-sha256-air`). See `docs/sha512-spec.md` for the design rationale,
//! constraint inventory, and soundness analysis.

pub mod air;
pub mod columns;
pub mod constants;
pub mod generation;

#[cfg(test)]
mod coverage_tests;

#[cfg(test)]
mod nist_tests;

#[cfg(test)]
mod soundness_tests;
