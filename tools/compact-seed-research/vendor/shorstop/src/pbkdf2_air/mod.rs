//! PBKDF2 orchestrator AIR — sits above `Pbkdf2HmacAir` and produces
//! the final 64-byte seed by XOR-folding the per-iteration `U_i`
//! digests. Spec source: `docs/pipeline-spec.md` §7.
//!
//! For PBKDF2 with `dkLen = 64` (the BIP-39 case where the SHA-512
//! HMAC output already matches the desired key length), the seed is
//! simply the XOR of all `c` U-values:
//!
//!   `T = U_1 ⊕ U_2 ⊕ … ⊕ U_c    seed = T   (no concatenation needed)`
//!
//! This AIR has no SHA-512 awareness — it never registers a Lookup on
//! `sha512_compressions`. Its sole upstream link is the
//! `pbkdf2_outputs` bus on which `Pbkdf2HmacAir` sends one
//! `(iter_index, U_i)` tuple per outer row.

pub mod air;
pub mod columns;
pub mod constants;
pub mod generation;

#[cfg(test)]
mod tests;
