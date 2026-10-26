//! SLIP-0010 orchestrator AIR — sits above `Slip10HmacAir` and
//! exposes the derived Ed25519 private scalar as a 32 × 8-bit-limb
//! public value (`priv_packed`). Spec source:
//! `docs/pipeline-spec.md` §8 / §8.2.
//!
//! ### Phase 4 scope (minimal)
//!
//! This AIR currently does only one thing: receive the last step's
//! HMAC output's first 32 bytes (= the Ed25519 priv) on the
//! `slip10_priv_outputs` bus from `Slip10HmacAir`'s last outer row,
//! and pin those bits to a `priv_packed` 8-bit-limb public-value
//! vector (the §8.2 bit-form bridge to Ed25519's input format).
//!
//! It does **not** enforce:
//!   - the per-step key chain (`step_{k+1}.key = step_k.out_chain`)
//!   - master key = "ed25519 seed" constant
//!   - per-step msg construction with hardened path indices
//!   - the bus binding from Slip10HmacAir's individual compression
//!     rows back to the orchestrator's per-step (key, msg, chain,
//!     priv) tuples
//!
//! In other words: the priv is correctly **extracted** from
//! Slip10HmacAir's last outer row, but a malicious prover can claim
//! arbitrary HMAC outputs in Slip10HmacAir's rows because no AIR
//! constrains those outputs to be a valid SLIP-0010 derivation from
//! the seed. **This is a documented soundness gap** that Phase 4-full
//! (or Phase 5 with extended Slip10HmacAir constraints) will close.
//!
//! For the bench question — "what does the full pipeline cost?" —
//! the trace shape and FRI cost of Phase 4-full will be essentially
//! identical to Phase 4-minimal, since the constraints are inside
//! the AIR's eval and don't grow the column count meaningfully. So
//! Phase 4-minimal is sufficient for the cost estimate; correctness
//! enforcement is the follow-up.

pub mod air;
pub mod columns;
pub mod generation;

#[cfg(test)]
mod tests;
