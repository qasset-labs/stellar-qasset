//! HMAC-SHA512 reusable AIR module.
//!
//! Spec source: `docs/pipeline-spec.md` §6 ("HMAC reusable module"). This
//! module hosts shared helpers + constants used by all three HMAC AIR
//! instances (`HmacKeyschedAir`, `Pbkdf2HmacAir`, `Slip10HmacAir`) and by
//! the `Sha512Air` sender on the `sha512_compressions` LogUp bus.
//!
//! Phase 1c only ships the keystone helper [`helpers::compression_tuple`]
//! (the canonical 128-element bus-tuple builder) and the bus / pad
//! constants. The three AIR structs land in subsequent phases.

pub mod constants;
pub mod helpers;
pub mod keysched;
pub mod pbkdf2_hmac;
pub mod slip10_hmac;

#[cfg(test)]
mod bus_smoke_tests;

#[cfg(test)]
mod keysched_tests;

#[cfg(test)]
mod pbkdf2_hmac_tests;

#[cfg(test)]
mod slip10_hmac_tests;
