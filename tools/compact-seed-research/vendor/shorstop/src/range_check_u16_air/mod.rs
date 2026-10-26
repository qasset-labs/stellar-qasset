//! 16-bit range-check AIR.
//!
//! Acts as the "receive" side of a global LogUp bus named `"u16_range"`.
//! Other AIRs (e.g. [`crate::ed25519_air::air::Ed25519Air`]) "send" 16-bit
//! limb values to this bus; this AIR receives them with multiplicities,
//! against a fixed preprocessed table containing the values
//! $0, 1, \ldots, 2^{16} - 1$.
//!
//! Trace shape:
//!
//! - **Height**: $2^{16} = 65{,}536$ rows.
//! - **Preprocessed trace** (1 column): row $i$ holds the table value $i$.
//! - **Main trace** (1 column): `multiplicity` — how many times value $i$
//!   was sent to the bus by any participating AIR.
//! - **Permutation trace** (1 column, allocated by `LogUpGadget`): the
//!   running sum of LogUp denominators.
//!
//! The AIR's `Air::eval` is empty by design — the only constraint that
//! ties multiplicity to the table is the LogUp lookup itself, evaluated
//! by `eval_with_lookups`.

pub mod air;
pub mod columns;
pub mod constants;
pub mod generation;
