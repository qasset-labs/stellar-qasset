//! BIP-39 → Solana composition AIR. Spec source:
//! `docs/pipeline-spec.md` §9 (v1 PVs) and §11 (production-required
//! extensions: PQ destination address binding + freshness binding).
//!
//! ### What this AIR does
//!
//! It's a thin **public-value adapter** sitting at the top of the
//! BIP-39 → Solana proof chain. The pipeline's actual cryptographic
//! work happens in the upstream AIRs:
//!
//!   - `Sha512Air` (×3 senders) proves SHA-512 compressions on the bus.
//!   - `HmacKeyschedAir` + `Pbkdf2HmacAir` + `Pbkdf2Air` prove that
//!     `seed_packed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || INT(1), c=2048)`.
//!   - `Slip10HmacAir` + `Slip10Air` prove that `priv_packed` is the
//!     SLIP-0010 derivation of `seed_packed` along the Solana path
//!     `m/44'/501'/0'/0'`.
//!   - `Ed25519Air` proves `(x_A, y_A) = [priv_packed] · B`.
//!   - `RangeCheckU16Air` services the `u16_range` LogUp bus.
//!
//! Cross-AIR public-value equalities (verifier passes the *same* vector
//! to multiple instances' PV slots in `verify_batch`) already bind the
//! chain end-to-end. What's missing without this AIR is a single
//! canonical PV surface labelled "Solana address" — and a place for
//! the spec §11 production-required PV extensions (PQ destination
//! address, freshness blockhash) to land.
//!
//! ### v1 public values (this AIR's `NUM_PUBLIC_VALUES = 32`)
//!
//! Layout (8-bit limbs, byte-flat):
//!
//!   `[solana_address_y[0..32]]` — the 32-byte Ed25519 public key `y_A`
//!   coordinate. Solana addresses are the **base58 encoding** of this
//!   32-byte form; encoding is verifier-side cheap and off-circuit.
//!
//! Bound to Ed25519's `y_A` PV (offset `PUBLIC_INPUT_Y_OFFSET..
//! PUBLIC_INPUT_Y_OFFSET + 32` in `Ed25519Air::NUM_PUBLIC_VALUES`)
//! by **passing the same 32-cell vector to both AIR slots** in
//! `verify_batch` — Plonky3's cross-AIR PV mechanism does not require
//! a separate constraint surface.
//!
//! ### Production extensions slated for spec §11 (not yet implemented)
//!
//!   - **PQ destination address** (32 cells, 8-bit limbs): `hash(pq_pubkey)`
//!     where `pq_pubkey` is the user's FN-DSA-512 public key. Binds
//!     the proof to a specific destination so an attacker who
//!     intercepts the proof can't redirect funds.
//!   - **Freshness** (32 cells, 8-bit limbs): a recent Solana
//!     blockhash. Prevents replaying old proofs after fund movement.
//!
//! Both extensions are pure PV additions — no new constraint surface
//! is needed. They will grow this AIR's `NUM_PUBLIC_VALUES` from 32
//! to 96 once wired. The current AIR's constraint set is intentionally
//! empty (just bool checks on the witnessed cells); the §11 additions
//! are zero-constraint passthrough cells too.

pub mod air;
pub mod columns;
pub mod generation;

#[cfg(test)]
mod tests;
