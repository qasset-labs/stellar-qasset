//! Ed25519 curve parameters and AIR-shape constants.
//!
//! Sources of truth (cross-checked):
//!   - RFC 8032 §5.1 (`references/ed25519/rfc8032/`)
//!   - NIST FIPS 186-5 (`references/ed25519/fips-186-5/`)
//!
//! Spec reference: `docs/ed25519-spec.md` §2 (curve math), §3 (AIR encoding).
//! This is an independent implementation based on those sources — not a
//! port of any reference. Cross-check happens after our tests pass.

/// Bits per limb. **8** so the per-position schoolbook sum
/// $\sum_{i+j=k} a[i] \cdot b[j]$ stays safely below the BabyBear
/// characteristic $p_{\text{BB}} \approx 2^{30.91}$. With 32 × 8-bit
/// limbs, max position-k sum is $32 \cdot 2^{16} = 2^{21}$ vs
/// $p_{\text{BB}} \approx 2^{31}$ — leaves $\sim 240\times$ headroom
/// for signed-carry offsets, witness slack, etc. Matches SP1 / OpenVM
/// (`succinctlabs/sp1/crates/curves/src/params.rs`,
/// `openvm-org/openvm/crates/circuits/mod-builder/src/cuda/constants.rs`).
///
/// **NOT** the SHA-512 limb width — that AIR uses 16-bit limbs. The
/// shared `u16_range` LogUp bus over-approximates the 8-bit ed25519
/// range (every 8-bit value is also a 16-bit-bounded value, so the
/// soundness argument still holds).
pub const LIMB_BITS: usize = 8;

/// Number of 8-bit limbs per field element. $32 \times 8 = 256 \ge 255 = \lceil \log_2 p \rceil$.
pub const NUM_LIMBS: usize = 32;

/// Top-limb width in bits. The high limb of any *reduced* element of
/// $\mathbb{F}_{2^{255}-19}$ uses only `LIMB_BITS - 1` bits (since
/// $p \approx 2^{255}$ and `NUM_LIMBS · LIMB_BITS = 256`). Intermediate
/// (unreduced) values may use the full `LIMB_BITS` width.
pub const TOP_LIMB_WIDTH_BITS: usize = LIMB_BITS - 1;

/// $2^{\text{LIMB\_BITS}}$ — limb place-value used for carry propagation.
/// At every site that "shifts to the next limb", reference this rather
/// than hardcoding `<< LIMB_BITS`.
pub const LIMB_BASE: u64 = 1u64 << LIMB_BITS;

/// Mask for one limb ($\text{LIMB\_BASE} - 1$). Use to extract the low
/// `LIMB_BITS` of a wider integer when carry-propagating.
pub const LIMB_MASK: u64 = LIMB_BASE - 1;

/// Mask for the top limb of a *reduced* element ($2^{\text{TOP\_LIMB\_WIDTH\_BITS}} - 1$).
/// Used by the $2^{255} \equiv 19$ top-bit-fold trick after every
/// `add` / `mul` to canonicalize.
pub const TOP_LIMB_MASK: u64 = (1u64 << TOP_LIMB_WIDTH_BITS) - 1;

/// Number of scalar bits processed by the AIR. Equals the bit-width of
/// the clamped scalar `s ∈ [2^254, 2^255)`. One trace row per bit.
pub const NUM_SCALAR_BITS: usize = 256;

/// Number of trace rows for one scalar multiplication.
pub const NUM_ROWS_PER_SCALAR_MUL: usize = NUM_SCALAR_BITS;

/// Bit positions forced to 0 by ed25519 clamping (low three bits).
/// $s \equiv 0 \pmod 8$ kills the cofactor.
pub const CLAMP_LOW_ZERO_BITS_POS: [usize; 3] = [0, 1, 2];

/// Bit position forced to 1 by clamping. Ensures $s \ge 2^{254}$.
pub const CLAMP_HIGH_ONE_BIT_POS: usize = 254;

/// Bit position forced to 0 by clamping. Ensures $s < 2^{255}$.
pub const CLAMP_HIGH_ZERO_BIT_POS: usize = 255;

/// Index of the last row in the trace (`NUM_ROWS_PER_SCALAR_MUL - 1`).
/// The transition constraint binds `next_row.acc_*` to the HWCD output
/// for rows `0..LAST_ROW_INDEX`; the last-row boundary handles row
/// `LAST_ROW_INDEX` separately by binding the same output to public
/// input limbs instead of a non-existent `next_row`.
pub const LAST_ROW_INDEX: usize = NUM_ROWS_PER_SCALAR_MUL - 1;

// ---------------- Range-check / carry-witness constants -------------------

/// Magnitude bound (in bits) for signed mul-carry cells, used as the
/// witness offset à la SP1 (`crates/curves/src/params.rs`'s
/// `WITNESS_OFFSET = 2^14`). Honest carry magnitude bound is
/// $2 \cdot \text{NUM\_LIMBS} \cdot (2^{\text{LIMB\_BITS}} - 1)^2 / 2^{\text{LIMB\_BITS}}
/// \approx 2 \cdot 32 \cdot 2^{16} / 2^8 = 2^{14}$. Choosing 15 (= one
/// extra bit) gives 2× safety margin and lands the offset-shifted
/// carry in `[0, 2^{16})` — fits the existing `u16_range` bus exactly.
pub const MUL_CARRY_OFFSET_BITS: usize = 15;

/// Offset added to a signed mul-carry to make it non-negative for
/// range-checking. Committed value = honest carry + this.
pub const MUL_CARRY_OFFSET: u64 = 1u64 << MUL_CARRY_OFFSET_BITS;

/// Bit-width of the offset-shifted mul-carry cell. Shifted carry lies
/// in `[0, 2^{MUL_CARRY_RANGE_BITS})`; we send it to `u16_range`, so
/// this must be `≤ 16`.
pub const MUL_CARRY_RANGE_BITS: usize = MUL_CARRY_OFFSET_BITS + 1;

/// Linear add/sub carry magnitude is far smaller than mul carry (a few
/// units, since each per-position $S_k$ has only ~3 small terms). We
/// reuse the same offset/range as for mul carries — over-conservative
/// but keeps a single witness-shift convention across the AIR and
/// requires only one range-check bus.
pub const LINEAR_CARRY_OFFSET_BITS: usize = MUL_CARRY_OFFSET_BITS;
pub const LINEAR_CARRY_OFFSET: u64 = MUL_CARRY_OFFSET;

// All values below are computed and verified by `scripts/derive_ed25519_constants.py`
// cross-checked against the canonical values in RFC 8032 and against curve membership.

/// Limbs of the Ed25519 base-field prime $p = 2^{255} - 19$, little-endian 8-bit.
/// Limb 0 = `0xED` ($256 - 19$); limbs 1..30 = `0xFF`; limb 31 = `0x7F`.
pub const PRIME_LIMBS: [u8; NUM_LIMBS] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// Limbs of the Ed25519 curve constant $d = -121665 / 121666 \pmod p$.
pub const D_LIMBS: [u8; NUM_LIMBS] = [
    0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00,
    0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52,
];

/// Limbs of $2 d \pmod p$. Used as a constant operand in the HWCD mixed-add
/// formula's `C' = T_1 · (2 d · x_Q · y_Q)` step (spec §2.7).
pub const TWO_D_LIMBS: [u8; NUM_LIMBS] = [
    0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB, 0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00,
    0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19, 0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24,
];

/// Limbs of the base-point $x$-coordinate $B_x$.
/// Decimal: `15112221349535400772501151409588531511454012693041857206046113283949847762202`.
pub const BASE_POINT_X_LIMBS: [u8; NUM_LIMBS] = [
    0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
    0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21,
];

/// Limbs of the base-point $y$-coordinate $B_y = 4/5 \pmod p$.
/// Decimal: `46316835694926478169428394003475163141307993866256225615783033603165251855960`.
pub const BASE_POINT_Y_LIMBS: [u8; NUM_LIMBS] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];
