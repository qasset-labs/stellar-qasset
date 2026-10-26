//! Shared LogUp-tuple constructor for the `sha512_compressions` bus.
//!
//! This is the **single source of truth** for the canonical 128-element
//! limb sequence that the SHA-512 AIR (sender) and every HMAC wrapper
//! AIR (receiver) emits per compression row. Spec source:
//! `docs/pipeline-spec.md` §5.4 ("Canonical limb order — binding
//! convention") and §6.2 (helper inventory).
//!
//! Centralizing the order matters because β-Horner inside `p3-lookup`'s
//! gadget is order-sensitive: `a + b·β ≠ b + a·β` unless `a = b`. Any
//! drift in canonical order between sender and receiver silently breaks
//! the bus — multiset equality fails and `verify_batch` rejects with
//! no localized error. The negative regression test in
//! `bus_smoke_tests` exercises this binding from both directions.

use p3_air::{AirBuilder, SymbolicExpression};
use p3_field::{Field, PrimeCharacteristicRing};

use crate::sha512_air::constants::{
    BITS_PER_LIMB, BLOCK_WORDS, NUM_SHA512_TUPLE_LIMBS, STATE_WORDS, U64_LIMBS, WORD_BITS,
};

// ── Bit-layout conventions ─────────────────────────────────────────────
//
// Two layouts coexist; centralizing the conversion in helpers keeps it
// out of the per-AIR code.
//
//   - **byte-flat** (used for committed `key_bits` / `msg_bits`):
//       `bits[byte_idx * 8 + bit_in_byte]`, LSB-first within each byte.
//     This is the natural shape for filling from a `&[u8]` source.
//
//   - **word-flat** (used for committed `h_out_bits` and the
//     `block_bits` *output* of the inline helpers, matching
//     `Sha512Cols::w` / `Sha512Cols::h_out`):
//       `bits[word_idx * 64 + bit_in_word]`, LSB-first within each
//     64-bit word.
//
// The mapping byte_flat → word_flat:
//   word_idx     = byte_idx / 8
//   byte_in_word = byte_idx % 8                  // 0 = high byte, 7 = low byte
//   bit_in_word  = (7 - byte_in_word) * 8 + bit_in_byte
// Inverse word_flat → byte_flat:
//   byte_idx     = word_idx * 8 + 7 - bit_in_word / 8
//   bit_in_byte  = bit_in_word % 8
//
// (The 7−byte_in_word inversion is the big-endian byte order inside a
// `u64::from_be_bytes` interpretation: bytes[0] becomes bits 56..64,
// bytes[7] becomes bits 0..8 of the u64.)

/// Bit count of a 128-byte SHA-512 block in **byte-flat** layout
/// (128 bytes × 8 bits-per-byte). Used to size committed `key_bits` /
/// `msg_bits` slices that the HMAC AIRs feed into the `inline_*`
/// helpers.
pub const BLOCK_BIT_COUNT_BYTE_FLAT: usize = 128 * 8;

/// Expected length of the `h_in_limbs` argument: 8 state words × 4
/// 16-bit limbs = 32 elements, in `[word_0.limb_0, ..., word_7.limb_3]`
/// order with `limb[0]` = low 16 bits of the word.
pub const H_IN_LIMB_COUNT: usize = STATE_WORDS * U64_LIMBS;

/// Expected length of the `block_bits` argument to `compression_tuple`:
/// 16 block words × 64 bits = 1024 elements in **word-flat** layout
/// (`block_bits[word * WORD_BITS + bit]`, bit LSB-first within each
/// word). Spec §5.4.
pub const BLOCK_BIT_COUNT_WORD_FLAT: usize = BLOCK_WORDS * WORD_BITS;

/// Expected length of the `h_out_bits` argument: 8 state words × 64
/// bits = 512 elements, same intra-word LSB-first convention.
pub const H_OUT_BIT_COUNT: usize = STATE_WORDS * WORD_BITS;

/// Build the canonical 128-element compression tuple in the order pinned
/// by `pipeline-spec.md` §5.4:
///
/// ```text
/// [ h_in[0].limb[0..4], h_in[1].limb[0..4], ..., h_in[7].limb[0..4],   //   0..32
///   block[0].limb[0..4], ..., block[15].limb[0..4],                    //  32..96
///   h_out[0].limb[0..4], ..., h_out[7].limb[0..4] ]                    //  96..128
/// ```
///
/// Per-limb packing for the bit-form inputs:
/// `limb[k] = Σ_{b=0..15} 2^b · bits[k·16 + b]` — degree-1 in the input
/// expressions. The bit→limb pack happens here (not at call sites) so
/// the canonical order stays in one place.
///
/// # Arguments
///
/// * `h_in_limbs` — slice of `H_IN_LIMB_COUNT` (= 32) `SymbolicExpression`s
///   representing the input chaining state, already in 16-bit-limb form.
///   Order: `h_in_limbs[word * U64_LIMBS + limb]`. The SHA-512 AIR's
///   `Sha512Cols::h_in[i][k]` cells are already in this layout (the
///   convention the assert_add carry chain runs on, see
///   `sha512_air/columns.rs` doc).
/// * `block_bits` — slice of `BLOCK_BIT_COUNT_WORD_FLAT` (= 1024)
///   bit-form expressions representing the message block. Order:
///   `block_bits[word * WORD_BITS + bit]`. Bits within a word are
///   LSB-first.
/// * `h_out_bits` — slice of `H_OUT_BIT_COUNT` (= 512) bit-form
///   expressions for the output chaining state. Same layout as
///   `block_bits` but per-word over `STATE_WORDS` words.
///
/// # Panics
///
/// Asserts on slice lengths. A length mismatch is a programming error,
/// not a runtime one — catch it at AIR-instantiation time rather than
/// silently producing a degenerate tuple.
pub fn compression_tuple<F: Field>(
    h_in_limbs: &[SymbolicExpression<F>],
    block_bits: &[SymbolicExpression<F>],
    h_out_bits: &[SymbolicExpression<F>],
) -> Vec<SymbolicExpression<F>> {
    assert_eq!(
        h_in_limbs.len(),
        H_IN_LIMB_COUNT,
        "h_in_limbs must be {H_IN_LIMB_COUNT} elements (8 words × 4 limbs)"
    );
    assert_eq!(
        block_bits.len(),
        BLOCK_BIT_COUNT_WORD_FLAT,
        "block_bits must be {BLOCK_BIT_COUNT_WORD_FLAT} elements (16 words × 64 bits)"
    );
    assert_eq!(
        h_out_bits.len(),
        H_OUT_BIT_COUNT,
        "h_out_bits must be {H_OUT_BIT_COUNT} elements (8 words × 64 bits)"
    );

    let mut tuple: Vec<SymbolicExpression<F>> = Vec::with_capacity(NUM_SHA512_TUPLE_LIMBS);

    // h_in: already 16-bit-limb-packed — push verbatim in canonical order.
    for limb in h_in_limbs.iter() {
        tuple.push(limb.clone());
    }

    // block: 16 words × pack each word's 64 bits to 4 × 16-bit limbs.
    for block_word_index in 0..BLOCK_WORDS {
        let word_bits = &block_bits
            [block_word_index * WORD_BITS..(block_word_index + 1) * WORD_BITS];
        for limb_index in 0..U64_LIMBS {
            tuple.push(pack_limb_from_bit_expressions(word_bits, limb_index));
        }
    }

    // h_out: same as block, over STATE_WORDS words.
    for state_word_index in 0..STATE_WORDS {
        let word_bits = &h_out_bits
            [state_word_index * WORD_BITS..(state_word_index + 1) * WORD_BITS];
        for limb_index in 0..U64_LIMBS {
            tuple.push(pack_limb_from_bit_expressions(word_bits, limb_index));
        }
    }

    debug_assert_eq!(tuple.len(), NUM_SHA512_TUPLE_LIMBS);
    tuple
}

/// `Σ_{b=0..15} 2^b · word_bits[limb_index·16 + b]` — packs 16 bit-form
/// expressions into one 16-bit limb expression. Degree-1 in inputs.
fn pack_limb_from_bit_expressions<F: Field>(
    word_bits: &[SymbolicExpression<F>],
    limb_index: usize,
) -> SymbolicExpression<F> {
    debug_assert_eq!(word_bits.len(), WORD_BITS);
    let mut acc: SymbolicExpression<F> = F::ZERO.into();
    for bit_offset in 0..BITS_PER_LIMB {
        let pow: SymbolicExpression<F> = F::from_u32(1u32 << bit_offset).into();
        let bit = word_bits[limb_index * BITS_PER_LIMB + bit_offset].clone();
        acc = acc + pow * bit;
    }
    acc
}

// ── Inline block-bit derivation (HMAC schedulers) ──────────────────────
//
// HMAC wrapper AIRs do not commit `block_bits` as a column family;
// instead the block bits are degree-1 polynomial expressions over
// committed `key_bits` / `msg_bits`, evaluated inline inside the LogUp
// tuple builder. Spec §6.2's "column-commitment principle". This saves
// 1024 cells per row across thousands of rows in PBKDF2 → big total.

/// `key_bit ⊕ pad_bit` as a degree-1 expression. For `pad_bit = false`
/// returns `key_bit` (no-op); for `pad_bit = true` returns
/// `1 − key_bit` (since {0,1} XOR 1 = NOT). The branched form keeps
/// the AST leaner than the universal `key_bit · (1 − 2c) + c` formula.
pub fn xor_bit_with_constant<AB: AirBuilder>(key_bit: AB::Expr, pad_bit: bool) -> AB::Expr {
    if pad_bit {
        AB::Expr::ONE - key_bit
    } else {
        key_bit
    }
}

/// Build the 1024-element word-flat block-bit expression vector for the
/// HMAC ipad / opad pre-compression: `block = K_padded ⊕ pad_word`,
/// where `pad_word` is `pad_byte` repeated 8 times (so every 64-bit
/// word's bit `b` is the constant `(pad_byte >> (b mod 8)) & 1`).
///
/// Output layout: word-flat (matches `compression_tuple`'s `block_bits`
/// expectation, see §5.4).
///
/// # Arguments
/// * `key_bits` — `BLOCK_BIT_COUNT_BYTE_FLAT` (= 1024) committed bit cells in
///   **byte-flat** order: `key_bits[byte_idx * 8 + bit_in_byte]` with
///   `bit_in_byte` LSB-first.
/// * `pad_byte` — `IPAD_BYTE` (`0x36`) or `OPAD_BYTE` (`0x5C`) per RFC
///   2104. Other values are not rejected (the helper is generic) but
///   the AIR call site MUST pass one of the canonical pads.
pub fn inline_block_bits_for_ipad_or_opad<AB: AirBuilder>(
    key_bits: &[AB::Var],
    pad_byte: u8,
) -> Vec<AB::Expr>
where
    AB::Var: Copy + Into<AB::Expr>,
{
    assert_eq!(
        key_bits.len(),
        BLOCK_BIT_COUNT_BYTE_FLAT,
        "key_bits must be {BLOCK_BIT_COUNT_BYTE_FLAT} elements (128 bytes × 8 bits)"
    );

    let mut block_bits: Vec<AB::Expr> = Vec::with_capacity(BLOCK_BIT_COUNT_WORD_FLAT);
    for word_index in 0..BLOCK_WORDS {
        for bit_in_word in 0..WORD_BITS {
            // word-flat → byte-flat translation.
            let byte_in_word = 7 - bit_in_word / 8;
            let byte_idx = word_index * 8 + byte_in_word;
            let bit_in_byte = bit_in_word % 8;
            let pad_bit_set = ((pad_byte >> bit_in_byte) & 1) == 1;
            let key_bit_expr: AB::Expr = key_bits[byte_idx * 8 + bit_in_byte].into();
            block_bits.push(xor_bit_with_constant::<AB>(key_bit_expr, pad_bit_set));
        }
    }
    debug_assert_eq!(block_bits.len(), BLOCK_BIT_COUNT_WORD_FLAT);
    block_bits
}

/// Build the 1024-element word-flat block-bit vector for a SHA-512-
/// padded message: `[msg_bytes (msg_byte_len), 0x80, zero-pad, length
/// (16 BE bytes)]`, totaling exactly 128 bytes. The message bits are
/// degree-1 references to `msg_bits`; the 0x80 separator, zero-pad,
/// and length suffix are constants.
///
/// Single-block padding only: this helper produces ONE 128-byte
/// block, so `msg_byte_len ≤ 111`. For HMAC inner / outer
/// compressions the K'⊕ipad / opad_state already-compressed prefix
/// means the SHA-512 input is `prior_block_bytes + msg_byte_len`
/// bytes long, and the length suffix in the final block must reflect
/// the **full** input length (RFC 3174 / FIPS 180-4 §5.1.2). Use
/// `prior_block_bytes = 0` for standalone SHA-512 padding,
/// `prior_block_bytes = 128` for HMAC inner / outer (since the
/// keyschedule precompute consumed exactly one block).
///
/// # Arguments
/// * `msg_bits` — `msg_byte_len * 8` committed bit cells in **byte-flat**
///   order, LSB-first within each byte.
/// * `msg_byte_len` — message length in bytes; must be `≤ 111`.
/// * `prior_block_bytes` — bytes of input that preceded this msg (must
///   be a multiple of 128, since SHA-512 processes block-by-block).
///   Affects ONLY the 16-byte length suffix at the end of the block.
pub fn inline_block_bits_for_padded_msg<AB: AirBuilder>(
    msg_bits: &[AB::Var],
    msg_byte_len: usize,
    prior_block_bytes: usize,
) -> Vec<AB::Expr>
where
    AB::Var: Copy + Into<AB::Expr>,
{
    assert!(
        msg_byte_len <= 111,
        "single-block SHA-512 padding requires msg_byte_len ≤ 111 (got {msg_byte_len})"
    );
    assert_eq!(
        msg_bits.len(),
        msg_byte_len * 8,
        "msg_bits length must be msg_byte_len * 8"
    );
    assert_eq!(
        prior_block_bytes % 128,
        0,
        "prior_block_bytes must be a multiple of the SHA-512 block size"
    );

    let msg_bit_len = ((prior_block_bytes + msg_byte_len) * 8) as u128;

    let mut block_bits: Vec<AB::Expr> = Vec::with_capacity(BLOCK_BIT_COUNT_WORD_FLAT);
    for word_index in 0..BLOCK_WORDS {
        for bit_in_word in 0..WORD_BITS {
            let byte_in_word = 7 - bit_in_word / 8;
            let byte_idx = word_index * 8 + byte_in_word;
            let bit_in_byte = bit_in_word % 8;

            let bit_expr: AB::Expr = if byte_idx < msg_byte_len {
                // Message byte → committed bit.
                msg_bits[byte_idx * 8 + bit_in_byte].into()
            } else if byte_idx == msg_byte_len {
                // 0x80 separator — only the MSB of this byte is set.
                if bit_in_byte == 7 {
                    AB::Expr::ONE
                } else {
                    AB::Expr::ZERO
                }
            } else if byte_idx < 112 {
                // Zero pad.
                AB::Expr::ZERO
            } else {
                // 16-byte big-endian length suffix at offsets [112, 128).
                let length_byte_offset = byte_idx - 112;
                let shift_bits = 8 * (15 - length_byte_offset);
                let length_byte_value = ((msg_bit_len >> shift_bits) & 0xFF) as u8;
                if ((length_byte_value >> bit_in_byte) & 1) == 1 {
                    AB::Expr::ONE
                } else {
                    AB::Expr::ZERO
                }
            };
            block_bits.push(bit_expr);
        }
    }
    debug_assert_eq!(block_bits.len(), BLOCK_BIT_COUNT_WORD_FLAT);
    block_bits
}

// ── Cross-row state binding ────────────────────────────────────────────

/// Constrain a 32-element 16-bit-limb `state_packed` view (e.g.
/// `ipad_state_packed`) to equal a 512-element `h_out_bits` row, via
/// per-limb `Σ 2^j · bit` packing. Degree-1 in inputs.
///
/// Used by HMAC AIRs to pin "this row's `h_in_packed` equals the
/// public-value `ipad_state_packed`" (`Pbkdf2HmacAir`) and to pin
/// `priv_packed` against `out_priv_bits` at the SLIP-0010 → Ed25519
/// boundary (§8.2). The receiver always commits in word-flat layout to
/// match `Sha512Cols::h_out`.
///
/// # Arguments
/// * `state_packed` — 32 limb cells, low-first per word
///   (`state_packed[word * 4 + limb]`).
/// * `h_out_bits` — 512 bit cells in word-flat layout
///   (`h_out_bits[word * 64 + bit_in_word]`).
pub fn eval_state_packed_equals_h_out_bits<AB: AirBuilder>(
    builder: &mut AB,
    state_packed: &[AB::Var],
    h_out_bits: &[AB::Var],
) where
    AB::Var: Copy + Into<AB::Expr>,
{
    assert_eq!(
        state_packed.len(),
        STATE_WORDS * U64_LIMBS,
        "state_packed must be {} elements (8 words × 4 limbs)",
        STATE_WORDS * U64_LIMBS
    );
    assert_eq!(
        h_out_bits.len(),
        STATE_WORDS * WORD_BITS,
        "h_out_bits must be {} elements (8 words × 64 bits)",
        STATE_WORDS * WORD_BITS
    );

    for word_index in 0..STATE_WORDS {
        for limb_index in 0..U64_LIMBS {
            let packed_cell: AB::Expr = state_packed[word_index * U64_LIMBS + limb_index].into();
            let mut bit_packed: AB::Expr = AB::Expr::ZERO;
            for bit_offset in 0..BITS_PER_LIMB {
                let pow: AB::Expr = AB::Expr::from_u32(1u32 << bit_offset);
                let bit_idx =
                    word_index * WORD_BITS + limb_index * BITS_PER_LIMB + bit_offset;
                let bit_expr: AB::Expr = h_out_bits[bit_idx].into();
                bit_packed = bit_packed + pow * bit_expr;
            }
            builder.assert_zero(packed_cell - bit_packed);
        }
    }
}
