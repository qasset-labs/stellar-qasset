//! Trace generation for the SHA-512 compression AIR.
//!
//! Given a chaining state `H^in` and one 1024-bit message block, fill all
//! columns of one row of the trace. The algorithm follows the FIPS 180-4
//! SHA-512 spec; columns are written per the layout in `columns.rs` and
//! the carry semantics in `docs/sha512-spec.md` §6.1.
//!
//! Independent implementation based on the spec — not a port of any reference.

use core::borrow::{Borrow, BorrowMut};

use p3_field::PrimeField64;

use crate::sha512_air::columns::{Sha512Cols, CARRIES_PER_ADD, NUM_SHA512_COLS};
use crate::sha512_air::constants::{
    BIG_SIGMA0_ROTATIONS, BIG_SIGMA1_ROTATIONS, BLOCK_WORDS, CHAIN_LEN, NUM_COMPRESSION_ROUNDS,
    SHA512_K, SMALL_SIGMA0_ROTATIONS, SMALL_SIGMA0_SHIFT, SMALL_SIGMA1_ROTATIONS,
    SMALL_SIGMA1_SHIFT, STATE_WORDS, U64_LIMBS, WORD_BITS,
};

/// Split a 64-bit value into 4 × 16-bit limbs (limb 0 = low).
fn to_limbs_le(x: u64) -> [u64; U64_LIMBS] {
    [
        x & 0xFFFF,
        (x >> 16) & 0xFFFF,
        (x >> 32) & 0xFFFF,
        (x >> 48) & 0xFFFF,
    ]
}

/// Reconstruct a 64-bit value from its 4 little-endian 16-bit limbs.
fn limbs_to_u64(limbs: [u64; U64_LIMBS]) -> u64 {
    limbs[0] | (limbs[1] << 16) | (limbs[2] << 32) | (limbs[3] << 48)
}

/// Split a 64-bit value into 64 bits, LSB first.
fn to_bits_le(x: u64) -> [u64; WORD_BITS] {
    let mut out = [0u64; WORD_BITS];
    for i in 0..WORD_BITS {
        out[i] = (x >> i) & 1;
    }
    out
}

/// 3-input modular add `s ≡ x + y + z (mod 2^64)` per spec §6.1.
///
/// For each limb index `k ∈ {0, 1, 2, 3}` (low to high) the per-limb
/// equation is
///
/// ```text
///     x^(k) + y^(k) + z^(k) + c^(k-1) = s^(k) + 2^16 · c^(k)
/// ```
///
/// with `c^(-1) = 0` and outgoing carries `c^(k) ∈ {0, 1, 2}` for
/// `k = 0, 1, 2`. The outgoing carry from the top limb (`c^(3)`) is
/// **discarded** — that's the `mod 2^64` reduction.
///
/// Carry bound (so `c^(k)` always fits in 2 bits):
///
/// ```text
///     max sum at any limb
///         = 3 · (2^16 − 1) + max(c^(k-1))
///         = 3 · 65535 + 2
///         = 196 607
///         < 2^18
///     so c^(k) = sum >> 16 ≤ 2.
/// ```
///
/// Returns `(sum_limbs, [c^(0), c^(1), c^(2)])` — only the in-between
/// carries are committed to the trace; the top one is enforced
/// implicitly by a cubic on the top-limb difference in `air.rs`.
fn add3_with_carries(x: u64, y: u64, z: u64) -> ([u64; U64_LIMBS], [u64; CARRIES_PER_ADD]) {
    let xl = to_limbs_le(x);
    let yl = to_limbs_le(y);
    let zl = to_limbs_le(z);

    let mut s = [0u64; U64_LIMBS];
    let mut carries = [0u64; CARRIES_PER_ADD];
    let mut c_in: u64 = 0;

    for k in 0..U64_LIMBS {
        let total = xl[k] + yl[k] + zl[k] + c_in;
        s[k] = total & 0xFFFF;
        c_in = total >> 16;
        if k < CARRIES_PER_ADD {
            carries[k] = c_in;
        }
        // For add3, carry magnitude is bounded by ⌊(3·(2^16-1) + 2)/2^16⌋ = 2.
        debug_assert!(c_in <= 2, "add3 carry out of range");
    }
    (s, carries)
}

/// 2-input modular add. Same shape as add3 with `z = 0`. Carries always in
/// range `{0, 1}` because per-limb max is `2*(2^16 − 1) + 1 < 2^17`.
fn add2_with_carries(x: u64, y: u64) -> ([u64; U64_LIMBS], [u64; CARRIES_PER_ADD]) {
    let (s, carries) = add3_with_carries(x, y, 0);
    debug_assert!(carries.iter().all(|&c| c <= 1), "add2 carry out of {{0,1}}");
    (s, carries)
}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}
fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(BIG_SIGMA0_ROTATIONS[0])
        ^ x.rotate_right(BIG_SIGMA0_ROTATIONS[1])
        ^ x.rotate_right(BIG_SIGMA0_ROTATIONS[2])
}
fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(BIG_SIGMA1_ROTATIONS[0])
        ^ x.rotate_right(BIG_SIGMA1_ROTATIONS[1])
        ^ x.rotate_right(BIG_SIGMA1_ROTATIONS[2])
}
fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(SMALL_SIGMA0_ROTATIONS[0])
        ^ x.rotate_right(SMALL_SIGMA0_ROTATIONS[1])
        ^ (x >> SMALL_SIGMA0_SHIFT)
}
fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(SMALL_SIGMA1_ROTATIONS[0])
        ^ x.rotate_right(SMALL_SIGMA1_ROTATIONS[1])
        ^ (x >> SMALL_SIGMA1_SHIFT)
}

/// Fill one trace row with the cells implied by `(h_in, block)`.
///
/// Internal version that operates on `[u64]` — easier to reason about
/// without field arithmetic. The public `fill_row` below converts to a
/// generic field at the end.
pub fn fill_row_u64(h_in: [u64; STATE_WORDS], block: [u64; BLOCK_WORDS], row: &mut [u64]) {
    assert_eq!(row.len(), NUM_SHA512_COLS);
    let cols: &mut Sha512Cols<u64> = row.borrow_mut();

    // ── §5.1, §4.7: H_in (packed)
    for i in 0..STATE_WORDS {
        cols.h_in[i] = to_limbs_le(h_in[i]);
    }

    // ── §4.4 / §5.3: a_chain[0..4], e_chain[0..4] = reversed initial state ─
    // a_chain[3-i] = H_in[i] for i ∈ {0..4}, so reading round-0 reads
    // a = a_chain[3] = H_0, b = a_chain[2] = H_1, c = a_chain[1] = H_2,
    // d = a_chain[0] = H_3.
    for i in 0..4 {
        cols.a_chain[3 - i] = to_bits_le(h_in[i]);
        cols.e_chain[3 - i] = to_bits_le(h_in[4 + i]);
    }

    // ── §4.6: W[0..16] from the block (bit form)
    for t in 0..BLOCK_WORDS {
        cols.w[t] = to_bits_le(block[t]);
    }

    // ── §5.4: Message-schedule extension W[16..80]
    // We track u64 values alongside the bit columns for the algorithm,
    // since rotations and adds are easier on u64s.
    let mut w_values = [0u64; NUM_COMPRESSION_ROUNDS];
    w_values[..BLOCK_WORDS].copy_from_slice(&block);

    for t in BLOCK_WORDS..NUM_COMPRESSION_ROUNDS {
        let i = t - BLOCK_WORDS;

        let s0 = small_sigma0(w_values[t - 15]);
        let s1 = small_sigma1(w_values[t - 2]);
        cols.sched_sigma0[i] = to_limbs_le(s0);
        cols.sched_sigma1[i] = to_limbs_le(s1);

        // sched_tmp = s1 + W[t - 7]   (add2)
        let (sched_tmp_limbs, sched_tmp_carries) = add2_with_carries(s1, w_values[t - 7]);
        cols.sched_tmp[i] = sched_tmp_limbs;
        cols.sched_tmp_carries[i] = sched_tmp_carries;
        let sched_tmp_value = limbs_to_u64(sched_tmp_limbs);

        // W[t] = sched_tmp + s0 + W[t - 16]   (add3); output goes to w[t] in bit form
        let (wt_limbs, w_car) = add3_with_carries(sched_tmp_value, s0, w_values[t - 16]);
        cols.w_carries[i] = w_car;
        let wt_value = limbs_to_u64(wt_limbs);
        cols.w[t] = to_bits_le(wt_value);
        w_values[t] = wt_value;
    }

    // ── §5.5: 80 compression rounds
    let mut a_values = [0u64; CHAIN_LEN];
    let mut e_values = [0u64; CHAIN_LEN];
    for i in 0..4 {
        a_values[3 - i] = h_in[i];
        e_values[3 - i] = h_in[4 + i];
    }

    for t in 0..NUM_COMPRESSION_ROUNDS {
        // Working-variable mapping per spec §4.4.
        let a = a_values[t + 3];
        let b = a_values[t + 2];
        let c = a_values[t + 1];
        let d = a_values[t];
        let e = e_values[t + 3];
        let f = e_values[t + 2];
        let g = e_values[t + 1];
        let h = e_values[t];

        // (a) Σ_1(e), (b) Ch(e, f, g)
        let s1 = big_sigma1(e);
        let ch_val = ch(e, f, g);
        cols.rounds[t].sigma1_e = to_limbs_le(s1);
        cols.rounds[t].ch = to_limbs_le(ch_val);

        // (c) tmp_1 = h + Σ_1(e) + Ch(e,f,g)
        let (tmp1_limbs, tmp1_car) = add3_with_carries(h, s1, ch_val);
        cols.rounds[t].tmp1 = tmp1_limbs;
        cols.rounds[t].tmp1_carries = tmp1_car;
        let tmp1_value = limbs_to_u64(tmp1_limbs);

        // (d) T_1 = tmp_1 + K_t + W_t
        let (t1_limbs, t1_car) = add3_with_carries(tmp1_value, SHA512_K[t], w_values[t]);
        cols.rounds[t].t1 = t1_limbs;
        cols.rounds[t].t1_carries = t1_car;
        let t1_value = limbs_to_u64(t1_limbs);

        // (e) Σ_0(a), Maj(a, b, c)
        let s0 = big_sigma0(a);
        let maj_val = maj(a, b, c);
        cols.rounds[t].sigma0_a = to_limbs_le(s0);
        cols.rounds[t].maj = to_limbs_le(maj_val);

        // (f) a' = T_1 + Σ_0(a) + Maj — output goes to a_chain[t+4] (bit view)
        let (a_prime_limbs, a_prime_car) = add3_with_carries(t1_value, s0, maj_val);
        cols.rounds[t].a_prime_carries = a_prime_car;
        let a_prime_value = limbs_to_u64(a_prime_limbs);
        cols.a_chain[t + 4] = to_bits_le(a_prime_value);
        a_values[t + 4] = a_prime_value;

        // (g) e' = d + T_1 — output goes to e_chain[t+4] (bit view)
        let (e_prime_limbs, e_prime_car) = add2_with_carries(d, t1_value);
        cols.rounds[t].e_prime_carries = e_prime_car;
        let e_prime_value = limbs_to_u64(e_prime_limbs);
        cols.e_chain[t + 4] = to_bits_le(e_prime_value);
        e_values[t + 4] = e_prime_value;
    }

    // ── §5.6: Final state addition (output H_out in bit form) ──────
    // Mapping (spec §5.6 table):
    //   H_out_0..3 from a_chain[83], a_chain[82], a_chain[81], a_chain[80]
    //   H_out_4..7 from e_chain[83], e_chain[82], e_chain[81], e_chain[80]
    for i in 0..STATE_WORDS {
        let final_var = if i < 4 {
            a_values[CHAIN_LEN - 1 - i]
        } else {
            e_values[CHAIN_LEN - 1 - (i - 4)]
        };
        let (h_out_limbs, h_out_car) = add2_with_carries(h_in[i], final_var);
        cols.h_out_carries[i] = h_out_car;
        let h_out_value = limbs_to_u64(h_out_limbs);
        cols.h_out[i] = to_bits_le(h_out_value);
    }
}

/// Fill one trace row in a generic prime field.
///
/// First runs the `u64` filler (clean separation between algorithm and
/// field conversion), then maps each cell into `F` via `from_u64`.
/// All values written are < 2^17 — fits BabyBear with margin.
pub fn fill_row<F: PrimeField64>(
    h_in: [u64; STATE_WORDS],
    block: [u64; BLOCK_WORDS],
    row: &mut [F],
) {
    assert_eq!(row.len(), NUM_SHA512_COLS);
    let mut buf = vec![0u64; NUM_SHA512_COLS];
    fill_row_u64(h_in, block, &mut buf);
    for (slot, &v) in row.iter_mut().zip(buf.iter()) {
        *slot = F::from_u64(v);
    }
}

/// Build a `RowMajorMatrix` trace for a list of compression inputs.
///
/// Length is rounded up to the next power of two (FRI requirement); the
/// padding rows repeat the first input, so every row is independently a
/// valid witness for *some* compression — the AIR has no transition
/// constraints, so this is sound.
pub fn generate_trace<F: PrimeField64>(
    inputs: &[([u64; STATE_WORDS], [u64; BLOCK_WORDS])],
) -> p3_matrix::dense::RowMajorMatrix<F> {
    assert!(
        !inputs.is_empty(),
        "generate_trace: at least one input required"
    );
    let n = inputs.len().next_power_of_two();
    let mut values = vec![F::ZERO; n * NUM_SHA512_COLS];
    for (i, (h_in, block)) in inputs.iter().enumerate() {
        let row = &mut values[i * NUM_SHA512_COLS..(i + 1) * NUM_SHA512_COLS];
        fill_row::<F>(*h_in, *block, row);
    }
    let (first_h, first_block) = inputs[0];
    for i in inputs.len()..n {
        let row = &mut values[i * NUM_SHA512_COLS..(i + 1) * NUM_SHA512_COLS];
        fill_row::<F>(first_h, first_block, row);
    }
    p3_matrix::dense::RowMajorMatrix::new(values, NUM_SHA512_COLS)
}

/// Reconstruct the 64-byte SHA-512 digest from a filled row's `H_out`
/// columns. Used by tests; not used in proving / verifying.
pub fn h_out_bytes_be(row: &[u64]) -> [u8; 64] {
    let cols: &Sha512Cols<u64> = row.borrow();
    let mut bytes = [0u8; 64];
    for i in 0..STATE_WORDS {
        let mut word: u64 = 0;
        for j in 0..WORD_BITS {
            word |= cols.h_out[i][j] << j;
        }
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    use crate::sha512_air::constants::SHA512_IV;

    /// FIPS 180-4 Appendix C.1: SHA-512("abc") expected digest.
    const SHA512_ABC_DIGEST: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];

    /// Padded "abc" as a single 1024-bit block (FIPS 180-4 Appendix C.1):
    ///   "abc" || 0x80 || zeros || (bit-length 24 in last 128 bits).
    /// Encoded as 16 × u64 big-endian-ish (W_t = block bytes interpreted big-endian).
    const ABC_BLOCK: [u64; BLOCK_WORDS] = [
        0x6162638000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000018,
    ];

    /// Padded empty string as a single 1024-bit block:
    ///   0x80 || zeros || (bit-length 0).
    const EMPTY_BLOCK: [u64; BLOCK_WORDS] = [
        0x8000000000000000,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    /// FIPS 180-4 Appendix C.2 / NIST: SHA-512("") expected digest.
    const SHA512_EMPTY_DIGEST: [u8; 64] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80,
        0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
        0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
        0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e,
    ];

    /// The row generator's `H_out` reproduces the FIPS 180-4 digest for
    /// SHA-512("abc"). If any column wiring is wrong (chain reverse,
    /// limb ordering, carry propagation, σ/Σ rotations) this fails.
    #[test]
    fn fill_row_matches_fips_for_abc() {
        let mut row = vec![0u64; NUM_SHA512_COLS];
        fill_row_u64(SHA512_IV, ABC_BLOCK, &mut row);
        let digest = h_out_bytes_be(&row);
        assert_eq!(digest, SHA512_ABC_DIGEST, "digest mismatch on \"abc\"");
    }

    /// Same check for SHA-512(""). Different bit pattern in W and
    /// different carry behavior — orthogonal sanity check.
    #[test]
    fn fill_row_matches_fips_for_empty() {
        let mut row = vec![0u64; NUM_SHA512_COLS];
        fill_row_u64(SHA512_IV, EMPTY_BLOCK, &mut row);
        let digest = h_out_bytes_be(&row);
        assert_eq!(digest, SHA512_EMPTY_DIGEST, "digest mismatch on \"\"");
    }

    /// Verify the reverse-initial-state convention: after fill, reading
    /// `a_chain[t+3]` for `t=0` should give `H_in[0]`, etc.
    #[test]
    fn round_zero_working_vars_equal_initial_state() {
        let mut row = vec![0u64; NUM_SHA512_COLS];
        fill_row_u64(SHA512_IV, ABC_BLOCK, &mut row);
        let cols: &Sha512Cols<u64> = <[u64] as core::borrow::Borrow<Sha512Cols<u64>>>::borrow(&row);

        for i in 0..4 {
            // a_chain[3-i] (bit form) should equal H_in[i] (bit form).
            let bits = &cols.a_chain[3 - i];
            let mut reconstructed: u64 = 0;
            for j in 0..WORD_BITS {
                reconstructed |= bits[j] << j;
            }
            assert_eq!(
                reconstructed,
                SHA512_IV[i],
                "a_chain[{}] bits do not reconstruct H_in[{}]",
                3 - i,
                i
            );

            let bits = &cols.e_chain[3 - i];
            let mut reconstructed: u64 = 0;
            for j in 0..WORD_BITS {
                reconstructed |= bits[j] << j;
            }
            assert_eq!(
                reconstructed,
                SHA512_IV[4 + i],
                "e_chain[{}] bits do not reconstruct H_in[{}]",
                3 - i,
                4 + i
            );
        }
    }

    /// Carries are in the expected ranges — 3-input adds in {0,1,2},
    /// 2-input adds in {0,1}. If any carry escapes its range, the AIR's
    /// add-type-specific constraint (cubic for add3, boolean for add2)
    /// would silently disagree with the witness.
    #[test]
    fn all_carries_in_expected_range() {
        let mut row = vec![0u64; NUM_SHA512_COLS];
        fill_row_u64(SHA512_IV, ABC_BLOCK, &mut row);
        let cols: &Sha512Cols<u64> = <[u64] as core::borrow::Borrow<Sha512Cols<u64>>>::borrow(&row);

        // Per round: tmp1, t1, a_prime are add3 (carries in {0,1,2});
        //            e_prime is add2 (carries in {0,1}).
        for (t, r) in cols.rounds.iter().enumerate() {
            for &c in r.tmp1_carries.iter() {
                assert!(c <= 2, "round {t} tmp1 carry {c} out of {{0,1,2}}");
            }
            for &c in r.t1_carries.iter() {
                assert!(c <= 2, "round {t} t1 carry {c} out of {{0,1,2}}");
            }
            for &c in r.a_prime_carries.iter() {
                assert!(c <= 2, "round {t} a' carry {c} out of {{0,1,2}}");
            }
            for &c in r.e_prime_carries.iter() {
                assert!(c <= 1, "round {t} e' carry {c} out of {{0,1}}");
            }
        }
        // Schedule: sched_tmp is add2, w is add3.
        for i in 0..cols.sched_tmp_carries.len() {
            for &c in cols.sched_tmp_carries[i].iter() {
                assert!(c <= 1, "sched_tmp[{i}] carry {c} out of {{0,1}}");
            }
            for &c in cols.w_carries[i].iter() {
                assert!(c <= 2, "w[{i}] carry {c} out of {{0,1,2}}");
            }
        }
        // Final state: add2.
        for i in 0..cols.h_out_carries.len() {
            for &c in cols.h_out_carries[i].iter() {
                assert!(c <= 1, "h_out[{i}] carry {c} out of {{0,1}}");
            }
        }
    }

    /// Field-typed version of the digest test: fill a BabyBear-typed row
    /// and decode H_out back to bytes, compare to the FIPS vector.
    /// Validates the `from_u64` conversion path.
    #[test]
    fn fill_row_field_typed_matches_fips_for_abc() {
        let mut row = vec![BabyBear::ZERO; NUM_SHA512_COLS];
        fill_row::<BabyBear>(SHA512_IV, ABC_BLOCK, &mut row);

        // Convert back to u64 column-by-column.
        let row_u64: Vec<u64> = row.iter().map(|f| f.as_canonical_u32() as u64).collect();
        let digest = h_out_bytes_be(&row_u64);
        assert_eq!(digest, SHA512_ABC_DIGEST);
    }
}
