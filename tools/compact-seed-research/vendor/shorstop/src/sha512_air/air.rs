//! AIR constraints for the SHA-512 compression function.
//!
//! Independent implementation from `docs/sha512-spec.md` §5 (constraint
//! groups by algorithm phase) and §6 (modular-add encoding). Not a port of
//! any reference; cross-checked against PR #1563 and Binius64 in
//! `docs/sha512-reference-comparison.md`.
//!
//! Layout: each row encodes one full SHA-512 compression. All constraints
//! are intra-row — no transitions. Constraint-degree budget is ≤ 3
//! (matches Plonky3 convention); the carry cubic in `assert_add3` and the
//! XOR3 of bits in σ/Σ are the degree-3 hot spots.

use core::borrow::Borrow;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::sha512_air::columns::{
    Sha512Cols, Sha512PreprocessedCols, CARRIES_PER_ADD, NUM_SHA512_COLS,
    NUM_SHA512_PREPROCESSED_COLS,
};
use crate::sha512_air::constants::{
    BIG_SIGMA0_ROTATIONS, BIG_SIGMA1_ROTATIONS, BITS_PER_LIMB, BLOCK_WORDS, CHAIN_LEN,
    NUM_COMPRESSION_ROUNDS, SCHEDULE_EXTENSIONS, SHA512_COMPRESSIONS_BUS_NAME, SHA512_K,
    SMALL_SIGMA0_ROTATIONS, SMALL_SIGMA0_SHIFT, SMALL_SIGMA1_ROTATIONS, SMALL_SIGMA1_SHIFT,
    STATE_WORDS, U64_LIMBS, WORD_BITS,
};

/// AIR for the SHA-512 compression. Stateful so the `LookupAir` extension
/// (added in pipeline-spec.md §5.6) can size its `is_real_compression_row`
/// preprocessed selector to the trace's effective length.
///
/// `num_real_rows` is the number of rows in the main trace that hold real
/// SHA-512 compressions; the trace is then padded up to the next power of
/// two with copies of the row-0 input (see [`crate::sha512_air::generation`]).
/// The padding rows are functionally valid (the AIR has no transition
/// constraints) but must not be sent on the `sha512_compressions` LogUp bus
/// — the preprocessed selector is what gates that.
///
/// For the standalone single-table flow (`prove`/`verify` from
/// `p3-uni-stark`, which ignores `LookupAir` entirely), `num_real_rows` is
/// unused. Use `Sha512Air::default()` in that path.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha512Air {
    /// Number of real (non-padding) compression rows in the trace. Set
    /// at AIR-instantiation time so the preprocessed-trace selector
    /// pattern is deterministic from the row index.
    pub num_real_rows: usize,
}

impl Sha512Air {
    /// Construct a `Sha512Air` with the effective real-row count. Use
    /// this in the batched (`prove_batch`) flow where the LogUp bus is
    /// engaged. For standalone `prove`/`verify`, `Sha512Air::default()`
    /// is equivalent.
    pub const fn new(num_real_rows: usize) -> Self {
        Self { num_real_rows }
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Sha512Air {
    fn width(&self) -> usize {
        NUM_SHA512_COLS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        // Standalone path (`prove`/`verify` from p3-uni-stark) constructs
        // `Sha512Air::default()` (`num_real_rows = 0`) and ignores
        // `LookupAir`. Returning `None` here keeps that flow byte-identical
        // to the pre-LookupAir behavior.
        if self.num_real_rows == 0 {
            return None;
        }
        // Batched flow: trace generator pads `num_real_rows` to the next
        // power of two with copies of the row-0 input
        // (see `crate::sha512_air::generation::generate_trace`). The
        // selector mirrors that pattern: 1 for the original rows, 0 for
        // the padding tail. Multiset equality on the bus then ignores
        // the padding rows (`docs/pipeline-spec.md` §5.7).
        let padded_height = self.num_real_rows.next_power_of_two();
        let mut values = vec![F::ZERO; padded_height * NUM_SHA512_PREPROCESSED_COLS];
        for row_index in 0..self.num_real_rows {
            values[row_index * NUM_SHA512_PREPROCESSED_COLS] = F::ONE;
        }
        Some(RowMajorMatrix::new(values, NUM_SHA512_PREPROCESSED_COLS))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder> Air<AB> for Sha512Air
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Sha512Cols<AB::Var> = (*main.current_slice()).borrow();

        eval_booleans(builder, local);
        eval_initial_state(builder, local);
        eval_message_schedule(builder, local);
        eval_compression(builder, local);
        eval_finalization(builder, local);
    }
}

/// `Σ 2^j · bits[k * BITS_PER_LIMB + j]` — packs 16 bits into one 16-bit limb.
fn pack_limb_from_bits<AB: AirBuilder>(bits: &[AB::Var; WORD_BITS], k: usize) -> AB::Expr {
    let mut acc: AB::Expr = AB::Expr::ZERO;
    for j in 0..BITS_PER_LIMB {
        let pow = AB::Expr::from_u32(1u32 << j);
        let bit_expr: AB::Expr = bits[k * BITS_PER_LIMB + j].into();
        acc = acc + pow * bit_expr;
    }
    acc
}

/// Pack a 64-bit value's 64 bit-columns into 4 × 16-bit limb expressions.
fn pack_word<AB: AirBuilder>(bits: &[AB::Var; WORD_BITS]) -> [AB::Expr; U64_LIMBS] {
    core::array::from_fn(|k| pack_limb_from_bits::<AB>(bits, k))
}

/// Convert a packed-column array (4 committed `Var`s) into 4 `Expr`s.
fn packed_to_expr<AB: AirBuilder>(p: &[AB::Var; U64_LIMBS]) -> [AB::Expr; U64_LIMBS] {
    core::array::from_fn(|k| p[k].into())
}

/// Pack 16 per-bit polynomial expressions (one per output bit position
/// in the 16-bit limb range) into one limb expression.
fn pack_limb_from_bit_exprs<AB: AirBuilder>(
    k: usize,
    bit_fn: &impl Fn(usize) -> AB::Expr,
) -> AB::Expr {
    let mut acc: AB::Expr = AB::Expr::ZERO;
    for j in 0..BITS_PER_LIMB {
        let pow = AB::Expr::from_u32(1u32 << j);
        acc = acc + pow * bit_fn(k * BITS_PER_LIMB + j);
    }
    acc
}

/// XOR of three booleans: `a + b + c − 2(ab + ac + bc) + 4abc`. Degree 3.
fn xor3_expr<AB: AirBuilder>(a: AB::Expr, b: AB::Expr, c: AB::Expr) -> AB::Expr {
    let two: AB::Expr = AB::Expr::TWO;
    let four: AB::Expr = AB::Expr::from_u32(4);
    let ab = a.clone() * b.clone();
    let ac = a.clone() * c.clone();
    let bc = b.clone() * c.clone();
    let abc = ab.clone() * c.clone();
    a + b + c - two * (ab + ac + bc) + four * abc
}

/// `Σ` (big-sigma) per-bit polynomial: XOR of three rotations.
fn big_sigma_bit_at<AB: AirBuilder>(
    bits: &[AB::Var; WORD_BITS],
    i: usize,
    rots: [u32; 3],
) -> AB::Expr {
    xor3_expr::<AB>(
        bits[(i + rots[0] as usize) % WORD_BITS].into(),
        bits[(i + rots[1] as usize) % WORD_BITS].into(),
        bits[(i + rots[2] as usize) % WORD_BITS].into(),
    )
}

/// `σ` (small-sigma) per-bit polynomial: ROTR ⊕ ROTR ⊕ SHR.
/// `SHR^k` returns 0 for bit positions `i + k ≥ 64`.
fn small_sigma_bit_at<AB: AirBuilder>(
    bits: &[AB::Var; WORD_BITS],
    i: usize,
    rots: [u32; 2],
    shift: u32,
) -> AB::Expr {
    let r1: AB::Expr = bits[(i + rots[0] as usize) % WORD_BITS].into();
    let r2: AB::Expr = bits[(i + rots[1] as usize) % WORD_BITS].into();
    let shr: AB::Expr = if i + shift as usize >= WORD_BITS {
        AB::Expr::ZERO
    } else {
        bits[i + shift as usize].into()
    };
    xor3_expr::<AB>(r1, r2, shr)
}

/// `sum ≡ x + y + z (mod 2^64)`. Per-limb sum with explicit carries on
/// limbs 0..2; top-limb carry implicit via diff-cubic.
fn assert_add3<AB: AirBuilder>(
    builder: &mut AB,
    x: &[AB::Expr; U64_LIMBS],
    y: &[AB::Expr; U64_LIMBS],
    z: &[AB::Expr; U64_LIMBS],
    sum: &[AB::Expr; U64_LIMBS],
    carries: &[AB::Var; CARRIES_PER_ADD],
) {
    let two_16 = AB::Expr::from_u32(1u32 << 16);
    let two_17 = two_16.clone() + two_16.clone();

    let mut c_in: AB::Expr = AB::Expr::ZERO;
    for k in 0..U64_LIMBS {
        let lhs = x[k].clone() + y[k].clone() + z[k].clone() + c_in.clone();
        if k < CARRIES_PER_ADD {
            let c_out: AB::Expr = carries[k].into();
            // x_k + y_k + z_k + c_in − sum_k − 2^16 · c_out = 0
            builder.assert_zero(lhs - sum[k].clone() - two_16.clone() * c_out.clone());
            c_in = c_out;
        } else {
            // Top limb (k=3): no committed carry. Force diff_3 ∈ {0, 2^16, 2·2^16}.
            let diff = lhs - sum[k].clone();
            builder.assert_zero(
                diff.clone() * (diff.clone() - two_16.clone()) * (diff - two_17.clone()),
            );
        }
    }
}

/// `sum ≡ x + y (mod 2^64)`. Carries `∈ {0, 1}` (boolean range, separately
/// asserted in `eval_booleans`).
fn assert_add2<AB: AirBuilder>(
    builder: &mut AB,
    x: &[AB::Expr; U64_LIMBS],
    y: &[AB::Expr; U64_LIMBS],
    sum: &[AB::Expr; U64_LIMBS],
    carries: &[AB::Var; CARRIES_PER_ADD],
) {
    let two_16 = AB::Expr::from_u32(1u32 << 16);

    let mut c_in: AB::Expr = AB::Expr::ZERO;
    for k in 0..U64_LIMBS {
        let lhs = x[k].clone() + y[k].clone() + c_in.clone();
        if k < CARRIES_PER_ADD {
            let c_out: AB::Expr = carries[k].into();
            builder.assert_zero(lhs - sum[k].clone() - two_16.clone() * c_out.clone());
            c_in = c_out;
        } else {
            // Top-limb diff ∈ {0, 2^16}.
            let diff = lhs - sum[k].clone();
            builder.assert_zero(diff.clone() * (diff - two_16.clone()));
        }
    }
}

fn eval_booleans<AB: AirBuilder>(builder: &mut AB, local: &Sha512Cols<AB::Var>) {
    // Bit columns: a_chain, e_chain, w, h_out
    for chain in [&local.a_chain, &local.e_chain] {
        for entry in chain.iter() {
            for &bit in entry.iter() {
                builder.assert_bool(bit);
            }
        }
    }
    for entry in local.w.iter() {
        for &bit in entry.iter() {
            builder.assert_bool(bit);
        }
    }
    for entry in local.h_out.iter() {
        for &bit in entry.iter() {
            builder.assert_bool(bit);
        }
    }

    // add2 carries (boolean): h_out, sched_tmp, e_prime
    for entry in local.h_out_carries.iter() {
        for &c in entry.iter() {
            builder.assert_bool(c);
        }
    }
    for entry in local.sched_tmp_carries.iter() {
        for &c in entry.iter() {
            builder.assert_bool(c);
        }
    }
    for round in local.rounds.iter() {
        for &c in round.e_prime_carries.iter() {
            builder.assert_bool(c);
        }
    }

    // add3 carries (cubic c·(c−1)·(c−2) = 0): tmp1, t1, a_prime, w
    for entry in local.w_carries.iter() {
        for &c in entry.iter() {
            assert_in_0_1_2::<AB>(builder, c);
        }
    }
    for round in local.rounds.iter() {
        for &c in round.tmp1_carries.iter() {
            assert_in_0_1_2::<AB>(builder, c);
        }
        for &c in round.t1_carries.iter() {
            assert_in_0_1_2::<AB>(builder, c);
        }
        for &c in round.a_prime_carries.iter() {
            assert_in_0_1_2::<AB>(builder, c);
        }
    }
}

fn assert_in_0_1_2<AB: AirBuilder>(builder: &mut AB, c: AB::Var) {
    let c_expr: AB::Expr = c.into();
    let one = AB::Expr::ONE;
    let two = AB::Expr::TWO;
    builder.assert_zero(c_expr.clone() * (c_expr.clone() - one) * (c_expr - two));
}

fn eval_initial_state<AB: AirBuilder>(builder: &mut AB, local: &Sha512Cols<AB::Var>) {
    // a_chain[3 - i] (bit form) = H_in[i] (packed) for i ∈ {0, 1, 2, 3}.
    for i in 0..4 {
        let chain_bits = &local.a_chain[3 - i];
        for k in 0..U64_LIMBS {
            let h_packed: AB::Expr = local.h_in[i][k].into();
            let chain_packed = pack_limb_from_bits::<AB>(chain_bits, k);
            builder.assert_zero(h_packed - chain_packed);
        }
    }
    // e_chain[3 - i] (bit form) = H_in[4 + i] (packed) for i ∈ {0, 1, 2, 3}.
    for i in 0..4 {
        let chain_bits = &local.e_chain[3 - i];
        for k in 0..U64_LIMBS {
            let h_packed: AB::Expr = local.h_in[4 + i][k].into();
            let chain_packed = pack_limb_from_bits::<AB>(chain_bits, k);
            builder.assert_zero(h_packed - chain_packed);
        }
    }
}

fn eval_message_schedule<AB: AirBuilder>(builder: &mut AB, local: &Sha512Cols<AB::Var>) {
    for i in 0..SCHEDULE_EXTENSIONS {
        let t = i + BLOCK_WORDS;

        // (a) σ_0(W_{t-15}) packed equals polynomial in W_{t-15} bits.
        let w_t_15 = &local.w[t - 15];
        for k in 0..U64_LIMBS {
            let expected = pack_limb_from_bit_exprs::<AB>(k, &|bit_i| {
                small_sigma_bit_at::<AB>(w_t_15, bit_i, SMALL_SIGMA0_ROTATIONS, SMALL_SIGMA0_SHIFT)
            });
            let committed: AB::Expr = local.sched_sigma0[i][k].into();
            builder.assert_zero(committed - expected);
        }

        // (b) σ_1(W_{t-2}) packed equals polynomial in W_{t-2} bits.
        let w_t_2 = &local.w[t - 2];
        for k in 0..U64_LIMBS {
            let expected = pack_limb_from_bit_exprs::<AB>(k, &|bit_i| {
                small_sigma_bit_at::<AB>(w_t_2, bit_i, SMALL_SIGMA1_ROTATIONS, SMALL_SIGMA1_SHIFT)
            });
            let committed: AB::Expr = local.sched_sigma1[i][k].into();
            builder.assert_zero(committed - expected);
        }

        // (c) sched_tmp = σ_1(W_{t-2}) + W_{t-7}  (add2)
        let sigma1 = packed_to_expr::<AB>(&local.sched_sigma1[i]);
        let w_t_7 = pack_word::<AB>(&local.w[t - 7]);
        let sched_tmp = packed_to_expr::<AB>(&local.sched_tmp[i]);
        assert_add2::<AB>(
            builder,
            &sigma1,
            &w_t_7,
            &sched_tmp,
            &local.sched_tmp_carries[i],
        );

        // (d) W_t = sched_tmp + σ_0(W_{t-15}) + W_{t-16}  (add3)
        let sigma0 = packed_to_expr::<AB>(&local.sched_sigma0[i]);
        let w_t_16 = pack_word::<AB>(&local.w[t - 16]);
        let w_t = pack_word::<AB>(&local.w[t]);
        assert_add3::<AB>(
            builder,
            &sched_tmp,
            &sigma0,
            &w_t_16,
            &w_t,
            &local.w_carries[i],
        );
    }
}

fn eval_compression<AB: AirBuilder>(builder: &mut AB, local: &Sha512Cols<AB::Var>) {
    for t in 0..NUM_COMPRESSION_ROUNDS {
        let round = &local.rounds[t];

        // Working-variable bit slices, per §4.4.
        let a_bits = &local.a_chain[t + 3];
        let b_bits = &local.a_chain[t + 2];
        let c_bits = &local.a_chain[t + 1];
        let d_bits = &local.a_chain[t];
        let e_bits = &local.e_chain[t + 3];
        let f_bits = &local.e_chain[t + 2];
        let g_bits = &local.e_chain[t + 1];
        let h_bits = &local.e_chain[t];

        // (a) Σ_1(e) packed.
        for k in 0..U64_LIMBS {
            let expected = pack_limb_from_bit_exprs::<AB>(k, &|bit_i| {
                big_sigma_bit_at::<AB>(e_bits, bit_i, BIG_SIGMA1_ROTATIONS)
            });
            let committed: AB::Expr = round.sigma1_e[k].into();
            builder.assert_zero(committed - expected);
        }

        // (b) Ch(e, f, g) packed. Per-bit: ch_i = e·f + (1−e)·g  =  e·f + g − e·g. Degree 2.
        for k in 0..U64_LIMBS {
            let expected = pack_limb_from_bit_exprs::<AB>(k, &|bit_i| {
                let e: AB::Expr = e_bits[bit_i].into();
                let f: AB::Expr = f_bits[bit_i].into();
                let g: AB::Expr = g_bits[bit_i].into();
                e.clone() * f - e * g.clone() + g
            });
            let committed: AB::Expr = round.ch[k].into();
            builder.assert_zero(committed - expected);
        }

        // (c) tmp_1 = h + Σ_1(e) + Ch  (add3)
        let h_packed = pack_word::<AB>(h_bits);
        let sigma1_e = packed_to_expr::<AB>(&round.sigma1_e);
        let ch = packed_to_expr::<AB>(&round.ch);
        let tmp1 = packed_to_expr::<AB>(&round.tmp1);
        assert_add3::<AB>(
            builder,
            &h_packed,
            &sigma1_e,
            &ch,
            &tmp1,
            &round.tmp1_carries,
        );

        // (d) T_1 = tmp_1 + K_t + W_t  (add3). K_t is a constant.
        let k_packed: [AB::Expr; U64_LIMBS] = core::array::from_fn(|limb_idx| {
            let limb = (SHA512_K[t] >> (16 * limb_idx)) & 0xFFFF;
            AB::Expr::from_u32(limb as u32)
        });
        let w_t = pack_word::<AB>(&local.w[t]);
        let t1 = packed_to_expr::<AB>(&round.t1);
        assert_add3::<AB>(builder, &tmp1, &k_packed, &w_t, &t1, &round.t1_carries);

        // (e) Σ_0(a) packed.
        for k in 0..U64_LIMBS {
            let expected = pack_limb_from_bit_exprs::<AB>(k, &|bit_i| {
                big_sigma_bit_at::<AB>(a_bits, bit_i, BIG_SIGMA0_ROTATIONS)
            });
            let committed: AB::Expr = round.sigma0_a[k].into();
            builder.assert_zero(committed - expected);
        }

        // (f) Maj(a, b, c) packed. Per-bit: maj_i = ab + ac + bc − 2abc. Degree 3.
        for k in 0..U64_LIMBS {
            let expected = pack_limb_from_bit_exprs::<AB>(k, &|bit_i| {
                let a: AB::Expr = a_bits[bit_i].into();
                let b: AB::Expr = b_bits[bit_i].into();
                let c: AB::Expr = c_bits[bit_i].into();
                let ab = a.clone() * b.clone();
                let ac = a.clone() * c.clone();
                let bc = b.clone() * c.clone();
                let abc = ab.clone() * c.clone();
                let two = AB::Expr::TWO;
                ab + ac + bc - two * abc
            });
            let committed: AB::Expr = round.maj[k].into();
            builder.assert_zero(committed - expected);
        }

        // (g) a' = T_1 + Σ_0(a) + Maj  (add3); output is `pack_word(a_chain[t+4])`.
        let sigma0_a = packed_to_expr::<AB>(&round.sigma0_a);
        let maj = packed_to_expr::<AB>(&round.maj);
        let a_prime = pack_word::<AB>(&local.a_chain[t + 4]);
        assert_add3::<AB>(
            builder,
            &t1,
            &sigma0_a,
            &maj,
            &a_prime,
            &round.a_prime_carries,
        );

        // (h) e' = d + T_1  (add2); output is `pack_word(e_chain[t+4])`.
        let d_packed = pack_word::<AB>(d_bits);
        let e_prime = pack_word::<AB>(&local.e_chain[t + 4]);
        assert_add2::<AB>(builder, &d_packed, &t1, &e_prime, &round.e_prime_carries);
    }
}

fn eval_finalization<AB: AirBuilder>(builder: &mut AB, local: &Sha512Cols<AB::Var>) {
    for i in 0..STATE_WORDS {
        // Final-var location per spec §5.6.
        let final_bits = if i < 4 {
            &local.a_chain[CHAIN_LEN - 1 - i]
        } else {
            &local.e_chain[CHAIN_LEN - 1 - (i - 4)]
        };
        let h_in = packed_to_expr::<AB>(&local.h_in[i]);
        let final_packed = pack_word::<AB>(final_bits);
        let h_out = pack_word::<AB>(&local.h_out[i]);
        assert_add2::<AB>(
            builder,
            &h_in,
            &final_packed,
            &h_out,
            &local.h_out_carries[i],
        );
    }
}

// ── LogUp `sha512_compressions` bus ────────────────────────────────────
//
// Per `docs/pipeline-spec.md` §5: the SHA-512 AIR is the sole **sender**
// on a global LogUp bus named `sha512_compressions`; wrapper AIRs
// (HMAC instances) **receive** to enforce that every claimed
// compression has a matching SHA-512 row.
//
// The transition constraint emitted by `p3-lookup`'s `LogUpGadget` is
//
//   when_transition: (s_next - s_local) * ∏_i (α - combined_elt[i]) - num = 0
//
// where the product runs over OUTER ENTRIES of the Lookup. With one
// outer entry whose inner tuple has 128 elements, β-Horner inside the
// gadget collapses the tuple to a single field-element value
// (`p3_lookup::logup::combine_elements`, deg 1 in committed cells).
// The constraint stays at degree 3 regardless of tuple size — see the
// degree analysis in `ed25519_air/air.rs` and `pipeline-spec.md` §5.1.

impl<F: Field> LookupAir<F> for Sha512Air {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        // Sha512Air owns no lookup-allocation counter (only one Lookup
        // per row). Always allocates index 0; the Lookup gadget
        // namespaces this index per AIR within `prove_batch`.
        vec![0]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        // Build symbolic references to the main and preprocessed traces.
        // The `Borrow` impls give a typed view over each row; the cell
        // type is the symbolic builder's column variable (convertible
        // to `SymbolicExpression<F>` via `Into`).
        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_SHA512_COLS,
            preprocessed_width: NUM_SHA512_PREPROCESSED_COLS,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &Sha512Cols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &Sha512PreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();

        // Flatten this row's witness cells into the slice shapes the
        // shared `compression_tuple` helper expects (see
        // `hmac_air::helpers` for the canonical order). Going through
        // the helper guarantees sender and every receiver build the
        // bus-tuple in lockstep — drift is the §13.5 endianness-
        // mismatch failure mode.
        let mut h_in_limbs: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(STATE_WORDS * U64_LIMBS);
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                h_in_limbs.push(main_local.h_in[word_index][limb_index].into());
            }
        }
        let mut block_bits: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(BLOCK_WORDS * WORD_BITS);
        for block_word_index in 0..BLOCK_WORDS {
            for bit_index in 0..WORD_BITS {
                block_bits.push(main_local.w[block_word_index][bit_index].into());
            }
        }
        let mut h_out_bits: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(STATE_WORDS * WORD_BITS);
        for state_word_index in 0..STATE_WORDS {
            for bit_index in 0..WORD_BITS {
                h_out_bits.push(main_local.h_out[state_word_index][bit_index].into());
            }
        }
        let tuple = crate::hmac_air::helpers::compression_tuple::<F>(
            &h_in_limbs,
            &block_bits,
            &h_out_bits,
        );

        // Multiplicity = preprocessed `is_real_compression_row` selector
        // (1 on real rows, 0 on padding). Padding rows are functionally
        // valid compressions but must not appear on the bus
        // (pipeline-spec.md §5.7).
        let multiplicity: SymbolicExpression<F> =
            preprocessed_local.is_real_compression_row.into();

        let lookup_inputs: [(Vec<SymbolicExpression<F>>, SymbolicExpression<F>, Direction); 1] =
            [(tuple, multiplicity, Direction::Send)];

        let lookup = LookupAir::register_lookup(
            self,
            Kind::Global(SHA512_COMPRESSIONS_BUS_NAME.to_string()),
            &lookup_inputs,
        );
        vec![lookup]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;

    use crate::sha512_air::constants::{NUM_SHA512_TUPLE_LIMBS, SHA512_IV};
    use crate::sha512_air::generation::fill_row;

    /// FIPS 180-4 padded "abc" block (1024 bits, big-endian-encoded).
    const ABC_BLOCK: [u64; BLOCK_WORDS] = [
        0x6162638000000000,
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
        0x0000000000000018,
    ];

    /// Padded empty string.
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

    /// Build a minimal-height (one-row) BabyBear trace for the given inputs.
    fn make_trace(h_in: [u64; STATE_WORDS], block: [u64; BLOCK_WORDS]) -> RowMajorMatrix<BabyBear> {
        let mut row = vec![BabyBear::ZERO; NUM_SHA512_COLS];
        fill_row::<BabyBear>(h_in, block, &mut row);
        // p3_uni_stark requires a power-of-two row count; pad by repeating
        // the same valid row (the AIR has no transition constraints, so
        // each row is independently valid).
        let mut all = row.clone();
        all.extend(row);
        RowMajorMatrix::new(all, NUM_SHA512_COLS)
    }

    /// Run `p3_uni_stark::check_constraints` against a fresh trace and
    /// assert no constraint fires. The "constraints accept the honest
    /// witness" smoke test for this module.
    fn assert_constraints_accept(trace: RowMajorMatrix<BabyBear>) {
        check_constraints(&Sha512Air::default(), &trace, &[]);
    }

    #[test]
    fn constraints_accept_abc_witness() {
        let trace = make_trace(SHA512_IV, ABC_BLOCK);
        assert_constraints_accept(trace);
    }

    #[test]
    fn constraints_accept_witness_empty_message() {
        let trace = make_trace(SHA512_IV, EMPTY_BLOCK);
        assert_constraints_accept(trace);
    }

    /// Make sure the trace size matches the column count expectation.
    /// A drift between `NUM_SHA512_COLS` and `make_trace`'s row width
    /// would cause `check_constraints` to either panic or silently pass
    /// nonsense.
    #[test]
    fn trace_width_equals_num_cols() {
        let trace = make_trace(SHA512_IV, EMPTY_BLOCK);
        assert_eq!(trace.width(), NUM_SHA512_COLS);
        assert_eq!(trace.height(), 2); // two rows after pad
    }

    /// Default `Sha512Air` (`num_real_rows = 0`) returns no preprocessed
    /// trace — preserves the standalone p3-uni-stark flow byte-for-byte.
    #[test]
    fn preprocessed_trace_is_none_for_default() {
        let air = Sha512Air::default();
        assert!(<Sha512Air as BaseAir<BabyBear>>::preprocessed_trace(&air).is_none());
    }

    /// `Sha512Air::new(n)` produces a 1-column preprocessed trace of
    /// height `next_power_of_two(n)`, with 1 in the first `n` rows and
    /// 0 in the padding tail. This is the §5.7 selector that gates
    /// LogUp sends so padding rows do not appear on the bus.
    #[test]
    fn preprocessed_selector_matches_real_row_count() {
        for &num_real in &[1usize, 2, 3, 5, 7, 8, 13, 16] {
            let air = Sha512Air::new(num_real);
            let trace = <Sha512Air as BaseAir<BabyBear>>::preprocessed_trace(&air)
                .expect("Sha512Air::new(>0) must return Some");
            let expected_height = num_real.next_power_of_two();
            assert_eq!(trace.height(), expected_height, "n={num_real}");
            assert_eq!(trace.width(), NUM_SHA512_PREPROCESSED_COLS);
            for row_index in 0..expected_height {
                let cell = trace.values[row_index * NUM_SHA512_PREPROCESSED_COLS];
                let expected = if row_index < num_real {
                    BabyBear::ONE
                } else {
                    BabyBear::ZERO
                };
                assert_eq!(cell, expected, "n={num_real}, row={row_index}");
            }
        }
    }

    /// Pin the §5.4 canonical-tuple length. The constraint-degree
    /// argument and the receiver-side soundness analysis all hinge on
    /// the tuple having exactly 128 elements (32 h_in + 64 block + 32
    /// h_out). Drift here is a silent break of LogUp multiset equality.
    #[test]
    fn lookup_tuple_length_is_128() {
        let mut air = Sha512Air::default();
        let lookups = <Sha512Air as LookupAir<BabyBear>>::get_lookups(&mut air);
        assert_eq!(lookups.len(), 1, "Sha512Air must register exactly one Lookup");
        let lookup = &lookups[0];
        // One outer entry (the canonical compression tuple).
        assert_eq!(lookup.element_exprs.len(), 1, "exactly one outer entry");
        // 128 limbs in the inner tuple — the binding contract of §5.4.
        assert_eq!(
            lookup.element_exprs[0].len(),
            NUM_SHA512_TUPLE_LIMBS,
            "inner tuple must be 128 elements (32 h_in + 64 block + 32 h_out)"
        );
        // The bus name must match the canonical constant; receivers
        // pair on this exact string.
        match &lookup.kind {
            p3_lookup::lookup_traits::Kind::Global(name) => {
                assert_eq!(name, SHA512_COMPRESSIONS_BUS_NAME);
            }
            other => panic!("expected Global bus, got {other:?}"),
        }
    }
}
