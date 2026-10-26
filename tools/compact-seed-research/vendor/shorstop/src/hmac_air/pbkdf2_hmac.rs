//! `Pbkdf2HmacAir` — the per-compression layer of PBKDF2-HMAC-SHA512.
//! Spec source: `docs/pipeline-spec.md` §6.3.2.
//!
//! For PBKDF2 with iteration count `c` and PRF = HMAC-SHA512:
//!
//!   U_1 = HMAC(K, salt || INT(1))            (1 inner + 1 outer compression)
//!   U_i = HMAC(K, U_{i-1})       i = 2..c    (1 inner + 1 outer compression)
//!   T   = U_1 ⊕ U_2 ⊕ … ⊕ U_c                (XOR fold — orchestrator's job)
//!
//! Each HMAC iteration costs **two** SHA-512 compressions (inner +
//! outer) — the keyschedule already pre-computed `ipad_state` and
//! `opad_state` (one compression each), so each HMAC body is just
//! `SHA-512_compress(ipad_state, padded_msg)` followed by
//! `SHA-512_compress(opad_state, padded_inner_digest)`. Total: `2c`
//! rows in this AIR.
//!
//! Trace shape (`2 * num_iterations` rows, no padding):
//!
//!   row 0: i=0, role=inner, msg = salt || INT(1)        (12 bytes)
//!   row 1: i=0, role=outer, msg = h_out of row 0        (64 bytes)
//!   row 2: i=1, role=inner, msg = h_out of row 1 = U_1  (64 bytes)
//!   row 3: i=1, role=outer, msg = h_out of row 2        (64 bytes)
//!   ...
//!   row 2c-1: i=c-1, role=outer, msg = h_out of row 2c-2 (64 bytes)
//!
//! Per-row committed columns (~1024 cells; `h_in_packed` is NOT
//! committed — we reference the `ipad_state` / `opad_state` PV
//! inputs directly in the LogUp tuples, saving 32 cells/row × 4096
//! rows ≈ 130k cells of RAM. Documented deviation from spec §6.3.2's
//! "h_in_packed: 32" entry):
//!
//!   - `msg_bits`:    512 bits in **byte-flat** layout (64 bytes max).
//!     For row 0 only the first 96 bits hold the salt+INT(1) message;
//!     bits [96, 512) are constrained to zero by the boundary.
//!   - `h_out_bits`:  512 bits in **word-flat** layout matching
//!     `Sha512Cols::h_out`.
//!
//! Per-row preprocessed columns (3 cells):
//!
//!   - `role`:           0 = inner, 1 = outer (alternating).
//!   - `is_first_inner`: 1 only on row 0, gates the first-iter Lookup.
//!   - `iter_index`:     0..num_iterations-1, repeated 2× (inner then
//!     outer of iteration `k` both carry value `k`). Reserved for the
//!     `pbkdf2_outputs` bus that Phase 3's orchestrator will receive on.
//!
//! Public values (64): `[ipad_state_packed (32) || opad_state_packed (32)]`
//! — same shape and order as `HmacKeyschedAir::public_values`. The
//! caller wires them across by passing the keyschedule witness's PV
//! vector to both AIRs.
//!
//! ### LogUp on `sha512_compressions`
//!
//! Three separate `Receive` Lookups, one per compression category:
//!
//!   L_first_inner: mult = `is_first_inner`, h_in = ipad_state PV,
//!                  msg padded with `msg_byte_len = 12`.
//!   L_other_inner: mult = `(1 - role) · (1 - is_first_inner)`,
//!                  h_in = ipad_state PV, msg padded with 64.
//!   L_outer:       mult = `role`, h_in = opad_state PV, msg padded
//!                  with 64.
//!
//! Splitting into three Lookups (rather than role-switched block_bits
//! inside one Lookup) keeps each `combined_elt` at degree 1 in
//! committed cells, leaving the LogUp transition constraint at degree
//! 2 — comfortable headroom under the cap of 3.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::helpers::{
    compression_tuple, inline_block_bits_for_padded_msg, BLOCK_BIT_COUNT_WORD_FLAT,
    H_IN_LIMB_COUNT, H_OUT_BIT_COUNT,
};
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::constants::{
    SHA512_COMPRESSIONS_BUS_NAME, STATE_WORDS, U64_LIMBS, WORD_BITS,
};
use crate::sha512_air::generation::{fill_row_u64, h_out_bytes_be};

// ── Constants ──────────────────────────────────────────────────────────

/// PBKDF2 salt for BIP-39 with empty passphrase: ASCII `"mnemonic"`.
/// Concatenated with `INT(1)` (4 bytes big-endian = `0x00000001`)
/// gives the 12-byte message that feeds row 0's inner compression.
pub const BIP39_SALT_BYTES: &[u8] = b"mnemonic";

/// Length of the salt + INT(1) message used as the input to the very
/// first PBKDF2 inner HMAC (`U_1 = HMAC(K, salt || INT(1))`). For BIP-39
/// with empty passphrase this is 8 + 4 = 12 bytes.
pub const FIRST_ITER_MSG_BYTE_LEN: usize = 12;

/// All non-first-iter messages are SHA-512 digests fed back into the
/// next HMAC: 64 bytes.
pub const STANDARD_MSG_BYTE_LEN: usize = 64;

/// `num_iterations` for production BIP-39 PBKDF2 (RFC 8018 / BIP-39
/// spec). Tests instantiate the AIR with smaller values.
pub const BIP39_DEFAULT_ITERATIONS: usize = 2048;

/// Public-value count: `[ipad_state_packed (32) || opad_state_packed (32)]`.
pub const NUM_PUBLIC_VALUES: usize = H_IN_LIMB_COUNT * 2;

/// Public-value index range start for `ipad_state_packed`.
pub const IPAD_PV_OFFSET: usize = 0;
/// Public-value index range start for `opad_state_packed`.
pub const OPAD_PV_OFFSET: usize = H_IN_LIMB_COUNT;

/// Bytes of the role-encoding tag in the preprocessed `role` column.
pub const ROLE_INNER: u32 = 0;
pub const ROLE_OUTER: u32 = 1;

/// Width of `msg_bits`: 64 bytes × 8 bits = 512 cells, **byte-flat**
/// (`msg_bits[byte_idx * 8 + bit_in_byte]`, LSB-first within each
/// byte). For row 0 the first `FIRST_ITER_MSG_BYTE_LEN * 8 = 96` bits
/// hold the actual message; bits `[96, 512)` are constrained to zero
/// at the first-row boundary.
pub const NUM_MSG_BITS: usize = STANDARD_MSG_BYTE_LEN * 8;

/// Width of `h_out_bits`: 8 state words × 64 bits = 512 cells, **word-flat**.
pub const NUM_H_OUT_BITS: usize = STATE_WORDS * WORD_BITS;

/// Name of the global LogUp bus that pairs Pbkdf2HmacAir's per-iteration
/// HMAC output (the `U_i` digest at the outer row's `h_out_bits`) with
/// the Pbkdf2Air orchestrator's `u_packed` row. Spec source:
/// `docs/pipeline-spec.md` §6.3.2 ("Output bus") and §7. Tuple shape:
/// `[iter_index, U_i_limb_0, ..., U_i_limb_31]` (33 elements; `U_i`
/// in 16-bit-limbs-low-first order matching the canonical
/// `compression_tuple` h_out portion).
pub const PBKDF2_OUTPUTS_BUS_NAME: &str = "pbkdf2_outputs";

// ── Main-trace columns ────────────────────────────────────────────────

#[repr(C)]
pub struct Pbkdf2HmacCols<T> {
    /// Message bits in **byte-flat** layout. For row 0 only the first
    /// 96 bits are semantically the message (salt+INT(1)); the rest
    /// are zero-padding bits. For rows ≥ 1 all 512 bits are the
    /// message.
    pub msg_bits: [T; NUM_MSG_BITS],
    /// Compression output in **word-flat** layout matching
    /// `Sha512Cols::h_out` (`h_out_bits[word][bit_in_word]`,
    /// LSB-first within each 64-bit word).
    pub h_out_bits: [[T; WORD_BITS]; STATE_WORDS],
}

pub const NUM_PBKDF2_HMAC_COLS: usize = size_of::<Pbkdf2HmacCols<u8>>();

impl<T> Borrow<Pbkdf2HmacCols<T>> for [T] {
    fn borrow(&self) -> &Pbkdf2HmacCols<T> {
        debug_assert_eq!(self.len(), NUM_PBKDF2_HMAC_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Pbkdf2HmacCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Pbkdf2HmacCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Pbkdf2HmacCols<T> {
        debug_assert_eq!(self.len(), NUM_PBKDF2_HMAC_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Pbkdf2HmacCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// ── Preprocessed-trace columns ─────────────────────────────────────────

#[repr(C)]
pub struct Pbkdf2HmacPreprocessedCols<T> {
    /// `ROLE_INNER` (= 0) on inner-compression rows, `ROLE_OUTER`
    /// (= 1) on outer rows. Alternates row-by-row.
    pub role: T,
    /// 1 on row 0 only (first iteration's inner row, which uses the
    /// 12-byte salt+INT(1) message). 0 on every other row. Gates the
    /// `L_first_inner` Lookup's multiplicity.
    pub is_first_inner: T,
    /// Iteration index: row 0 and row 1 carry value 0, rows 2-3 carry
    /// 1, etc. Currently unused; reserved for the `pbkdf2_outputs`
    /// bus (Phase 3 orchestrator).
    pub iter_index: T,
}

pub const NUM_PBKDF2_HMAC_PREPROCESSED_COLS: usize =
    size_of::<Pbkdf2HmacPreprocessedCols<u8>>();

impl<T> Borrow<Pbkdf2HmacPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Pbkdf2HmacPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_PBKDF2_HMAC_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<Pbkdf2HmacPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// ── The AIR ────────────────────────────────────────────────────────────

/// Marker AIR for the PBKDF2 per-compression layer. Stateful for two
/// reasons: `num_iterations` parameterizes the trace shape (BIP-39
/// uses 2048; tests use small values to keep prove/verify cycles
/// fast), and `num_lookups` is the per-call counter
/// `LookupAir::add_lookup_columns` requires.
#[derive(Clone, Debug)]
pub struct Pbkdf2HmacAir {
    /// PBKDF2 iteration count. Production BIP-39 = 2048; tests use 1-4.
    pub num_iterations: usize,
    num_lookups: usize,
}

impl Default for Pbkdf2HmacAir {
    fn default() -> Self {
        Self {
            num_iterations: BIP39_DEFAULT_ITERATIONS,
            num_lookups: 0,
        }
    }
}

impl Pbkdf2HmacAir {
    /// Build the AIR for an arbitrary iteration count. Must be ≥ 1.
    /// Production callers use [`BIP39_DEFAULT_ITERATIONS`].
    pub const fn new(num_iterations: usize) -> Self {
        Self {
            num_iterations,
            num_lookups: 0,
        }
    }

    /// Trace height = `2 * num_iterations` (one inner + one outer row
    /// per iteration). Must be ≥ 2.
    pub const fn trace_height(&self) -> usize {
        2 * self.num_iterations
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Pbkdf2HmacAir {
    fn width(&self) -> usize {
        NUM_PBKDF2_HMAC_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // `Air::eval` constraints: bool checks (deg 1), per-bit
        // transition `next.msg_bits = local.h_out_bits` (deg 1),
        // first-row boundary on row 0's msg_bits (deg 1). LogUp
        // transition is deg 2 (per the three-Lookup split). Cap 3.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let trace_height = 2 * self.num_iterations;
        let mut values = vec![F::ZERO; trace_height * NUM_PBKDF2_HMAC_PREPROCESSED_COLS];
        for row_index in 0..trace_height {
            let iter_index = row_index / 2;
            let is_inner = row_index % 2 == 0;
            let role = if is_inner { ROLE_INNER } else { ROLE_OUTER };
            let is_first_inner = row_index == 0;
            let base = row_index * NUM_PBKDF2_HMAC_PREPROCESSED_COLS;
            values[base] = F::from_u32(role);
            values[base + 1] = if is_first_inner { F::ONE } else { F::ZERO };
            values[base + 2] = F::from_u32(iter_index as u32);
        }
        Some(RowMajorMatrix::new(
            values,
            NUM_PBKDF2_HMAC_PREPROCESSED_COLS,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for Pbkdf2HmacAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot pattern (see `HmacKeyschedAir::eval` for the why):
        // clone main / preprocessed windows so subsequent &mut calls
        // don't conflict with the immutable borrows.
        let main_window = builder.main();
        let local: &Pbkdf2HmacCols<AB::Var> = (*main_window.current_slice()).borrow();
        let next: &Pbkdf2HmacCols<AB::Var> = (*main_window.next_slice()).borrow();
        let preprocessed_window = builder.preprocessed().clone();
        let preprocessed_local: &Pbkdf2HmacPreprocessedCols<AB::Var> =
            (*preprocessed_window.current_slice()).borrow();

        let msg_bits_local = local.msg_bits;
        let h_out_bits_local = local.h_out_bits;
        let msg_bits_next = next.msg_bits;
        let _role_var = preprocessed_local.role;
        let _is_first_inner_var = preprocessed_local.is_first_inner;

        // 1. Boolean range checks on primitive bit columns.
        for &bit in msg_bits_local.iter() {
            builder.assert_bool(bit);
        }
        for word in h_out_bits_local.iter() {
            for &bit in word.iter() {
                builder.assert_bool(bit);
            }
        }

        // 2. Cross-row chaining: `next.msg_bits == local.h_out_bits`,
        //    bit-by-bit. This is the central PBKDF2 invariant — every
        //    compression's output flows into the next compression's
        //    message slot:
        //      outer row's msg_bits = its inner row's h_out (the inner
        //        SHA-512 digest)
        //      next iter's inner row's msg_bits = previous iter's
        //        outer row's h_out (= U_{i-1})
        //    Both cases are the same constraint shape.
        //
        //    The mapping: `local.h_out_bits[word][bit_in_word]` is in
        //    word-flat layout; `next.msg_bits[byte * 8 + bit_in_byte]`
        //    is in byte-flat layout. We translate index-by-index.
        let mut when_trans = builder.when_transition();
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                // word-flat → byte-flat translation (same as the
                // helpers' convention; see `hmac_air/helpers.rs`):
                //   byte_in_word = 7 - bit_in_word / 8 (BE byte order)
                //   bit_in_byte  = bit_in_word % 8
                let byte_in_word = 7 - bit_in_word / 8;
                let byte_idx = word_index * 8 + byte_in_word;
                let bit_in_byte = bit_in_word % 8;
                let next_msg_bit = msg_bits_next[byte_idx * 8 + bit_in_byte];
                let local_h_out_bit = h_out_bits_local[word_index][bit_in_word];
                when_trans.assert_eq(next_msg_bit, local_h_out_bit);
            }
        }

        // 3. First-row boundary: row 0's msg_bits hold salt+INT(1).
        //    BIP-39 v1: salt = "mnemonic" || INT(1) = 12 bytes
        //    (8-byte ASCII + 4-byte big-endian counter).
        //    The first 96 bits are these constants; the remaining
        //    [96, 512) bits are constrained to zero so the first-iter
        //    Lookup's `msg_byte_len = 12` slice is well-defined.
        let mut salt_int1 = [0u8; FIRST_ITER_MSG_BYTE_LEN];
        salt_int1[..BIP39_SALT_BYTES.len()].copy_from_slice(BIP39_SALT_BYTES);
        salt_int1[BIP39_SALT_BYTES.len()..].copy_from_slice(&1u32.to_be_bytes());

        let mut when_first_row = builder.when_first_row();
        for byte_index in 0..FIRST_ITER_MSG_BYTE_LEN {
            let byte_value = salt_int1[byte_index];
            for bit_in_byte in 0..8 {
                let expected_bit = ((byte_value >> bit_in_byte) & 1) as u32;
                let cell: AB::Expr = msg_bits_local[byte_index * 8 + bit_in_byte].into();
                when_first_row.assert_zero(cell - AB::Expr::from_u32(expected_bit));
            }
        }
        // Zero-pad bits [96, 512) on row 0 only.
        for bit_index in (FIRST_ITER_MSG_BYTE_LEN * 8)..NUM_MSG_BITS {
            let cell: AB::Expr = msg_bits_local[bit_index].into();
            when_first_row.assert_zero(cell);
        }
    }
}

impl<F: Field> LookupAir<F> for Pbkdf2HmacAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        // Build symbolic refs to main, preprocessed, and PVs.
        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_PBKDF2_HMAC_COLS,
            preprocessed_width: NUM_PBKDF2_HMAC_PREPROCESSED_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &Pbkdf2HmacCols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &Pbkdf2HmacPreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();
        let public_value_vars = symbolic_builder.public_values();

        // h_in_limbs_ipad: 32 limbs from the ipad_state PV input. Used
        // by both inner Lookups. h_in_limbs_opad: same for outer.
        let mut h_in_limbs_ipad: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(H_IN_LIMB_COUNT);
        for limb_index in 0..H_IN_LIMB_COUNT {
            h_in_limbs_ipad.push(public_value_vars[IPAD_PV_OFFSET + limb_index].into());
        }
        let mut h_in_limbs_opad: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(H_IN_LIMB_COUNT);
        for limb_index in 0..H_IN_LIMB_COUNT {
            h_in_limbs_opad.push(public_value_vars[OPAD_PV_OFFSET + limb_index].into());
        }

        // h_out_bits expressions from this row's committed cells.
        let mut h_out_bits_exprs: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(H_OUT_BIT_COUNT);
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                h_out_bits_exprs.push(main_local.h_out_bits[word_index][bit_in_word].into());
            }
        }

        // block_bits per category: each uses
        // `inline_block_bits_for_padded_msg` with the appropriate
        // msg slice + `msg_byte_len`.
        // Inner / outer compressions both follow the keyschedule's
        // pre-compressed K'⊕ipad / K'⊕opad block — `prior_block_bytes
        // = 128` so the length suffix in the padded block encodes the
        // full HMAC input length (FIPS 180-4 §5.1.2 padding rule).
        const HMAC_PRIOR_BLOCK_BYTES: usize = 128;
        let first_inner_block_bits =
            inline_block_bits_for_padded_msg::<SymbolicAirBuilder<F>>(
                &main_local.msg_bits[..FIRST_ITER_MSG_BYTE_LEN * 8],
                FIRST_ITER_MSG_BYTE_LEN,
                HMAC_PRIOR_BLOCK_BYTES,
            );
        debug_assert_eq!(first_inner_block_bits.len(), BLOCK_BIT_COUNT_WORD_FLAT);
        let standard_block_bits = inline_block_bits_for_padded_msg::<SymbolicAirBuilder<F>>(
            &main_local.msg_bits[..STANDARD_MSG_BYTE_LEN * 8],
            STANDARD_MSG_BYTE_LEN,
            HMAC_PRIOR_BLOCK_BYTES,
        );
        debug_assert_eq!(standard_block_bits.len(), BLOCK_BIT_COUNT_WORD_FLAT);

        // Multiplicities, all preprocessed-derived (deg 1 or 2):
        //   L_first_inner: is_first_inner               (deg 1)
        //   L_other_inner: (1 - role) · (1 - is_first)  (deg 2)
        //   L_outer:        role                         (deg 1)
        let role: SymbolicExpression<F> = preprocessed_local.role.into();
        let one_minus_role: SymbolicExpression<F> =
            SymbolicExpression::from(F::ONE) - role.clone();
        let is_first_inner: SymbolicExpression<F> = preprocessed_local.is_first_inner.into();
        let one_minus_is_first: SymbolicExpression<F> =
            SymbolicExpression::from(F::ONE) - is_first_inner.clone();

        let mult_first_inner = is_first_inner;
        let mult_other_inner = one_minus_role * one_minus_is_first;
        let mult_outer = role;

        let tuple_first_inner = compression_tuple::<F>(
            &h_in_limbs_ipad,
            &first_inner_block_bits,
            &h_out_bits_exprs,
        );
        let tuple_other_inner = compression_tuple::<F>(
            &h_in_limbs_ipad,
            &standard_block_bits,
            &h_out_bits_exprs,
        );
        let tuple_outer = compression_tuple::<F>(
            &h_in_limbs_opad,
            &standard_block_bits,
            &h_out_bits_exprs,
        );

        let bus_kind = || Kind::Global(SHA512_COMPRESSIONS_BUS_NAME.to_string());
        let mut lookups: Vec<Lookup<F>> = Vec::with_capacity(4);

        let inputs_first_inner = [(tuple_first_inner, mult_first_inner, Direction::Receive)];
        lookups.push(LookupAir::register_lookup(self, bus_kind(), &inputs_first_inner));

        let inputs_other_inner = [(tuple_other_inner, mult_other_inner, Direction::Receive)];
        lookups.push(LookupAir::register_lookup(self, bus_kind(), &inputs_other_inner));

        let inputs_outer = [(tuple_outer, mult_outer.clone(), Direction::Receive)];
        lookups.push(LookupAir::register_lookup(self, bus_kind(), &inputs_outer));

        // Output bus: per outer row, send `(iter_index, U_i_limbs)` to
        // the Phase 3 orchestrator (`Pbkdf2Air`). `U_i` is this row's
        // `h_out` packed as 16-bit limbs in low-first per-word order
        // (the same canonical packing used inside `compression_tuple`'s
        // h_out portion). Multiplicity = role (= 1 only on outer rows).
        // Spec §6.3.2 "Output bus".
        let mut u_i_packed_inline: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(H_IN_LIMB_COUNT);
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                let mut limb_expr: SymbolicExpression<F> = F::ZERO.into();
                for bit_offset in 0..16 {
                    let pow: SymbolicExpression<F> = F::from_u32(1u32 << bit_offset).into();
                    let bit_idx = word_index * WORD_BITS + limb_index * 16 + bit_offset;
                    let bit_expr: SymbolicExpression<F> =
                        main_local.h_out_bits[word_index][limb_index * 16 + bit_offset].into();
                    let _ = bit_idx;
                    limb_expr = limb_expr + pow * bit_expr;
                }
                u_i_packed_inline.push(limb_expr);
            }
        }
        debug_assert_eq!(u_i_packed_inline.len(), H_IN_LIMB_COUNT);

        let mut output_bus_tuple: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(1 + H_IN_LIMB_COUNT);
        output_bus_tuple.push(preprocessed_local.iter_index.into());
        output_bus_tuple.extend(u_i_packed_inline);

        let inputs_output_bus = [(output_bus_tuple, mult_outer, Direction::Send)];
        lookups.push(LookupAir::register_lookup(
            self,
            Kind::Global(PBKDF2_OUTPUTS_BUS_NAME.to_string()),
            &inputs_output_bus,
        ));

        lookups
    }
}

// ── Trace generation ──────────────────────────────────────────────────

/// Aggregate output of the off-circuit PBKDF2 simulation: the trace,
/// the public-value vector to feed the AIR, and the ordered sequence
/// of `U_i` digests (one per iteration) that the Phase 3 orchestrator
/// will XOR-fold to produce the final seed.
pub struct Pbkdf2HmacWitness<F: PrimeCharacteristicRing + Clone> {
    /// Main trace, sized `(2 * num_iterations) × NUM_PBKDF2_HMAC_COLS`.
    pub trace: RowMajorMatrix<F>,
    /// `[ipad_state_packed (32) || opad_state_packed (32)]` — the PV
    /// vector the verifier needs (and that the AIR's `Air::eval`
    /// reads). Same shape as `HmacKeyschedAir::public_values`'s
    /// output; callers wire them across by passing this verbatim.
    pub public_values: Vec<F>,
    /// `U_1, U_2, …, U_c`, each a 64-byte SHA-512 digest. Phase 3's
    /// orchestrator consumes these via the (future) `pbkdf2_outputs`
    /// bus.
    pub u_digests: Vec<[u8; 64]>,
}

/// Run PBKDF2-HMAC-SHA512 for `num_iterations` rounds, given the
/// pre-computed `ipad_state` / `opad_state` from the keyschedule.
/// Returns the trace + PV vector + ordered `U_i` digests.
///
/// `salt_plus_int1_bytes` is the 12-byte `salt || INT(1)` for BIP-39
/// (or whatever 12-byte first-iter message the caller wants —
/// `BIP39_SALT_BYTES` followed by `1u32.to_be_bytes()` is the
/// canonical value).
pub fn generate_pbkdf2_hmac_witness<F>(
    num_iterations: usize,
    ipad_state_words: [u64; STATE_WORDS],
    opad_state_words: [u64; STATE_WORDS],
    salt_plus_int1_bytes: &[u8; FIRST_ITER_MSG_BYTE_LEN],
) -> Pbkdf2HmacWitness<F>
where
    F: PrimeField64,
{
    assert!(num_iterations >= 1, "PBKDF2 requires ≥ 1 iteration");

    let trace_height = 2 * num_iterations;
    let mut trace_values = vec![F::ZERO; trace_height * NUM_PBKDF2_HMAC_COLS];
    let mut u_digests: Vec<[u8; 64]> = Vec::with_capacity(num_iterations);

    // Reusable scratch row for off-circuit SHA-512 compression.
    let mut sha_row_scratch = vec![0u64; NUM_SHA512_COLS];

    // Working state: `current_inner_msg_bytes` is the 64-byte input to
    // the current iteration's inner compression. For iter 0 it's
    // logically only 12 bytes (salt+INT(1)), but we carry it as a
    // 64-byte buffer with leading zeros in the unused tail to keep the
    // row layout uniform; the AIR's first-row boundary pins those tail
    // bits to zero anyway.
    for iter_index in 0..num_iterations {
        // ── Inner compression ─────────────────────────────────────────
        let (inner_msg_bytes, inner_msg_byte_len) = if iter_index == 0 {
            // First iter: 12-byte salt+INT(1), zero-padded to 64 bytes
            // for the trace's msg_bits column.
            let mut buf = [0u8; STANDARD_MSG_BYTE_LEN];
            buf[..FIRST_ITER_MSG_BYTE_LEN].copy_from_slice(salt_plus_int1_bytes);
            (buf, FIRST_ITER_MSG_BYTE_LEN)
        } else {
            // Subsequent iters: 64-byte U_{iter_index} from the
            // previous outer row's output.
            (
                u_digests[iter_index - 1],
                STANDARD_MSG_BYTE_LEN,
            )
        };

        let inner_padded_block =
            sha512_pad_single_block(&inner_msg_bytes[..inner_msg_byte_len], 128);
        fill_row_u64(ipad_state_words, inner_padded_block, &mut sha_row_scratch);
        let inner_h_out_bytes = h_out_bytes_be(&sha_row_scratch);

        let inner_row_index = 2 * iter_index;
        fill_pbkdf2_row::<F>(
            &mut trace_values[inner_row_index * NUM_PBKDF2_HMAC_COLS
                ..(inner_row_index + 1) * NUM_PBKDF2_HMAC_COLS],
            &inner_msg_bytes,
            &inner_h_out_bytes,
        );

        // ── Outer compression ─────────────────────────────────────────
        let outer_msg_bytes = inner_h_out_bytes;
        let outer_padded_block = sha512_pad_single_block(&outer_msg_bytes, 128);
        fill_row_u64(opad_state_words, outer_padded_block, &mut sha_row_scratch);
        let outer_h_out_bytes = h_out_bytes_be(&sha_row_scratch);

        let outer_row_index = 2 * iter_index + 1;
        fill_pbkdf2_row::<F>(
            &mut trace_values[outer_row_index * NUM_PBKDF2_HMAC_COLS
                ..(outer_row_index + 1) * NUM_PBKDF2_HMAC_COLS],
            &outer_msg_bytes,
            &outer_h_out_bytes,
        );

        u_digests.push(outer_h_out_bytes);
    }

    // Build PV vector: [ipad_state_packed || opad_state_packed], both
    // in 16-bit-limbs-low-first order matching `HmacKeyschedAir`.
    let mut public_values = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for word_index in 0..STATE_WORDS {
        for limb_index in 0..U64_LIMBS {
            let limb_value = (ipad_state_words[word_index] >> (limb_index * 16)) & 0xFFFF;
            public_values.push(F::from_u64(limb_value));
        }
    }
    for word_index in 0..STATE_WORDS {
        for limb_index in 0..U64_LIMBS {
            let limb_value = (opad_state_words[word_index] >> (limb_index * 16)) & 0xFFFF;
            public_values.push(F::from_u64(limb_value));
        }
    }
    debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);

    Pbkdf2HmacWitness {
        trace: RowMajorMatrix::new(trace_values, NUM_PBKDF2_HMAC_COLS),
        public_values,
        u_digests,
    }
}

/// Fill one row's main-trace cells from a 64-byte message buffer
/// (byte-flat → bit-flat) and an 8 × u64 `h_out` state (decomposed
/// into 64 word-flat bits).
fn fill_pbkdf2_row<F: PrimeField64>(
    row_slice: &mut [F],
    msg_bytes: &[u8; STANDARD_MSG_BYTE_LEN],
    h_out_bytes: &[u8; 64],
) {
    let cols: &mut Pbkdf2HmacCols<F> = row_slice.borrow_mut();

    // msg_bits in byte-flat layout (LSB-first within each byte).
    for byte_index in 0..STANDARD_MSG_BYTE_LEN {
        let byte_value = msg_bytes[byte_index];
        for bit_in_byte in 0..8 {
            let bit_value = ((byte_value >> bit_in_byte) & 1) as u64;
            cols.msg_bits[byte_index * 8 + bit_in_byte] = F::from_u64(bit_value);
        }
    }

    // h_out_bytes is a 64-byte big-endian digest = 8 u64 words.
    // Decompose each into 64 word-flat LSB-first bits.
    for word_index in 0..STATE_WORDS {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&h_out_bytes[word_index * 8..(word_index + 1) * 8]);
        let word_value = u64::from_be_bytes(word_bytes);
        for bit_in_word in 0..WORD_BITS {
            let bit_value = ((word_value >> bit_in_word) & 1) as u64;
            cols.h_out_bits[word_index][bit_in_word] = F::from_u64(bit_value);
        }
    }
}

/// SHA-512-pad a single final message block, mirroring what
/// `inline_block_bits_for_padded_msg` produces in expression form.
/// `prior_block_bytes` is the count of input bytes consumed by
/// previous (already-compressed) blocks — needed because the SHA-512
/// length suffix encodes the **full** input length (FIPS 180-4
/// §5.1.2). For HMAC inner / outer this is 128 (the K'⊕ipad / opad
/// block).
fn sha512_pad_single_block(msg: &[u8], prior_block_bytes: usize) -> [u64; 16] {
    assert!(msg.len() <= 111);
    assert!(prior_block_bytes % 128 == 0);
    let mut block_bytes = [0u8; 128];
    block_bytes[..msg.len()].copy_from_slice(msg);
    block_bytes[msg.len()] = 0x80;
    let bit_len = ((prior_block_bytes + msg.len()) as u128) * 8;
    block_bytes[112..128].copy_from_slice(&bit_len.to_be_bytes());

    let mut block_words = [0u64; 16];
    for word_index in 0..16 {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&block_bytes[word_index * 8..(word_index + 1) * 8]);
        block_words[word_index] = u64::from_be_bytes(word_bytes);
    }
    block_words
}

/// Build the canonical 12-byte `salt || INT(1)` message for BIP-39.
/// Equivalent to `b"mnemonic" || 1u32.to_be_bytes()`.
pub fn bip39_salt_plus_int1() -> [u8; FIRST_ITER_MSG_BYTE_LEN] {
    let mut buf = [0u8; FIRST_ITER_MSG_BYTE_LEN];
    buf[..BIP39_SALT_BYTES.len()].copy_from_slice(BIP39_SALT_BYTES);
    buf[BIP39_SALT_BYTES.len()..].copy_from_slice(&1u32.to_be_bytes());
    buf
}
