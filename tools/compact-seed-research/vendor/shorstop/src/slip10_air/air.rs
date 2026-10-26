//! AIR + LookupAir for the Phase 4 minimal SLIP-0010 priv-extractor.
//!
//! ### What this AIR emits
//!
//! The PV is the **RFC 8032 clamped scalar** derived from the
//! SLIP-0010 chain's last-step priv (received bit-by-bit from
//! [`crate::hmac_air::slip10_hmac::Slip10HmacAir`] over the
//! `slip10_priv_outputs` bus). Clamping is done **in-circuit** here so
//! that the verifier can pass the same Vec to this AIR's PV slot AND
//! to `Ed25519Air`'s `scalar_packed` PV slot, closing the
//! mnemonic → seed → priv → clamped-scalar → `[s]B` soundness chain.
//!
//! Clamping (RFC 8032 §5.1.5):
//!
//!   - byte 0:   low 3 bits cleared (`priv[0] & 0xF8`)
//!   - byte 31:  high bit cleared, bit 6 forced set (`(priv[31] & 0x7F) | 0x40`)
//!
//! The received priv_bits (the un-clamped chain output) are still
//! bool-checked, just not all of them contribute to the packed scalar
//! bytes — the cleared bits are dropped from the per-byte sum, and the
//! forced-1 bit is added as a constant.

use core::borrow::Borrow;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::slip10_hmac::{NUM_PRIV_BITS, SLIP10_PRIV_OUTPUTS_BUS_NAME};
use crate::slip10_air::columns::{
    priv_byte_bit_to_word_flat, Slip10AirCols, Slip10AirPreprocessedCols, NUM_PRIV_BYTES,
    NUM_SLIP10_AIR_COLS, NUM_SLIP10_AIR_PREPROCESSED_COLS, SLIP10_AIR_TRACE_HEIGHT,
};

/// Public-value count: 32 × 8-bit limbs of the clamped Ed25519 scalar.
/// Same shape as `Ed25519Air`'s `scalar_packed` slot — the verifier
/// passes one Vec to both AIRs to enforce equality.
pub const NUM_PUBLIC_VALUES: usize = NUM_PRIV_BYTES;

/// Byte index in the packed scalar where RFC 8032 clamping clears the
/// low 3 bits (bits 0, 1, 2 of `priv[0]`).
const CLAMP_LOW_BYTE_INDEX: usize = 0;
/// Range of bit positions within `priv[0]` that survive clamping
/// (bits 3..8). Bits below this range are dropped.
const CLAMP_LOW_BYTE_PRESERVED_BITS: core::ops::Range<usize> = 3..8;
/// Byte index where RFC 8032 clamping clears bit 7 and forces bit 6 to 1.
const CLAMP_HIGH_BYTE_INDEX: usize = NUM_PRIV_BYTES - 1;
/// Range of bit positions within `priv[31]` that survive clamping
/// unchanged (bits 0..6). Bit 6 is replaced by a forced constant,
/// bit 7 is dropped.
const CLAMP_HIGH_BYTE_PRESERVED_BITS: core::ops::Range<usize> = 0..6;
/// Mask added to byte 31 to force bit 6 on (the bit-254-of-scalar
/// forced-set rule).
const CLAMP_HIGH_FORCED_BIT_MASK: u32 = 0x40;

#[derive(Clone, Default, Debug)]
pub struct Slip10Air {
    num_lookups: usize,
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Slip10Air {
    fn width(&self) -> usize {
        NUM_SLIP10_AIR_COLS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        // bool checks (deg 1) + per-byte 8-bit packing (deg 1, gated
        // by deg-1 preprocessed selector → deg 2). LogUp transition
        // is deg 2. Cap 3 with headroom.
        Some(3)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = vec![F::ZERO; SLIP10_AIR_TRACE_HEIGHT * NUM_SLIP10_AIR_PREPROCESSED_COLS];
        // Row 0: is_extract_row = 1. Row 1: padding (= 0).
        values[0] = F::ONE;
        Some(RowMajorMatrix::new(
            values,
            NUM_SLIP10_AIR_PREPROCESSED_COLS,
        ))
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for Slip10Air
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot pattern.
        let main_window = builder.main();
        let local: &Slip10AirCols<AB::Var> = (*main_window.current_slice()).borrow();
        let preprocessed_window = builder.preprocessed().clone();
        let preprocessed_local: &Slip10AirPreprocessedCols<AB::Var> =
            (*preprocessed_window.current_slice()).borrow();

        let priv_bits_local = local.priv_bits;
        let is_extract_var = preprocessed_local.is_extract_row;

        let public_values_snapshot: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public_values = builder.public_values();
            debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);
            let mut snapshot = [public_values[0]; NUM_PUBLIC_VALUES];
            for index in 0..NUM_PUBLIC_VALUES {
                snapshot[index] = public_values[index];
            }
            snapshot
        };

        // 1. Boolean range checks on priv_bits.
        for &bit in priv_bits_local.iter() {
            builder.assert_bool(bit);
        }

        // 2. Per-byte PV binding gated by is_extract_row, with RFC 8032
        // clamping applied at the packing level. For byte k:
        //
        //   is_extract_row · (scalar_packed_pv[k] - clamp_packed_k(priv_bits)) = 0
        //
        // where clamp_packed_k drops the cleared bit positions from the
        // sum and adds the forced-set bit as a constant:
        //
        //   k = 0:   Σ_{j=3..8} 2^j · priv_bits[word_flat(0, j)]
        //   k = 31:  Σ_{j=0..6} 2^j · priv_bits[word_flat(31, j)] + 0x40
        //   k ∈ 1..30: Σ_{j=0..8} 2^j · priv_bits[word_flat(k, j)]
        //
        // The dropped bits (priv_bits at byte 0 / bits 0..2 and byte 31 /
        // bits 6..7) are still bool-checked above — they just don't
        // contribute to the packed scalar, encoding the clamp's
        // bit-clear in-circuit.
        let is_extract_expr: AB::Expr = is_extract_var.into();
        for byte_idx in 0..NUM_PRIV_BYTES {
            let (preserved_bits, forced_constant) = if byte_idx == CLAMP_LOW_BYTE_INDEX {
                (CLAMP_LOW_BYTE_PRESERVED_BITS, 0u32)
            } else if byte_idx == CLAMP_HIGH_BYTE_INDEX {
                (CLAMP_HIGH_BYTE_PRESERVED_BITS, CLAMP_HIGH_FORCED_BIT_MASK)
            } else {
                (0..8, 0u32)
            };
            let mut packed_byte: AB::Expr = AB::Expr::ZERO;
            for bit_in_byte in preserved_bits {
                let pow = AB::Expr::from_u32(1u32 << bit_in_byte);
                let bit_index = priv_byte_bit_to_word_flat(byte_idx, bit_in_byte);
                let bit: AB::Expr = priv_bits_local[bit_index].into();
                packed_byte = packed_byte + pow * bit;
            }
            if forced_constant != 0 {
                packed_byte = packed_byte + AB::Expr::from_u32(forced_constant);
            }
            let pv: AB::Expr = public_values_snapshot[byte_idx].into();
            builder.assert_zero(is_extract_expr.clone() * (pv - packed_byte));
        }
    }
}

impl<F: Field> LookupAir<F> for Slip10Air {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_SLIP10_AIR_COLS,
            preprocessed_width: NUM_SLIP10_AIR_PREPROCESSED_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &Slip10AirCols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &Slip10AirPreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();

        // Tuple = 256 priv_bits in word-flat layout (matches the
        // sender side in `Slip10HmacAir::get_lookups`).
        let mut tuple: Vec<SymbolicExpression<F>> = Vec::with_capacity(NUM_PRIV_BITS);
        for bit_index in 0..NUM_PRIV_BITS {
            tuple.push(main_local.priv_bits[bit_index].into());
        }
        debug_assert_eq!(tuple.len(), NUM_PRIV_BITS);

        let multiplicity: SymbolicExpression<F> = preprocessed_local.is_extract_row.into();
        let lookup_inputs = [(tuple, multiplicity, Direction::Receive)];
        vec![LookupAir::register_lookup(
            self,
            Kind::Global(SLIP10_PRIV_OUTPUTS_BUS_NAME.to_string()),
            &lookup_inputs,
        )]
    }
}
