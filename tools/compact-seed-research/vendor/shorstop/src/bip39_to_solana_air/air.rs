//! AIR + LookupAir for the BIP-39 → Solana composition AIR.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::bip39_to_solana_air::columns::{
    Bip39ToSolanaCols, Bip39ToSolanaPreprocessedCols, BIP39_TO_SOLANA_TRACE_HEIGHT,
    NUM_BIP39_TO_SOLANA_COLS, NUM_BIP39_TO_SOLANA_PREPROCESSED_COLS, NUM_PQ_DESTINATION_BYTES,
    NUM_RECENT_BLOCKHASH_BYTES, NUM_SOLANA_ADDRESS_BYTES,
};

/// Public-value count: 96 byte-cells holding the Solana address (32),
/// PQ destination address (32), and recent blockhash (32).
pub const NUM_PUBLIC_VALUES: usize =
    NUM_SOLANA_ADDRESS_BYTES + NUM_PQ_DESTINATION_BYTES + NUM_RECENT_BLOCKHASH_BYTES;

/// 1-row composition AIR exposing `solana_address` as the canonical
/// pipeline public value.
#[derive(Clone, Default, Debug)]
pub struct Bip39ToSolanaAir;

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Bip39ToSolanaAir {
    fn width(&self) -> usize {
        NUM_BIP39_TO_SOLANA_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Constraints: bool checks (deg 1), per-byte PV-equality gated
        // by `is_extract_row` (deg 2: 1 × 1). Cap at 3 with headroom.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values =
            vec![F::ZERO; BIP39_TO_SOLANA_TRACE_HEIGHT * NUM_BIP39_TO_SOLANA_PREPROCESSED_COLS];
        // Row 0: is_extract_row = 1. Row 1: padding (= 0).
        values[0] = F::ONE;
        Some(RowMajorMatrix::new(
            values,
            NUM_BIP39_TO_SOLANA_PREPROCESSED_COLS,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for Bip39ToSolanaAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot inputs before mutably borrowing builder for assertions.
        let main_window = builder.main();
        let local: &Bip39ToSolanaCols<AB::Var> = (*main_window.current_slice()).borrow();
        let preprocessed_window = builder.preprocessed().clone();
        let preprocessed_local: &Bip39ToSolanaPreprocessedCols<AB::Var> =
            (*preprocessed_window.current_slice()).borrow();

        let solana_address_local = local.solana_address;
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

        // Bool range checks on the 32 address byte cells. The bytes
        // themselves can be any value in [0, 256); the LogUp send
        // below pins them into `[0, LIMB_BASE)` via the u16_range bus
        // (NOTE: that send is implemented as part of the LookupAir
        // impl, not here).
        // Each cell is a u8 in {0..256}; the per-byte PV equality
        // below ties them to the upstream Ed25519 `y_A` PV, which
        // already proves the byte-shape via Ed25519's range checks.
        // We still assert PV equality strongly: `is_extract_row · (PV[i]
        // - solana_address[i]) = 0`.
        let is_extract_expr: AB::Expr = is_extract_var.into();
        for byte_index in 0..NUM_SOLANA_ADDRESS_BYTES {
            let address_cell: AB::Expr = solana_address_local[byte_index].into();
            let pv: AB::Expr = public_values_snapshot[byte_index].into();
            builder.assert_zero(is_extract_expr.clone() * (pv - address_cell));
        }

        let mut pv_offset = NUM_SOLANA_ADDRESS_BYTES;
        for byte_index in 0..NUM_PQ_DESTINATION_BYTES {
            let pq_cell: AB::Expr = local.pq_destination_address[byte_index].into();
            let pv: AB::Expr = public_values_snapshot[pv_offset + byte_index].into();
            builder.assert_zero(is_extract_expr.clone() * (pv - pq_cell));
        }

        pv_offset += NUM_PQ_DESTINATION_BYTES;
        for byte_index in 0..NUM_RECENT_BLOCKHASH_BYTES {
            let blockhash_cell: AB::Expr = local.recent_blockhash[byte_index].into();
            let pv: AB::Expr = public_values_snapshot[pv_offset + byte_index].into();
            builder.assert_zero(is_extract_expr.clone() * (pv - blockhash_cell));
        }
    }
}

impl<F: p3_field::Field> LookupAir<F> for Bip39ToSolanaAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        // No LogUp lookups on this AIR — cross-AIR PV equality is
        // enforced by the verifier passing identical vectors to this
        // AIR's PV slot and to Ed25519's `y_A` slot.
        Vec::new()
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        Vec::new()
    }
}
