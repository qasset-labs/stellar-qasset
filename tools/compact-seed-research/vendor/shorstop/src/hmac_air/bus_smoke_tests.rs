//! End-to-end `prove_batch` / `verify_batch` smoke test for the
//! `sha512_compressions` LogUp bus introduced in Phase 1.
//!
//! Spec source: `docs/pipeline-spec.md` §5 (the bus design) and §15
//! Phase 1d ("stub-consumer test that proves a SHA + receiver pair via
//! `prove_batch`").
//!
//! This test wires:
//!
//!   - the real `Sha512Air` (sender, instantiated via `Sha512Air::new`)
//!     producing the canonical 128-element compression tuple per row;
//!   - a tiny test-only `Sha512MirrorConsumerAir` (receiver) whose
//!     committed cells are exactly the §6.2 receiver-side shape:
//!     `(h_in_packed, block_bits, h_out_bits)`. Its `Air::eval` is
//!     empty — the only constraint binding its witness is the LogUp
//!     receive on the bus.
//!
//! With the canonical-order helper [`crate::hmac_air::helpers::compression_tuple`]
//! used on **both** sides, multiset equality on the bus must hold for
//! an honest (matching) sender + receiver, and `verify_batch` must
//! accept. That single assertion covers:
//!
//!   1. SHA-512's `LookupAir::Send` is well-formed (Phase 1b output).
//!   2. The shared helper produces a tuple shape that pairs with
//!      itself across two AIRs (Phase 1c).
//!   3. The `is_real_compression_row` preprocessed selector survives
//!      `prove_batch`'s preprocessed-trace pipeline.
//!
//! Subsequent phases extend this skeleton: HMAC AIR structs replace
//! `Sha512MirrorConsumerAir` as production receivers, and the §13.5
//! endianness-mismatch negative test will live in `soundness_tests.rs`.

#![cfg(test)]

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::helpers::compression_tuple;
use crate::sha512_air::air::Sha512Air;
use crate::sha512_air::columns::{Sha512Cols, NUM_SHA512_COLS};
use crate::sha512_air::constants::{
    BLOCK_WORDS, SHA512_COMPRESSIONS_BUS_NAME, SHA512_IV, STATE_WORDS, U64_LIMBS, WORD_BITS,
};
use crate::sha512_air::generation::generate_trace as generate_sha512_trace;
use crate::{make_config, Val};

// ── Mirror-consumer AIR (test-only) ────────────────────────────────────
//
// The simplest receiver-side shape: each row commits a full
// `(h_in_packed, block_bits, h_out_bits)` triple in the same layout
// HMAC instances will use. No internal constraints; the bus does all
// the work.

#[repr(C)]
struct MirrorCols<T> {
    /// Input chaining state, 16-bit-limb-packed (low-first, matching
    /// `Sha512Cols::h_in`).
    h_in_packed: [[T; U64_LIMBS]; STATE_WORDS],
    /// Message block in bit-form (LSB-first, matching `Sha512Cols::w[0..16]`).
    block_bits: [[T; WORD_BITS]; BLOCK_WORDS],
    /// Output chaining state in bit-form (matching `Sha512Cols::h_out`).
    h_out_bits: [[T; WORD_BITS]; STATE_WORDS],
}

const NUM_MIRROR_COLS: usize = size_of::<MirrorCols<u8>>();

impl<T> Borrow<MirrorCols<T>> for [T] {
    fn borrow(&self) -> &MirrorCols<T> {
        debug_assert_eq!(self.len(), NUM_MIRROR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MirrorCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MirrorCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MirrorCols<T> {
        debug_assert_eq!(self.len(), NUM_MIRROR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MirrorCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

#[derive(Clone, Default)]
struct Sha512MirrorConsumerAir;

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Sha512MirrorConsumerAir {
    fn width(&self) -> usize {
        NUM_MIRROR_COLS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        // Only the LogUp transition constraint (degree 3) fires here.
        Some(3)
    }
}

impl<AB: AirBuilder> Air<AB> for Sha512MirrorConsumerAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, _builder: &mut AB) {
        // Intentionally empty.
    }
}

impl<F: Field> LookupAir<F> for Sha512MirrorConsumerAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        vec![0]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_MIRROR_COLS,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &MirrorCols<_> = (*main_window.current_slice()).borrow();

        let mut h_in_limbs: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(STATE_WORDS * U64_LIMBS);
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                h_in_limbs.push(main_local.h_in_packed[word_index][limb_index].into());
            }
        }
        let mut block_bits: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(BLOCK_WORDS * WORD_BITS);
        for word_index in 0..BLOCK_WORDS {
            for bit_index in 0..WORD_BITS {
                block_bits.push(main_local.block_bits[word_index][bit_index].into());
            }
        }
        let mut h_out_bits: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(STATE_WORDS * WORD_BITS);
        for word_index in 0..STATE_WORDS {
            for bit_index in 0..WORD_BITS {
                h_out_bits.push(main_local.h_out_bits[word_index][bit_index].into());
            }
        }

        let tuple = compression_tuple::<F>(&h_in_limbs, &block_bits, &h_out_bits);
        let multiplicity: SymbolicExpression<F> = F::ONE.into();
        let lookup_inputs = [(tuple, multiplicity, Direction::Receive)];
        vec![LookupAir::register_lookup(
            self,
            Kind::Global(SHA512_COMPRESSIONS_BUS_NAME.to_string()),
            &lookup_inputs,
        )]
    }
}

// ── Test-local enum for the heterogeneous prove_batch slice ────────────

#[derive(Clone)]
enum BusBatchedAir {
    Sha512(Sha512Air),
    MirrorConsumer(Sha512MirrorConsumerAir),
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for BusBatchedAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::width(inner),
            Self::MirrorConsumer(inner) => {
                <Sha512MirrorConsumerAir as BaseAir<F>>::width(inner)
            }
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::max_constraint_degree(inner),
            Self::MirrorConsumer(inner) => {
                <Sha512MirrorConsumerAir as BaseAir<F>>::max_constraint_degree(inner)
            }
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::preprocessed_trace(inner),
            Self::MirrorConsumer(inner) => {
                <Sha512MirrorConsumerAir as BaseAir<F>>::preprocessed_trace(inner)
            }
        }
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => {
                <Sha512Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::MirrorConsumer(inner) => {
                <Sha512MirrorConsumerAir as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
        }
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for BusBatchedAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Sha512(inner) => <Sha512Air as Air<AB>>::eval(inner, builder),
            Self::MirrorConsumer(inner) => {
                <Sha512MirrorConsumerAir as Air<AB>>::eval(inner, builder)
            }
        }
    }
}

impl<F: Field> LookupAir<F> for BusBatchedAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::MirrorConsumer(inner) => LookupAir::<F>::add_lookup_columns(inner),
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::get_lookups(inner),
            Self::MirrorConsumer(inner) => LookupAir::<F>::get_lookups(inner),
        }
    }
}

// ── Trace generators ───────────────────────────────────────────────────

/// Build the mirror trace by copying `(h_in_packed, w[0..16], h_out)`
/// directly out of an honest SHA-512 trace, row by row. Same row count
/// → 1:1 multiset balance with the sender.
fn build_mirror_trace_from_sha_trace(sha_trace: &RowMajorMatrix<Val>) -> RowMajorMatrix<Val> {
    use p3_matrix::Matrix;

    let row_count = sha_trace.height();
    let mut values = vec![Val::ZERO; row_count * NUM_MIRROR_COLS];

    for row_index in 0..row_count {
        let sha_row: &[Val] = &sha_trace.values
            [row_index * NUM_SHA512_COLS..(row_index + 1) * NUM_SHA512_COLS];
        let sha_cols: &Sha512Cols<Val> = sha_row.borrow();

        let mirror_row: &mut [Val] = &mut values
            [row_index * NUM_MIRROR_COLS..(row_index + 1) * NUM_MIRROR_COLS];
        let mirror_cols: &mut MirrorCols<Val> = mirror_row.borrow_mut();

        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                mirror_cols.h_in_packed[word_index][limb_index] =
                    sha_cols.h_in[word_index][limb_index];
            }
        }
        for word_index in 0..BLOCK_WORDS {
            for bit_index in 0..WORD_BITS {
                mirror_cols.block_bits[word_index][bit_index] =
                    sha_cols.w[word_index][bit_index];
            }
        }
        for word_index in 0..STATE_WORDS {
            for bit_index in 0..WORD_BITS {
                mirror_cols.h_out_bits[word_index][bit_index] =
                    sha_cols.h_out[word_index][bit_index];
            }
        }
    }

    RowMajorMatrix::new(values, NUM_MIRROR_COLS)
}

// ── The smoke test ─────────────────────────────────────────────────────

/// Number of distinct compressions in the smoke test. Already a power
/// of two so `generate_trace` does not insert padding rows — keeps the
/// 1:1 sender / receiver multiset balance trivial.
const SMOKE_NUM_COMPRESSIONS: usize = 8;

/// `log2(SMOKE_NUM_COMPRESSIONS) + 1` (the `+ 1` is the is_zk hiding
/// extension; matches the Ed25519 prove/verify tests' convention).
const SMOKE_EXT_LOG_HEIGHT: usize = 3 + 1;

/// Eight distinct `(h_in, block)` inputs. `h_in[0]` walks `SHA512_IV[0]`
/// by `i` so each row's tuple is unique on the bus — a degenerate
/// "all rows equal" set would still pass multiset equality but would
/// hide a bus that silently collapses on duplicates.
fn distinct_smoke_inputs() -> Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> {
    (0..SMOKE_NUM_COMPRESSIONS)
        .map(|i| {
            let mut h = SHA512_IV;
            h[0] = h[0].wrapping_add(i as u64);
            // FIPS 180-4-style padded "empty" block, also varied so the
            // block bits are not identical row-to-row.
            let mut block = [0u64; BLOCK_WORDS];
            block[0] = 0x8000_0000_0000_0000u64.wrapping_add((i as u64) << 32);
            (h, block)
        })
        .collect()
}

#[test]
fn sha512_sender_and_mirror_receiver_balance_on_bus() {
    let inputs = distinct_smoke_inputs();
    let sha_trace = generate_sha512_trace::<Val>(&inputs);
    let mirror_trace = build_mirror_trace_from_sha_trace(&sha_trace);

    let mut airs = [
        BusBatchedAir::Sha512(Sha512Air::new(SMOKE_NUM_COMPRESSIONS)),
        BusBatchedAir::MirrorConsumer(Sha512MirrorConsumerAir),
    ];

    let config = make_config();
    let prover_data = ProverData::from_airs_and_degrees(
        &config,
        &mut airs,
        &[SMOKE_EXT_LOG_HEIGHT, SMOKE_EXT_LOG_HEIGHT],
    );

    let traces = [&sha_trace, &mirror_trace];
    let public_values_per_instance = [Vec::<Val>::new(), Vec::<Val>::new()];

    let common = &prover_data.common;
    let instances =
        StarkInstance::new_multiple(&airs, &traces, &public_values_per_instance, common);
    let proof = prove_batch(&config, &instances, &prover_data);

    let public_values = vec![Vec::<Val>::new(), Vec::<Val>::new()];
    verify_batch(&config, &airs, &proof, &public_values, common)
        .expect("honest sender + matching receiver must pass batched verify");
}
