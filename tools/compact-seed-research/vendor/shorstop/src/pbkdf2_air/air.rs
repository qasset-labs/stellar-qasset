//! AIR + LookupAir for the PBKDF2 orchestrator.
//!
//! Constraints (per `docs/pipeline-spec.md` §7):
//!
//!   1. `u_packed[k] = Σ_{j=0..15} 2^j · u_bits_word_flat[k * 16 + j]`
//!      — bind the limb-form cross-row carrier to the bit-form
//!      column (degree-1 packing per limb).
//!   2. Boolean range checks on `u_bits` and `u_xor_acc_bits`.
//!   3. **First-row boundary**: `u_xor_acc_bits[i] = u_bits[i]` per
//!      bit (the XOR fold starts with `U_1`; equivalent to XOR'ing
//!      with the identity element 0).
//!   4. **Cross-row transition**: `next.u_xor_acc_bits[i] =
//!      next.u_bits[i] ⊕ local.u_xor_acc_bits[i]` per bit (XOR over
//!      GF(2) is `a + b - 2ab` — degree 2).
//!   5. **Last-row PV emit**: the public value `seed_packed[k]`
//!      equals `Σ 2^j · u_xor_acc_bits[k * 16 + j]` evaluated on the
//!      last row.
//!   6. **LogUp Receive** on `pbkdf2_outputs`: per row, receive
//!      `(iter_index, u_packed[0..32])` with multiplicity 1, paired
//!      against the `Pbkdf2HmacAir` outer-row sender.

use core::borrow::Borrow;

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::pbkdf2_hmac::{BIP39_DEFAULT_ITERATIONS, PBKDF2_OUTPUTS_BUS_NAME};
use crate::pbkdf2_air::columns::{
    Pbkdf2AirCols, Pbkdf2AirPreprocessedCols, NUM_PBKDF2_AIR_COLS,
    NUM_PBKDF2_AIR_PREPROCESSED_COLS,
};
use crate::pbkdf2_air::constants::{NUM_SEED_LIMBS, NUM_U_LIMBS, PBKDF2_OUTPUTS_TUPLE_LEN};
use crate::sha512_air::constants::{BITS_PER_LIMB, STATE_WORDS, U64_LIMBS, WORD_BITS};

/// Public-value count: just `seed_packed` (32 cells × 16-bit limbs).
pub const NUM_PUBLIC_VALUES: usize = NUM_SEED_LIMBS;

/// PBKDF2 orchestrator AIR. Stateful by `num_iterations` (production
/// = `BIP39_DEFAULT_ITERATIONS = 2048`; tests use small values) and
/// `num_lookups` for the per-call permutation-trace column counter.
#[derive(Clone, Debug)]
pub struct Pbkdf2Air {
    pub num_iterations: usize,
    num_lookups: usize,
}

impl Default for Pbkdf2Air {
    fn default() -> Self {
        Self {
            num_iterations: BIP39_DEFAULT_ITERATIONS,
            num_lookups: 0,
        }
    }
}

impl Pbkdf2Air {
    pub const fn new(num_iterations: usize) -> Self {
        Self {
            num_iterations,
            num_lookups: 0,
        }
    }

    pub const fn trace_height(&self) -> usize {
        self.num_iterations
    }
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for Pbkdf2Air {
    fn width(&self) -> usize {
        NUM_PBKDF2_AIR_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Constraints in `eval`:
        //   - bool checks: deg 1
        //   - u_packed = pack(u_bits): deg 1
        //   - first-row boundary: deg 1
        //   - XOR transition `next.acc = next.u_bits + local.acc - 2 ·
        //     next.u_bits · local.acc`: deg 2 (one product term)
        //   - last-row PV emit: deg 1
        // LogUp transition: deg 2 (one outer entry, deg-1 mult).
        // Cap at 3 with headroom.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let trace_height = self.num_iterations;
        let mut values = vec![F::ZERO; trace_height * NUM_PBKDF2_AIR_PREPROCESSED_COLS];
        for row_index in 0..trace_height {
            values[row_index * NUM_PBKDF2_AIR_PREPROCESSED_COLS] = F::from_u32(row_index as u32);
        }
        Some(RowMajorMatrix::new(
            values,
            NUM_PBKDF2_AIR_PREPROCESSED_COLS,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for Pbkdf2Air
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot pattern (consistent with the rest of this codebase).
        let main_window = builder.main();
        let local: &Pbkdf2AirCols<AB::Var> = (*main_window.current_slice()).borrow();
        let next: &Pbkdf2AirCols<AB::Var> = (*main_window.next_slice()).borrow();

        let u_packed_local = local.u_packed;
        let u_bits_local = local.u_bits;
        let u_xor_acc_bits_local = local.u_xor_acc_bits;
        let u_bits_next = next.u_bits;
        let u_xor_acc_bits_next = next.u_xor_acc_bits;

        let public_values_snapshot: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public_values = builder.public_values();
            debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);
            let mut snapshot = [public_values[0]; NUM_PUBLIC_VALUES];
            for index in 0..NUM_PUBLIC_VALUES {
                snapshot[index] = public_values[index];
            }
            snapshot
        };

        // 1. Boolean range checks on primitive bit columns.
        for word in u_bits_local.iter() {
            for &bit in word.iter() {
                builder.assert_bool(bit);
            }
        }
        for word in u_xor_acc_bits_local.iter() {
            for &bit in word.iter() {
                builder.assert_bool(bit);
            }
        }

        // 2. `u_packed[k] = Σ 2^j · u_bits_word_flat[k * 16 + j]`
        // — per-limb packing, low-first within each 64-bit word.
        // `u_packed[word_index * 4 + limb_index]` aggregates
        // `u_bits[word_index][limb_index * 16 + (0..16)]`.
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                let mut packed: AB::Expr = AB::Expr::ZERO;
                for bit_offset in 0..BITS_PER_LIMB {
                    let pow = AB::Expr::from_u32(1u32 << bit_offset);
                    let bit: AB::Expr =
                        u_bits_local[word_index][limb_index * BITS_PER_LIMB + bit_offset]
                            .into();
                    packed = packed + pow * bit;
                }
                let cell: AB::Expr = u_packed_local[word_index * U64_LIMBS + limb_index].into();
                builder.assert_zero(cell - packed);
            }
        }

        // 3. First-row boundary: `u_xor_acc_bits[i] = u_bits[i]`.
        let mut when_first = builder.when_first_row();
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                when_first.assert_eq(
                    u_xor_acc_bits_local[word_index][bit_in_word],
                    u_bits_local[word_index][bit_in_word],
                );
            }
        }

        // 4. Cross-row transition: `next.u_xor_acc_bits[i] =
        // next.u_bits[i] ⊕ local.u_xor_acc_bits[i]`. XOR over GF(2)
        // for two booleans `a, b`: `a ⊕ b = a + b - 2ab`. Degree 2.
        let mut when_trans = builder.when_transition();
        let two_expr: AB::Expr = AB::Expr::TWO;
        for word_index in 0..STATE_WORDS {
            for bit_in_word in 0..WORD_BITS {
                let a: AB::Expr = u_bits_next[word_index][bit_in_word].into();
                let b: AB::Expr = u_xor_acc_bits_local[word_index][bit_in_word].into();
                let xor = a.clone() + b.clone() - two_expr.clone() * a * b;
                let next_acc: AB::Expr =
                    u_xor_acc_bits_next[word_index][bit_in_word].into();
                when_trans.assert_zero(next_acc - xor);
            }
        }

        // 5. Last-row PV emit: `seed_packed[k] = Σ 2^j ·
        // u_xor_acc_bits[k * 16 + j]` on the last row, per limb. The
        // packing matches the canonical 16-bits-low-first-per-word
        // convention (same as `compression_tuple`'s h_out portion).
        let mut when_last = builder.when_last_row();
        for word_index in 0..STATE_WORDS {
            for limb_index in 0..U64_LIMBS {
                let mut packed: AB::Expr = AB::Expr::ZERO;
                for bit_offset in 0..BITS_PER_LIMB {
                    let pow = AB::Expr::from_u32(1u32 << bit_offset);
                    let bit: AB::Expr = u_xor_acc_bits_local[word_index]
                        [limb_index * BITS_PER_LIMB + bit_offset]
                        .into();
                    packed = packed + pow * bit;
                }
                let pv_index = word_index * U64_LIMBS + limb_index;
                let pv: AB::Expr = public_values_snapshot[pv_index].into();
                when_last.assert_zero(pv - packed);
            }
        }
    }
}

impl<F: Field> LookupAir<F> for Pbkdf2Air {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;

        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_PBKDF2_AIR_COLS,
            preprocessed_width: NUM_PBKDF2_AIR_PREPROCESSED_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local: &Pbkdf2AirCols<_> = (*main_window.current_slice()).borrow();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local: &Pbkdf2AirPreprocessedCols<_> =
            (*preprocessed_window.current_slice()).borrow();

        // Tuple: [iter_index, u_packed[0..32]]. Same shape as the
        // sender's `Pbkdf2HmacAir` outer-row send (4th Lookup there).
        let mut tuple: Vec<SymbolicExpression<F>> =
            Vec::with_capacity(PBKDF2_OUTPUTS_TUPLE_LEN);
        tuple.push(preprocessed_local.iter_index.into());
        for limb_index in 0..NUM_U_LIMBS {
            tuple.push(main_local.u_packed[limb_index].into());
        }
        debug_assert_eq!(tuple.len(), PBKDF2_OUTPUTS_TUPLE_LEN);

        let multiplicity: SymbolicExpression<F> = SymbolicExpression::from(F::ONE);
        let lookup_inputs = [(tuple, multiplicity, Direction::Receive)];
        vec![LookupAir::register_lookup(
            self,
            Kind::Global(PBKDF2_OUTPUTS_BUS_NAME.to_string()),
            &lookup_inputs,
        )]
    }
}
