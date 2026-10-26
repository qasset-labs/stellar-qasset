//! AIR + LookupAir definition for the 16-bit range-check AIR.
//!
//! The AIR's `eval` is empty; the only constraint binding `multiplicity`
//! to the table value is the LogUp lookup itself, which is registered
//! via the `LookupAir` impl and evaluated by `eval_with_lookups` inside
//! the prover/verifier batch flow.

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::range_check_u16_air::columns::{
    NUM_RANGE_CHECK_U16_COLS, NUM_RANGE_CHECK_U16_PREPROCESSED_COLS,
};
use crate::range_check_u16_air::constants::{BUS_NAME, TABLE_HEIGHT};

/// Marker AIR for the 16-bit range-check table. Stateful (`num_lookups`)
/// because [`LookupAir::add_lookup_columns`] mutates per-call to allocate
/// fresh permutation-trace column indices.
#[derive(Clone, Default)]
pub struct RangeCheckU16Air {
    /// Number of lookup columns this AIR has allocated so far. Updated by
    /// [`LookupAir::add_lookup_columns`]; reset to 0 at the start of
    /// [`LookupAir::get_lookups`] so the call is idempotent.
    num_lookups: usize,
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for RangeCheckU16Air {
    fn width(&self) -> usize {
        NUM_RANGE_CHECK_U16_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // No `eval` constraints; LogUp constraints (handled separately by
        // the gadget) are degree ≤ 3 for our usage. Cap at 3.
        Some(3)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        // Row i holds the table value i. `from_u32` lifts u32 → F via the
        // ring's prime characteristic.
        let mut values: Vec<F> = Vec::with_capacity(TABLE_HEIGHT);
        for i in 0..TABLE_HEIGHT {
            values.push(F::from_u32(i as u32));
        }
        Some(RowMajorMatrix::new(
            values,
            NUM_RANGE_CHECK_U16_PREPROCESSED_COLS,
        ))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder> Air<AB> for RangeCheckU16Air
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, _builder: &mut AB) {
        // Intentionally empty. The lookup constraint is the entire purpose
        // of this AIR; it is added via `eval_with_lookups` (LogUpGadget).
    }
}

impl<F: Field> LookupAir<F> for RangeCheckU16Air {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_index = self.num_lookups;
        self.num_lookups += 1;
        vec![new_index]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        // Reset so this is idempotent across multiple calls.
        self.num_lookups = 0;

        // Build symbolic references to the preprocessed and main columns.
        let symbolic_builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: NUM_RANGE_CHECK_U16_COLS,
            preprocessed_width: NUM_RANGE_CHECK_U16_PREPROCESSED_COLS,
            ..Default::default()
        });
        let main_window = symbolic_builder.main();
        let main_local = main_window.current_slice();
        let preprocessed_window = symbolic_builder.preprocessed();
        let preprocessed_local = preprocessed_window.current_slice();

        // The receive side: one element-tuple per row, multiplicity from
        // the main `multiplicity` column.
        let element_tuple: Vec<SymbolicExpression<F>> = vec![preprocessed_local[0].into()];
        let multiplicity_expression: SymbolicExpression<F> = main_local[0].into();

        let lookup_inputs: [(Vec<SymbolicExpression<F>>, SymbolicExpression<F>, Direction); 1] = [(
            element_tuple,
            multiplicity_expression,
            Direction::Receive,
        )];

        let lookup = LookupAir::register_lookup(
            self,
            Kind::Global(BUS_NAME.to_string()),
            &lookup_inputs,
        );
        vec![lookup]
    }
}
