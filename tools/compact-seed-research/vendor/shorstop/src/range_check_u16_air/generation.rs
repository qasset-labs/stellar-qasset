//! Trace generation for the 16-bit range-check AIR.
//!
//! Given a stream of `u16` values that other AIRs sent to the bus, count
//! occurrences of each value and write the per-row `multiplicity` column
//! so multiset equality holds.

use core::borrow::BorrowMut;

use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

use crate::range_check_u16_air::columns::{NUM_RANGE_CHECK_U16_COLS, RangeCheckU16Cols};
use crate::range_check_u16_air::constants::TABLE_HEIGHT;

/// Build the range-check AIR's main trace from a flat list of values
/// that were sent to the global `u16_range` bus.
///
/// The trace has exactly `TABLE_HEIGHT = 2^16` rows. Row $i$'s
/// `multiplicity` column is the count of `i` in `sent_values`.
pub fn generate_trace<F: PrimeField64>(sent_values: &[u16]) -> RowMajorMatrix<F> {
    let mut occurrence_counts: Vec<u32> = vec![0; TABLE_HEIGHT];
    for &sent_value in sent_values.iter() {
        occurrence_counts[sent_value as usize] += 1;
    }

    let mut trace_values = vec![F::ZERO; TABLE_HEIGHT * NUM_RANGE_CHECK_U16_COLS];
    for (row_index, row_chunk) in trace_values
        .chunks_exact_mut(NUM_RANGE_CHECK_U16_COLS)
        .enumerate()
    {
        let columns: &mut RangeCheckU16Cols<F> = row_chunk.borrow_mut();
        columns.multiplicity = F::from_u64(occurrence_counts[row_index] as u64);
    }

    RowMajorMatrix::new(trace_values, NUM_RANGE_CHECK_U16_COLS)
}
