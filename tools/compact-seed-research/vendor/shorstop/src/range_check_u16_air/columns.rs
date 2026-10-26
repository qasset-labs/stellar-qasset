//! Column layout for the 16-bit range-check AIR.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

/// Main-trace columns (one row per table value).
#[repr(C)]
pub struct RangeCheckU16Cols<T> {
    /// How many times this row's table value was sent to the global bus
    /// across all participating AIRs.
    pub multiplicity: T,
}

/// Total main-trace column count.
pub const NUM_RANGE_CHECK_U16_COLS: usize = size_of::<RangeCheckU16Cols<u8>>();

/// Preprocessed-trace columns. Row $i$ has `value = i`.
#[repr(C)]
pub struct RangeCheckU16PreprocessedCols<T> {
    pub value: T,
}

/// Total preprocessed-trace column count.
pub const NUM_RANGE_CHECK_U16_PREPROCESSED_COLS: usize =
    size_of::<RangeCheckU16PreprocessedCols<u8>>();

impl<T> Borrow<RangeCheckU16Cols<T>> for [T] {
    fn borrow(&self) -> &RangeCheckU16Cols<T> {
        debug_assert_eq!(self.len(), NUM_RANGE_CHECK_U16_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<RangeCheckU16Cols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<RangeCheckU16Cols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut RangeCheckU16Cols<T> {
        debug_assert_eq!(self.len(), NUM_RANGE_CHECK_U16_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<RangeCheckU16Cols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<T> Borrow<RangeCheckU16PreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &RangeCheckU16PreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_RANGE_CHECK_U16_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<RangeCheckU16PreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
