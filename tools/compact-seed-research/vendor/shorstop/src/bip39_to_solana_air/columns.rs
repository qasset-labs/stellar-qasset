//! Column layout for the BIP-39 → Solana composition AIR.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

/// Number of 8-bit-limb cells exposing the Solana address (= Ed25519
/// `y_A` coordinate, 32 bytes). Solana addresses are the base58
/// encoding of this 32-byte form.
pub const NUM_SOLANA_ADDRESS_BYTES: usize = 32;
pub const NUM_PQ_DESTINATION_BYTES: usize = 32;
pub const NUM_RECENT_BLOCKHASH_BYTES: usize = 32;

/// Trace height: 2 rows (FRI's minimum). Row 0 holds the address
/// cells; row 1 is padding gated out of any future bus interaction
/// by `is_extract_row`.
pub const BIP39_TO_SOLANA_TRACE_HEIGHT: usize = 2;

#[repr(C)]
pub struct Bip39ToSolanaCols<T> {
    /// 32 cells holding the Solana address bytes
    /// (= Ed25519 `y_A` as 8-bit limbs, byte-flat).
    pub solana_address: [T; NUM_SOLANA_ADDRESS_BYTES],
    /// 32 cells holding the destination PQ address for binding.
    pub pq_destination_address: [T; NUM_PQ_DESTINATION_BYTES],
    /// 32 cells holding the recent Solana blockhash for freshness.
    pub recent_blockhash: [T; NUM_RECENT_BLOCKHASH_BYTES],
}

pub const NUM_BIP39_TO_SOLANA_COLS: usize = size_of::<Bip39ToSolanaCols<u8>>();

impl<T> Borrow<Bip39ToSolanaCols<T>> for [T] {
    fn borrow(&self) -> &Bip39ToSolanaCols<T> {
        debug_assert_eq!(self.len(), NUM_BIP39_TO_SOLANA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Bip39ToSolanaCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Bip39ToSolanaCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Bip39ToSolanaCols<T> {
        debug_assert_eq!(self.len(), NUM_BIP39_TO_SOLANA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Bip39ToSolanaCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

#[repr(C)]
pub struct Bip39ToSolanaPreprocessedCols<T> {
    /// 1 on row 0, 0 on row 1. Gates the PV-equality constraint
    /// (`solana_address[i] = PV[i]`) to fire on row 0 only.
    pub is_extract_row: T,
}

pub const NUM_BIP39_TO_SOLANA_PREPROCESSED_COLS: usize =
    size_of::<Bip39ToSolanaPreprocessedCols<u8>>();

impl<T> Borrow<Bip39ToSolanaPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &Bip39ToSolanaPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_BIP39_TO_SOLANA_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<Bip39ToSolanaPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment mismatch");
        debug_assert!(suffix.is_empty(), "alignment mismatch");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
