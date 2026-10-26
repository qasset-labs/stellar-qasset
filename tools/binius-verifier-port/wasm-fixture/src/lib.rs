// SPDX-License-Identifier: MIT
//! Raw Wasm fixed public-fixture experiment. No authority changes or contract ABI.
#![no_std]
extern crate alloc;
use core::alloc::{GlobalAlloc, Layout};
mod frozen;

const MAX_MEMORY: usize = 40 * 1024 * 1024;
struct Bump;
static mut CURSOR: usize = 0;
static mut PHASE: u32 = 0;
static mut ERROR_PTR: u32 = 0;
static mut ERROR_LEN: u32 = 0;
#[global_allocator]
static ALLOCATOR: Bump = Bump;
// Single-threaded, import-free fixture module. Allocation never calls guest code.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let initial = core::arch::wasm32::memory_size(0) * 65536;
        let cursor = unsafe { CURSOR };
        let cursor = if cursor == 0 { initial } else { cursor };
        let Some(start) = cursor.checked_next_multiple_of(layout.align()) else {
            return core::ptr::null_mut();
        };
        let Some(end) = start.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > MAX_MEMORY {
            return core::ptr::null_mut();
        }
        let pages = end.div_ceil(65536);
        let current = core::arch::wasm32::memory_size(0);
        if pages > current && core::arch::wasm32::memory_grow(0, pages - current) == usize::MAX {
            return core::ptr::null_mut();
        }
        unsafe {
            CURSOR = end;
        }
        core::ptr::with_exposed_provenance_mut(start)
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_error_ptr() -> u32 {
    unsafe { ERROR_PTR }
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_error_len() -> u32 {
    unsafe { ERROR_LEN }
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_phase() -> u32 {
    unsafe { PHASE }
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_allocated_end() -> u32 {
    unsafe { CURSOR as u32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_verify_fixture(case: u32) -> u32 {
    // This public RFC8032 fixture's scalar-point equality is independently pinned.
    // It is not a generic supplied-key interface or a deployable recovery contract.
    let scalar: [u8; 32] = SCALAR;
    let mut action: [u8; 64] = ACTION;
    let original = include_bytes!(concat!(env!("QASSET_RESEARCH_FIXTURE_DIR"), "/proof.bin"));
    let mut changed = alloc::vec::Vec::new();
    let proof: &[u8] = match case {
        0 | 1 | 6 | 7 | 8 => original,
        2 => {
            changed.extend_from_slice(original);
            changed[100] ^= 1;
            &changed
        }
        3 => {
            changed.extend_from_slice(original);
            changed.push(0);
            &changed
        }
        4 => &original[..original.len() - 1],
        5 => &[],
        _ => return 0,
    };
    if case == 1 {
        action[0] ^= 1;
    }
    let mut scalar_arg = scalar;
    if case == 6 {
        scalar_arg[8] ^= 1;
    }
    if case == 8 {
        scalar_arg[0] |= 1;
    }
    // Fail closed when scalar differs from the protected fixture identity.
    if scalar_arg != SCALAR {
        return 0;
    }
    unsafe {
        PHASE = 1;
    }
    let verifier = match frozen::load(include_bytes!(concat!(
        env!("QASSET_RESEARCH_FIXTURE_DIR"),
        "/fixed-setup.bin"
    ))) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if case == 7 {
        let same = frozen::padded_constraints_sha256(&verifier)
            .is_ok_and(|h| h == "0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938");
        unsafe {
            PHASE = 3;
        }
        return same as u32;
    }
    unsafe {
        PHASE = 2;
    }
    let detailed = qasset_binius_nostd_verifier::verify_preprocessed_detailed(
        &verifier,
        proof,
        &scalar_arg,
        &action,
    );
    let result = detailed.is_ok();
    if let Err(error) = detailed {
        unsafe {
            ERROR_PTR = error.as_ptr() as u32;
            ERROR_LEN = error.len() as u32;
        }
    }
    unsafe {
        PHASE = 3;
    }
    result as u32
}

const SCALAR: [u8; 32] = [
    48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104, 217,
    128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79,
];
const ACTION: [u8; 64] = [
    255, 44, 210, 159, 4, 68, 214, 65, 255, 84, 87, 83, 209, 204, 191, 239, 221, 102, 225, 214,
    141, 237, 234, 32, 57, 231, 221, 100, 244, 218, 180, 73, 24, 108, 200, 187, 177, 179, 10, 130,
    101, 223, 172, 144, 165, 93, 46, 100, 28, 77, 60, 40, 6, 154, 168, 29, 108, 24, 216, 187, 157,
    93, 190, 100,
];

#[unsafe(no_mangle)]
pub extern "C" fn qasset_transcript_vector(index: u32) -> u32 {
    qasset_binius_nostd_verifier::regression::transcript_vector()
        .get(index as usize)
        .copied()
        .unwrap_or(u32::MAX)
}
