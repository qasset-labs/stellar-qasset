// SPDX-License-Identifier: MIT
//! Bounded external-input raw Wasm experiment. No contract ABI or authority changes.
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

// The host writes exactly one bounded input slab before calling either verifier.
// These raw-memory exports are a test ABI, not a Soroban contract interface.
static mut INPUT_PTR: usize = 0;
static mut SETUP_LEN: usize = 0;
static mut PROOF_LEN: usize = 0;
static mut CONSUMED: bool = false;

#[unsafe(no_mangle)]
pub extern "C" fn qasset_prepare_input(setup_len: u32, proof_len: u32) -> u32 {
    if setup_len == 0
        || setup_len > 3 * 1024 * 1024
        || proof_len > 1024 * 1024
        || unsafe { INPUT_PTR != 0 }
    {
        return 0;
    }
    let Some(total) = (setup_len as usize)
        .checked_add(proof_len as usize)
        .and_then(|n| n.checked_add(96))
    else {
        return 0;
    };
    let input = alloc::vec![0u8;total].into_boxed_slice();
    let pointer = input.as_ptr() as usize;
    unsafe {
        INPUT_PTR = pointer;
        SETUP_LEN = setup_len as usize;
        PROOF_LEN = proof_len as usize;
    }
    let _ = alloc::boxed::Box::into_raw(input);
    pointer as u32
}

fn execute(identity_only: bool) -> u32 {
    let (pointer, setup_len, proof_len) = unsafe { (INPUT_PTR, SETUP_LEN, PROOF_LEN) };
    if pointer == 0 || unsafe { CONSUMED } {
        return 0;
    }
    unsafe {
        CONSUMED = true;
    }
    // Pointer and lengths originate only from the checked allocation above.
    // The single-threaded no-import module cannot run another export concurrently.
    let input =
        unsafe { core::slice::from_raw_parts(pointer as *const u8, setup_len + 96 + proof_len) };
    let setup = &input[..setup_len];
    let scalar: &[u8; 32] = match input[setup_len..setup_len + 32].try_into() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let action: &[u8; 64] = match input[setup_len + 32..setup_len + 96].try_into() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // This experiment supports only the independently pinned RFC8032 public key.
    // Accepting a different protected identity requires a separate reviewed point anchor.
    if scalar != &SCALAR {
        return 0;
    }
    unsafe {
        PHASE = 1;
    }
    let verifier = match frozen::load(setup) {
        Ok(v) => v,
        Err(_) => {
            let error = "preprocessing_identity_or_decode_failed";
            unsafe {
                ERROR_PTR = error.as_ptr() as u32;
                ERROR_LEN = error.len() as u32;
            }
            return 0;
        }
    };
    if identity_only {
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
    let proof = &input[setup_len + 96..];
    let result = qasset_binius_nostd_verifier::verify_preprocessed_detailed(
        &verifier, proof, scalar, action,
    );
    if let Err(error) = result {
        unsafe {
            ERROR_PTR = error.as_ptr() as u32;
            ERROR_LEN = error.len() as u32;
        }
    }
    unsafe {
        PHASE = 3;
    }
    result.is_ok() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn qasset_verify_external() -> u32 {
    execute(false)
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_check_preprocessing() -> u32 {
    execute(true)
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_transcript_vector(index: u32) -> u32 {
    qasset_binius_nostd_verifier::regression::transcript_vector()
        .get(index as usize)
        .copied()
        .unwrap_or(u32::MAX)
}
const SCALAR: [u8; 32] = [
    48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104, 217,
    128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79,
];
