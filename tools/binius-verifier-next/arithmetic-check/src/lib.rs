// SPDX-License-Identifier: MIT
//! Pure arithmetic cross-implementation checks, not a proof verifier.
#![no_std]
use binius_field::WithUnderlier;
use binius_field::{BinaryField128bGhash as F, Field};
use core::alloc::{GlobalAlloc, Layout};
struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
static mut CURSOR: usize = 0;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let current = core::arch::wasm32::memory_size(0) * 65536;
        let cursor = unsafe { CURSOR };
        let cursor = if cursor == 0 { current } else { cursor };
        let Some(start) = cursor.checked_next_multiple_of(layout.align()) else {
            return core::ptr::null_mut();
        };
        let Some(end) = start.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > 40 * 1024 * 1024 {
            return core::ptr::null_mut();
        }
        let pages = end.div_ceil(65536);
        let old = core::arch::wasm32::memory_size(0);
        if pages > old && core::arch::wasm32::memory_grow(0, pages - old) == usize::MAX {
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
static mut RESULT: [u32; 4] = [0; 4];
#[unsafe(no_mangle)]
pub extern "C" fn qasset_arithmetic_inverse(w0: u32, w1: u32, w2: u32, w3: u32) -> u32 {
    let value = (w0 as u128) | ((w1 as u128) << 32) | ((w2 as u128) << 64) | ((w3 as u128) << 96);
    let field = F::new(value);
    let inverse = field.invert().unwrap_or(F::ZERO);
    let raw = inverse.to_underlier();
    unsafe {
        RESULT = [
            raw as u32,
            (raw >> 32) as u32,
            (raw >> 64) as u32,
            (raw >> 96) as u32,
        ];
    }
    ((field * inverse) == if value == 0 { F::ZERO } else { F::ONE }) as u32
}
#[unsafe(no_mangle)]
pub extern "C" fn qasset_arithmetic_word(index: u32) -> u32 {
    if index >= 4 {
        return 0;
    }
    unsafe { RESULT[index as usize] }
}
