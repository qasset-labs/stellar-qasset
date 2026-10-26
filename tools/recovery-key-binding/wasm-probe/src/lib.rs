//! Public-fixture mathematical binding execution; no signatures, seeds or authority.
#![no_std]
use qasset_recovery_key_binding::{check_clamped_scalar_binding, fixture_vectors::VECTORS};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

/// IDs0..17 verify independent RFC8032/SEP5 vectors; IDs18..24 reject mutations.
#[no_mangle]
pub extern "C" fn qasset_check_binding(case: u32) -> i32 {
    let mut fixture = VECTORS[0];
    if case < VECTORS.len() as u32 {
        fixture = VECTORS[case as usize];
    } else {
        match case {
            18 => fixture.public_key = VECTORS[1].public_key,
            19 => fixture.scalar[1] ^= 1,
            20 => fixture.scalar[0] ^= 1,
            21 => {
                fixture.public_key = [0u8; 32];
                fixture.public_key[0] = 1;
            }
            22 => fixture.public_key = [0u8; 32],
            23 => {
                fixture.public_key = [0xff; 32];
                fixture.public_key[0] = 0xed;
                fixture.public_key[31] = 0x7f;
            }
            24 => {
                fixture.public_key = [0u8; 32];
                fixture.public_key[0] = 1;
                fixture.public_key[31] = 0x80;
            }
            _ => return -1,
        }
    }
    i32::from(check_clamped_scalar_binding(&fixture.scalar, &fixture.public_key).is_ok())
}
