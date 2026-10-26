//! Witness-level sanity test for [`Pbkdf2HmacAir`]. The full
//! prove/verify integration (with the keyschedule + the Phase 3
//! orchestrator that closes the `pbkdf2_outputs` bus) lives in
//! [`crate::pbkdf2_air::tests`].
//!
//! This file used to also host a 3-AIR prove/verify test — that test
//! became infeasible (and redundant with `pbkdf2_air::tests`) once
//! Phase 3 added the `pbkdf2_outputs` bus send to `Pbkdf2HmacAir`:
//! the bus must be balanced by a receiver, which only `Pbkdf2Air`
//! provides.

#![cfg(test)]

use p3_field::PrimeField32;
use sha2::{Digest, Sha512};

use crate::hmac_air::keysched::{
    generate_keysched_witness, public_values as keysched_public_values,
};
use crate::hmac_air::pbkdf2_hmac::{
    bip39_salt_plus_int1, generate_pbkdf2_hmac_witness, FIRST_ITER_MSG_BYTE_LEN,
};
use crate::sha512_air::constants::STATE_WORDS;
use crate::Val;

/// One HMAC-SHA512 with K' zero-padded to 128 bytes (short-key path).
fn reference_hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    assert!(key.len() <= 128);
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);
    let mut ipad_block = [0u8; 128];
    let mut opad_block = [0u8; 128];
    for i in 0..128 {
        ipad_block[i] = key_padded[i] ^ 0x36;
        opad_block[i] = key_padded[i] ^ 0x5C;
    }
    let mut inner = Sha512::new();
    inner.update(ipad_block);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad_block);
    outer.update(&inner_digest);
    let outer_digest = outer.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&outer_digest);
    output
}

fn read_state_from_pv(pv: &[Val], pv_offset: usize) -> [u64; STATE_WORDS] {
    let mut state = [0u64; STATE_WORDS];
    for word_index in 0..STATE_WORDS {
        let mut word_value: u64 = 0;
        for limb_index in 0..4 {
            let limb_u32 = pv[pv_offset + word_index * 4 + limb_index].as_canonical_u32();
            word_value |= (limb_u32 as u64) << (limb_index * 16);
        }
        state[word_index] = word_value;
    }
    state
}

/// With `c = 1`, `U_1 = HMAC(K, salt+INT(1))`. The PBKDF2 generator's
/// outer row's `h_out` (= the only `u_digest`) must equal a reference
/// HMAC byte-for-byte. Catches generator bugs without engaging the
/// global `sha512_compressions` or `pbkdf2_outputs` busses.
#[test]
fn pbkdf2_witness_u1_matches_reference_hmac() {
    let key: &[u8] = b"abc";
    let salt_plus_int1 = bip39_salt_plus_int1();

    let keysched = generate_keysched_witness::<Val>(key);
    let keysched_pv = keysched_public_values(&keysched);
    let ipad_state_words = read_state_from_pv(&keysched_pv, 0);
    let opad_state_words = read_state_from_pv(&keysched_pv, STATE_WORDS * 4);

    let _ = FIRST_ITER_MSG_BYTE_LEN; // documentation cross-link
    let witness = generate_pbkdf2_hmac_witness::<Val>(
        1,
        ipad_state_words,
        opad_state_words,
        &salt_plus_int1,
    );

    let expected_u1 = reference_hmac_sha512(key, &salt_plus_int1);
    assert_eq!(witness.u_digests.len(), 1);
    assert_eq!(
        witness.u_digests[0], expected_u1,
        "PBKDF2 generator's U_1 must equal reference HMAC(K, salt||INT(1))"
    );
}
