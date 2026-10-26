//! `prove_batch` / `verify_batch` test for the PBKDF2 orchestrator
//! paired with the full upstream chain: `Sha512Air` (sender) +
//! `HmacKeyschedAir` (PV producer) + `Pbkdf2HmacAir` (per-iteration
//! HMACs, sends on `pbkdf2_outputs`) + `Pbkdf2Air` (this AIR,
//! receives + XOR-folds).
//!
//! Cross-check: the AIR's emitted `seed_packed` PV must equal the
//! XOR of `(U_1, …, U_c)` computed off-circuit by a reference
//! HMAC-SHA512 chain.

#![cfg(test)]

use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha512};

use crate::hmac_air::keysched::{
    generate_keysched_witness, public_values as keysched_public_values, HmacKeyschedAir,
    KEYSCHED_TRACE_HEIGHT,
};
use crate::hmac_air::pbkdf2_hmac::{
    bip39_salt_plus_int1, generate_pbkdf2_hmac_witness, Pbkdf2HmacAir, FIRST_ITER_MSG_BYTE_LEN,
};
use crate::pbkdf2_air::air::Pbkdf2Air;
use crate::pbkdf2_air::generation::generate_pbkdf2_air_witness;
use crate::sha512_air::air::Sha512Air;
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::constants::{BLOCK_WORDS, SHA512_IV, STATE_WORDS};
use crate::sha512_air::generation::{
    fill_row_u64, generate_trace as generate_sha512_trace, h_out_bytes_be,
};
use crate::{make_config, Val};

#[derive(Clone)]
enum FullChainAir {
    Sha512(Sha512Air),
    HmacKeysched(HmacKeyschedAir),
    Pbkdf2Hmac(Pbkdf2HmacAir),
    Pbkdf2(Pbkdf2Air),
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for FullChainAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::width(inner),
            Self::HmacKeysched(inner) => <HmacKeyschedAir as BaseAir<F>>::width(inner),
            Self::Pbkdf2Hmac(inner) => <Pbkdf2HmacAir as BaseAir<F>>::width(inner),
            Self::Pbkdf2(inner) => <Pbkdf2Air as BaseAir<F>>::width(inner),
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::max_constraint_degree(inner),
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::max_constraint_degree(inner)
            }
            Self::Pbkdf2Hmac(inner) => {
                <Pbkdf2HmacAir as BaseAir<F>>::max_constraint_degree(inner)
            }
            Self::Pbkdf2(inner) => <Pbkdf2Air as BaseAir<F>>::max_constraint_degree(inner),
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::preprocessed_trace(inner),
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::preprocessed_trace(inner)
            }
            Self::Pbkdf2Hmac(inner) => <Pbkdf2HmacAir as BaseAir<F>>::preprocessed_trace(inner),
            Self::Pbkdf2(inner) => <Pbkdf2Air as BaseAir<F>>::preprocessed_trace(inner),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => {
                <Sha512Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::Pbkdf2Hmac(inner) => {
                <Pbkdf2HmacAir as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::Pbkdf2(inner) => {
                <Pbkdf2Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::num_public_values(inner),
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::num_public_values(inner)
            }
            Self::Pbkdf2Hmac(inner) => <Pbkdf2HmacAir as BaseAir<F>>::num_public_values(inner),
            Self::Pbkdf2(inner) => <Pbkdf2Air as BaseAir<F>>::num_public_values(inner),
        }
    }
}

impl<AB: AirBuilder> Air<AB> for FullChainAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Sha512(inner) => <Sha512Air as Air<AB>>::eval(inner, builder),
            Self::HmacKeysched(inner) => <HmacKeyschedAir as Air<AB>>::eval(inner, builder),
            Self::Pbkdf2Hmac(inner) => <Pbkdf2HmacAir as Air<AB>>::eval(inner, builder),
            Self::Pbkdf2(inner) => <Pbkdf2Air as Air<AB>>::eval(inner, builder),
        }
    }
}

impl<F: Field> LookupAir<F> for FullChainAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::HmacKeysched(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::Pbkdf2Hmac(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::Pbkdf2(inner) => LookupAir::<F>::add_lookup_columns(inner),
        }
    }
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::get_lookups(inner),
            Self::HmacKeysched(inner) => LookupAir::<F>::get_lookups(inner),
            Self::Pbkdf2Hmac(inner) => LookupAir::<F>::get_lookups(inner),
            Self::Pbkdf2(inner) => LookupAir::<F>::get_lookups(inner),
        }
    }
}

// ── Reference HMAC + PBKDF2 (sha2 backend) ────────────────────────────

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

fn reference_pbkdf2_seed(
    key: &[u8],
    salt_plus_int1: &[u8; FIRST_ITER_MSG_BYTE_LEN],
    iterations: usize,
) -> [u8; 64] {
    let mut chain: Vec<[u8; 64]> = Vec::with_capacity(iterations);
    chain.push(reference_hmac_sha512(key, salt_plus_int1));
    for i in 1..iterations {
        chain.push(reference_hmac_sha512(key, &chain[i - 1]));
    }
    let mut seed = [0u8; 64];
    for u_i in chain.iter() {
        for j in 0..64 {
            seed[j] ^= u_i[j];
        }
    }
    seed
}

const fn ext_log_for(real_height: usize) -> usize {
    let mut log = 0;
    let mut x = real_height;
    while x > 1 {
        x >>= 1;
        log += 1;
    }
    log + 1
}

const TEST_NUM_ITERATIONS: usize = 2;

/// Pair the full upstream chain with `Pbkdf2Air` and verify that the
/// emitted `seed_packed` PV equals the XOR-fold of the reference
/// PBKDF2 chain.
#[test]
fn pbkdf2_air_emits_correct_seed_for_small_chain() {
    let key: &[u8] = b"test-orchestrator-key";
    let salt_plus_int1 = bip39_salt_plus_int1();

    // Off-circuit reference seed.
    let expected_seed = reference_pbkdf2_seed(key, &salt_plus_int1, TEST_NUM_ITERATIONS);

    // Witnesses for each AIR.
    let keysched = generate_keysched_witness::<Val>(key);
    let keysched_pv = keysched_public_values(&keysched);
    let read_state_from_pv = |offset: usize| -> [u64; STATE_WORDS] {
        let mut state = [0u64; STATE_WORDS];
        for word_index in 0..STATE_WORDS {
            let mut word_value: u64 = 0;
            for limb_index in 0..4 {
                let limb_u32 = keysched_pv[offset + word_index * 4 + limb_index]
                    .as_canonical_u32();
                word_value |= (limb_u32 as u64) << (limb_index * 16);
            }
            state[word_index] = word_value;
        }
        state
    };
    let ipad_state_words = read_state_from_pv(0);
    let opad_state_words = read_state_from_pv(STATE_WORDS * 4);

    let pbkdf2_hmac = generate_pbkdf2_hmac_witness::<Val>(
        TEST_NUM_ITERATIONS,
        ipad_state_words,
        opad_state_words,
        &salt_plus_int1,
    );
    let pbkdf2_air = generate_pbkdf2_air_witness::<Val>(&pbkdf2_hmac.u_digests);

    // Verify the orchestrator's `seed_packed` matches the reference
    // seed BEFORE running prove/verify (catches generator bugs early).
    let mut expected_seed_packed: Vec<Val> = Vec::with_capacity(32);
    for word_index in 0..STATE_WORDS {
        let mut w = [0u8; 8];
        w.copy_from_slice(&expected_seed[word_index * 8..(word_index + 1) * 8]);
        let word_value = u64::from_be_bytes(w);
        for limb_index in 0..4 {
            let limb_value = (word_value >> (limb_index * 16)) & 0xFFFF;
            expected_seed_packed.push(Val::from_u64(limb_value));
        }
    }
    assert_eq!(
        pbkdf2_air.seed_packed, expected_seed_packed,
        "Pbkdf2Air generator must produce seed = XOR(U_1, …, U_c)"
    );

    // Build SHA-512 sender input set.
    let sha_inputs = build_sha512_inputs_for_full_chain(
        key,
        &salt_plus_int1,
        ipad_state_words,
        opad_state_words,
        &pbkdf2_hmac.u_digests,
    );
    let sha_trace = generate_sha512_trace::<Val>(&sha_inputs);
    let total_sha_compressions = sha_inputs.len();

    let mut airs = [
        FullChainAir::Sha512(Sha512Air::new(total_sha_compressions)),
        FullChainAir::HmacKeysched(HmacKeyschedAir::default()),
        FullChainAir::Pbkdf2Hmac(Pbkdf2HmacAir::new(TEST_NUM_ITERATIONS)),
        FullChainAir::Pbkdf2(Pbkdf2Air::new(TEST_NUM_ITERATIONS)),
    ];

    let sha_real_height = total_sha_compressions.next_power_of_two();
    let pbkdf2_hmac_height = 2 * TEST_NUM_ITERATIONS;
    let ext_log_heights = [
        ext_log_for(sha_real_height),
        ext_log_for(KEYSCHED_TRACE_HEIGHT),
        ext_log_for(pbkdf2_hmac_height),
        ext_log_for(TEST_NUM_ITERATIONS),
    ];

    let config = make_config();
    let prover_data =
        ProverData::from_airs_and_degrees(&config, &mut airs, &ext_log_heights);
    let traces = [
        &sha_trace,
        &keysched.trace,
        &pbkdf2_hmac.trace,
        &pbkdf2_air.trace,
    ];
    let public_values_per_instance = [
        Vec::<Val>::new(),
        keysched_pv.clone(),
        pbkdf2_hmac.public_values.clone(),
        pbkdf2_air.seed_packed.clone(),
    ];

    let common = &prover_data.common;
    let instances =
        StarkInstance::new_multiple(&airs, &traces, &public_values_per_instance, common);
    let proof = prove_batch(&config, &instances, &prover_data);

    let public_values_for_verify = vec![
        Vec::<Val>::new(),
        keysched_pv,
        pbkdf2_hmac.public_values,
        pbkdf2_air.seed_packed,
    ];
    verify_batch(&config, &airs, &proof, &public_values_for_verify, common)
        .expect("honest full-chain witness must pass batched verify");
}

// ── SHA-512 sender input list builder ────────────────────────────────

fn build_sha512_inputs_for_full_chain(
    key: &[u8],
    salt_plus_int1: &[u8; FIRST_ITER_MSG_BYTE_LEN],
    ipad_state_words: [u64; STATE_WORDS],
    opad_state_words: [u64; STATE_WORDS],
    u_chain: &[[u8; 64]],
) -> Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> {
    let mut inputs: Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> = Vec::new();

    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);
    let mut ipad_block_bytes = [0u8; 128];
    let mut opad_block_bytes = [0u8; 128];
    for i in 0..128 {
        ipad_block_bytes[i] = key_padded[i] ^ 0x36;
        opad_block_bytes[i] = key_padded[i] ^ 0x5C;
    }
    inputs.push((SHA512_IV, bytes_128_to_words(&ipad_block_bytes)));
    inputs.push((SHA512_IV, bytes_128_to_words(&opad_block_bytes)));

    for iter_index in 0..u_chain.len() {
        let inner_msg: Vec<u8> = if iter_index == 0 {
            salt_plus_int1.to_vec()
        } else {
            u_chain[iter_index - 1].to_vec()
        };
        let inner_block_bytes = sha512_pad_for_hmac(&inner_msg);
        inputs.push((ipad_state_words, bytes_128_to_words(&inner_block_bytes)));

        let inner_digest = compress_off_circuit(ipad_state_words, &inner_block_bytes);
        let outer_block_bytes = sha512_pad_for_hmac(&inner_digest);
        inputs.push((opad_state_words, bytes_128_to_words(&outer_block_bytes)));
    }

    inputs
}

fn sha512_pad_for_hmac(msg: &[u8]) -> [u8; 128] {
    assert!(msg.len() <= 111);
    let mut block = [0u8; 128];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] = 0x80;
    let bit_len = ((128 + msg.len()) as u128) * 8;
    block[112..128].copy_from_slice(&bit_len.to_be_bytes());
    block
}

fn bytes_128_to_words(bytes: &[u8; 128]) -> [u64; BLOCK_WORDS] {
    let mut words = [0u64; BLOCK_WORDS];
    for word_index in 0..BLOCK_WORDS {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&bytes[word_index * 8..(word_index + 1) * 8]);
        words[word_index] = u64::from_be_bytes(word_bytes);
    }
    words
}

fn compress_off_circuit(h_in: [u64; STATE_WORDS], block_bytes: &[u8; 128]) -> [u8; 64] {
    let block_words = bytes_128_to_words(block_bytes);
    let mut row = vec![0u64; NUM_SHA512_COLS];
    fill_row_u64(h_in, block_words, &mut row);
    h_out_bytes_be(&row)
}
