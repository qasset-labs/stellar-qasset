//! `prove_batch` / `verify_batch` test for the Phase 4 minimal
//! SLIP-0010 priv-extractor paired with `Slip10HmacAir` + a dedicated
//! SHA-512 sender. Validates the `slip10_priv_outputs` bus pairing
//! and that the emitted `priv_packed` PV equals the first 32 bytes
//! of the chain's last HMAC output.

#![cfg(test)]

use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::slip10_hmac::{
    generate_slip10_hmac_trace, public_values_for_instance as slip10_hmac_pv,
    Slip10CompressionInput, Slip10HmacAir, NUM_PATH_INDEX_BE_BYTES, NUM_REAL_SLIP10_ROWS,
    SLIP10_TRACE_HEIGHT,
};
use crate::sha512_air::air::Sha512Air;
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::constants::{BLOCK_WORDS, SHA512_IV, STATE_WORDS};
use crate::sha512_air::generation::{
    fill_row_u64, generate_trace as generate_sha512_trace, h_out_bytes_be,
};
use crate::slip10_air::air::Slip10Air;
use crate::slip10_air::generation::generate_slip10_air_witness;
use crate::{make_config, Val};

#[derive(Clone)]
enum BenchAir {
    Sha512(Sha512Air),
    Slip10Hmac(Slip10HmacAir),
    Slip10(Slip10Air),
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for BenchAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::width(inner),
            Self::Slip10Hmac(inner) => <Slip10HmacAir as BaseAir<F>>::width(inner),
            Self::Slip10(inner) => <Slip10Air as BaseAir<F>>::width(inner),
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::max_constraint_degree(inner),
            Self::Slip10Hmac(inner) => {
                <Slip10HmacAir as BaseAir<F>>::max_constraint_degree(inner)
            }
            Self::Slip10(inner) => <Slip10Air as BaseAir<F>>::max_constraint_degree(inner),
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::preprocessed_trace(inner),
            Self::Slip10Hmac(inner) => <Slip10HmacAir as BaseAir<F>>::preprocessed_trace(inner),
            Self::Slip10(inner) => <Slip10Air as BaseAir<F>>::preprocessed_trace(inner),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => {
                <Sha512Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::Slip10Hmac(inner) => {
                <Slip10HmacAir as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::Slip10(inner) => {
                <Slip10Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::num_public_values(inner),
            Self::Slip10Hmac(inner) => <Slip10HmacAir as BaseAir<F>>::num_public_values(inner),
            Self::Slip10(inner) => <Slip10Air as BaseAir<F>>::num_public_values(inner),
        }
    }
}

impl<AB: AirBuilder> Air<AB> for BenchAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Sha512(inner) => <Sha512Air as Air<AB>>::eval(inner, builder),
            Self::Slip10Hmac(inner) => <Slip10HmacAir as Air<AB>>::eval(inner, builder),
            Self::Slip10(inner) => <Slip10Air as Air<AB>>::eval(inner, builder),
        }
    }
}

impl<F: Field> LookupAir<F> for BenchAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::Slip10Hmac(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::Slip10(inner) => LookupAir::<F>::add_lookup_columns(inner),
        }
    }
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::get_lookups(inner),
            Self::Slip10Hmac(inner) => LookupAir::<F>::get_lookups(inner),
            Self::Slip10(inner) => LookupAir::<F>::get_lookups(inner),
        }
    }
}

// ── Reference SLIP-0010 chain (sha2 backend) ──────────────────────────
//
// Mirrors the construction in `hmac_air::slip10_hmac_tests`.

const ED25519_SEED_KEY: &[u8] = b"ed25519 seed";
const SOLANA_PATH_INDICES: [u32; 4] = [
    0x80000000 + 44,
    0x80000000 + 501,
    0x80000000,
    0x80000000,
];

fn compress_off_circuit(h_in: [u64; STATE_WORDS], block_bytes: &[u8; 128]) -> [u8; 64] {
    let block_words = bytes_to_be_u64_block(block_bytes);
    let mut row = vec![0u64; NUM_SHA512_COLS];
    fill_row_u64(h_in, block_words, &mut row);
    h_out_bytes_be(&row)
}

fn bytes_to_be_u64_block(bytes: &[u8; 128]) -> [u64; BLOCK_WORDS] {
    let mut words = [0u64; BLOCK_WORDS];
    for word_index in 0..BLOCK_WORDS {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&bytes[word_index * 8..(word_index + 1) * 8]);
        words[word_index] = u64::from_be_bytes(word_bytes);
    }
    words
}

fn bytes_to_be_u64_state(bytes: &[u8; 64]) -> [u64; STATE_WORDS] {
    let mut state = [0u64; STATE_WORDS];
    for word_index in 0..STATE_WORDS {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&bytes[word_index * 8..(word_index + 1) * 8]);
        state[word_index] = u64::from_be_bytes(word_bytes);
    }
    state
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

// Compressions are returned in [ipad_pre, inner, opad_pre, outer]
// order matching the post-soundness-refactor row layout.
fn build_step_compressions(key: &[u8], msg: &[u8]) -> [Slip10CompressionInput; 4] {
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);

    let mut ipad_block_bytes = [0u8; 128];
    let mut opad_block_bytes = [0u8; 128];
    for i in 0..128 {
        ipad_block_bytes[i] = key_padded[i] ^ 0x36;
        opad_block_bytes[i] = key_padded[i] ^ 0x5C;
    }

    let ipad_state_bytes = compress_off_circuit(SHA512_IV, &ipad_block_bytes);
    let ipad_state_words = bytes_to_be_u64_state(&ipad_state_bytes);
    let opad_state_bytes = compress_off_circuit(SHA512_IV, &opad_block_bytes);
    let opad_state_words = bytes_to_be_u64_state(&opad_state_bytes);

    let inner_msg_block = sha512_pad_for_hmac(msg);
    let inner_digest_bytes = compress_off_circuit(ipad_state_words, &inner_msg_block);

    let outer_msg_block = sha512_pad_for_hmac(&inner_digest_bytes);
    let outer_digest_bytes = compress_off_circuit(opad_state_words, &outer_msg_block);

    [
        Slip10CompressionInput {
            h_in_words: SHA512_IV,
            block_bytes: ipad_block_bytes,
            h_out_bytes: ipad_state_bytes,
        },
        Slip10CompressionInput {
            h_in_words: ipad_state_words,
            block_bytes: inner_msg_block,
            h_out_bytes: inner_digest_bytes,
        },
        Slip10CompressionInput {
            h_in_words: SHA512_IV,
            block_bytes: opad_block_bytes,
            h_out_bytes: opad_state_bytes,
        },
        Slip10CompressionInput {
            h_in_words: opad_state_words,
            block_bytes: outer_msg_block,
            h_out_bytes: outer_digest_bytes,
        },
    ]
}

// Returns the 20-row compression list AND the per-step zero-padded
// 128-byte keys (needed so the AIR's `key_bits` column can be
// populated by the trace generator).
fn build_slip10_chain(
    seed: &[u8; 64],
) -> ([Slip10CompressionInput; NUM_REAL_SLIP10_ROWS], [[u8; 128]; 5]) {
    let mut step_keys: [[u8; 128]; 5] = [[0u8; 128]; 5];
    step_keys[0][..ED25519_SEED_KEY.len()].copy_from_slice(ED25519_SEED_KEY);

    let master = build_step_compressions(ED25519_SEED_KEY, seed);
    let mut all: Vec<Slip10CompressionInput> = master.to_vec();
    // Outer is now at position 3 in the per-step layout.
    let mut current_output = master[3].h_out_bytes;

    for (path_step_idx, &index_be_value) in SOLANA_PATH_INDICES.iter().enumerate() {
        let prev_chain: [u8; 32] = current_output[32..64].try_into().unwrap();
        let prev_priv: [u8; 32] = current_output[0..32].try_into().unwrap();
        // Record the zero-padded key for this step (= prev chain).
        step_keys[path_step_idx + 1][..32].copy_from_slice(&prev_chain);
        let mut step_msg = Vec::with_capacity(37);
        step_msg.push(0x00);
        step_msg.extend_from_slice(&prev_priv);
        step_msg.extend_from_slice(&index_be_value.to_be_bytes());
        let step = build_step_compressions(&prev_chain, &step_msg);
        current_output = step[3].h_out_bytes;
        all.extend_from_slice(&step);
    }

    let mut out = [Slip10CompressionInput {
        h_in_words: SHA512_IV,
        block_bytes: [0u8; 128],
        h_out_bytes: [0u8; 64],
    }; NUM_REAL_SLIP10_ROWS];
    out.copy_from_slice(&all);
    (out, step_keys)
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

#[test]
fn slip10_air_emits_correct_priv_for_solana_path() {
    let mut seed = [0u8; 64];
    for i in 0..64 {
        seed[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }

    let (chain, step_keys) = build_slip10_chain(&seed);
    let last_priv: [u8; 32] = chain[NUM_REAL_SLIP10_ROWS - 1].h_out_bytes[0..32]
        .try_into()
        .unwrap();

    // Build SHA-512 sender input list: 20 compressions in row order.
    let sha_inputs: Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> = chain
        .iter()
        .map(|input| (input.h_in_words, bytes_to_be_u64_block(&input.block_bytes)))
        .collect();
    let sha_trace = generate_sha512_trace::<Val>(&sha_inputs);

    let slip10_hmac_trace = generate_slip10_hmac_trace::<Val>(chain, step_keys);
    let slip10_air_witness = generate_slip10_air_witness::<Val>(&last_priv);

    // Build the seed_packed PV that Slip10HmacAir's master-inner
    // constraint binds against (16-bit limbs low-first per word, same
    // shape as Pbkdf2Air's seed_packed output).
    let seed_packed: Vec<Val> = (0..STATE_WORDS)
        .flat_map(|word_index| {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&seed[word_index * 8..(word_index + 1) * 8]);
            let word_value = u64::from_be_bytes(word_bytes);
            (0..4).map(move |limb_index| {
                let limb_value = (word_value >> (limb_index * 16)) & 0xFFFF;
                Val::from_u64(limb_value)
            })
        })
        .collect();

    // Sanity: the witness's `priv_packed` is the RFC 8032 clamped form
    // of `last_priv` byte-by-byte (Critical #2 fix: Slip10Air emits
    // the clamped scalar so it can be shared with Ed25519's PV slot).
    let mut expected_clamped = last_priv;
    expected_clamped[0] &= 0xF8;
    expected_clamped[31] &= 0x7F;
    expected_clamped[31] |= 0x40;
    for byte_idx in 0..32 {
        assert_eq!(
            slip10_air_witness.priv_packed[byte_idx].as_canonical_u32(),
            expected_clamped[byte_idx] as u32,
            "clamped priv_packed byte {byte_idx} mismatch"
        );
    }

    let mut airs = [
        BenchAir::Sha512(Sha512Air::new(NUM_REAL_SLIP10_ROWS)),
        BenchAir::Slip10Hmac(Slip10HmacAir::default()),
        BenchAir::Slip10(Slip10Air::default()),
    ];

    let sha_padded = NUM_REAL_SLIP10_ROWS.next_power_of_two();
    let ext_log_heights = [
        ext_log_for(sha_padded),
        ext_log_for(SLIP10_TRACE_HEIGHT),
        ext_log_for(2),
    ];

    let config = make_config();
    let prover_data =
        ProverData::from_airs_and_degrees(&config, &mut airs, &ext_log_heights);
    let traces = [&sha_trace, &slip10_hmac_trace, &slip10_air_witness.trace];

    let path_index_to_be_byte_pv = |index: u32| -> [Val; NUM_PATH_INDEX_BE_BYTES] {
        let be_bytes = index.to_be_bytes();
        let mut out = [Val::ZERO; NUM_PATH_INDEX_BE_BYTES];
        for (slot, byte) in out.iter_mut().zip(be_bytes.iter()) {
            *slot = Val::from_u32(*byte as u32);
        }
        out
    };
    let purpose_be_pv = path_index_to_be_byte_pv(SOLANA_PATH_INDICES[0]);
    let coin_type_be_pv = path_index_to_be_byte_pv(SOLANA_PATH_INDICES[1]);
    let slip10_hmac_public_values =
        slip10_hmac_pv(&seed_packed, &purpose_be_pv, &coin_type_be_pv);

    let public_values_per_instance = [
        Vec::<Val>::new(),
        slip10_hmac_public_values.clone(),
        slip10_air_witness.priv_packed.clone(),
    ];

    let common = &prover_data.common;
    let instances =
        StarkInstance::new_multiple(&airs, &traces, &public_values_per_instance, common);
    let proof = prove_batch(&config, &instances, &prover_data);

    let public_values_for_verify = vec![
        Vec::<Val>::new(),
        slip10_hmac_public_values,
        slip10_air_witness.priv_packed,
    ];
    verify_batch(&config, &airs, &proof, &public_values_for_verify, common)
        .expect("honest SLIP-0010 + priv-extractor chain must pass batched verify");
}
