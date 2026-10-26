//! End-to-end `prove_batch` / `verify_batch` test for
//! [`HmacKeyschedAir`] paired with `Sha512Air` (sender on the
//! `sha512_compressions` bus).
//!
//! The HMAC keyschedule alone is not directly testable against
//! NIST FIPS 198-1 vectors — those vectors specify full HMAC tags,
//! whereas this AIR exposes only the two intermediate states
//! `ipad_state = SHA512(IV, K' ⊕ ipad)` and `opad_state = SHA512(IV,
//! K' ⊕ opad)`. We instead validate by construction:
//!
//!   1. Compute `ipad_state` / `opad_state` off-circuit using the
//!      existing `sha512_air::generation::fill_row_u64` reference.
//!   2. Build a 2-row SHA-512 trace whose inputs are exactly
//!      `(IV, K' ⊕ ipad)` and `(IV, K' ⊕ opad)`.
//!   3. Build the keyschedule trace via `generate_keysched_witness`.
//!   4. Run `prove_batch` over both AIRs.
//!   5. `verify_batch` succeeds iff the bus balances — which requires
//!      the receiver-derived `block_bits` (key_bits XOR pad_byte) to
//!      match the sender's committed `w` cells, *and* `h_out_bits` on
//!      both sides to be byte-identical.
//!
//! This catches helper bugs (byte-flat / word-flat swap, pad-byte XOR
//! direction, public-value packing) without needing a separate
//! reference HMAC implementation.

#![cfg(test)]

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::hmac_air::constants::{IPAD_BYTE, OPAD_BYTE};
use crate::hmac_air::keysched::{
    generate_keysched_witness, public_values, HmacKeyschedAir, HmacKeyschedCols,
    KEYSCHED_TRACE_HEIGHT, NUM_HMAC_KEYSCHED_COLS, NUM_PUBLIC_VALUES,
};
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::generation::{fill_row_u64, h_out_bytes_be};
use crate::sha512_air::air::Sha512Air;
use crate::sha512_air::constants::{BLOCK_WORDS, SHA512_IV, STATE_WORDS};
use crate::sha512_air::generation::generate_trace as generate_sha512_trace;
use crate::{make_config, Val};

// ── Test-local BatchedAir enum (Sha512 + HmacKeysched) ─────────────────
//
// Mirrors the production `BatchedAir` enum's delegation pattern. Lives
// here so the test does not pollute the production enum with
// in-progress variants.

#[derive(Clone)]
enum KeyschedBatchedAir {
    Sha512(Sha512Air),
    HmacKeysched(HmacKeyschedAir),
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for KeyschedBatchedAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::width(inner),
            Self::HmacKeysched(inner) => <HmacKeyschedAir as BaseAir<F>>::width(inner),
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::max_constraint_degree(inner),
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::max_constraint_degree(inner)
            }
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::preprocessed_trace(inner),
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::preprocessed_trace(inner)
            }
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
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Sha512(inner) => <Sha512Air as BaseAir<F>>::num_public_values(inner),
            Self::HmacKeysched(inner) => {
                <HmacKeyschedAir as BaseAir<F>>::num_public_values(inner)
            }
        }
    }
}

impl<AB: AirBuilder> Air<AB> for KeyschedBatchedAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Sha512(inner) => <Sha512Air as Air<AB>>::eval(inner, builder),
            Self::HmacKeysched(inner) => <HmacKeyschedAir as Air<AB>>::eval(inner, builder),
        }
    }
}

impl<F: Field> LookupAir<F> for KeyschedBatchedAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::HmacKeysched(inner) => LookupAir::<F>::add_lookup_columns(inner),
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Sha512(inner) => LookupAir::<F>::get_lookups(inner),
            Self::HmacKeysched(inner) => LookupAir::<F>::get_lookups(inner),
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Build the two `(h_in, block)` SHA-512 inputs that pair with the
/// keyschedule's two real rows: `(IV, K' ⊕ ipad)` and `(IV, K' ⊕ opad)`.
/// Mirrors the byte→u64-be conversion the helpers do internally so
/// sender and receiver agree on the bus tuples.
fn sha512_inputs_for_key(key: &[u8]) -> Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> {
    assert!(key.len() <= 128);
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);

    let mut ipad_block = [0u8; 128];
    let mut opad_block = [0u8; 128];
    for byte_index in 0..128 {
        ipad_block[byte_index] = key_padded[byte_index] ^ IPAD_BYTE;
        opad_block[byte_index] = key_padded[byte_index] ^ OPAD_BYTE;
    }

    let bytes_to_block = |bytes: &[u8; 128]| -> [u64; BLOCK_WORDS] {
        let mut block = [0u64; BLOCK_WORDS];
        for word_index in 0..BLOCK_WORDS {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&bytes[word_index * 8..(word_index + 1) * 8]);
            block[word_index] = u64::from_be_bytes(word_bytes);
        }
        block
    };

    vec![
        (SHA512_IV, bytes_to_block(&ipad_block)),
        (SHA512_IV, bytes_to_block(&opad_block)),
    ]
}

// ── ext_log_height constants ───────────────────────────────────────────

/// `Sha512Air` sender: 2 real compressions → padded to 2 → log2 = 1.
/// Plus is_zk hiding extension (+1). Same convention as the Ed25519
/// prove/verify tests.
const SHA512_EXT_LOG_HEIGHT: usize = 1 + 1;

/// `HmacKeyschedAir`: `KEYSCHED_TRACE_HEIGHT` = 4 → log2 = 2 → ext = 3.
const KEYSCHED_EXT_LOG_HEIGHT: usize = {
    let n = KEYSCHED_TRACE_HEIGHT;
    let mut log = 0;
    let mut x = n;
    while x > 1 {
        x >>= 1;
        log += 1;
    }
    log + 1
};

// ── The positive test ─────────────────────────────────────────────────

/// Honest-witness end-to-end: the keyschedule's role-gated bus
/// receives match the SHA-512 sender's two real compressions, and the
/// 64-cell public-value vector matches the off-circuit
/// `(ipad_state, opad_state)`.
#[test]
fn hmac_keysched_paired_with_sha512_passes_batched_verify() {
    // A short, distinctive test key (mnemonic-shaped — 11 bytes).
    let key: &[u8] = b"test-key-0!";

    // Compute SHA-512 sender trace inputs.
    let sha_inputs = sha512_inputs_for_key(key);
    assert_eq!(sha_inputs.len(), 2, "ipad-pre and opad-pre");
    let sha_trace = generate_sha512_trace::<Val>(&sha_inputs);

    // Compute keyschedule trace + public values.
    let keysched_witness = generate_keysched_witness::<Val>(key);
    let pv_vector = public_values(&keysched_witness);
    debug_assert_eq!(pv_vector.len(), NUM_PUBLIC_VALUES);

    // Pair the AIRs into one batched proof.
    let mut airs = [
        KeyschedBatchedAir::Sha512(Sha512Air::new(sha_inputs.len())),
        KeyschedBatchedAir::HmacKeysched(HmacKeyschedAir::default()),
    ];

    let config = make_config();
    let prover_data = ProverData::from_airs_and_degrees(
        &config,
        &mut airs,
        &[SHA512_EXT_LOG_HEIGHT, KEYSCHED_EXT_LOG_HEIGHT],
    );
    let traces = [&sha_trace, &keysched_witness.trace];
    let public_values_per_instance = [Vec::<Val>::new(), pv_vector.clone()];

    let common = &prover_data.common;
    let instances =
        StarkInstance::new_multiple(&airs, &traces, &public_values_per_instance, common);
    let proof = prove_batch(&config, &instances, &prover_data);

    let public_values_for_verify = vec![Vec::<Val>::new(), pv_vector];
    verify_batch(&config, &airs, &proof, &public_values_for_verify, common)
        .expect("honest keyschedule witness must pass batched verify");
}

/// Sanity check on the keyschedule witness: row 0's `h_out_bits`
/// (decoded as u64 big-endian bytes) matches the off-circuit
/// SHA-512 compression of `(IV, K' ⊕ ipad)`. Catches generator bugs
/// before the prove/verify path is even engaged.
#[test]
fn keysched_witness_h_out_matches_sha512_reference() {
    let key: &[u8] = b"abc";
    let witness = generate_keysched_witness::<Val>(key);

    // Pull row 0 (ipad-pre) and decode h_out_bits → 64 bytes.
    let row_0: &[Val] = &witness.trace.values[..NUM_HMAC_KEYSCHED_COLS];
    let row_0_cols: &HmacKeyschedCols<Val> = row_0.borrow();

    let mut digest_bytes = [0u8; 64];
    for word_index in 0..STATE_WORDS {
        let mut word_value: u64 = 0;
        for bit_in_word in 0..64 {
            let bit_field = row_0_cols.h_out_bits[word_index][bit_in_word];
            let bit = bit_field.as_canonical_u32();
            assert!(bit == 0 || bit == 1, "h_out_bits cell must be boolean");
            word_value |= (bit as u64) << bit_in_word;
        }
        digest_bytes[word_index * 8..(word_index + 1) * 8]
            .copy_from_slice(&word_value.to_be_bytes());
    }

    // Off-circuit reference: SHA-512(K' ⊕ ipad) one-block compression.
    let inputs = sha512_inputs_for_key(key);
    let mut sha_row = vec![0u64; NUM_SHA512_COLS];
    fill_row_u64(inputs[0].0, inputs[0].1, &mut sha_row);
    let reference_digest = h_out_bytes_be(&sha_row);

    assert_eq!(
        digest_bytes, reference_digest,
        "keysched row 0 h_out must equal SHA-512(IV, K' ⊕ ipad) byte-for-byte"
    );
}

