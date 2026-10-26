//! High-level entry point for the BIP-39 → Solana chain proof.
//!
//! This is what an external caller of the library uses. Two functions:
//!
//!   - [`prove`] — given a BIP-39 mnemonic (UTF-8 bytes), produce a
//!     STARK proof of "I know a mnemonic whose Solana address for
//!     path m/44'/501'/0'/0' is `A`", along with the proven address.
//!   - [`verify`] — validate a proof and return the verified address.
//!
//! Internally this wires the 10-AIR `prove_batch` slice described in
//! `docs/pipeline-spec.md` §3.1. The proof binds the chain end-to-end
//! (mnemonic → PBKDF2 seed → SLIP-0010 priv → Ed25519 pubkey =
//! address); see the chain of constraints listed in
//! `bench_split::pbkdf2_split_prove_2048`'s docstring for the
//! soundness inventory.
//!
//! The serialized proof is a [`Bip39ToSolanaArtifact`] (postcard
//! encoded): the `BatchProof` itself plus the public-value vectors
//! and the salted preprocessed commitment that the verifier needs to
//! reconstruct the `CommonData`. Proof size ≈ 40 MB for v1
//! parameters (see `BenchmarksPlonky3.md`).

use p3_air::{Air, AirBuilder, BaseAir};
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_batch_stark::{
    prove_batch, verify_batch, BatchProof, Commitment, CommonData, ProverData, StarkInstance,
};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize};

use crate::bip39_to_solana_air::air::Bip39ToSolanaAir;
use crate::bip39_to_solana_air::columns::NUM_SOLANA_ADDRESS_BYTES;
use crate::bip39_to_solana_air::generation::generate_bip39_to_solana_witness;
use crate::ed25519_air::air::Ed25519Air;
use crate::ed25519_air::constants::NUM_ROWS_PER_SCALAR_MUL;
use crate::ed25519_air::prove_verify_helpers::build_batched_inputs as build_ed25519_inputs;
use crate::hmac_air::keysched::{
    generate_keysched_witness, public_values as keysched_public_values, HmacKeyschedAir,
    KEYSCHED_TRACE_HEIGHT,
};
use crate::hmac_air::pbkdf2_hmac::{
    bip39_salt_plus_int1, generate_pbkdf2_hmac_witness, Pbkdf2HmacAir,
    BIP39_DEFAULT_ITERATIONS,
};
use crate::hmac_air::slip10_hmac::{
    generate_slip10_hmac_trace, public_values_for_instance as slip10_hmac_pv,
    Slip10CompressionInput, Slip10HmacAir, NONMASTER_MSG_BYTE_LEN, NUM_PATH_INDEX_BE_BYTES,
    NUM_REAL_SLIP10_ROWS, SLIP10_TRACE_HEIGHT,
};
use crate::pbkdf2_air::air::Pbkdf2Air;
use crate::pbkdf2_air::generation::generate_pbkdf2_air_witness;
use crate::range_check_u16_air::air::RangeCheckU16Air;
use crate::range_check_u16_air::constants::TABLE_HEIGHT;
use crate::sha512_air::air::Sha512Air;
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::constants::{BLOCK_WORDS, SHA512_IV, STATE_WORDS};
use crate::sha512_air::generation::{
    fill_row_u64, generate_trace as generate_sha512_trace, h_out_bytes_be,
};
use crate::slip10_air::air::Slip10Air;
use crate::slip10_air::generation::generate_slip10_air_witness;
use crate::{make_config, Cfg, Plonky3Error, Val};

const KEYSCHED_SHA_COMPRESSIONS: usize = 2;
const SLIP10_SHA_COMPRESSIONS: usize = NUM_REAL_SLIP10_ROWS;

const ED25519_SEED_KEY: &[u8] = b"ed25519 seed";

/// SLIP-0010 hardening bit (`| 0x80000000`). Every BIP-44 / SLIP-0010
/// path index for Ed25519 must have this bit set.
const HARDENED_BIT: u32 = 0x8000_0000;

/// BIP-44 `purpose'` index, the leading SLIP-0010 derivation step.
const BIP44_PURPOSE: u32 = HARDENED_BIT | 44;

/// BIP-44 `coin_type'` index for Solana. This wrapper is Solana-
/// specific; a sibling wrapper for another chain would pick a
/// different value (e.g. `60` for Ethereum) and a different curve.
const SOLANA_COIN_TYPE: u32 = HARDENED_BIT | 501;

/// Assemble the 4-step path indices for a Solana derivation. The
/// caller supplies the unhardened account / change numbers; this
/// function applies the SLIP-0010 hardening bit.
const fn solana_path_indices(account_index: u32, change_index: u32) -> [u32; 4] {
    [
        BIP44_PURPOSE,
        SOLANA_COIN_TYPE,
        HARDENED_BIT | account_index,
        HARDENED_BIT | change_index,
    ]
}

/// Encode a 32-bit path index as 4 big-endian byte cells in the
/// configured field. Used to build Slip10HmacAir's public-value slots
/// for `purpose'` and `coin_type'`.
fn path_index_to_be_byte_pv(index: u32) -> [Val; NUM_PATH_INDEX_BE_BYTES] {
    let be_bytes = index.to_be_bytes();
    let mut out = [Val::ZERO; NUM_PATH_INDEX_BE_BYTES];
    for (slot, byte) in out.iter_mut().zip(be_bytes.iter()) {
        *slot = Val::from_u32(*byte as u32);
    }
    out
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

/// Canonical serialized proof for the BIP-39 → Solana chain. Postcard-
/// encoded for the on-disk / on-wire form. Carries:
///
///   - `BatchProof` itself,
///   - the **non-redundant** per-instance public-value vectors,
///   - the preprocessed commitment (salted by hiding MMCS at
///     prover-side commit time; can't be reproduced by the verifier
///     without this hint).
///
/// Several cross-AIR PV bindings are enforced by the verifier
/// **reconstructing** one slot's PV from another slot's stored PV
/// (rather than trusting two prover-supplied copies to match). The
/// fields below are the unique slots; redundant ones are derived in
/// `verify()`:
///
///   - `keysched_pv` is also passed to `Pbkdf2HmacAir`'s slot.
///   - `ed25519_pv[SCALAR_PACKED_OFFSET..+32]` is also passed to
///     `Slip10Air`'s slot.
///   - `ed25519_pv[PUBLIC_INPUT_Y_OFFSET..+32]` is also passed as the
///     `solana_address` portion of `Bip39ToSolanaAir`'s PV.
///
/// Without this reconstruction the artifact would carry independent
/// copies of those values and the verifier would have no way to pin
/// them equal, breaking the mnemonic-to-address soundness chain.
///
/// Internal layout subject to change; treat the postcard bytes as opaque.
#[derive(Serialize, Deserialize)]
pub struct Bip39ToSolanaArtifact {
    /// PBKDF2 iteration count the prover used. Production is always
    /// `BIP39_DEFAULT_ITERATIONS = 2048`; tests use small values via
    /// [`prove_with_iterations`]. The verifier needs this to
    /// reconstruct the AIR slice with matching trace heights.
    num_iterations: u32,
    /// `[ipad_state_packed (32) || opad_state_packed (32)]`. Shared
    /// by `HmacKeyschedAir` (output) and `Pbkdf2HmacAir` (input) —
    /// the verifier passes this same vector to both AIR slots so the
    /// two PV vectors are pinned to identical field elements.
    keysched_pv: Vec<u32>,
    /// `seed_packed` (32 cells). Shared by `Pbkdf2Air` (output) and
    /// the master-inner block of `Slip10HmacAir` (input).
    seed_packed_pv: Vec<u32>,
    /// `[x_A (32) || y_A (32) || scalar_packed (32)]`. The
    /// `scalar_packed` slot is also used as `Slip10Air`'s PV; the
    /// `y_A` slot is also used as the `solana_address` portion of
    /// `Bip39ToSolanaAir`'s PV.
    ed25519_pv: Vec<u32>,
    /// The non-redundant 64 bytes of `Bip39ToSolanaAir`'s PV:
    /// `[pq_destination (32) || recent_blockhash (32)]`. The
    /// `solana_address` portion is derived from
    /// `ed25519_pv[PUBLIC_INPUT_Y_OFFSET..+32]` at verify time.
    pq_destination_and_blockhash_pv: Vec<u32>,
    preprocessed_commitment: Vec<u8>,
    proof_bytes: Vec<u8>,
}

/// Number of cells in the `pq_destination_and_blockhash_pv` artifact
/// field: 32 bytes of PQ destination address + 32 bytes of recent
/// blockhash.
const PQ_DEST_AND_BLOCKHASH_PV_LEN: usize = 64;

/// Enum wrapping the 10 AIRs used by the chain. Required for
/// `prove_batch` (homogeneous slice). Each variant delegates every
/// `BaseAir`/`Air`/`LookupAir` method to its inner AIR.
#[derive(Clone)]
pub enum ChainAir {
    Sha512(Sha512Air),
    HmacKeysched(HmacKeyschedAir),
    Pbkdf2Hmac(Pbkdf2HmacAir),
    Pbkdf2(Pbkdf2Air),
    Slip10Hmac(Slip10HmacAir),
    Slip10(Slip10Air),
    Ed25519(Ed25519Air),
    RangeCheckU16(RangeCheckU16Air),
    Bip39ToSolana(Bip39ToSolanaAir),
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for ChainAir {
    fn width(&self) -> usize {
        match self {
            Self::Sha512(x) => <Sha512Air as BaseAir<F>>::width(x),
            Self::HmacKeysched(x) => <HmacKeyschedAir as BaseAir<F>>::width(x),
            Self::Pbkdf2Hmac(x) => <Pbkdf2HmacAir as BaseAir<F>>::width(x),
            Self::Pbkdf2(x) => <Pbkdf2Air as BaseAir<F>>::width(x),
            Self::Slip10Hmac(x) => <Slip10HmacAir as BaseAir<F>>::width(x),
            Self::Slip10(x) => <Slip10Air as BaseAir<F>>::width(x),
            Self::Ed25519(x) => <Ed25519Air as BaseAir<F>>::width(x),
            Self::RangeCheckU16(x) => <RangeCheckU16Air as BaseAir<F>>::width(x),
            Self::Bip39ToSolana(x) => <Bip39ToSolanaAir as BaseAir<F>>::width(x),
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Sha512(x) => <Sha512Air as BaseAir<F>>::max_constraint_degree(x),
            Self::HmacKeysched(x) => <HmacKeyschedAir as BaseAir<F>>::max_constraint_degree(x),
            Self::Pbkdf2Hmac(x) => <Pbkdf2HmacAir as BaseAir<F>>::max_constraint_degree(x),
            Self::Pbkdf2(x) => <Pbkdf2Air as BaseAir<F>>::max_constraint_degree(x),
            Self::Slip10Hmac(x) => <Slip10HmacAir as BaseAir<F>>::max_constraint_degree(x),
            Self::Slip10(x) => <Slip10Air as BaseAir<F>>::max_constraint_degree(x),
            Self::Ed25519(x) => <Ed25519Air as BaseAir<F>>::max_constraint_degree(x),
            Self::RangeCheckU16(x) => <RangeCheckU16Air as BaseAir<F>>::max_constraint_degree(x),
            Self::Bip39ToSolana(x) => <Bip39ToSolanaAir as BaseAir<F>>::max_constraint_degree(x),
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Sha512(x) => <Sha512Air as BaseAir<F>>::preprocessed_trace(x),
            Self::HmacKeysched(x) => <HmacKeyschedAir as BaseAir<F>>::preprocessed_trace(x),
            Self::Pbkdf2Hmac(x) => <Pbkdf2HmacAir as BaseAir<F>>::preprocessed_trace(x),
            Self::Pbkdf2(x) => <Pbkdf2Air as BaseAir<F>>::preprocessed_trace(x),
            Self::Slip10Hmac(x) => <Slip10HmacAir as BaseAir<F>>::preprocessed_trace(x),
            Self::Slip10(x) => <Slip10Air as BaseAir<F>>::preprocessed_trace(x),
            Self::Ed25519(x) => <Ed25519Air as BaseAir<F>>::preprocessed_trace(x),
            Self::RangeCheckU16(x) => <RangeCheckU16Air as BaseAir<F>>::preprocessed_trace(x),
            Self::Bip39ToSolana(x) => <Bip39ToSolanaAir as BaseAir<F>>::preprocessed_trace(x),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Sha512(x) => {
                <Sha512Air as BaseAir<F>>::preprocessed_next_row_columns(x)
            }
            Self::HmacKeysched(x) => {
                <HmacKeyschedAir as BaseAir<F>>::preprocessed_next_row_columns(x)
            }
            Self::Pbkdf2Hmac(x) => {
                <Pbkdf2HmacAir as BaseAir<F>>::preprocessed_next_row_columns(x)
            }
            Self::Pbkdf2(x) => <Pbkdf2Air as BaseAir<F>>::preprocessed_next_row_columns(x),
            Self::Slip10Hmac(x) => {
                <Slip10HmacAir as BaseAir<F>>::preprocessed_next_row_columns(x)
            }
            Self::Slip10(x) => <Slip10Air as BaseAir<F>>::preprocessed_next_row_columns(x),
            Self::Ed25519(x) => <Ed25519Air as BaseAir<F>>::preprocessed_next_row_columns(x),
            Self::RangeCheckU16(x) => {
                <RangeCheckU16Air as BaseAir<F>>::preprocessed_next_row_columns(x)
            }
            Self::Bip39ToSolana(x) => {
                <Bip39ToSolanaAir as BaseAir<F>>::preprocessed_next_row_columns(x)
            }
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Sha512(x) => <Sha512Air as BaseAir<F>>::num_public_values(x),
            Self::HmacKeysched(x) => <HmacKeyschedAir as BaseAir<F>>::num_public_values(x),
            Self::Pbkdf2Hmac(x) => <Pbkdf2HmacAir as BaseAir<F>>::num_public_values(x),
            Self::Pbkdf2(x) => <Pbkdf2Air as BaseAir<F>>::num_public_values(x),
            Self::Slip10Hmac(x) => <Slip10HmacAir as BaseAir<F>>::num_public_values(x),
            Self::Slip10(x) => <Slip10Air as BaseAir<F>>::num_public_values(x),
            Self::Ed25519(x) => <Ed25519Air as BaseAir<F>>::num_public_values(x),
            Self::RangeCheckU16(x) => <RangeCheckU16Air as BaseAir<F>>::num_public_values(x),
            Self::Bip39ToSolana(x) => {
                <Bip39ToSolanaAir as BaseAir<F>>::num_public_values(x)
            }
        }
    }
}

impl<AB: AirBuilder> Air<AB> for ChainAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Sha512(x) => <Sha512Air as Air<AB>>::eval(x, b),
            Self::HmacKeysched(x) => <HmacKeyschedAir as Air<AB>>::eval(x, b),
            Self::Pbkdf2Hmac(x) => <Pbkdf2HmacAir as Air<AB>>::eval(x, b),
            Self::Pbkdf2(x) => <Pbkdf2Air as Air<AB>>::eval(x, b),
            Self::Slip10Hmac(x) => <Slip10HmacAir as Air<AB>>::eval(x, b),
            Self::Slip10(x) => <Slip10Air as Air<AB>>::eval(x, b),
            Self::Ed25519(x) => <Ed25519Air as Air<AB>>::eval(x, b),
            Self::RangeCheckU16(x) => <RangeCheckU16Air as Air<AB>>::eval(x, b),
            Self::Bip39ToSolana(x) => <Bip39ToSolanaAir as Air<AB>>::eval(x, b),
        }
    }
}

impl<F: Field> LookupAir<F> for ChainAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Sha512(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::HmacKeysched(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::Pbkdf2Hmac(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::Pbkdf2(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::Slip10Hmac(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::Slip10(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::Ed25519(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::RangeCheckU16(x) => LookupAir::<F>::add_lookup_columns(x),
            Self::Bip39ToSolana(x) => LookupAir::<F>::add_lookup_columns(x),
        }
    }
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Sha512(x) => LookupAir::<F>::get_lookups(x),
            Self::HmacKeysched(x) => LookupAir::<F>::get_lookups(x),
            Self::Pbkdf2Hmac(x) => LookupAir::<F>::get_lookups(x),
            Self::Pbkdf2(x) => LookupAir::<F>::get_lookups(x),
            Self::Slip10Hmac(x) => LookupAir::<F>::get_lookups(x),
            Self::Slip10(x) => LookupAir::<F>::get_lookups(x),
            Self::Ed25519(x) => LookupAir::<F>::get_lookups(x),
            Self::RangeCheckU16(x) => LookupAir::<F>::get_lookups(x),
            Self::Bip39ToSolana(x) => LookupAir::<F>::get_lookups(x),
        }
    }
}

// ─── Off-circuit chain builders ─────────────────────────────────────────

fn compress_off_circuit(h_in: [u64; STATE_WORDS], block_bytes: &[u8; 128]) -> [u8; 64] {
    let block_words = bytes_128_to_words(block_bytes);
    let mut row = vec![0u64; NUM_SHA512_COLS];
    fill_row_u64(h_in, block_words, &mut row);
    h_out_bytes_be(&row)
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

fn sha512_pad_for_hmac(msg: &[u8]) -> [u8; 128] {
    assert!(msg.len() <= 111);
    let mut block = [0u8; 128];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] = 0x80;
    let bit_len = ((128 + msg.len()) as u128) * 8;
    block[112..128].copy_from_slice(&bit_len.to_be_bytes());
    block
}

fn build_sha512_inputs_for_pbkdf2_only(
    salt_plus_int1: &[u8; 12],
    ipad_state_words: [u64; STATE_WORDS],
    opad_state_words: [u64; STATE_WORDS],
    u_chain: &[[u8; 64]],
) -> Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> {
    let mut inputs = Vec::with_capacity(2 * u_chain.len());
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

fn build_sha512_inputs_for_keysched(
    key: &[u8],
) -> Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> {
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);
    let mut ipad_block_bytes = [0u8; 128];
    let mut opad_block_bytes = [0u8; 128];
    for i in 0..128 {
        ipad_block_bytes[i] = key_padded[i] ^ 0x36;
        opad_block_bytes[i] = key_padded[i] ^ 0x5C;
    }
    vec![
        (SHA512_IV, bytes_128_to_words(&ipad_block_bytes)),
        (SHA512_IV, bytes_128_to_words(&opad_block_bytes)),
    ]
}

fn slip10_build_step(key: &[u8], msg: &[u8]) -> [Slip10CompressionInput; 4] {
    let mut key_padded = [0u8; 128];
    key_padded[..key.len()].copy_from_slice(key);

    let mut ipad_block_bytes = [0u8; 128];
    let mut opad_block_bytes = [0u8; 128];
    for i in 0..128 {
        ipad_block_bytes[i] = key_padded[i] ^ 0x36;
        opad_block_bytes[i] = key_padded[i] ^ 0x5C;
    }

    let ipad_state_bytes = compress_off_circuit(SHA512_IV, &ipad_block_bytes);
    let mut ipad_state_words = [0u64; STATE_WORDS];
    for i in 0..STATE_WORDS {
        let mut w = [0u8; 8];
        w.copy_from_slice(&ipad_state_bytes[i * 8..(i + 1) * 8]);
        ipad_state_words[i] = u64::from_be_bytes(w);
    }
    let opad_state_bytes = compress_off_circuit(SHA512_IV, &opad_block_bytes);
    let mut opad_state_words = [0u64; STATE_WORDS];
    for i in 0..STATE_WORDS {
        let mut w = [0u8; 8];
        w.copy_from_slice(&opad_state_bytes[i * 8..(i + 1) * 8]);
        opad_state_words[i] = u64::from_be_bytes(w);
    }

    let inner_msg_block = sha512_pad_for_hmac(msg);
    let inner_digest_bytes = compress_off_circuit(ipad_state_words, &inner_msg_block);

    let outer_msg_block = sha512_pad_for_hmac(&inner_digest_bytes);
    let outer_digest_bytes = compress_off_circuit(opad_state_words, &outer_msg_block);

    // [ipad_pre, inner, opad_pre, outer] per Slip10HmacAir's
    // post-soundness-refactor row layout.
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

fn build_slip10_chain(
    seed: &[u8; 64],
    path_indices: [u32; 4],
) -> ([Slip10CompressionInput; NUM_REAL_SLIP10_ROWS], [[u8; 128]; 5]) {
    let mut step_keys: [[u8; 128]; 5] = [[0u8; 128]; 5];
    step_keys[0][..ED25519_SEED_KEY.len()].copy_from_slice(ED25519_SEED_KEY);

    let master = slip10_build_step(ED25519_SEED_KEY, seed);
    let mut all: Vec<Slip10CompressionInput> = master.to_vec();
    let mut current_output = master[3].h_out_bytes;

    for (path_step_idx, &index_be_value) in path_indices.iter().enumerate() {
        let prev_chain: [u8; 32] = current_output[32..64].try_into().unwrap();
        let prev_priv: [u8; 32] = current_output[0..32].try_into().unwrap();
        step_keys[path_step_idx + 1][..32].copy_from_slice(&prev_chain);
        let mut step_msg = Vec::with_capacity(NONMASTER_MSG_BYTE_LEN);
        step_msg.push(0x00);
        step_msg.extend_from_slice(&prev_priv);
        step_msg.extend_from_slice(&index_be_value.to_be_bytes());
        let step = slip10_build_step(&prev_chain, &step_msg);
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

fn build_sha512_inputs_for_slip10(
    chain: &[Slip10CompressionInput; NUM_REAL_SLIP10_ROWS],
) -> Vec<([u64; STATE_WORDS], [u64; BLOCK_WORDS])> {
    chain
        .iter()
        .map(|input| (input.h_in_words, bytes_128_to_words(&input.block_bytes)))
        .collect()
}

// ─── Public API ─────────────────────────────────────────────────────────

/// Produce a STARK proof that the caller knows a BIP-39 mnemonic
/// whose Solana address (Ed25519 public key, base58-encoded
/// off-circuit) for the standard derivation path `m/44'/501'/0'/0'`
/// is the address embedded in the proof.
///
/// `mnemonic_bytes` is the **UTF-8-encoded mnemonic** — typically the
/// joined-words form (12 or 24 words separated by single spaces).
/// v1 supports any mnemonic byte length ≤ 128 (covers 12-word
/// mnemonics fully; 24-word mnemonics need the long-key path, spec
/// §1.1, not yet wired).
///
/// Returns the postcard-encoded [`Bip39ToSolanaArtifact`]. The proven
/// address is embedded inside; use [`verify`] to extract and validate it.
pub fn prove(
    mnemonic_bytes: &[u8],
    pq_destination_address: &[u8; 32],
    recent_blockhash: &[u8; 32],
    account_index: u32,
    change_index: u32,
) -> Result<Vec<u8>, Plonky3Error> {
    prove_with_iterations(
        mnemonic_bytes,
        pq_destination_address,
        recent_blockhash,
        account_index,
        change_index,
        BIP39_DEFAULT_ITERATIONS,
    )
}

/// Implementation backing [`prove`], parameterized by PBKDF2 iteration
/// count so tests can run the full chain at a small `c` (e.g. 1) in
/// ~1 s. **Production callers must use [`prove`]** with the hard-
/// coded BIP-39 `c = 2048`.
///
/// `account_index` and `change_index` are raw u32s; this wrapper
/// applies SLIP-0010 hardening (`| 0x80000000`) internally before
/// feeding them into the derivation. Pass `0, 0` to recover the
/// default Solana wallet account at `m/44'/501'/0'/0'`.
pub fn prove_with_iterations(
    mnemonic_bytes: &[u8],
    pq_destination_address: &[u8; 32],
    recent_blockhash: &[u8; 32],
    account_index: u32,
    change_index: u32,
    num_iterations: usize,
) -> Result<Vec<u8>, Plonky3Error> {
    if mnemonic_bytes.len() > 128 {
        return Err(Plonky3Error::Encode(format!(
            "mnemonic too long: {} bytes (v1 max = 128, see spec §1.1)",
            mnemonic_bytes.len()
        )));
    }
    if num_iterations == 0 {
        return Err(Plonky3Error::Encode(
            "PBKDF2 num_iterations must be ≥ 1".to_string(),
        ));
    }

    let salt_plus_int1 = bip39_salt_plus_int1();

    // Keysched: ipad_state / opad_state = SHA512(IV, K' ⊕ {ipad, opad}).
    let keysched = generate_keysched_witness::<Val>(mnemonic_bytes);
    let keysched_pv = keysched_public_values(&keysched);

    let read_state_from_pv = |pv: &[Val], pv_offset: usize| -> [u64; STATE_WORDS] {
        let mut state = [0u64; STATE_WORDS];
        for word_index in 0..STATE_WORDS {
            let mut word_value: u64 = 0;
            for limb_index in 0..4 {
                let limb_u32 =
                    pv[pv_offset + word_index * 4 + limb_index].as_canonical_u32();
                word_value |= (limb_u32 as u64) << (limb_index * 16);
            }
            state[word_index] = word_value;
        }
        state
    };
    let ipad_state_words = read_state_from_pv(&keysched_pv, 0);
    let opad_state_words = read_state_from_pv(&keysched_pv, STATE_WORDS * 4);

    // PBKDF2 2048-iteration chain.
    let pbkdf2 = generate_pbkdf2_hmac_witness::<Val>(
        num_iterations,
        ipad_state_words,
        opad_state_words,
        &salt_plus_int1,
    );

    // XOR-fold all U_i into the 64-byte seed.
    let pbkdf2_orchestrator = generate_pbkdf2_air_witness::<Val>(&pbkdf2.u_digests);

    let mut seed_bytes = [0u8; 64];
    for word_index in 0..STATE_WORDS {
        let mut word: u64 = 0;
        for limb_index in 0..4 {
            let limb_field =
                pbkdf2_orchestrator.seed_packed[word_index * 4 + limb_index];
            let limb_u32 = limb_field.as_canonical_u32();
            word |= (limb_u32 as u64) << (limb_index * 16);
        }
        let bytes = word.to_be_bytes();
        seed_bytes[word_index * 8..(word_index + 1) * 8].copy_from_slice(&bytes);
    }

    let path_indices = solana_path_indices(account_index, change_index);
    let (slip10_chain, slip10_step_keys) = build_slip10_chain(&seed_bytes, path_indices);
    let slip10_trace = generate_slip10_hmac_trace::<Val>(slip10_chain, slip10_step_keys);

    let last_priv: [u8; 32] = slip10_chain[NUM_REAL_SLIP10_ROWS - 1].h_out_bytes[0..32]
        .try_into()
        .expect("32-byte priv slice");
    let slip10_air_witness = generate_slip10_air_witness::<Val>(&last_priv);

    // Ed25519: clamp the priv (RFC 8032 — Solana wallets clamp at
    // signing-side; matches real-world usage), then run [s]B.
    let mut clamped_priv = last_priv;
    clamped_priv[0] &= 0xF8;
    clamped_priv[31] &= 0x7F;
    clamped_priv[31] |= 0x40;
    let ed25519_inputs = build_ed25519_inputs(&clamped_priv);

    // Extract Solana address (= Ed25519 y_A) from Ed25519's PV vector.
    // Layout: [x_A (32) || y_A (32) || scalar_packed (32)].
    let mut solana_address_bytes = [0u8; 32];
    for i in 0..32 {
        let pv_field = ed25519_inputs.ed25519_public_values
            [crate::ed25519_air::air::PUBLIC_INPUT_Y_OFFSET + i];
        let pv_u32 = pv_field.as_canonical_u32();
        debug_assert!(pv_u32 < 256, "y_A limb must fit in a u8");
        solana_address_bytes[i] = pv_u32 as u8;
    }
    let bip39_to_solana_witness = generate_bip39_to_solana_witness::<Val>(
        &solana_address_bytes,
        pq_destination_address,
        recent_blockhash,
    );

    // SHA-512 sender input lists. Three separate Sha512Air instances
    // for clean power-of-two send counts (see `feedback_split_sender_pow2`).
    let sha_pbkdf2_inputs = build_sha512_inputs_for_pbkdf2_only(
        &salt_plus_int1,
        ipad_state_words,
        opad_state_words,
        &pbkdf2.u_digests,
    );
    let sha_pbkdf2_trace = generate_sha512_trace::<Val>(&sha_pbkdf2_inputs);

    let sha_keysched_inputs = build_sha512_inputs_for_keysched(mnemonic_bytes);
    let sha_keysched_trace = generate_sha512_trace::<Val>(&sha_keysched_inputs);

    let sha_slip10_inputs = build_sha512_inputs_for_slip10(&slip10_chain);
    let sha_slip10_trace = generate_sha512_trace::<Val>(&sha_slip10_inputs);

    // 11-AIR slice: 3 SHA-512 senders + 8 receivers / orchestrators.
    let pbkdf2_sha_compressions = 2 * num_iterations;
    let mut airs = [
        ChainAir::Sha512(Sha512Air::new(pbkdf2_sha_compressions)),
        ChainAir::Sha512(Sha512Air::new(KEYSCHED_SHA_COMPRESSIONS)),
        ChainAir::Sha512(Sha512Air::new(SLIP10_SHA_COMPRESSIONS)),
        ChainAir::HmacKeysched(HmacKeyschedAir::default()),
        ChainAir::Pbkdf2Hmac(Pbkdf2HmacAir::new(num_iterations)),
        ChainAir::Pbkdf2(Pbkdf2Air::new(num_iterations)),
        ChainAir::Slip10Hmac(Slip10HmacAir::default()),
        ChainAir::Slip10(Slip10Air::default()),
        ChainAir::Ed25519(Ed25519Air::default()),
        ChainAir::RangeCheckU16(RangeCheckU16Air::default()),
        ChainAir::Bip39ToSolana(Bip39ToSolanaAir),
    ];

    let pbkdf2_height = 2 * num_iterations;
    let ext_log_heights = [
        ext_log_for(pbkdf2_sha_compressions.next_power_of_two()),
        ext_log_for(KEYSCHED_SHA_COMPRESSIONS.next_power_of_two()),
        ext_log_for(SLIP10_SHA_COMPRESSIONS.next_power_of_two()),
        ext_log_for(KEYSCHED_TRACE_HEIGHT),
        ext_log_for(pbkdf2_height),
        ext_log_for(num_iterations),
        ext_log_for(SLIP10_TRACE_HEIGHT),
        ext_log_for(2),
        ext_log_for(NUM_ROWS_PER_SCALAR_MUL),
        ext_log_for(TABLE_HEIGHT),
        ext_log_for(2),
    ];

    let config = make_config();
    let prover_data =
        ProverData::from_airs_and_degrees(&config, &mut airs, &ext_log_heights);

    let traces = [
        &sha_pbkdf2_trace,
        &sha_keysched_trace,
        &sha_slip10_trace,
        &keysched.trace,
        &pbkdf2.trace,
        &pbkdf2_orchestrator.trace,
        &slip10_trace,
        &slip10_air_witness.trace,
        &ed25519_inputs.ed25519_trace,
        &ed25519_inputs.range_check_trace,
        &bip39_to_solana_witness.trace,
    ];

    // Cross-AIR PV bindings via SHARED Vec elements (the verifier
    // mirrors this construction so each shared value lives in exactly
    // one artifact field and is fed to every AIR that needs it):
    //
    //   `keysched_pv` → HmacKeyschedAir (output) AND Pbkdf2HmacAir (input)
    //     — Critical #1 fix. Pbkdf2's PV slot at index 4 receives the
    //     same Vec as Keysched's at index 3, NOT an independently-built
    //     `pbkdf2.public_values`.
    //   `seed_packed` → Pbkdf2Air (output) AND Slip10HmacAir (input)
    //     — pre-existing shared-Vec binding (already correct).
    //   `ed25519_pv[SCALAR_PACKED_OFFSET..+32]` → Ed25519Air's
    //     scalar_packed slot AND Slip10Air's PV (the clamped scalar) —
    //     Critical #2 fix. Slip10Air now emits the clamped scalar
    //     (clamping done in-circuit; see slip10_air/air.rs); the same
    //     32 cells reach both AIRs.
    //   `ed25519_pv[PUBLIC_INPUT_Y_OFFSET..+32]` → Ed25519Air's y_A
    //     slot AND Bip39ToSolanaAir's solana_address slot — Critical
    //     #3 fix. The solana_address portion is taken from Ed25519's
    //     PV rather than re-supplied as an independent value.
    let purpose_be_pv = path_index_to_be_byte_pv(path_indices[0]);
    let coin_type_be_pv = path_index_to_be_byte_pv(path_indices[1]);
    let slip10_hmac_public_values = slip10_hmac_pv(
        &pbkdf2_orchestrator.seed_packed,
        &purpose_be_pv,
        &coin_type_be_pv,
    );

    let scalar_packed_slot: Vec<Val> = ed25519_inputs.ed25519_public_values
        [crate::ed25519_air::air::SCALAR_PACKED_OFFSET
            ..crate::ed25519_air::air::SCALAR_PACKED_OFFSET + 32]
        .to_vec();
    debug_assert_eq!(
        scalar_packed_slot, slip10_air_witness.priv_packed,
        "Ed25519's scalar_packed slot and Slip10's clamped priv_packed must agree at honest prove time"
    );

    let public_values_per_instance = [
        Vec::<Val>::new(),                            // SHA-512 PBKDF2 sender
        Vec::<Val>::new(),                            // SHA-512 keysched sender
        Vec::<Val>::new(),                            // SHA-512 SLIP-0010 sender
        keysched_pv.clone(),                          // HmacKeysched
        keysched_pv.clone(),                          // Pbkdf2Hmac — SAME vector as slot 3
        pbkdf2_orchestrator.seed_packed.clone(),      // Pbkdf2 orchestrator
        slip10_hmac_public_values,                    // Slip10Hmac (seed + purpose')
        scalar_packed_slot,                           // Slip10 priv-extractor — clamped scalar
        ed25519_inputs.ed25519_public_values.clone(), // Ed25519
        Vec::<Val>::new(),                            // RangeCheckU16
        bip39_to_solana_witness.bip39_to_solana_pv.clone(), // Bip39ToSolana
    ];

    let common = &prover_data.common;
    let instances =
        StarkInstance::new_multiple(&airs, &traces, &public_values_per_instance, common);
    let proof = prove_batch(&config, &instances, &prover_data);

    let proof_bytes =
        postcard::to_allocvec(&proof).map_err(|e| Plonky3Error::Encode(e.to_string()))?;
    let preprocessed_commitment = postcard::to_allocvec(
        &prover_data
            .common
            .preprocessed
            .as_ref()
            .expect("batch must have preprocessed commitment")
            .commitment,
    )
    .map_err(|e| Plonky3Error::Encode(e.to_string()))?;

    let to_u32 = |fields: &[Val]| -> Vec<u32> {
        fields.iter().map(|f| f.as_canonical_u32()).collect()
    };
    // Bip39ToSolana's PV is [solana_address (32) || pq_dest (32) ||
    // blockhash (32)]. Only the last 64 bytes are stored — the
    // address bytes are derived from ed25519_pv's y_A slot at verify
    // time. See `Bip39ToSolanaArtifact` doc.
    let pq_dest_and_blockhash_slice =
        &bip39_to_solana_witness.bip39_to_solana_pv[NUM_SOLANA_ADDRESS_BYTES..];
    debug_assert_eq!(pq_dest_and_blockhash_slice.len(), PQ_DEST_AND_BLOCKHASH_PV_LEN);
    let artifact = Bip39ToSolanaArtifact {
        num_iterations: num_iterations as u32,
        keysched_pv: to_u32(&keysched_pv),
        seed_packed_pv: to_u32(&pbkdf2_orchestrator.seed_packed),
        ed25519_pv: to_u32(&ed25519_inputs.ed25519_public_values),
        pq_destination_and_blockhash_pv: to_u32(pq_dest_and_blockhash_slice),
        preprocessed_commitment,
        proof_bytes,
    };
    postcard::to_allocvec(&artifact).map_err(|e| Plonky3Error::Encode(e.to_string()))
}

/// Build the verifier-side [`CommonData`] without re-running
/// `pcs.commit_preprocessing`. The preprocessed-trace LDE + Merkle
/// commit on the verifier is wasted work — the prover's salted
/// commitment is already in `pp_commit`, and lookups are deterministic
/// from each AIR. This mirrors what `ProverData::from_airs_and_degrees`
/// does (see `p3_batch_stark::common`) minus the expensive PCS commit.
fn build_verify_common_data(
    airs: &mut [ChainAir],
    ext_log_heights: &[usize],
    pp_commit: Commitment<Cfg>,
) -> CommonData<Cfg> {
    let mut instances_meta: Vec<Option<PreprocessedInstanceMeta>> = Vec::with_capacity(airs.len());
    let mut matrix_to_instance: Vec<usize> = Vec::new();
    let mut next_matrix_index: usize = 0;
    for (i, (air, &ext_db)) in airs.iter().zip(ext_log_heights.iter()).enumerate() {
        let preprocessed: Option<RowMajorMatrix<Val>> =
            <ChainAir as BaseAir<Val>>::preprocessed_trace(air);
        let Some(preprocessed) = preprocessed else {
            instances_meta.push(None);
            continue;
        };
        let width = preprocessed.width();
        if width == 0 {
            instances_meta.push(None);
            continue;
        }
        instances_meta.push(Some(PreprocessedInstanceMeta {
            matrix_index: next_matrix_index,
            width,
            degree_bits: ext_db,
        }));
        matrix_to_instance.push(i);
        next_matrix_index += 1;
    }

    let lookups: Vec<Vec<Lookup<Val>>> =
        airs.iter_mut().map(|air| air.get_lookups()).collect();

    CommonData::new(
        Some(GlobalPreprocessed {
            commitment: pp_commit,
            instances: instances_meta,
            matrix_to_instance,
        }),
        lookups,
    )
}

/// Verify a [`prove`]-produced proof and return the proven 32-byte
/// Solana address, PQ destination address, and recent blockhash on success.
///
/// The address is the **canonical Ed25519 public-key form** (32 bytes).
/// To get the base58 address string a Solana wallet displays, the
/// caller should base58-encode these 32 bytes off-circuit. The verify
/// path does NOT do the base58 encoding because encoding is invertible
/// and verifier-side trivial.
pub fn verify(artifact_bytes: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32]), Plonky3Error> {
    let artifact: Bip39ToSolanaArtifact = postcard::from_bytes(artifact_bytes)
        .map_err(|e| Plonky3Error::Decode(e.to_string()))?;
    let proof: BatchProof<Cfg> = postcard::from_bytes(&artifact.proof_bytes)
        .map_err(|e| Plonky3Error::Decode(e.to_string()))?;

    if artifact.pq_destination_and_blockhash_pv.len() != PQ_DEST_AND_BLOCKHASH_PV_LEN {
        return Err(Plonky3Error::Decode(format!(
            "pq_destination_and_blockhash_pv must be {PQ_DEST_AND_BLOCKHASH_PV_LEN} cells (got {})",
            artifact.pq_destination_and_blockhash_pv.len()
        )));
    }
    let expected_ed25519_pv_len = crate::ed25519_air::air::NUM_PUBLIC_VALUES;
    if artifact.ed25519_pv.len() != expected_ed25519_pv_len {
        return Err(Plonky3Error::Decode(format!(
            "ed25519_pv must be {expected_ed25519_pv_len} cells (got {})",
            artifact.ed25519_pv.len()
        )));
    }

    let num_iterations = artifact.num_iterations as usize;
    if num_iterations == 0 {
        return Err(Plonky3Error::Decode(
            "artifact's num_iterations must be ≥ 1".to_string(),
        ));
    }
    let pbkdf2_sha_compressions = 2 * num_iterations;

    let mut airs = [
        ChainAir::Sha512(Sha512Air::new(pbkdf2_sha_compressions)),
        ChainAir::Sha512(Sha512Air::new(KEYSCHED_SHA_COMPRESSIONS)),
        ChainAir::Sha512(Sha512Air::new(SLIP10_SHA_COMPRESSIONS)),
        ChainAir::HmacKeysched(HmacKeyschedAir::default()),
        ChainAir::Pbkdf2Hmac(Pbkdf2HmacAir::new(num_iterations)),
        ChainAir::Pbkdf2(Pbkdf2Air::new(num_iterations)),
        ChainAir::Slip10Hmac(Slip10HmacAir::default()),
        ChainAir::Slip10(Slip10Air::default()),
        ChainAir::Ed25519(Ed25519Air::default()),
        ChainAir::RangeCheckU16(RangeCheckU16Air::default()),
        ChainAir::Bip39ToSolana(Bip39ToSolanaAir),
    ];

    let pbkdf2_height = 2 * num_iterations;
    let ext_log_heights = [
        ext_log_for(pbkdf2_sha_compressions.next_power_of_two()),
        ext_log_for(KEYSCHED_SHA_COMPRESSIONS.next_power_of_two()),
        ext_log_for(SLIP10_SHA_COMPRESSIONS.next_power_of_two()),
        ext_log_for(KEYSCHED_TRACE_HEIGHT),
        ext_log_for(pbkdf2_height),
        ext_log_for(num_iterations),
        ext_log_for(SLIP10_TRACE_HEIGHT),
        ext_log_for(2),
        ext_log_for(NUM_ROWS_PER_SCALAR_MUL),
        ext_log_for(TABLE_HEIGHT),
        ext_log_for(2),
    ];

    let config = make_config();
    let pp_commit: Commitment<Cfg> = postcard::from_bytes(&artifact.preprocessed_commitment)
        .map_err(|e| Plonky3Error::Decode(e.to_string()))?;
    let common = build_verify_common_data(&mut airs, &ext_log_heights, pp_commit);

    let from_u32 = |xs: &[u32]| -> Vec<Val> {
        xs.iter().map(|&u| Val::from_u32(u)).collect()
    };
    let keysched_pv = from_u32(&artifact.keysched_pv);
    let seed_pv = from_u32(&artifact.seed_packed_pv);
    let ed25519_pv = from_u32(&artifact.ed25519_pv);
    let pq_dest_and_blockhash = from_u32(&artifact.pq_destination_and_blockhash_pv);

    // Slip10's PV = `ed25519_pv[SCALAR_PACKED_OFFSET..+32]`. Critical
    // #2 binding: by passing the same field elements to both AIRs the
    // verifier pins Slip10's emitted clamped scalar to equal Ed25519's
    // `scalar_packed` PV slot. Slip10's AIR-internal constraint
    // enforces "scalar_packed = clamp(priv_bits)"; Ed25519's enforces
    // "scalar_bit cells == scalar_packed"; the shared Vec connects them.
    let scalar_packed_pv: Vec<Val> = ed25519_pv[crate::ed25519_air::air::SCALAR_PACKED_OFFSET
        ..crate::ed25519_air::air::SCALAR_PACKED_OFFSET + 32]
        .to_vec();

    // Bip39ToSolana's PV = `[ed25519_pv[Y_OFFSET..+32] || pq_dest_and_blockhash]`.
    // Critical #3 binding: the solana_address portion is taken from
    // Ed25519's `y_A` slot rather than from a prover-supplied,
    // unconstrained-equality field. The shared Vec elements pin the
    // two AIRs' PVs to the same bytes.
    let mut bip39_to_solana_pv: Vec<Val> = ed25519_pv
        [crate::ed25519_air::air::PUBLIC_INPUT_Y_OFFSET
            ..crate::ed25519_air::air::PUBLIC_INPUT_Y_OFFSET + 32]
        .to_vec();
    bip39_to_solana_pv.extend_from_slice(&pq_dest_and_blockhash);

    let purpose_be_pv = path_index_to_be_byte_pv(BIP44_PURPOSE);
    let coin_type_be_pv = path_index_to_be_byte_pv(SOLANA_COIN_TYPE);
    let slip10_hmac_public_values =
        slip10_hmac_pv(&seed_pv, &purpose_be_pv, &coin_type_be_pv);

    // Pbkdf2HmacAir's PV slot receives the SAME `keysched_pv` Vec as
    // HmacKeyschedAir's slot — Critical #1 binding. Internally each
    // AIR pins this vector to its own trace; the shared elements
    // force the prover to agree on a single `[ipad_state, opad_state]`.
    let public_values = vec![
        Vec::<Val>::new(),
        Vec::<Val>::new(),
        Vec::<Val>::new(),
        keysched_pv.clone(),
        keysched_pv,
        seed_pv,
        slip10_hmac_public_values,
        scalar_packed_pv,
        ed25519_pv,
        Vec::<Val>::new(),
        bip39_to_solana_pv,
    ];

    verify_batch(&config, &airs, &proof, &public_values, &common)
        .map_err(|e| Plonky3Error::Decode(format!("verify_batch rejected: {e:?}")))?;

    // Pull the proven Solana address from Ed25519's `y_A` PV slot
    // (= canonical source after Critical #3 fix). PQ destination and
    // recent blockhash come from the stored 64-cell aux field.
    let mut solana_address = [0u8; 32];
    let mut pq_destination_address = [0u8; 32];
    let mut recent_blockhash = [0u8; 32];

    for i in 0..32 {
        let byte = artifact.ed25519_pv[crate::ed25519_air::air::PUBLIC_INPUT_Y_OFFSET + i];
        if byte > 0xFF {
            return Err(Plonky3Error::Decode(format!(
                "solana_address byte {i} out of range: {byte}"
            )));
        }
        solana_address[i] = byte as u8;
    }

    for i in 0..32 {
        let byte = artifact.pq_destination_and_blockhash_pv[i];
        if byte > 0xFF {
            return Err(Plonky3Error::Decode(format!(
                "pq_destination_address byte {i} out of range: {byte}"
            )));
        }
        pq_destination_address[i] = byte as u8;
    }

    for i in 0..32 {
        let byte = artifact.pq_destination_and_blockhash_pv[32 + i];
        if byte > 0xFF {
            return Err(Plonky3Error::Decode(format!(
                "recent_blockhash byte {i} out of range: {byte}"
            )));
        }
        recent_blockhash[i] = byte as u8;
    }

    Ok((solana_address, pq_destination_address, recent_blockhash))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end round-trip at PBKDF2 `c = 1` (so it runs in a couple
    /// seconds). The constraint shape is identical to the production
    /// `c = 2048` instance; only the trace heights for PBKDF2 +
    /// SHA-512 PBKDF2 sender shrink. Validates that the canonical
    /// `prove` / `verify` API works end-to-end for the default
    /// `m/44'/501'/0'/0'` account.
    #[test]
    fn prove_verify_round_trip_short_mnemonic() {
        let mnemonic: &[u8] = b"abc-test-mnemonic";
        let pq_dest = [0x11; 32];
        let blockhash = [0x22; 32];
        let artifact_bytes = prove_with_iterations(mnemonic, &pq_dest, &blockhash, 0, 0, 1)
            .expect("prove must succeed for short mnemonic");
        let (address, proven_pq_dest, proven_blockhash) = verify(&artifact_bytes)
            .expect("verify of an honest prover-produced artifact must succeed");
        // Sanity: 32-byte address is non-zero (an honest scalar mult
        // of a non-zero scalar against the Ed25519 base produces a
        // non-identity point — its y_A would only be all-zero by
        // astronomical coincidence).
        let any_nonzero = address.iter().any(|&b| b != 0);
        assert!(any_nonzero, "proven Solana address is all zeros (suspicious)");
        assert_eq!(proven_pq_dest, pq_dest);
        assert_eq!(proven_blockhash, blockhash);
    }

    /// Same round-trip as `prove_verify_round_trip_short_mnemonic`, but
    /// derives a non-default account / change pair (`m/44'/501'/5'/2'`).
    /// Confirms the path-index plumbing actually varies the proven
    /// address and that committed `account'` / `change'` bytes reach
    /// the verifier intact.
    #[test]
    fn prove_verify_round_trip_non_default_account_change() {
        let mnemonic: &[u8] = b"abc-test-mnemonic";
        let pq_dest = [0x11; 32];
        let blockhash = [0x22; 32];

        let default_artifact =
            prove_with_iterations(mnemonic, &pq_dest, &blockhash, 0, 0, 1)
                .expect("prove must succeed for default account");
        let (default_address, _, _) = verify(&default_artifact)
            .expect("verify default-account artifact must succeed");

        let varied_artifact =
            prove_with_iterations(mnemonic, &pq_dest, &blockhash, 5, 2, 1)
                .expect("prove must succeed for account=5 change=2");
        let (varied_address, proven_pq_dest, proven_blockhash) = verify(&varied_artifact)
            .expect("verify non-default-account artifact must succeed");

        assert_eq!(proven_pq_dest, pq_dest);
        assert_eq!(proven_blockhash, blockhash);
        assert_ne!(
            default_address, varied_address,
            "different (account', change') must derive a different address"
        );
    }

    /// Tampering with the proof bytes must cause `verify` to fail.
    #[test]
    fn verify_rejects_corrupted_proof_bytes() {
        let mnemonic: &[u8] = b"tamper-test-mnemonic";
        let artifact_bytes = prove_with_iterations(mnemonic, &[0; 32], &[0; 32], 0, 0, 1)
            .expect("prove must succeed");

        // Postcard-decode, flip a byte in the inner proof, re-encode.
        let mut artifact: Bip39ToSolanaArtifact =
            postcard::from_bytes(&artifact_bytes).unwrap();
        let mid = artifact.proof_bytes.len() / 2;
        artifact.proof_bytes[mid] ^= 0xFF;
        let bad_bytes = postcard::to_allocvec(&artifact).unwrap();

        let result = verify(&bad_bytes);
        assert!(
            result.is_err(),
            "corrupted proof must be rejected; got {:?}",
            result
        );
    }
}
