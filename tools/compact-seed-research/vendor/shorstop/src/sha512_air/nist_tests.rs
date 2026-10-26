//! NIST CAVS SHA-512 ShortMsg / LongMsg vectors against our AIR.
//!
//! For each `(message, expected_digest)`:
//!   1. FIPS 180-4 pad the message into 1024-bit blocks.
//!   2. Chain our `fill_row` across blocks (h_in of block k+1 = h_out of block k).
//!   3. Decode the last row's `H_out` bit columns; assert byte-equality with NIST.
//!   4. For a curated subset of lengths, also run `p3_air::check_constraints`
//!      on the chained trace — confirms the AIR accepts the witness too.
//!
//! Spec reference: `docs/sha512-spec.md` §1 (padding is caller's responsibility,
//! AIR sees fully-padded blocks).

use p3_air::check_constraints;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::sha512_air::air::Sha512Air;
use crate::sha512_air::columns::NUM_SHA512_COLS;
use crate::sha512_air::constants::{BLOCK_WORDS, SHA512_IV, STATE_WORDS};
use crate::sha512_air::generation::{fill_row_u64, h_out_bytes_be};

const SHORT_MSG_RSP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../references/sha512/nist/shabytetestvectors/SHA512ShortMsg.rsp"
);

const LONG_MSG_RSP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../references/sha512/nist/shabytetestvectors/SHA512LongMsg.rsp"
);

// ── Vector parsing ──────────────────────────────────────────────────────

#[derive(Debug)]
struct CavsVector {
    len_bits: usize,
    message: Vec<u8>,
    expected_digest: [u8; 64],
}

fn parse_rsp(path: &str) -> Vec<CavsVector> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));

    let mut out = Vec::new();
    let mut len_bits: Option<usize> = None;
    let mut msg: Option<Vec<u8>> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("Len = ") {
            len_bits = Some(rest.trim().parse().expect("invalid Len"));
        } else if let Some(rest) = line.strip_prefix("Msg = ") {
            // The CAVS file uses "00" as a placeholder for the empty message
            // (Len = 0). Detect that and substitute an empty Vec.
            let hex_part = rest.trim();
            if matches!(len_bits, Some(0)) {
                msg = Some(Vec::new());
            } else {
                msg = Some(hex_decode(hex_part));
            }
        } else if let Some(rest) = line.strip_prefix("MD = ") {
            let bytes = hex_decode(rest.trim());
            assert_eq!(bytes.len(), 64, "MD must be 64 bytes (512 bits)");
            let mut digest = [0u8; 64];
            digest.copy_from_slice(&bytes);
            out.push(CavsVector {
                len_bits: len_bits.expect("Len must precede MD"),
                message: msg.take().expect("Msg must precede MD"),
                expected_digest: digest,
            });
            len_bits = None;
        }
    }
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── FIPS 180-4 padding (the part our AIR doesn't do — caller's responsibility) ──

/// Pad a byte message per FIPS 180-4 §5.1.2 (SHA-512 padding) and group
/// into 1024-bit blocks of 16 big-endian u64s. Length is encoded as
/// 128 big-endian bits in the last 16 bytes of the final block.
fn sha512_pad(message: &[u8]) -> Vec<[u64; BLOCK_WORDS]> {
    // Block size = 128 bytes; padding ≥ 17 bytes (1 byte 0x80 + 16 bytes
    // length). If `message_len mod 128 ≤ 111`, single extra block of
    // padding suffices; otherwise two extra blocks.
    let bit_len = (message.len() as u128) * 8;
    let mut bytes = Vec::with_capacity(message.len() + 17 + 128);
    bytes.extend_from_slice(message);
    bytes.push(0x80);
    while bytes.len() % 128 != 112 {
        bytes.push(0);
    }
    // 128-bit big-endian length
    bytes.extend_from_slice(&bit_len.to_be_bytes());
    debug_assert!(bytes.len() % 128 == 0);

    bytes
        .chunks_exact(128)
        .map(|chunk| {
            let mut block = [0u64; BLOCK_WORDS];
            for (i, w) in chunk.chunks_exact(8).enumerate() {
                block[i] = u64::from_be_bytes(w.try_into().unwrap());
            }
            block
        })
        .collect()
}

// ── Trace + digest helpers ──────────────────────────────────────────────

/// Compute SHA-512 of `message` by chaining `fill_row_u64` per block.
/// Returns `(digest, trace_u64)` so callers can inspect both.
fn digest_via_air(message: &[u8]) -> ([u8; 64], Vec<u64>) {
    let blocks = sha512_pad(message);
    assert!(!blocks.is_empty());

    let mut all_rows = vec![0u64; blocks.len() * NUM_SHA512_COLS];
    let mut state = SHA512_IV;
    for (i, block) in blocks.iter().enumerate() {
        let row = &mut all_rows[i * NUM_SHA512_COLS..(i + 1) * NUM_SHA512_COLS];
        fill_row_u64(state, *block, row);

        // Decode H_out of this row to chain into next row's H_in.
        let digest_bytes = h_out_bytes_be(row);
        for j in 0..STATE_WORDS {
            state[j] = u64::from_be_bytes(
                digest_bytes[j * 8..(j + 1) * 8].try_into().unwrap(),
            );
        }
    }
    let last = &all_rows[(blocks.len() - 1) * NUM_SHA512_COLS..];
    let digest = h_out_bytes_be(last);
    (digest, all_rows)
}

/// Build a BabyBear `RowMajorMatrix` from a u64 row buffer, padded to the
/// next power of 2 by repeating the first row (each row is independently
/// valid because the AIR has no transition constraints).
fn babybear_trace_from_u64(rows_u64: &[u64], n_rows: usize) -> RowMajorMatrix<BabyBear> {
    let padded_n = n_rows.next_power_of_two().max(2);
    let mut values: Vec<BabyBear> = rows_u64
        .iter()
        .map(|&v| BabyBear::from_u64(v))
        .collect();
    let first_row = values[..NUM_SHA512_COLS].to_vec();
    while values.len() < padded_n * NUM_SHA512_COLS {
        values.extend_from_slice(&first_row);
    }
    RowMajorMatrix::new(values, NUM_SHA512_COLS)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[test]
fn nist_short_msg_digests_match() {
    let vectors = parse_rsp(SHORT_MSG_RSP);
    assert!(!vectors.is_empty(), "no vectors parsed; check rsp path");

    let mut failures = Vec::new();
    for v in &vectors {
        // Self-check: the parsed message length matches Len / 8 (CAVS files
        // use byte-oriented messages even though Len is in bits, with one
        // exception: Len=0 has Msg="00").
        if v.len_bits > 0 {
            assert_eq!(v.message.len() * 8, v.len_bits, "message len mismatch");
        }
        let (digest, _) = digest_via_air(&v.message);
        if digest != v.expected_digest {
            failures.push(v.len_bits);
        }
    }
    assert!(
        failures.is_empty(),
        "digest mismatch on lengths (bits): {failures:?} out of {} vectors",
        vectors.len()
    );
}

#[test]
fn nist_long_msg_digests_match() {
    // LongMsg covers messages 1KB..51KB (multi-block heavy). Our AIR's
    // chaining is what's exercised here.
    let vectors = parse_rsp(LONG_MSG_RSP);
    assert!(!vectors.is_empty(), "no LongMsg vectors parsed");

    let mut failures = Vec::new();
    for v in &vectors {
        let (digest, _) = digest_via_air(&v.message);
        if digest != v.expected_digest {
            failures.push(v.len_bits);
        }
    }
    assert!(
        failures.is_empty(),
        "LongMsg digest mismatch on lengths (bits): {failures:?} of {} vectors",
        vectors.len()
    );
}

/// Run `check_constraints` on the chained trace for a curated subset of
/// boundary-style lengths from ShortMsg. Slow, so we deliberately pick a
/// handful that exercise different padding regimes.
#[test]
fn nist_subset_passes_check_constraints() {
    let vectors = parse_rsp(SHORT_MSG_RSP);

    // Lengths that exercise distinct padding regimes:
    //   0    — empty message, padding is the entire block
    //   64   — small message, plenty of room for padding in one block
    //   888  — 111 bytes = max-fits-in-one-block boundary
    //   896  — 112 bytes = first length that overflows to second block
    //   1024 — 128 bytes = full-block message, padding is full second block
    let target_lens: [usize; 5] = [0, 64, 888, 896, 1024];

    for target in target_lens {
        let v = vectors
            .iter()
            .find(|v| v.len_bits == target)
            .unwrap_or_else(|| panic!("no NIST vector with Len = {target} bits"));

        let (digest, rows_u64) = digest_via_air(&v.message);
        assert_eq!(digest, v.expected_digest, "digest precondition for Len={target}");

        let n_rows = rows_u64.len() / NUM_SHA512_COLS;
        let trace = babybear_trace_from_u64(&rows_u64, n_rows);

        check_constraints(&Sha512Air::default(), &trace, &[]);
    }
}
