//! FIPS 180-4 SHA-512 constants and AIR-shape parameters.
//!
//! Spec reference: `docs/sha512-spec.md` §2.1 (algorithm constants), §4
//! (AIR-shape parameters). The IV and round-constant values are
//! cross-checked against:
//!   - Electron-Labs plonky2_sha512 `gadgets/sha512.rs`
//!   - Binius64 `crates/circuits/src/sha512/compress.rs`
//! Both references agree byte-for-byte with the values below.

/// SHA-512 word size in bits.
pub const WORD_BITS: usize = 64;

/// Number of 16-bit packed limbs per 64-bit word. `4 × 16 = 64`.
pub const U64_LIMBS: usize = 4;

/// Bits per packed limb. Chosen so each limb fits in BabyBear with margin
/// (limb max `2^16 − 1 < p ≈ 2^31`) and so 16-bit range checks are
/// implicit via bit decomposition. Spec §4.1, §6.3.
pub const BITS_PER_LIMB: usize = 16;

/// Number of state words `(H_0..H_7)`.
pub const STATE_WORDS: usize = 8;

/// Number of message words per 1024-bit block `(M_0..M_15)`.
pub const BLOCK_WORDS: usize = 16;

/// Compression rounds.
pub const NUM_COMPRESSION_ROUNDS: usize = 80;

/// Schedule extension count: `W_t` for `t ∈ [16, 80)`.
pub const SCHEDULE_EXTENSIONS: usize = NUM_COMPRESSION_ROUNDS - BLOCK_WORDS;

/// Length of each `a`/`e` working-variable chain. Four initial-state
/// entries plus one entry per compression round. Spec §4.4.
pub const CHAIN_LEN: usize = 4 + NUM_COMPRESSION_ROUNDS;

/// First 64 bits of the fractional parts of the square roots of the first
/// eight primes (FIPS 180-4 §5.3.5).

#[rustfmt::skip]
pub const SHA512_IV: [u64; STATE_WORDS] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// First 64 bits of the fractional parts of the cube roots of the first 80
/// primes (FIPS 180-4 §4.2.3).
#[rustfmt::skip]
pub const SHA512_K: [u64; NUM_COMPRESSION_ROUNDS] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// `Σ_0(x) = ROTR^28(x) ⊕ ROTR^34(x) ⊕ ROTR^39(x)` — SHA-256 uses (2, 13, 22).
pub const BIG_SIGMA0_ROTATIONS: [u32; 3] = [28, 34, 39];

/// `Σ_1(x) = ROTR^14(x) ⊕ ROTR^18(x) ⊕ ROTR^41(x)` — SHA-256 uses (6, 11, 25).
pub const BIG_SIGMA1_ROTATIONS: [u32; 3] = [14, 18, 41];

/// `σ_0(x) = ROTR^1(x) ⊕ ROTR^8(x) ⊕ SHR^7(x)` — SHA-256 uses (7, 18, SHR 3).
pub const SMALL_SIGMA0_ROTATIONS: [u32; 2] = [1, 8];
pub const SMALL_SIGMA0_SHIFT: u32 = 7;

/// `σ_1(x) = ROTR^19(x) ⊕ ROTR^61(x) ⊕ SHR^6(x)` — SHA-256 uses (17, 19, SHR 10).
pub const SMALL_SIGMA1_ROTATIONS: [u32; 2] = [19, 61];
pub const SMALL_SIGMA1_SHIFT: u32 = 6;

/// Name of the global LogUp bus that pairs SHA-512 compression rows
/// (sender) with wrapper-AIR receivers (HMAC instances, etc.). Per
/// `docs/pipeline-spec.md` §5: "every wrapper-claimed compression has a
/// corresponding proven SHA-512 row, and vice versa". All AIRs that
/// participate must register `Kind::Global(SHA512_COMPRESSIONS_BUS_NAME)`.
pub const SHA512_COMPRESSIONS_BUS_NAME: &str = "sha512_compressions";

/// Length of the canonical compression-tuple sent on the
/// `sha512_compressions` bus. One tuple binds one full compression as
/// `(h_in, block, h_out)` decomposed into 16-bit limbs:
///   8 state words × 4 limbs (h_in)
/// + 16 block words × 4 limbs (block)
/// + 8 state words × 4 limbs (h_out)
/// = 128 limbs. β-Horner inside the LogUp gadget collapses the 128
/// elements to a single combined value at constraint-eval time, so the
/// transition constraint stays at degree 3 regardless of tuple size
/// (`docs/pipeline-spec.md` §5.1).
pub const NUM_SHA512_TUPLE_LIMBS: usize =
    STATE_WORDS * U64_LIMBS + BLOCK_WORDS * U64_LIMBS + STATE_WORDS * U64_LIMBS;

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference computation against the `sha2` crate. Hashes "abc" and
    /// confirms our IV + K table produces the canonical FIPS 180-4 test
    /// vector digest. This is purely a self-check that the IV/K constants
    /// are byte-exact; it doesn't exercise any AIR logic.
    #[test]
    fn iv_and_k_produce_correct_digest_for_abc() {
        // FIPS 180-4 Appendix C.1 — SHA-512("abc"):
        let expected: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];

        // Run the reference SHA-512 ourselves using `compress`-style
        // pseudocode driven by SHA512_IV and SHA512_K. If any constant
        // is off by a bit, the digest mismatches.
        let digest = reference_sha512_abc();
        assert_eq!(
            digest, expected,
            "constants.rs IV/K do not produce FIPS 180-4 SHA-512(\"abc\")"
        );
    }

    /// Compute SHA-512("abc") by running one block of compression with
    /// our hard-coded IV and K.
    /// By avoiding the `sha2` dependency, we keep
    /// the test self-contained.
    fn reference_sha512_abc() -> [u8; 64] {
        // Padded "abc" as one 1024-bit block. From FIPS 180-4 Appendix C.1.
        // Length = 24 bits = 0x18; padding starts at byte 3 with 0x80,
        // then zeros, length encoded as the low 64 bits of a 128-bit
        // big-endian integer in the last two words.
        let mut w = [0u64; NUM_COMPRESSION_ROUNDS];
        w[0] = 0x6162638000000000; // "abc" || 0x80 || zeros
                                   // w[1..14] are zero (already initialised).
        w[14] = 0;
        w[15] = 0x0000000000000018; // 24 bits

        // Schedule extension: W_t = σ_1(W_{t-2}) + W_{t-7} + σ_0(W_{t-15}) + W_{t-16}
        for t in BLOCK_WORDS..NUM_COMPRESSION_ROUNDS {
            w[t] = small_sigma1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(small_sigma0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        // Compression
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = SHA512_IV;
        for t in 0..NUM_COMPRESSION_ROUNDS {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA512_K[t])
                .wrapping_add(w[t]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Final hash
        let h_out = [
            SHA512_IV[0].wrapping_add(a),
            SHA512_IV[1].wrapping_add(b),
            SHA512_IV[2].wrapping_add(c),
            SHA512_IV[3].wrapping_add(d),
            SHA512_IV[4].wrapping_add(e),
            SHA512_IV[5].wrapping_add(f),
            SHA512_IV[6].wrapping_add(g),
            SHA512_IV[7].wrapping_add(h),
        ];

        // Pack as big-endian bytes
        let mut out = [0u8; 64];
        for (i, word) in h_out.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }
    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn big_sigma0(x: u64) -> u64 {
        x.rotate_right(BIG_SIGMA0_ROTATIONS[0])
            ^ x.rotate_right(BIG_SIGMA0_ROTATIONS[1])
            ^ x.rotate_right(BIG_SIGMA0_ROTATIONS[2])
    }
    fn big_sigma1(x: u64) -> u64 {
        x.rotate_right(BIG_SIGMA1_ROTATIONS[0])
            ^ x.rotate_right(BIG_SIGMA1_ROTATIONS[1])
            ^ x.rotate_right(BIG_SIGMA1_ROTATIONS[2])
    }
    fn small_sigma0(x: u64) -> u64 {
        x.rotate_right(SMALL_SIGMA0_ROTATIONS[0])
            ^ x.rotate_right(SMALL_SIGMA0_ROTATIONS[1])
            ^ (x >> SMALL_SIGMA0_SHIFT)
    }
    fn small_sigma1(x: u64) -> u64 {
        x.rotate_right(SMALL_SIGMA1_ROTATIONS[0])
            ^ x.rotate_right(SMALL_SIGMA1_ROTATIONS[1])
            ^ (x >> SMALL_SIGMA1_SHIFT)
    }
}
