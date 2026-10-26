//! HMAC-SHA512 constants.
//!
//! Spec source: `docs/pipeline-spec.md` §2.2 / §6.2. Numerics are RFC 2104
//! HMAC's inner / outer pad bytes; the SHA-512 IV and block-size constants
//! re-export from `sha512_air::constants` so wrapper AIRs depend only on
//! this single namespace.

/// HMAC inner-pad byte (RFC 2104). Repeated 128 times to fill a SHA-512
/// block, then XOR'd byte-wise with the (zero-padded) key. The
/// "inner-pad" name is FIPS-198 / RFC-2104 standard usage.
pub const IPAD_BYTE: u8 = 0x36;

/// HMAC outer-pad byte (RFC 2104). Same role as `IPAD_BYTE`, different
/// constant — the XOR-with-two-different-pads construction is what
/// defeats SHA-512's length-extension property.
pub const OPAD_BYTE: u8 = 0x5C;

/// Bytes per SHA-512 block (1024 bits / 128 bytes). HMAC zero-pads the
/// key out to this length for `|K| ≤ 128` (the common path for BIP-39
/// mnemonics — see `pipeline-spec.md` §1.1).
pub const SHA512_BLOCK_BYTES: usize = 128;
