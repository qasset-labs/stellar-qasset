//! Q-Asset research wrapper, not an upstream ShorStop component.
//! Proves a 32-byte SHA512 seed preimage against a PUBLIC clamped scalar.
//! An action digest is bound in the Fiat-Shamir transcript, not computed by the AIR.
//! It does not prove root derivation or on-chain authorization.
use crate::sha512_air::{
    air::Sha512Air,
    columns::{Sha512Cols, NUM_SHA512_COLS},
    constants::SHA512_IV,
};
use crate::{Cfg, Plonky3Error, Val};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Copy, Default)]
pub struct LeafSeedAir;

// A single-row trace with 78 FRI queries has insufficient masking entropy.
// Keep 128 real rows (all satisfying this relation) for the hiding PCS.
// This is a conservative experimental choice, not an end-to-end ZK proof.
const TRACE_ROWS: usize = 128;
const DOMAIN: &[u8] = b"QASSET-COMPACT-LEAF-SEED-V1";

fn public_values(clamp: [u8; 32], action: [u8; 64]) -> Vec<Val> {
    clamp
        .into_iter()
        .chain(DOMAIN.iter().copied())
        .chain(action)
        .map(|b| Val::from_u32(b.into()))
        .collect()
}

impl BaseAir<Val> for LeafSeedAir {
    fn width(&self) -> usize {
        NUM_SHA512_COLS
    }
    fn num_public_values(&self) -> usize {
        32 + DOMAIN.len() + 64
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for LeafSeedAir {
    fn eval(&self, builder: &mut AB) {
        Sha512Air::default().eval(builder);
        let main = builder.main();
        let local: &Sha512Cols<AB::Var> = (*main.current_slice()).borrow();
        let public: Vec<_> = builder.public_values().to_vec();
        // SHA512 initial chaining state is fixed, not a witness-controlled hash.
        for (i, word) in SHA512_IV.iter().enumerate() {
            for limb in 0..4 {
                builder.assert_eq(
                    local.h_in[i][limb],
                    AB::Expr::from_u32(((word >> (16 * limb)) & 65535) as u32),
                );
            }
        }
        // The first four words are exactly the private 32-byte RFC8032 seed.
        // One-block SHA512 padding: 0x80, zeros, 128-bit bitlength=256.
        for word in 4..16 {
            let expected = if word == 4 {
                1u64 << 63
            } else if word == 15 {
                256u64
            } else {
                0u64
            };
            for bit in 0..64 {
                builder.assert_eq(
                    local.w[word][bit],
                    AB::Expr::from_u32(((expected >> bit) & 1) as u32),
                );
            }
        }
        // SHA512 emits words big endian; RFC8032 then clamps the first 32
        // bytes. The five overwritten bits remain private unconstrained bits
        // of the correctly constrained hash, not extra claimed seed entropy.
        for byte in 0..32 {
            let mut packed = AB::Expr::ZERO;
            for bit in 0..8 {
                let value = if byte == 0 && bit < 3 {
                    AB::Expr::ZERO
                } else if byte == 31 && bit == 7 {
                    AB::Expr::ZERO
                } else if byte == 31 && bit == 6 {
                    AB::Expr::ONE
                } else {
                    local.h_out[byte / 8][(7 - byte % 8) * 8 + bit].into()
                };
                packed += value * AB::Expr::from_u32(1 << bit);
            }
            builder.assert_eq(packed, public[byte]);
        }
    }
}

pub fn prove(
    seed: [u8; 32],
    expected_clamp: [u8; 32],
    action: [u8; 64],
) -> Result<Vec<u8>, Plonky3Error> {
    let mut padded = [0u8; 128];
    padded[..32].copy_from_slice(&seed);
    padded[32] = 128;
    padded[126] = 1;
    let block =
        core::array::from_fn(|i| u64::from_be_bytes(padded[i * 8..i * 8 + 8].try_into().unwrap()));
    let trace =
        crate::sha512_air::generation::generate_trace::<Val>(&vec![(SHA512_IV, block); TRACE_ROWS]);
    let public = public_values(expected_clamp, action);
    let proof = p3_uni_stark::prove(&crate::make_config(), &LeafSeedAir, trace, &public);
    postcard::to_allocvec(&proof).map_err(|e| Plonky3Error::Encode(e.to_string()))
}

pub fn verify(
    proof_bytes: &[u8],
    expected_clamp: [u8; 32],
    action: [u8; 64],
) -> Result<bool, Plonky3Error> {
    if expected_clamp[0] & 7 != 0 || expected_clamp[31] & 192 != 64 {
        return Ok(false);
    }
    if proof_bytes.len() > 256 * 1024 * 1024 {
        return Err(Plonky3Error::Decode("proof exceeds research limit".into()));
    }
    let (proof, remainder): (p3_uni_stark::Proof<Cfg>, &[u8]) =
        postcard::take_from_bytes(proof_bytes).map_err(|e| Plonky3Error::Decode(e.to_string()))?;
    if !remainder.is_empty() {
        return Err(Plonky3Error::Decode("trailing proof data".into()));
    }
    let public = public_values(expected_clamp, action);
    Ok(p3_uni_stark::verify(&crate::make_config(), &LeafSeedAir, &proof, &public).is_ok())
}
