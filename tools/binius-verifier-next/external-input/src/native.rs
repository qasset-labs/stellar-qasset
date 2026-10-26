//! Public-fixture experiment only. Not a production or approved quantum backend.
use binius_circuits::sha512::sha512_fixed;
use binius_core::{Word, constraint_system::ConstraintSystem};
use binius_frontend::{Circuit, CircuitBuilder, Wire};
use binius_hash::{StdCompression, StdDigest};
use binius_verifier::zk_config::ZKVerifier;
use curve25519_dalek::edwards::EdwardsPoint;

const DOMAIN: &[u8] = b"qasset-binius-leaf-clamp-research-v1\0";
const LOG_INV_RATE: usize = 1;
const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;
const FIXTURE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const FIXTURE_SCALAR: &str = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f";
const FIXTURE_POINT: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
type Verifier = ZKVerifier<StdDigest, StdCompression>;

pub(super) struct Built {
    pub(super) circuit: Circuit,
    seed: [Wire; 4],
    scalar: [Wire; 4],
}
pub(super) fn build() -> Built {
    let b = CircuitBuilder::new();
    let scalar = std::array::from_fn(|_| b.add_inout());
    let seed = std::array::from_fn(|_| b.add_witness());
    let digest = sha512_fixed(&b, &seed, 32);
    // SHA512 wires use big endian words; byte0 low three bits sit at bits56..58.
    // byte31's high/next-high bits sit at bits7/6 of the fourth word.
    let mut clamped = [digest[0], digest[1], digest[2], digest[3]];
    clamped[0] = b.band(digest[0], b.add_constant_64(0xf8ff_ffff_ffff_ffff));
    clamped[3] = b.bor(
        b.band(digest[3], b.add_constant_64(0xffff_ffff_ffff_ff7f)),
        b.add_constant_64(0x40),
    );
    for i in 0..4 {
        b.assert_eq(format!("clamped_scalar[{i}]"), clamped[i], scalar[i]);
    }
    Built {
        circuit: b.build(),
        seed,
        scalar,
    }
}
pub(super) fn decode<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|_| "invalid hex".to_owned())?;
    bytes.try_into().map_err(|_| format!("expected {N} bytes"))
}
fn words(bytes: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}
pub(super) fn check_scalar(scalar: &[u8; 32]) -> Result<(), String> {
    if scalar[0] & 7 != 0 || scalar[31] & 0xc0 != 0x40 {
        return Err("invalid clamped encoding".into());
    }
    let point = EdwardsPoint::mul_base_clamped(*scalar)
        .compress()
        .to_bytes();
    if point != decode::<32>(FIXTURE_POINT)? {
        return Err("scalar does not match independent fixture public key".into());
    }
    Ok(())
}
pub(super) fn public(cs: &ConstraintSystem, scalar: &[u8; 32]) -> Vec<Word> {
    let layout = &cs.value_vec_layout;
    assert_eq!(layout.n_inout, 4);
    let mut p = vec![Word::ZERO; layout.offset_witness];
    for (i, v) in cs.constants.iter().enumerate() {
        p[i] = *v;
    }
    for (i, v) in words(scalar).iter().enumerate() {
        p[layout.offset_inout + i] = Word(*v);
    }
    p
}
pub(super) fn setup_verifier(cs: ConstraintSystem) -> Result<Verifier, String> {
    ZKVerifier::setup(cs, LOG_INV_RATE, StdCompression::default())
        .map_err(|e| format!("setup: {e:?}"))
}
