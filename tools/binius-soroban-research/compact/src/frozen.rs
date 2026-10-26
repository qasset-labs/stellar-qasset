// SPDX-License-Identifier: MIT
//! Operator-trusted fixed preprocessing; cryptographic verifier protocol is unchanged.
use alloc::{string::String, vec, vec::Vec};
use binius_core::constraint_system::ConstraintSystem as InnerCs;
use binius_field::BinaryField128bGhash as F;
use binius_hash::{StdCompression, StdDigest};
use binius_iop::{
    basefold_compiler::BaseFoldZKVerifierCompiler, channel::OracleSpec, fri::FRIParams,
    merkle_tree::BinaryMerkleTreeScheme,
};
use binius_math::{BinarySubspace, reed_solomon::ReedSolomonCode};
use binius_spartan_frontend::constraint_system::{
    BlindingInfo, ConstraintSystem as OuterCs, MulConstraint, Operand, WitnessIndex, WitnessSegment,
};
use binius_spartan_verifier::{
    IOPVerifier as OuterVerifier, constraint_system::ConstraintSystemPadded,
};
use binius_utils::DeserializeBytes;
use binius_verifier::{IOPVerifier as InnerVerifier, zk_config::ZKVerifier};
use sha2::{Digest, Sha256};

pub type Verifier = ZKVerifier<StdDigest, StdCompression>;
pub const MAX_SETUP_BYTES: usize = 1_286_664;
const MAGIC: &[u8] = b"qasset-fixed-binius-zk-preprocessing-v2\0";
const PIN: &str = "115108d5a661d95c0b474b6ab02558bfe6c6bec7";
const PROGRAM: &str = "qasset-binius-leaf-clamp-research-v1";
// Precomputed exact source identity; avoids embedding and hashing source text in the guest.
const SOURCE_SHA256: [u8; 32] = [
    188, 48, 70, 17, 97, 105, 26, 88, 185, 117, 248, 136, 84, 133, 134, 235, 231, 33, 113, 63, 252,
    241, 214, 172, 112, 70, 11, 12, 133, 81, 9, 69,
];
const MAX_CONSTRAINTS: usize = 1 << 20;
const MAX_WIRES_PER_OPERAND: usize = 1 << 16;

fn u32out(b: &mut Vec<u8>, value: usize) -> Result<(), String> {
    b.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| "integer too large")?
            .to_le_bytes(),
    );
    Ok(())
}
fn operandout(b: &mut Vec<u8>, operand: &Operand<WitnessIndex>) -> Result<(), String> {
    u32out(b, operand.len())?;
    for wire in operand.wires() {
        b.push(match wire.segment {
            WitnessSegment::Public => 0,
            WitnessSegment::Precommit => 1,
            WitnessSegment::Private => 2,
        });
        u32out(b, wire.index as usize)?;
    }
    Ok(())
}

pub fn padded_constraints_sha256(v: &Verifier) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(b"qasset-outer-padded-constraints-v1\0");
    let cs = v.outer_iop_verifier().constraint_system();
    let mut buffer = Vec::new();
    u32out(&mut buffer, cs.mul_constraints().len())?;
    hash.update(&buffer);
    for constraint in cs.mul_constraints() {
        buffer.clear();
        for operand in [&constraint.a, &constraint.b, &constraint.c] {
            operandout(&mut buffer, operand)?;
        }
        hash.update(&buffer);
    }
    Ok(hex::encode(hash.finalize()))
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).ok_or("offset overflow")?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or("truncated preprocessing")?;
        self.at = end;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.bytes(4)?.try_into().map_err(|_| "u32")?,
        ))
    }
    fn count(&mut self, max: usize) -> Result<usize, String> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("preprocessing dimension too large".into());
        }
        Ok(n)
    }
    fn exact(&mut self, b: &[u8]) -> Result<(), String> {
        if self.bytes(b.len())? != b {
            return Err("preprocessing identity mismatch".into());
        }
        Ok(())
    }
    fn field(&mut self) -> Result<F, String> {
        F::deserialize(self.bytes(16)?).map_err(|_| String::from("field decode"))
    }
    fn var_u32(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for index in 0..5 {
            let byte = self.bytes(1)?[0];
            if index == 4 && byte > 15 {
                return Err("variable integer overflow".into());
            }
            value |= u32::from(byte & 127) << (7 * index);
            if byte & 128 == 0 {
                if index > 0 && byte == 0 {
                    return Err("nonminimal variable integer".into());
                }
                return Ok(value);
            }
        }
        Err("variable integer too long".into())
    }
    fn operand(&mut self, limits: [u32; 3]) -> Result<Operand<WitnessIndex>, String> {
        let n = self.var_u32()? as usize;
        if n > MAX_WIRES_PER_OPERAND {
            return Err("operand too large".into());
        }
        let mut wires = smallvec::SmallVec::<[WitnessIndex; 4]>::with_capacity(n);
        for _ in 0..n {
            let packed = self.var_u32()?;
            let tag = (packed & 3) as u8;
            let index = packed >> 2;
            let segment = match tag {
                0 => WitnessSegment::Public,
                1 => WitnessSegment::Precommit,
                2 => WitnessSegment::Private,
                _ => return Err("invalid wire tag".into()),
            };
            if index >= limits[tag as usize] {
                return Err("wire out of range".into());
            }
            wires.push(WitnessIndex { segment, index });
        }
        if wires.windows(2).any(|w| w[0] >= w[1]) {
            return Err("noncanonical operand".into());
        }
        Ok(Operand::new(wires))
    }
}

/// Loads only the exact immutable setup selected in source. Hashing precedes all nested decoding.
/// The approved hash is compiled operator configuration, never proof/request input.
pub fn load_from_host(
    env: &soroban_sdk::Env,
    setup: &soroban_sdk::Bytes,
) -> Result<Verifier, String> {
    // This single public entry hashes the SAME immutable host Bytes before copying
    // or nested decoding. No caller-supplied digest, boolean or bypass entry exists.
    const APPROVED: [u8; 32] = [
        13, 26, 59, 119, 92, 224, 6, 224, 125, 246, 175, 58, 161, 73, 29, 45, 124, 41, 32, 46, 17,
        152, 95, 214, 4, 94, 243, 152, 203, 59, 228, 36,
    ];
    if setup.len() != 1_286_664 {
        return Err("fixed preprocessing length mismatch".into());
    }
    let actual: soroban_sdk::BytesN<32> = env.crypto().sha256(setup).into();
    if actual.to_array() != APPROVED {
        return Err("fixed preprocessing SHA256 mismatch".into());
    }
    let mut bytes = alloc::vec![0u8; setup.len() as usize];
    setup.copy_into_slice(&mut bytes);
    decode_pinned_bytes(&bytes)
}

fn decode_pinned_bytes(bytes: &[u8]) -> Result<Verifier, String> {
    let mut r = Reader { bytes, at: 0 };
    r.exact(MAGIC)?;
    r.exact(PIN.as_bytes())?;
    r.exact(PROGRAM.as_bytes())?;
    r.exact(&SOURCE_SHA256)?;
    if r.u32()? != 96 || r.u32()? != 1 {
        return Err("parameter identity mismatch".into());
    }
    let n = r.count(16 * 1024 * 1024)?;
    let mut raw = r.bytes(n)?;
    let mut inner = InnerCs::deserialize(&mut raw).map_err(|_| String::from("inner decode"))?;
    if !raw.is_empty() {
        return Err("trailing inner preprocessing".into());
    }
    inner
        .validate_and_prepare()
        .map_err(|_| String::from("inner validate"))?;
    let log_public = r.count(24)?;
    if inner.value_vec_layout.offset_witness != 1usize << log_public {
        return Err("public layout mismatch".into());
    }
    if inner.value_vec_layout.n_inout != 4 {
        return Err("wrong leaf circuit layout".into());
    }
    let n = r.count(1 << 16)?;
    let constants = (0..n).map(|_| r.field()).collect::<Result<Vec<_>, _>>()?;
    let inout = r.u32()?;
    let precommit = r.u32()?;
    let private = r.u32()?;
    let outer_log_public = r.count(24)? as u32;
    let one = r.u32()?;
    if precommit > 1 << 24
        || private > 1 << 24
        || inout > 1 << 24
        || constants.len() + (inout as usize) > 1usize << outer_log_public
        || one as usize >= constants.len()
    {
        return Err("invalid outer dimensions".into());
    }
    let limits = [1u32 << outer_log_public, precommit, private];
    let n = r.count(MAX_CONSTRAINTS)?;
    if n != 82_373 {
        return Err("fixed constraint count mismatch".into());
    }
    let mut constraints = Vec::with_capacity((n + 2).next_power_of_two());
    for _ in 0..n {
        constraints.push(MulConstraint {
            a: r.operand(limits)?,
            b: r.operand(limits)?,
            c: r.operand(limits)?,
        });
    }
    let outer = OuterCs::new(
        constants,
        inout,
        precommit,
        private,
        outer_log_public,
        constraints,
        one,
    );
    let dummy_wires = r.count(4096)?;
    let dummy_constraints = r.count(4096)?;
    if dummy_wires != 232 || dummy_constraints != 2 {
        return Err("fixed blinding dimensions mismatch".into());
    }
    let padded = ConstraintSystemPadded::new_verifier_only(
        outer,
        BlindingInfo {
            n_dummy_wires: dummy_wires,
            n_dummy_constraints: dummy_constraints,
        },
    );
    let n = r.count(8)?;
    let specs = (0..n)
        .map(|_| {
            Ok(OracleSpec {
                log_msg_len: r.count(24)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let n = r.count(8)?;
    if n != specs.len() {
        return Err("FRI count mismatch".into());
    }
    let mut fri = Vec::with_capacity(n);
    for spec in &specs {
        let log_dim = r.count(24)?;
        let log_rate = r.count(24)?;
        let log_batch = r.count(24)?;
        let queries = r.count(4096)?;
        let n = r.count(24)?;
        let folds = (0..n).map(|_| r.count(24)).collect::<Result<Vec<_>, _>>()?;
        let n = r.count(128)?;
        let basis = (0..n).map(|_| r.field()).collect::<Result<Vec<_>, _>>()?;
        if log_dim + log_rate != basis.len()
            || log_dim + log_batch != spec.log_msg_len + 1
            || log_batch != 1
            || log_rate != 1
            || queries != 232
        {
            return Err("FRI identity mismatch".into());
        }
        let code =
            ReedSolomonCode::with_subspace(BinarySubspace::new_unchecked(basis), log_dim, log_rate);
        fri.push(
            FRIParams::new(code, log_batch, folds, queries)
                .map_err(|_| String::from("FRI decode"))?,
        );
    }
    if r.at != bytes.len() {
        return Err("trailing preprocessing bytes".into());
    }
    let inner = InnerVerifier::new(inner, log_public);
    let outer = OuterVerifier::new(padded);
    let expected_specs = [
        vec![outer.oracle_specs()[0]],
        inner.oracle_specs(),
        outer.oracle_specs()[1..].to_vec(),
    ]
    .concat();
    if specs.iter().map(|s| s.log_msg_len).collect::<Vec<_>>()
        != expected_specs
            .iter()
            .map(|s| s.log_msg_len)
            .collect::<Vec<_>>()
    {
        return Err("oracle layout mismatch".into());
    }
    let compiler = BaseFoldZKVerifierCompiler::from_preprocessed(
        BinaryMerkleTreeScheme::new(StdCompression::default()),
        specs,
        fri,
    );
    Ok(Verifier::from_preprocessed(inner, outer, compiler))
}

#[cfg(test)]
mod compact_integer_tests {
    use super::Reader;
    #[test]
    fn canonical_u32_boundaries() {
        for (bytes, expected) in [
            (&[0u8][..], 0),
            (&[1][..], 1),
            (&[127][..], 127),
            (&[128, 1][..], 128),
            (&[255, 127][..], 16383),
            (&[128, 128, 1][..], 16384),
            (&[255, 255, 255, 255, 15][..], u32::MAX),
        ] {
            let mut reader = Reader { bytes, at: 0 };
            assert_eq!(reader.var_u32().unwrap(), expected);
            assert_eq!(reader.at, bytes.len());
        }
    }
    #[test]
    fn malformed_u32_encodings_rejected() {
        for bytes in [
            &[][..],
            &[128][..],
            &[128, 0][..],
            &[129, 0][..],
            &[255, 255, 255, 255, 16][..],
            &[255, 255, 255, 255, 128][..],
            &[128, 128, 128, 128, 128, 0][..],
        ] {
            let mut reader = Reader { bytes, at: 0 };
            assert!(reader.var_u32().is_err());
        }
    }
}
