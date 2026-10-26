// SPDX-License-Identifier: MIT
//! Operator-trusted fixed preprocessing; cryptographic verifier protocol is unchanged.
use alloc::{format, string::String, vec, vec::Vec};
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
use binius_utils::{DeserializeBytes, SerializeBytes};
use binius_verifier::{IOPVerifier as InnerVerifier, zk_config::ZKVerifier};
use sha2::{Digest, Sha256};

pub type Verifier = ZKVerifier<StdDigest, StdCompression>;
pub const MAX_SETUP_BYTES: usize = 64 * 1024 * 1024;
const MAGIC: &[u8] = b"qasset-fixed-binius-zk-preprocessing-v1\0";
const PIN: &str = "115108d5a661d95c0b474b6ab02558bfe6c6bec7";
const PROGRAM: &str = "qasset-binius-leaf-clamp-research-v1";
const SOURCE: &[u8] = include_bytes!("native.rs");
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
fn fieldout(b: &mut Vec<u8>, field: &F) -> Result<(), String> {
    field
        .serialize(b)
        .map_err(|e| format!("field serialize: {e:?}"))
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

pub fn export(v: &Verifier) -> Result<Vec<u8>, String> {
    let mut b = MAGIC.to_vec();
    b.extend_from_slice(PIN.as_bytes());
    b.extend_from_slice(PROGRAM.as_bytes());
    b.extend_from_slice(&Sha256::digest(SOURCE));
    u32out(&mut b, 96)?;
    u32out(&mut b, 1)?;
    let mut inner = Vec::new();
    v.constraint_system()
        .serialize(&mut inner)
        .map_err(|e| format!("inner serialize: {e:?}"))?;
    u32out(&mut b, inner.len())?;
    b.extend(inner);
    u32out(&mut b, v.log_public_words())?;
    let padded = v.outer_iop_verifier().constraint_system();
    let c = padded.unpadded_constraint_system();
    u32out(&mut b, c.constants().len())?;
    for field in c.constants() {
        fieldout(&mut b, field)?;
    }
    for n in [
        c.n_inout(),
        c.n_precommit(),
        c.n_private(),
        c.log_public(),
        c.one_wire().index,
    ] {
        u32out(&mut b, n as usize)?;
    }
    u32out(&mut b, c.mul_constraints().len())?;
    for m in c.mul_constraints() {
        for o in [&m.a, &m.b, &m.c] {
            operandout(&mut b, o)?;
        }
    }
    u32out(&mut b, padded.blinding_info().n_dummy_wires)?;
    u32out(&mut b, padded.blinding_info().n_dummy_constraints)?;
    let compiler = v.basefold_compiler();
    u32out(&mut b, compiler.oracle_specs().len())?;
    for spec in compiler.oracle_specs() {
        u32out(&mut b, spec.log_msg_len)?;
    }
    u32out(&mut b, compiler.fri_params().len())?;
    for params in compiler.fri_params() {
        for n in [
            params.rs_code().log_dim(),
            params.rs_code().log_inv_rate(),
            params.log_batch_size(),
            params.n_test_queries(),
        ] {
            u32out(&mut b, n)?;
        }
        u32out(&mut b, params.fold_arities().len())?;
        for arity in params.fold_arities() {
            u32out(&mut b, *arity)?;
        }
        u32out(&mut b, params.rs_code().subspace().basis().len())?;
        for field in params.rs_code().subspace().basis() {
            fieldout(&mut b, field)?;
        }
    }
    if b.len() > MAX_SETUP_BYTES {
        return Err("preprocessing too large".into());
    }
    Ok(b)
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
        F::deserialize(self.bytes(16)?).map_err(|e| format!("field decode: {e:?}"))
    }
    fn operand(&mut self, limits: [u32; 3]) -> Result<Operand<WitnessIndex>, String> {
        let n = self.count(MAX_WIRES_PER_OPERAND)?;
        let mut wires = smallvec::SmallVec::<[WitnessIndex; 4]>::with_capacity(n);
        for _ in 0..n {
            let tag = self.bytes(1)?[0];
            let index = self.u32()?;
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
pub fn load(bytes: &[u8]) -> Result<Verifier, String> {
    load_with_approved_hash(bytes, include_str!("../setup.sha256").trim())
}

/// Host exporter roundtrip only; requires bytes produced by this trusted native object.
pub fn export_roundtrip(verifier: &Verifier, bytes: &[u8]) -> Result<Verifier, String> {
    if export(verifier)? != bytes {
        return Err("export does not match trusted verifier".into());
    }
    load_with_approved_hash(bytes, &hex::encode(Sha256::digest(bytes)))
}

fn load_with_approved_hash(bytes: &[u8], expected_sha256: &str) -> Result<Verifier, String> {
    if bytes.len() > MAX_SETUP_BYTES
        || expected_sha256.len() != 64
        || hex::encode(Sha256::digest(bytes)) != expected_sha256
    {
        return Err("fixed preprocessing SHA256 mismatch".into());
    }
    let mut r = Reader { bytes, at: 0 };
    r.exact(MAGIC)?;
    r.exact(PIN.as_bytes())?;
    r.exact(PROGRAM.as_bytes())?;
    r.exact(&Sha256::digest(SOURCE))?;
    if r.u32()? != 96 || r.u32()? != 1 {
        return Err("parameter identity mismatch".into());
    }
    let n = r.count(16 * 1024 * 1024)?;
    let mut raw = r.bytes(n)?;
    let mut inner = InnerCs::deserialize(&mut raw).map_err(|e| format!("inner decode: {e:?}"))?;
    if !raw.is_empty() {
        return Err("trailing inner preprocessing".into());
    }
    inner
        .validate_and_prepare()
        .map_err(|e| format!("inner validate: {e:?}"))?;
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
    let mut constraints = Vec::with_capacity(n);
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
    let padded = ConstraintSystemPadded::new(
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
                .map_err(|e| format!("FRI decode: {e:?}"))?,
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
