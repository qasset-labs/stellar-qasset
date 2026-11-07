//! Public ML-DSA-65 verification vectors exercised through the administrator's real
//! `__check_auth`, with a permitted authorization context so that every rejection below is
//! caused by signature verification. Fixtures, upstream revisions and hashes are recorded in
//! `contracts/pq-recovery-demo/test-vectors/provenance.json`. These are bounded regressions,
//! not ACVP validation or FIPS certification.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use qasset_sac_admin::{Error, QAssetSacAdmin, AUTH_CONTEXT};
use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::Address as _,
    vec, Address, Bytes, BytesN, Env, IntoVal, Symbol,
};

struct Vector {
    key: Vec<u8>,
    message: Vec<u8>,
    context: Vec<u8>,
    signature: Vec<u8>,
}

fn vector(text: &str) -> Vector {
    fn decode(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    let mut fields = text.lines();
    let parsed = Vector {
        key: decode(fields.next().unwrap()),
        message: decode(fields.next().unwrap()),
        context: decode(fields.next().unwrap()),
        signature: decode(fields.next().unwrap()),
    };
    assert!(fields.next().is_none());
    parsed
}

/// Registers an administrator for the vector's public key and calls `__check_auth` with
/// the one permitted context: a direct `set_authorized(holder, true)` on the configured SAC.
fn check_auth(v: &Vector, signature: &[u8]) -> Result<(), Error> {
    let env = Env::default();
    let sac = Address::generate(&env);
    let holder = Address::generate(&env);
    let key = Bytes::from_slice(&env, &v.key);
    let admin = env.register(QAssetSacAdmin, (&sac, &key));
    let payload: [u8; 32] = v.message.as_slice().try_into().unwrap();
    let context = Context::Contract(ContractContext {
        contract: sac,
        fn_name: Symbol::new(&env, "set_authorized"),
        args: (&holder, true).into_val(&env),
    });
    env.try_invoke_contract_check_auth::<Error>(
        &admin,
        &BytesN::from_array(&env, &payload),
        Bytes::from_slice(&env, signature).into_val(&env),
        &vec![&env, context],
    )
    .map_err(|e| e.unwrap())
}

fn library_accepts(v: &Vector) -> bool {
    let key = VerifyingKey::<MlDsa65>::decode(
        &EncodedVerifyingKey::<MlDsa65>::try_from(v.key.as_slice()).unwrap(),
    );
    Signature::<MlDsa65>::decode(
        &EncodedSignature::<MlDsa65>::try_from(v.signature.as_slice()).unwrap(),
    )
    .map(|signature| key.verify_with_context(&v.message, &v.context, &signature))
    .unwrap_or(false)
}

#[test]
fn malformed_hint_encodings_are_rejected_by_check_auth() {
    // Wycheproof tc16 (hints in reverse order), tc18 (non-zero hint padding) and tc19
    // (repeated hint, a regression for earlier RustCrypto releases).
    for text in [
        include_str!("../../pq-recovery-demo/test-vectors/wycheproof-tc16.txt"),
        include_str!("../../pq-recovery-demo/test-vectors/wycheproof-tc18.txt"),
        include_str!("../../pq-recovery-demo/test-vectors/wycheproof-tc19.txt"),
    ] {
        let v = vector(text);
        assert!(!library_accepts(&v));
        assert_eq!(check_auth(&v, &v.signature), Err(Error::InvalidSignature));
    }
}

#[test]
fn valid_signature_without_the_application_context_is_rejected() {
    // Wycheproof tc21 is a valid signature over a 32-byte message with an empty context.
    // The administrator verifies under its own domain context, so the same bytes must not
    // authorize SAC administration.
    let v = vector(include_str!(
        "../../pq-recovery-demo/test-vectors/wycheproof-tc21.txt"
    ));
    assert!(v.context.is_empty());
    assert!(library_accepts(&v));
    assert_ne!(AUTH_CONTEXT, v.context.as_slice());
    assert_eq!(check_auth(&v, &v.signature), Err(Error::InvalidSignature));
}

#[test]
fn wrong_length_signatures_are_rejected_before_decoding() {
    let v = vector(include_str!(
        "../../pq-recovery-demo/test-vectors/wycheproof-tc21.txt"
    ));
    assert_eq!(
        check_auth(&v, &v.signature[..v.signature.len() - 1]),
        Err(Error::BadSignatureLength)
    );
    let mut longer = v.signature.clone();
    longer.push(0);
    assert_eq!(check_auth(&v, &longer), Err(Error::BadSignatureLength));
}
