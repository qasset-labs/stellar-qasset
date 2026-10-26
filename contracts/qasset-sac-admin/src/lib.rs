//! Administrator for one Stellar Asset Contract, authorizing exactly one operation.
//!
//! After the issuer hands SAC administration to this contract with `set_admin`, the SAC
//! calls `require_auth` on this address for every administrative function. This contract's
//! `__check_auth` accepts only one context: a direct `set_authorized(id, authorize)` call on
//! the SAC fixed at construction. The authorizing credential is an ML-DSA-65 signature
//! (FIPS 204) over the host's standard Soroban authorization payload, with domain context
//! `qasset-sac-admin-auth-v1`.
//!
//! ML-DSA-65 is verified inside this contract's Wasm with RustCrypto `ml-dsa` 0.1.1, whose
//! implementation has not been independently audited. It is not the CAP-87 host function.
//!
//! Deliberately absent: upgrade, key rotation, any other SAC administrative function
//! (`mint`, `clawback`, `set_admin`), contract creation, composite authorization trees, and
//! any entry point through which this contract calls the SAC itself (such a call would be
//! authorized by the host as the direct invoker and would never reach `__check_auth`).
//!
//! Controlling SAC administration does not control the classic issuer account. A classic
//! issuer that can still sign retains its own powers over the asset; that path is outside
//! anything this contract can enforce.

#![no_std]

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Bytes, Env, Symbol, Vec,
};

pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
pub const AUTH_CONTEXT: &[u8] = b"qasset-sac-admin-auth-v1";
pub const PROTECTED_FUNCTION: &str = "set_authorized";
const PROTECTED_ARGS: u32 = 2;
// Approximately seven days at five seconds per ledger. Avoid paying the network's
// entire maximum lease at construction; successful authorized calls renew this target.
const TTL_TARGET: u32 = 120_960;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Sac,
    OperatorKey,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    BadKeyLength = 1,
    BadSignatureLength = 2,
    InvalidSignature = 3,
    UnsupportedAuthContext = 4,
}

fn decode_key(key: &Bytes) -> Result<VerifyingKey<MlDsa65>, Error> {
    if key.len() as usize != PUBLIC_KEY_BYTES {
        return Err(Error::BadKeyLength);
    }
    let mut encoded = [0u8; PUBLIC_KEY_BYTES];
    key.copy_into_slice(&mut encoded);
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(encoded.as_slice())
        .map_err(|_| Error::BadKeyLength)?;
    Ok(VerifyingKey::<MlDsa65>::decode(&encoded))
}

fn verify(key: &Bytes, digest: &[u8; 32], signature: &Bytes) -> Result<(), Error> {
    if signature.len() as usize != SIGNATURE_BYTES {
        return Err(Error::BadSignatureLength);
    }
    let key = decode_key(key)?;
    let mut encoded = [0u8; SIGNATURE_BYTES];
    signature.copy_into_slice(&mut encoded);
    let encoded = EncodedSignature::<MlDsa65>::try_from(encoded.as_slice())
        .map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::<MlDsa65>::decode(&encoded).ok_or(Error::InvalidSignature)?;
    if key.verify_with_context(digest, AUTH_CONTEXT, &signature) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

fn extend_instance(env: &Env) {
    let target = env.storage().max_ttl().min(TTL_TARGET);
    env.storage().instance().extend_ttl(target / 2, target);
}

#[contract]
pub struct QAssetSacAdmin;

#[contractimpl]
impl QAssetSacAdmin {
    /// Fixes the SAC and the ML-DSA-65 operator key for the contract's lifetime.
    pub fn __constructor(env: Env, sac: Address, operator_key: Bytes) -> Result<(), Error> {
        decode_key(&operator_key)?;
        env.storage().instance().set(&DataKey::Sac, &sac);
        env.storage()
            .instance()
            .set(&DataKey::OperatorKey, &operator_key);
        extend_instance(&env);
        Ok(())
    }

    pub fn sac(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Sac).unwrap()
    }

    pub fn operator_key(env: Env) -> Bytes {
        env.storage().instance().get(&DataKey::OperatorKey).unwrap()
    }

    pub fn protected_function(env: Env) -> Symbol {
        Symbol::new(&env, PROTECTED_FUNCTION)
    }
}

#[contractimpl]
impl CustomAccountInterface for QAssetSacAdmin {
    type Signature = Bytes;
    type Error = Error;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Bytes,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // Inspect the complete authorized tree before verifying anything: exactly one
        // direct call to the protected SAC function, nothing nested, nothing created.
        if auth_contexts.len() != 1 {
            return Err(Error::UnsupportedAuthContext);
        }
        let sac: Address = env.storage().instance().get(&DataKey::Sac).unwrap();
        match auth_contexts.get(0).unwrap() {
            Context::Contract(context)
                if context.contract == sac
                    && context.fn_name == Symbol::new(&env, PROTECTED_FUNCTION)
                    && context.args.len() == PROTECTED_ARGS => {}
            _ => return Err(Error::UnsupportedAuthContext),
        }
        let key: Bytes = env.storage().instance().get(&DataKey::OperatorKey).unwrap();
        verify(&key, &signature_payload.to_bytes().to_array(), &signature)?;
        extend_instance(&env);
        Ok(())
    }
}

mod test;
