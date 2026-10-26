//! TESTNET-ONLY baseline: pre-enrolled ML-DSA-65 recovery, not legacy seed ZK.
//!
//! Uses RustCrypto ml-dsa 0.1.1 (FIPS 204; Apache-2.0/MIT), whose implementation
//! has not been independently audited. The companion tool uses PUBLIC fixture
//! secrets. Anyone can sign for that fixture: never send this demo real assets.
//! This account authorizes only its own protected counter, never other contracts
//! or composite authorization trees. Soroban can cache an authorization within a
//! tree: unrestricted scopes could retain old authority across an inline recovery.
//! No new cryptographic construction is claimed. HKDF/key derivation happens
//! off-chain; this contract verifies actual ML-DSA signatures over exact digests.
//! Owner authorization is deployment consent only. No owner bypass, initializer,
//! upgrade method, or method for changing the enrolled recovery key exists.

#![no_std]

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, String, Symbol, Vec,
};

pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
pub const AUTH_CONTEXT: &[u8] = b"qasset-pq-auth-v1";
pub const RECOVERY_CONTEXT: &[u8] = b"qasset-recover-v1";
pub const MAX_RECOVERY_WINDOW: u32 = 1000;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    ActiveKey,
    RecoveryKey,
    Epoch,
    Consumed,
    Counter,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    BadKeyLength = 1,
    BadSignatureLength = 2,
    InvalidSignature = 3,
    RecoveryConsumed = 4,
    WrongEpoch = 5,
    Expired = 6,
    ExpiryTooFar = 7,
    KeyReuse = 8,
    CounterOverflow = 9,
    EpochOverflow = 10,
    UnsupportedAuthContext = 11,
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

fn verify(key: &Bytes, digest: &[u8; 32], context: &[u8], signature: &Bytes) -> Result<(), Error> {
    if signature.len() as usize != SIGNATURE_BYTES {
        return Err(Error::BadSignatureLength);
    }
    let key = decode_key(key)?;
    let mut encoded = [0u8; SIGNATURE_BYTES];
    signature.copy_into_slice(&mut encoded);
    let encoded = EncodedSignature::<MlDsa65>::try_from(encoded.as_slice())
        .map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::<MlDsa65>::decode(&encoded).ok_or(Error::InvalidSignature)?;
    if key.verify_with_context(digest, context, &signature) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[contract]
pub struct PqRecoveryDemo;

#[contractimpl]
impl PqRecoveryDemo {
    pub fn __constructor(
        env: Env,
        owner: Address,
        initial_key: Bytes,
        recovery_key: Bytes,
    ) -> Result<(), Error> {
        owner.require_auth();
        decode_key(&initial_key)?;
        decode_key(&recovery_key)?;
        if initial_key == recovery_key {
            return Err(Error::KeyReuse);
        }
        env.storage()
            .instance()
            .set(&DataKey::ActiveKey, &initial_key);
        env.storage()
            .instance()
            .set(&DataKey::RecoveryKey, &recovery_key);
        env.storage().instance().set(&DataKey::Epoch, &0u64);
        env.storage().instance().set(&DataKey::Consumed, &false);
        env.storage().instance().set(&DataKey::Counter, &0u64);
        Ok(())
    }

    pub fn active_key(env: Env) -> Bytes {
        env.storage().instance().get(&DataKey::ActiveKey).unwrap()
    }

    pub fn epoch(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::Epoch).unwrap()
    }

    pub fn recovery_enabled(env: Env) -> bool {
        !env.storage()
            .instance()
            .get::<_, bool>(&DataKey::Consumed)
            .unwrap()
    }

    pub fn counter(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::Counter).unwrap()
    }

    /// The host supplies the signature payload; it is never an argument to this method.
    pub fn protected(env: Env) -> Result<u64, Error> {
        env.current_contract_address().require_auth();
        let next = Self::counter(env.clone())
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;
        env.storage().instance().set(&DataKey::Counter, &next);
        Ok(next)
    }

    /// Canonical statement construction only; recover independently checks eligibility.
    pub fn recovery_digest(
        env: Env,
        expected_epoch: u64,
        replacement_key: Bytes,
        valid_until_ledger: u32,
    ) -> BytesN<32> {
        let statement = (
            String::from_str(&env, "qassetrecoverv1"),
            env.ledger().network_id(),
            env.current_contract_address(),
            expected_epoch,
            replacement_key,
            valid_until_ledger,
        );
        env.crypto().sha256(&statement.to_xdr(&env)).to_bytes()
    }

    /// One enrolled recovery signature plus proof of possession of a different replacement
    /// key. Neither key nor signature is accepted as an administrator declaration.
    pub fn recover(
        env: Env,
        expected_epoch: u64,
        replacement_key: Bytes,
        valid_until_ledger: u32,
        recovery_signature: Bytes,
        replacement_signature: Bytes,
    ) -> Result<(), Error> {
        if !Self::recovery_enabled(env.clone()) {
            return Err(Error::RecoveryConsumed);
        }
        let epoch = Self::epoch(env.clone());
        if expected_epoch != epoch {
            return Err(Error::WrongEpoch);
        }
        let now = env.ledger().sequence();
        if valid_until_ledger < now {
            return Err(Error::Expired);
        }
        if valid_until_ledger - now > MAX_RECOVERY_WINDOW {
            return Err(Error::ExpiryTooFar);
        }
        if replacement_key.len() as usize != PUBLIC_KEY_BYTES {
            return Err(Error::BadKeyLength);
        }
        if recovery_signature.len() as usize != SIGNATURE_BYTES
            || replacement_signature.len() as usize != SIGNATURE_BYTES
        {
            return Err(Error::BadSignatureLength);
        }
        let recovery_key: Bytes = env.storage().instance().get(&DataKey::RecoveryKey).unwrap();
        if replacement_key == Self::active_key(env.clone()) || replacement_key == recovery_key {
            return Err(Error::KeyReuse);
        }
        let digest = Self::recovery_digest(
            env.clone(),
            expected_epoch,
            replacement_key.clone(),
            valid_until_ledger,
        )
        .to_array();
        verify(
            &recovery_key,
            &digest,
            RECOVERY_CONTEXT,
            &recovery_signature,
        )?;
        verify(
            &replacement_key,
            &digest,
            RECOVERY_CONTEXT,
            &replacement_signature,
        )?;
        let next_epoch = epoch.checked_add(1).ok_or(Error::EpochOverflow)?;
        env.storage()
            .instance()
            .set(&DataKey::ActiveKey, &replacement_key);
        env.storage().instance().set(&DataKey::Epoch, &next_epoch);
        env.storage().instance().set(&DataKey::Consumed, &true);
        Ok(())
    }
}

#[contractimpl]
impl CustomAccountInterface for PqRecoveryDemo {
    type Signature = Bytes;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Bytes,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // This deliberately narrow counter demo is not a general wallet signer.
        // Inspect the complete tree before validating/caching any authority.
        if auth_contexts.len() != 1 {
            return Err(Error::UnsupportedAuthContext);
        }
        match auth_contexts.get(0).unwrap() {
            Context::Contract(context)
                if context.contract == env.current_contract_address()
                    && context.fn_name == Symbol::new(&env, "protected")
                    && context.args.is_empty() => {}
            _ => return Err(Error::UnsupportedAuthContext),
        }
        verify(
            &Self::active_key(env),
            &signature_payload.to_bytes().to_array(),
            AUTH_CONTEXT,
            &signature,
        )
    }
}

mod test;
