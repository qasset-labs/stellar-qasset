//! Reserved seed-recovery account interface. Authentication is unavailable.
//!
//! Seed-preimage hardness alone does not make a proof system post-quantum secure.
//! The former constant BN254 pairing accepted forged credentials and is removed.
//! Groth16/BN254 is not a post-quantum replacement. No production recovery backend
//! has been integrated or approved, so EVERY authorization returns BackendUnavailable.
//! Do not enroll this disabled account as a required signer for funds.
//!
//! Owner-authorized configuration is installed atomically by the constructor.
//! No initializer, reconfiguration, activation switch, or upgrade path is exposed.
//! A future backend requires independent review, measured Soroban costs, and a
//! statement binding the protected key/path, account, network, policy epoch,
//! action, replacement authority and expiry. See docs/ARCHITECTURE.md.

#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Bytes, BytesN, Env, Vec,
};

/// Reserved envelope, not an implemented proof format. A public binding field
/// alone is not evidence of seed knowledge or transaction-binding security.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RecoveryProof {
    pub binding: BytesN<32>,
    pub proof: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
    pub owner: Address,
    pub protected_pubkey: BytesN<32>,
    /// SEP-5 account index before applying the hardened-derivation bit.
    pub derivation_index: u32,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Config,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    BackendUnavailable = 1,
    NotInitialized = 2,
    InvalidDerivationIndex = 3,
}

#[contract]
pub struct SeedRecoveryVerifier;

#[contractimpl]
impl SeedRecoveryVerifier {
    /// Set immutable configuration during deployment, leaving no initialization
    /// window. Owner approval of a key is not itself proof of seed knowledge.
    pub fn __constructor(
        env: Env,
        owner: Address,
        protected_pubkey: BytesN<32>,
        derivation_index: u32,
    ) -> Result<(), Error> {
        owner.require_auth();
        if derivation_index >= (1u32 << 31) {
            return Err(Error::InvalidDerivationIndex);
        }
        env.storage().instance().set(
            &DataKey::Config,
            &RecoveryConfig {
                owner,
                protected_pubkey,
                derivation_index,
            },
        );
        Ok(())
    }

    pub fn config(env: Env) -> RecoveryConfig {
        env.storage().instance().get(&DataKey::Config).unwrap()
    }

    /// Capability discovery. There is intentionally no way to set this to true.
    pub fn backend_available(_env: Env) -> bool {
        false
    }
}

#[contractimpl]
impl CustomAccountInterface for SeedRecoveryVerifier {
    type Signature = RecoveryProof;
    type Error = Error;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signatures: RecoveryProof,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Config) {
            return Err(Error::NotInitialized);
        }
        Err(Error::BackendUnavailable)
    }
}

mod test;
