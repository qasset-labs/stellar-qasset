//! Research-only bounded proof transport. Stored bytes are NEVER proof approval.
//!
//! Anyone may sponsor their own upload; uploader authentication is a transport
//! control, not the protected account's recovery permission. No asset, signer,
//! eligibility or recovery epoch is changed. Temporary storage expires. A future
//! verifier must independently check its pinned relation, current authority,
//! expiry and atomic consumption; this contract does not supply that verifier.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, xdr::ToXdr, Address, Bytes,
    BytesN, Env, IntoVal, String, Val, Vec,
};

pub const CHUNK_BYTES: u32 = 32 * 1024;
pub const READ_BYTES: u32 = 8 * 1024;
pub const MAX_PROOF_BYTES: u32 = 1024 * 1024;
pub const MAX_WINDOW: u32 = 1000;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadHeader {
    pub uploader: Address,
    pub nonce: BytesN<32>,
    pub statement: BytesN<64>,
    pub verifier: BytesN<32>,
    pub parameters: BytesN<32>,
    pub length: u32,
    /// Exclusive logical expiry, also bounded by temporary-storage lifetime.
    pub expires: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadMetadata {
    pub header: UploadHeader,
    pub expected: BytesN<32>,
    pub rolling: BytesN<32>,
    pub received: u32,
    pub sealed_unverified: bool,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Session(BytesN<32>),
    Chunk(BytesN<32>, u32),
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    InvalidSize = 1,
    InvalidExpiry = 2,
    AlreadyExists = 3,
    NotFound = 4,
    Expired = 5,
    AlreadySealed = 6,
    InvalidIndex = 7,
    InvalidChunk = 8,
    Incomplete = 9,
    CommitmentMismatch = 10,
    Unsealed = 11,
    BackendUnavailable = 12,
    InvalidRange = 13,
}

#[contractevent]
pub struct UploadOpened {
    #[topic]
    pub id: BytesN<32>,
    pub length: u32,
}

#[contractevent]
pub struct UploadSealedUnverified {
    #[topic]
    pub id: BytesN<32>,
    pub commitment: BytesN<32>,
}

#[contract]
pub struct RecoveryProofMailbox;

fn identifier(env: &Env, header: &UploadHeader) -> BytesN<32> {
    let mut fields: Vec<Val> = Vec::new(env);
    fields.push_back(String::from_str(env, "qasset-proof-upload-v1").into_val(env));
    fields.push_back(env.ledger().network_id().into_val(env));
    fields.push_back(env.current_contract_address().into_val(env));
    fields.push_back(header.uploader.clone().into_val(env));
    fields.push_back(header.nonce.clone().into_val(env));
    fields.push_back(header.statement.clone().into_val(env));
    fields.push_back(header.verifier.clone().into_val(env));
    fields.push_back(header.parameters.clone().into_val(env));
    fields.push_back(header.length.into_val(env));
    fields.push_back(header.expires.into_val(env));
    fields.push_back(CHUNK_BYTES.into_val(env));
    env.crypto().sha256(&fields.to_xdr(env)).into()
}

fn initial(env: &Env, id: &BytesN<32>) -> BytesN<32> {
    let mut bytes = Bytes::from_slice(env, b"qasset-upload-start-v1");
    bytes.append(&id.clone().into());
    env.crypto().sha256(&bytes).into()
}

fn advance(env: &Env, rolling: &BytesN<32>, index: u32, data: &Bytes) -> BytesN<32> {
    let mut bytes = Bytes::from_slice(env, b"qasset-upload-chunk-v1");
    bytes.append(&rolling.clone().into());
    bytes.append(&Bytes::from_array(env, &index.to_be_bytes()));
    bytes.append(&Bytes::from_array(env, &data.len().to_be_bytes()));
    bytes.append(data);
    env.crypto().sha256(&bytes).into()
}

fn chunks(length: u32) -> u32 {
    length.div_ceil(CHUNK_BYTES)
}

fn load(env: &Env, id: &BytesN<32>) -> Result<UploadMetadata, Error> {
    let state: UploadMetadata = env
        .storage()
        .temporary()
        .get(&DataKey::Session(id.clone()))
        .ok_or(Error::NotFound)?;
    if env.ledger().sequence() >= state.header.expires {
        return Err(Error::Expired);
    }
    Ok(state)
}

fn persist(env: &Env, id: &BytesN<32>, state: &UploadMetadata) {
    let key = DataKey::Session(id.clone());
    env.storage().temporary().set(&key, state);
    let ttl = state.header.expires - env.ledger().sequence() + 1;
    env.storage().temporary().extend_ttl(&key, ttl, ttl);
}

#[contractimpl]
impl RecoveryProofMailbox {
    pub fn open(env: Env, header: UploadHeader, expected: BytesN<32>) -> Result<BytesN<32>, Error> {
        if header.length == 0 || header.length > MAX_PROOF_BYTES {
            return Err(Error::InvalidSize);
        }
        let now = env.ledger().sequence();
        if header.expires <= now || header.expires > now.saturating_add(MAX_WINDOW) {
            return Err(Error::InvalidExpiry);
        }
        header.uploader.require_auth();
        let id = identifier(&env, &header);
        if env.storage().temporary().has(&DataKey::Session(id.clone())) {
            return Err(Error::AlreadyExists);
        }
        let state = UploadMetadata {
            header,
            expected,
            rolling: initial(&env, &id),
            received: 0,
            sealed_unverified: false,
        };
        persist(&env, &id, &state);
        UploadOpened {
            id: id.clone(),
            length: state.header.length,
        }
        .publish(&env);
        Ok(id)
    }

    pub fn append(env: Env, id: BytesN<32>, index: u32, data: Bytes) -> Result<u32, Error> {
        let mut state = load(&env, &id)?;
        state.header.uploader.require_auth();
        if state.sealed_unverified {
            return Err(Error::AlreadySealed);
        }
        let count = chunks(state.header.length);
        if index != state.received || index >= count {
            return Err(Error::InvalidIndex);
        }
        let expected_len = if index + 1 == count {
            state.header.length - index * CHUNK_BYTES
        } else {
            CHUNK_BYTES
        };
        if data.len() != expected_len {
            return Err(Error::InvalidChunk);
        }
        state.rolling = advance(&env, &state.rolling, index, &data);
        state.received += 1;
        let key = DataKey::Chunk(id.clone(), index);
        env.storage().temporary().set(&key, &data);
        let ttl = state.header.expires - env.ledger().sequence() + 1;
        env.storage().temporary().extend_ttl(&key, ttl, ttl);
        persist(&env, &id, &state);
        Ok(state.received)
    }

    pub fn seal(env: Env, id: BytesN<32>) -> Result<UploadMetadata, Error> {
        let mut state = load(&env, &id)?;
        if state.sealed_unverified {
            return Err(Error::AlreadySealed);
        }
        if state.received != chunks(state.header.length) {
            return Err(Error::Incomplete);
        }
        if state.rolling != state.expected {
            return Err(Error::CommitmentMismatch);
        }
        state.sealed_unverified = true;
        persist(&env, &id, &state);
        UploadSealedUnverified {
            id,
            commitment: state.rolling.clone(),
        }
        .publish(&env);
        Ok(state)
    }

    pub fn metadata(env: Env, id: BytesN<32>) -> Result<UploadMetadata, Error> {
        load(&env, &id)
    }

    pub fn read_slice(
        env: Env,
        id: BytesN<32>,
        index: u32,
        offset: u32,
        length: u32,
    ) -> Result<Bytes, Error> {
        let state = load(&env, &id)?;
        if !state.sealed_unverified {
            return Err(Error::Unsealed);
        }
        if index >= chunks(state.header.length) {
            return Err(Error::InvalidIndex);
        }
        let data: Bytes = env
            .storage()
            .temporary()
            .get(&DataKey::Chunk(id, index))
            .ok_or(Error::NotFound)?;
        if length == 0 || length > READ_BYTES || offset > data.len() || length > data.len() - offset
        {
            return Err(Error::InvalidRange);
        }
        Ok(data.slice(offset..offset + length))
    }

    pub fn backend_available(_env: Env) -> bool {
        false
    }

    /// Capability gate: sealing authenticates byte order/length, never the proof relation.
    pub fn require_verified(_env: Env, _id: BytesN<32>) -> Result<(), Error> {
        Err(Error::BackendUnavailable)
    }
}

mod test;
