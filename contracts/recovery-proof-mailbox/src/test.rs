#![cfg(test)]
extern crate std;
use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};

fn header(env: &Env, length: u32) -> UploadHeader {
    UploadHeader {
        uploader: Address::generate(env),
        nonce: BytesN::from_array(env, &[1; 32]),
        statement: BytesN::from_array(env, &[2; 64]),
        verifier: BytesN::from_array(env, &[3; 32]),
        parameters: BytesN::from_array(env, &[4; 32]),
        length,
        expires: env.ledger().sequence() + 900,
    }
}

fn commitment(env: &Env, contract: &Address, h: &UploadHeader, data: &[u8]) -> BytesN<32> {
    env.as_contract(contract, || {
        let mut rolling = initial(env, &identifier(env, h));
        for (index, chunk) in data.chunks(CHUNK_BYTES as usize).enumerate() {
            rolling = advance(env, &rolling, index as u32, &Bytes::from_slice(env, chunk));
        }
        rolling
    })
}

#[test]
fn sealed_transport_is_never_a_verified_recovery() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let data = b"explicitly not a valid proof";
    let h = header(&env, data.len() as u32);
    let upload = client.open(&h, &commitment(&env, &id, &h, data));
    assert_eq!(
        client.try_read_slice(&upload, &0, &0, &1),
        Err(Ok(Error::Unsealed))
    );
    client.append(&upload, &0, &Bytes::from_slice(&env, data));
    let sealed = client.seal(&upload);
    assert!(sealed.sealed_unverified);
    assert_eq!(
        client.read_slice(&upload, &0, &0, &(data.len() as u32)),
        Bytes::from_slice(&env, data)
    );
    assert!(!client.backend_available());
    assert_eq!(
        client.try_require_verified(&upload),
        Err(Ok(Error::BackendUnavailable))
    );
}

#[test]
fn chunks_are_exact_sequential_and_immutable_after_sealing() {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let data = std::vec![7; CHUNK_BYTES as usize + 3];
    let h = header(&env, data.len() as u32);
    let upload = client.open(&h, &commitment(&env, &id, &h, &data));
    let first = Bytes::from_slice(&env, &data[..CHUNK_BYTES as usize]);
    assert_eq!(
        client.try_append(&upload, &1, &first),
        Err(Ok(Error::InvalidIndex))
    );
    assert_eq!(
        client.try_append(&upload, &0, &Bytes::from_array(&env, &[7])),
        Err(Ok(Error::InvalidChunk))
    );
    client.append(&upload, &0, &first);
    assert_eq!(
        client.try_append(&upload, &0, &first),
        Err(Ok(Error::InvalidIndex))
    );
    assert_eq!(client.try_seal(&upload), Err(Ok(Error::Incomplete)));
    client.append(
        &upload,
        &1,
        &Bytes::from_slice(&env, &data[CHUNK_BYTES as usize..]),
    );
    client.seal(&upload);
    assert_eq!(
        client.try_append(&upload, &1, &Bytes::from_slice(&env, &[7, 7, 7])),
        Err(Ok(Error::AlreadySealed))
    );
    assert_eq!(client.try_seal(&upload), Err(Ok(Error::AlreadySealed)));
    assert_eq!(
        client.try_read_slice(&upload, &2, &0, &1),
        Err(Ok(Error::InvalidIndex))
    );
}

#[test]
fn wrong_bytes_cannot_match_the_committed_chain() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let h = header(&env, 3);
    let upload = client.open(&h, &commitment(&env, &id, &h, b"abc"));
    client.append(&upload, &0, &Bytes::from_slice(&env, b"xyz"));
    assert_eq!(client.try_seal(&upload), Err(Ok(Error::CommitmentMismatch)));
    assert!(!client.metadata(&upload).sealed_unverified);
}

#[test]
fn expiry_rejects_upload_sealing_and_reads() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let h = header(&env, 3);
    let upload = client.open(&h, &commitment(&env, &id, &h, b"abc"));
    env.ledger()
        .with_mut(|info| info.sequence_number = h.expires);
    assert_eq!(
        client.try_append(&upload, &0, &Bytes::from_slice(&env, b"abc")),
        Err(Ok(Error::Expired))
    );
    assert_eq!(client.try_seal(&upload), Err(Ok(Error::Expired)));
    assert_eq!(
        client.try_read_slice(&upload, &0, &0, &1),
        Err(Ok(Error::Expired))
    );
}

#[test]
fn header_size_expiry_and_reinitialization_are_bounded() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let mut h = header(&env, 0);
    let root = BytesN::from_array(&env, &[5; 32]);
    assert_eq!(client.try_open(&h, &root), Err(Ok(Error::InvalidSize)));
    h.length = MAX_PROOF_BYTES + 1;
    assert_eq!(client.try_open(&h, &root), Err(Ok(Error::InvalidSize)));
    h.length = 1;
    h.expires = env.ledger().sequence();
    assert_eq!(client.try_open(&h, &root), Err(Ok(Error::InvalidExpiry)));
    h.expires += MAX_WINDOW + 1;
    assert_eq!(client.try_open(&h, &root), Err(Ok(Error::InvalidExpiry)));
    h.expires -= 1;
    let upload = client.open(&h, &root);
    assert_eq!(
        client.try_open(&h, &BytesN::from_array(&env, &[6; 32])),
        Err(Ok(Error::AlreadyExists))
    );
    assert_eq!(client.metadata(&upload).expected, root);
}

#[test]
fn header_changes_and_contract_network_domains_separate_sessions() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let other = env.register(RecoveryProofMailbox, ());
    let h = header(&env, 3);
    let original = env.as_contract(&id, || identifier(&env, &h));
    assert_ne!(original, env.as_contract(&other, || identifier(&env, &h)));
    let mut changed = h.clone();
    changed.parameters = BytesN::from_array(&env, &[9; 32]);
    assert_ne!(
        original,
        env.as_contract(&id, || identifier(&env, &changed))
    );
    env.ledger().with_mut(|info| info.network_id = [99; 32]);
    assert_ne!(original, env.as_contract(&id, || identifier(&env, &h)));
}

#[test]
fn uploader_authentication_is_required() {
    let env = Env::default();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    assert!(client
        .try_open(&header(&env, 1), &BytesN::from_array(&env, &[1; 32]))
        .is_err());
}

#[test]
fn unauthorized_append_and_rejected_chunks_leave_state_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let h = header(&env, 3);
    let upload = client.open(&h, &commitment(&env, &id, &h, b"abc"));
    let before = client.metadata(&upload);
    env.mock_auths(&[]);
    assert!(client
        .try_append(&upload, &0, &Bytes::from_slice(&env, b"abc"))
        .is_err());
    assert_eq!(client.metadata(&upload), before);
    env.as_contract(&id, || {
        assert!(!env
            .storage()
            .temporary()
            .has(&DataKey::Chunk(upload.clone(), 0)))
    });
    env.mock_all_auths();
    for (index, data) in [(1, b"abc".as_slice()), (0, b"ab".as_slice())] {
        assert!(client
            .try_append(&upload, &index, &Bytes::from_slice(&env, data))
            .is_err());
        assert_eq!(client.metadata(&upload), before);
    }
    client.append(&upload, &0, &Bytes::from_slice(&env, b"abc"));
    assert_eq!(client.metadata(&upload).received, 1);
}

#[test]
fn temporary_entries_survive_until_logical_expiry_across_upload_ledgers() {
    use soroban_sdk::testutils::storage::Temporary;
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let h = header(&env, 3);
    let upload = client.open(&h, &commitment(&env, &id, &h, b"abc"));
    env.ledger().with_mut(|info| info.sequence_number += 100);
    client.append(&upload, &0, &Bytes::from_slice(&env, b"abc"));
    env.as_contract(&id, || {
        let required = h.expires - env.ledger().sequence();
        assert!(
            env.storage()
                .temporary()
                .get_ttl(&DataKey::Session(upload.clone()))
                >= required
        );
        assert!(
            env.storage()
                .temporary()
                .get_ttl(&DataKey::Chunk(upload.clone(), 0))
                >= required
        );
    });
    env.ledger()
        .with_mut(|info| info.sequence_number = h.expires - 1);
    client.seal(&upload);
    assert_eq!(
        client.read_slice(&upload, &0, &0, &3),
        Bytes::from_slice(&env, b"abc")
    );
    env.ledger()
        .with_mut(|info| info.sequence_number = h.expires);
    assert_eq!(
        client.try_read_slice(&upload, &0, &0, &3),
        Err(Ok(Error::Expired))
    );
}

#[test]
fn exact_maximum_length_and_full_final_chunk_remain_bounded() {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let data = std::vec![8; MAX_PROOF_BYTES as usize];
    let h = header(&env, MAX_PROOF_BYTES);
    let upload = client.open(&h, &commitment(&env, &id, &h, &data));
    for index in 0..32 {
        client.append(
            &upload,
            &index,
            &Bytes::from_slice(&env, &data[..CHUNK_BYTES as usize]),
        );
    }
    client.seal(&upload);
    assert_eq!(client.metadata(&upload).received, 32);
    assert_eq!(
        client.try_append(&upload, &32, &Bytes::from_array(&env, &[8])),
        Err(Ok(Error::AlreadySealed))
    );
    assert_eq!(
        client
            .read_slice(&upload, &31, &(CHUNK_BYTES - READ_BYTES), &READ_BYTES)
            .len(),
        READ_BYTES
    );
}

#[test]
fn read_range_checks_reject_overflow_and_oversized_return_values() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let h = header(&env, 3);
    let upload = client.open(&h, &commitment(&env, &id, &h, b"abc"));
    client.append(&upload, &0, &Bytes::from_slice(&env, b"abc"));
    client.seal(&upload);
    for (offset, length) in [
        (0, 0),
        (u32::MAX, 1),
        (1, u32::MAX),
        (0, READ_BYTES + 1),
        (2, 2),
    ] {
        assert_eq!(
            client.try_read_slice(&upload, &0, &offset, &length),
            Err(Ok(Error::InvalidRange))
        );
    }
}

#[test]
fn independent_python_xdr_and_chain_vector_matches_rust() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_network_id([11; 32]);
    env.ledger().with_mut(|info| info.sequence_number = 1000);
    let id = Address::from_string(&String::from_str(
        &env,
        "CBKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVLO6Q",
    ));
    env.register_at(&id, RecoveryProofMailbox, ());
    let h = UploadHeader {
        uploader: Address::from_string(&String::from_str(
            &env,
            "GDLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRVHUR",
        )),
        nonce: BytesN::from_array(&env, &[1; 32]),
        statement: BytesN::from_array(&env, &[2; 64]),
        verifier: BytesN::from_array(&env, &[3; 32]),
        parameters: BytesN::from_array(&env, &[4; 32]),
        length: 3,
        expires: 1900,
    };
    // Constants generated independently with Python stellar-sdk SCVal XDR + hashlib.
    let session = BytesN::from_array(
        &env,
        &[
            0xa5, 0x90, 0xdd, 0xb4, 0xf4, 0x00, 0x41, 0x80, 0x67, 0x23, 0xa7, 0x81, 0x2b, 0x49,
            0xed, 0x2d, 0xb6, 0x57, 0x9e, 0x10, 0xb3, 0x4b, 0x75, 0xcf, 0x83, 0xe2, 0xb0, 0x64,
            0xfb, 0x97, 0xe8, 0xf0,
        ],
    );
    let expected = BytesN::from_array(
        &env,
        &[
            0xea, 0x72, 0x2d, 0x81, 0x05, 0xe3, 0x66, 0x58, 0xbe, 0xd9, 0x2c, 0x35, 0x82, 0x68,
            0x47, 0x0d, 0x9a, 0xb4, 0xb4, 0x05, 0x5b, 0x0d, 0x0e, 0x07, 0x63, 0x31, 0xf7, 0x4b,
            0x64, 0x90, 0xfa, 0xb2,
        ],
    );
    let client = RecoveryProofMailboxClient::new(&env, &id);
    assert_eq!(client.open(&h, &expected), session);
    client.append(&session, &0, &Bytes::from_slice(&env, b"abc"));
    assert_eq!(client.seal(&session).rolling, expected);
}

#[test]
fn commitment_from_one_session_cannot_seal_another() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(RecoveryProofMailbox, ());
    let client = RecoveryProofMailboxClient::new(&env, &id);
    let h = header(&env, 3);
    let first = commitment(&env, &id, &h, b"abc");
    let mut other = h.clone();
    other.nonce = BytesN::from_array(&env, &[8; 32]);
    let upload = client.open(&other, &first);
    client.append(&upload, &0, &Bytes::from_slice(&env, b"abc"));
    assert_eq!(client.try_seal(&upload), Err(Ok(Error::CommitmentMismatch)));
}
