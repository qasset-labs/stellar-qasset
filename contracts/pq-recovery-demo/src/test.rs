#![cfg(test)]

use super::*;
use ml_dsa::{ExpandedSigningKey, Seed};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, xdr, IntoVal, Symbol, TryIntoVal, Val,
};

struct Keys {
    active: ExpandedSigningKey<MlDsa65>,
    recovery: ExpandedSigningKey<MlDsa65>,
    replacement: ExpandedSigningKey<MlDsa65>,
}

fn key(seed: u8) -> ExpandedSigningKey<MlDsa65> {
    ExpandedSigningKey::from_seed(&Seed::from([seed; 32]))
}

fn public(env: &Env, key: &ExpandedSigningKey<MlDsa65>) -> Bytes {
    Bytes::from_slice(env, key.verifying_key().encode().as_slice())
}

fn sign(
    env: &Env,
    key: &ExpandedSigningKey<MlDsa65>,
    digest: &BytesN<32>,
    context: &[u8],
) -> Bytes {
    Bytes::from_slice(
        env,
        key.sign_deterministic(&digest.to_array(), context)
            .unwrap()
            .encode()
            .as_slice(),
    )
}

fn setup(env: &Env) -> (PqRecoveryDemoClient<'_>, Address, Keys) {
    let owner = Address::generate(env);
    let keys = Keys {
        active: key(1),
        recovery: key(2),
        replacement: key(3),
    };
    // Mock ONLY deployment consent, then require real cryptographic authorization.
    env.mock_all_auths();
    let id = env.register(
        PqRecoveryDemo,
        (
            &owner,
            public(env, &keys.active),
            public(env, &keys.recovery),
        ),
    );
    assert_eq!(env.auths().len(), 1);
    assert_eq!(env.auths()[0].0, owner);
    env.set_auths(&[]);
    (PqRecoveryDemoClient::new(env, &id), owner, keys)
}

fn auth_entry(
    env: &Env,
    client: &PqRecoveryDemoClient,
    key: &ExpandedSigningKey<MlDsa65>,
    nonce: i64,
    context: &[u8],
) -> xdr::SorobanAuthorizationEntry {
    use xdr::WriteXdr;
    let invocation: xdr::SorobanAuthorizedInvocation = (&MockAuthInvoke {
        contract: &client.address,
        fn_name: "protected",
        args: vec![env],
        sub_invokes: &[],
    })
        .into();
    let expiry = env.ledger().sequence() + 100;
    let preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: expiry,
            invocation: invocation.clone(),
        });
    let encoded = preimage.to_xdr(xdr::Limits::none()).unwrap();
    let digest = env
        .crypto()
        .sha256(&Bytes::from_slice(env, &encoded))
        .to_bytes();
    let signature: Val = sign(env, key, &digest, context).into_val(env);
    xdr::SorobanAuthorizationEntry {
        root_invocation: invocation,
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: (&client.address).into(),
            nonce,
            signature_expiration_ledger: expiry,
            signature: signature.try_into_val(env).unwrap(),
        }),
    }
}

fn assert_unrecovered(env: &Env, client: &PqRecoveryDemoClient, keys: &Keys) {
    assert_eq!(client.epoch(), 0);
    assert!(client.recovery_enabled());
    assert_eq!(client.active_key(), public(env, &keys.active));
    assert_eq!(client.counter(), 0);
}

#[test]
fn real_recovery_handoff_changes_which_key_passes_host_require_auth() {
    let env = Env::default();
    let (client, _owner, keys) = setup(&env);
    env.set_auths(&[auth_entry(&env, &client, &keys.active, 1, AUTH_CONTEXT)]);
    assert_eq!(client.protected(), 1);

    let replacement = public(&env, &keys.replacement);
    let digest = client.recovery_digest(&0, &replacement, &50);
    let recovery_signature = sign(&env, &keys.recovery, &digest, RECOVERY_CONTEXT);
    let replacement_signature = sign(&env, &keys.replacement, &digest, RECOVERY_CONTEXT);
    env.set_auths(&[]);
    client.recover(
        &0,
        &replacement,
        &50,
        &recovery_signature,
        &replacement_signature,
    );
    assert_eq!(client.epoch(), 1);
    assert!(!client.recovery_enabled());
    assert_eq!(client.active_key(), replacement);

    env.set_auths(&[auth_entry(&env, &client, &keys.active, 2, AUTH_CONTEXT)]);
    assert!(client.try_protected().is_err());
    assert_eq!(client.counter(), 1);
    env.set_auths(&[auth_entry(&env, &client, &keys.recovery, 3, AUTH_CONTEXT)]);
    assert!(client.try_protected().is_err());
    env.set_auths(&[auth_entry(
        &env,
        &client,
        &keys.replacement,
        4,
        AUTH_CONTEXT,
    )]);
    assert_eq!(client.protected(), 2);

    assert_eq!(
        client.try_recover(
            &0,
            &replacement,
            &50,
            &recovery_signature,
            &replacement_signature
        ),
        Err(Ok(Error::RecoveryConsumed))
    );
    // Even freshly signed epoch-1 instructions cannot reuse the one-time recovery authority.
    let next_key = key(4);
    let next_public = public(&env, &next_key);
    let next_digest = client.recovery_digest(&1, &next_public, &60);
    assert_eq!(
        client.try_recover(
            &1,
            &next_public,
            &60,
            &sign(&env, &keys.recovery, &next_digest, RECOVERY_CONTEXT),
            &sign(&env, &next_key, &next_digest, RECOVERY_CONTEXT),
        ),
        Err(Ok(Error::RecoveryConsumed))
    );
    assert_eq!(client.epoch(), 1);
    assert_eq!(client.active_key(), replacement);
}

#[test]
fn recovery_requires_both_real_signatures_and_preserves_state_on_failure() {
    let env = Env::default();
    let (client, _owner, keys) = setup(&env);
    let replacement = public(&env, &keys.replacement);
    let digest = client.recovery_digest(&0, &replacement, &50);
    let good_recovery = sign(&env, &keys.recovery, &digest, RECOVERY_CONTEXT);
    let good_replacement = sign(&env, &keys.replacement, &digest, RECOVERY_CONTEXT);
    for (recovery, replacement_signature) in [
        (
            sign(&env, &keys.active, &digest, RECOVERY_CONTEXT),
            good_replacement.clone(),
        ),
        (
            good_recovery.clone(),
            sign(&env, &keys.active, &digest, RECOVERY_CONTEXT),
        ),
        (
            sign(&env, &keys.recovery, &digest, AUTH_CONTEXT),
            good_replacement.clone(),
        ),
        (
            good_recovery.clone(),
            sign(&env, &keys.replacement, &digest, AUTH_CONTEXT),
        ),
        (
            Bytes::from_slice(&env, &[0; SIGNATURE_BYTES]),
            good_replacement.clone(),
        ),
    ] {
        assert_eq!(
            client.try_recover(&0, &replacement, &50, &recovery, &replacement_signature),
            Err(Ok(Error::InvalidSignature))
        );
        assert_unrecovered(&env, &client, &keys);
    }
    // A valid recovery signature is insufficient if the supplied replacement key changes.
    let different_key = public(&env, &key(4));
    assert_eq!(
        client.try_recover(&0, &different_key, &50, &good_recovery, &good_replacement),
        Err(Ok(Error::InvalidSignature))
    );
    assert_eq!(
        client.try_recover(&0, &replacement, &51, &good_recovery, &good_replacement),
        Err(Ok(Error::InvalidSignature))
    );
    assert_unrecovered(&env, &client, &keys);
    client.recover(&0, &replacement, &50, &good_recovery, &good_replacement);
    assert_eq!(client.active_key(), replacement);
}

#[test]
fn recovery_rejects_bad_epoch_expiry_key_reuse_and_lengths() {
    let env = Env::default();
    env.ledger().set_sequence_number(100);
    let (client, _owner, keys) = setup(&env);
    let replacement = public(&env, &keys.replacement);
    let signature = Bytes::from_slice(&env, &[0; SIGNATURE_BYTES]);
    for (epoch, public_key, expiry, recovery_sig, replacement_sig, error) in [
        (
            1,
            replacement.clone(),
            150,
            signature.clone(),
            signature.clone(),
            Error::WrongEpoch,
        ),
        (
            0,
            replacement.clone(),
            99,
            signature.clone(),
            signature.clone(),
            Error::Expired,
        ),
        (
            0,
            replacement.clone(),
            1101,
            signature.clone(),
            signature.clone(),
            Error::ExpiryTooFar,
        ),
        (
            0,
            public(&env, &keys.active),
            150,
            signature.clone(),
            signature.clone(),
            Error::KeyReuse,
        ),
        (
            0,
            public(&env, &keys.recovery),
            150,
            signature.clone(),
            signature.clone(),
            Error::KeyReuse,
        ),
        (
            0,
            Bytes::from_slice(&env, &[0; 1]),
            150,
            signature.clone(),
            signature.clone(),
            Error::BadKeyLength,
        ),
        (
            0,
            replacement.clone(),
            150,
            Bytes::new(&env),
            signature.clone(),
            Error::BadSignatureLength,
        ),
        (
            0,
            replacement.clone(),
            150,
            signature.clone(),
            Bytes::new(&env),
            Error::BadSignatureLength,
        ),
    ] {
        assert_eq!(
            client.try_recover(
                &epoch,
                &public_key,
                &expiry,
                &recovery_sig,
                &replacement_sig
            ),
            Err(Ok(error))
        );
        assert_unrecovered(&env, &client, &keys);
    }
}

#[test]
fn recovery_accepts_exact_current_and_maximum_expiry_boundaries() {
    for expiry in [100, 1100] {
        let env = Env::default();
        env.ledger().set_sequence_number(100);
        let (client, _owner, keys) = setup(&env);
        let replacement = public(&env, &keys.replacement);
        let digest = client.recovery_digest(&0, &replacement, &expiry);
        client.recover(
            &0,
            &replacement,
            &expiry,
            &sign(&env, &keys.recovery, &digest, RECOVERY_CONTEXT),
            &sign(&env, &keys.replacement, &digest, RECOVERY_CONTEXT),
        );
        assert_eq!(client.epoch(), 1);
        assert_eq!(client.active_key(), replacement);
    }
}

#[test]
fn recovery_is_bound_to_contract_and_network() {
    let env = Env::default();
    let (client, owner, keys) = setup(&env);
    env.mock_all_auths();
    let other_id = env.register(
        PqRecoveryDemo,
        (
            &owner,
            public(&env, &keys.active),
            public(&env, &keys.recovery),
        ),
    );
    env.set_auths(&[]);
    let other = PqRecoveryDemoClient::new(&env, &other_id);
    let replacement = public(&env, &keys.replacement);
    let digest = client.recovery_digest(&0, &replacement, &50);
    let recovery_signature = sign(&env, &keys.recovery, &digest, RECOVERY_CONTEXT);
    let replacement_signature = sign(&env, &keys.replacement, &digest, RECOVERY_CONTEXT);
    assert_ne!(digest, other.recovery_digest(&0, &replacement, &50));
    assert_eq!(
        other.try_recover(
            &0,
            &replacement,
            &50,
            &recovery_signature,
            &replacement_signature
        ),
        Err(Ok(Error::InvalidSignature))
    );
    assert_unrecovered(&env, &other, &keys);
    env.ledger().set_network_id([9; 32]);
    assert_ne!(digest, client.recovery_digest(&0, &replacement, &50));
    assert_eq!(
        client.try_recover(
            &0,
            &replacement,
            &50,
            &recovery_signature,
            &replacement_signature
        ),
        Err(Ok(Error::InvalidSignature))
    );
    assert_unrecovered(&env, &client, &keys);
}

#[test]
fn host_auth_checks_real_payload_context_and_nonce_replay() {
    let env = Env::default();
    let (client, _owner, keys) = setup(&env);
    let entry = auth_entry(&env, &client, &keys.active, 70, AUTH_CONTEXT);
    env.set_auths(core::slice::from_ref(&entry));
    assert_eq!(client.protected(), 1);
    env.set_auths(&[entry]);
    assert!(client.try_protected().is_err());
    assert_eq!(client.counter(), 1);

    env.set_auths(&[auth_entry(
        &env,
        &client,
        &keys.active,
        71,
        RECOVERY_CONTEXT,
    )]);
    assert!(client.try_protected().is_err());
    let mut tampered = auth_entry(&env, &client, &keys.active, 72, AUTH_CONTEXT);
    if let xdr::SorobanCredentials::Address(credentials) = &mut tampered.credentials {
        credentials.nonce = 73;
    }
    env.set_auths(&[tampered]);
    assert!(client.try_protected().is_err());
    assert_eq!(client.counter(), 1);
    env.set_auths(&[auth_entry(&env, &client, &keys.active, 74, AUTH_CONTEXT)]);
    assert_eq!(client.protected(), 2);
}

#[test]
fn constructor_owner_has_no_administrative_or_signing_bypass() {
    let env = Env::default();
    let (client, owner, keys) = setup(&env);
    let invoke = MockAuthInvoke {
        contract: &client.address,
        fn_name: "protected",
        args: vec![&env],
        sub_invokes: &[],
    };
    assert!(client
        .mock_auths(&[MockAuth {
            address: &owner,
            invoke: &invoke
        }])
        .try_protected()
        .is_err());
    // Supply valid constructor arguments and authenticated deployment consent. A second
    // constructor call would therefore succeed and replace both keys if the host exposed it.
    let attacker = Address::generate(&env);
    let fresh_active = public(&env, &key(4));
    let fresh_recovery = public(&env, &key(5));
    let constructor_args: Vec<Val> = (&attacker, &fresh_active, &fresh_recovery).into_val(&env);
    env.mock_all_auths();
    for (method, args) in [
        ("initialize", constructor_args.clone()),
        ("__constructor", constructor_args),
        ("set_key", (&fresh_active,).into_val(&env)),
        (
            "upgrade",
            (BytesN::from_array(&env, &[0; 32]),).into_val(&env),
        ),
    ] {
        assert!(env
            .try_invoke_contract::<(), Error>(&client.address, &Symbol::new(&env, method), args,)
            .is_err());
    }
    env.set_auths(&[]);
    assert_unrecovered(&env, &client, &keys);
}

#[test]
#[should_panic]
fn constructor_without_owner_consent_is_rejected() {
    let env = Env::default();
    let owner = Address::generate(&env);
    env.register(
        PqRecoveryDemo,
        (&owner, public(&env, &key(1)), public(&env, &key(2))),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn constructor_rejects_reusing_the_active_key_as_recovery_key() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let same_key = public(&env, &key(1));
    env.register(PqRecoveryDemo, (&owner, &same_key, &same_key));
}

// Extracted PUBLIC verification vectors, independently generated upstream.
// Exact revisions, original test IDs, source hashes and scope: test-vectors/provenance.json.
// No secrets or upstream executable code are included. These are bounded regressions,
// not ACVP validation, FIPS certification or a proof of contract authorization security.
extern crate std;

struct ExternalVector {
    key: std::vec::Vec<u8>,
    message: std::vec::Vec<u8>,
    context: std::vec::Vec<u8>,
    signature: std::vec::Vec<u8>,
}

fn external_vector(text: &str) -> ExternalVector {
    fn decode(hex: &str) -> std::vec::Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    let mut fields = text.lines();
    let vector = ExternalVector {
        key: decode(fields.next().unwrap()),
        message: decode(fields.next().unwrap()),
        context: decode(fields.next().unwrap()),
        signature: decode(fields.next().unwrap()),
    };
    assert!(fields.next().is_none());
    vector
}

#[test]
fn official_wycheproof_vectors_exercise_actual_digest_wrapper() {
    // tc19 specifically regresses the repeated-hint bug in earlier RustCrypto releases.
    // These external vectors use an empty context, so they test our verification wrapper,
    // not successful host authorization under the application's AUTH_CONTEXT.
    for (text, valid) in [
        (include_str!("../test-vectors/wycheproof-tc21.txt"), true),
        (include_str!("../test-vectors/wycheproof-tc16.txt"), false),
        (include_str!("../test-vectors/wycheproof-tc18.txt"), false),
        (include_str!("../test-vectors/wycheproof-tc19.txt"), false),
    ] {
        let vector = external_vector(text);
        let env = Env::default();
        let key = Bytes::from_slice(&env, &vector.key);
        let signature = Bytes::from_slice(&env, &vector.signature);
        let digest: [u8; 32] = vector.message.as_slice().try_into().unwrap();
        assert_eq!(
            verify(&key, &digest, &vector.context, &signature),
            if valid {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        );
        if valid {
            let mut changed_digest = digest;
            changed_digest[0] ^= 1;
            assert_eq!(
                verify(&key, &changed_digest, &vector.context, &signature),
                Err(Error::InvalidSignature)
            );
            assert_eq!(
                verify(&key, &digest, AUTH_CONTEXT, &signature),
                Err(Error::InvalidSignature)
            );
            assert_eq!(
                verify(&key, &digest, RECOVERY_CONTEXT, &signature),
                Err(Error::InvalidSignature)
            );
        }
    }
}

#[test]
fn official_external_pure_vectors_check_underlying_library_interface() {
    // NIST's selected external/pure ML-DSA-65 messages are not 32-byte digests. Do not
    // alter the production wrapper to fit them: these test the exact underlying API.
    // NIST tc43 also exercises its nonempty 149-byte context; Wycheproof tc138 is
    // exactly at the rejected z-norm boundary.
    for (text, valid) in [
        (include_str!("../test-vectors/nist-acvp-tc43.txt"), true),
        (include_str!("../test-vectors/nist-acvp-tc38.txt"), false),
        (include_str!("../test-vectors/wycheproof-tc3.txt"), true),
        (include_str!("../test-vectors/wycheproof-tc138.txt"), false),
    ] {
        let vector = external_vector(text);
        let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(vector.key.as_slice()).unwrap();
        let key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
        let encoded_signature =
            EncodedSignature::<MlDsa65>::try_from(vector.signature.as_slice()).unwrap();
        let accepted = Signature::<MlDsa65>::decode(&encoded_signature)
            .map(|signature| key.verify_with_context(&vector.message, &vector.context, &signature))
            .unwrap_or(false);
        assert_eq!(accepted, valid);
    }
}

#[test]
fn official_noncanonical_hint_and_norm_fixtures_fail_at_signature_decode() {
    for text in [
        include_str!("../test-vectors/wycheproof-tc16.txt"),
        include_str!("../test-vectors/wycheproof-tc18.txt"),
        include_str!("../test-vectors/wycheproof-tc19.txt"),
        include_str!("../test-vectors/wycheproof-tc138.txt"),
    ] {
        let vector = external_vector(text);
        let encoded = EncodedSignature::<MlDsa65>::try_from(vector.signature.as_slice()).unwrap();
        assert!(Signature::<MlDsa65>::decode(&encoded).is_none());
    }
}

#[soroban_sdk::contract]
struct RecoveryBatch;

#[soroban_sdk::contractimpl]
impl RecoveryBatch {
    pub fn handoff(
        env: Env,
        account: Address,
        replacement: Bytes,
        expiry: u32,
        recovery_sig: Bytes,
        replacement_sig: Bytes,
    ) -> u64 {
        account.require_auth();
        let client = PqRecoveryDemoClient::new(&env, &account);
        client.recover(&0, &replacement, &expiry, &recovery_sig, &replacement_sig);
        client.protected()
    }
}

#[test]
fn authorization_must_not_survive_a_handoff_in_an_unrelated_invocation_tree() {
    use xdr::WriteXdr;
    let env = Env::default();
    let (account, _, keys) = setup(&env);
    let batch_id = env.register(RecoveryBatch, ());
    let batch = RecoveryBatchClient::new(&env, &batch_id);
    let replacement = public(&env, &keys.replacement);
    let digest = account.recovery_digest(&0, &replacement, &50);
    let recovery_sig = sign(&env, &keys.recovery, &digest, RECOVERY_CONTEXT);
    let replacement_sig = sign(&env, &keys.replacement, &digest, RECOVERY_CONTEXT);
    let child = MockAuthInvoke {
        contract: &account.address,
        fn_name: "protected",
        args: vec![&env],
        sub_invokes: &[],
    };
    let invocation: xdr::SorobanAuthorizedInvocation = (&MockAuthInvoke {
        contract: &batch_id,
        fn_name: "handoff",
        args: (
            &account.address,
            &replacement,
            50u32,
            &recovery_sig,
            &replacement_sig,
        )
            .into_val(&env),
        sub_invokes: &[child],
    })
        .into();
    let preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(env.ledger().network_id().to_array()),
            nonce: 700,
            signature_expiration_ledger: 100,
            invocation: invocation.clone(),
        });
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(
            &env,
            &preimage.to_xdr(xdr::Limits::none()).unwrap(),
        ))
        .to_bytes();
    let credential: Val = sign(&env, &keys.active, &payload, AUTH_CONTEXT).into_val(&env);
    env.set_auths(&[xdr::SorobanAuthorizationEntry {
        root_invocation: invocation,
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: (&account.address).into(),
            nonce: 700,
            signature_expiration_ledger: 100,
            signature: credential.try_into_val(&env).unwrap(),
        }),
    }]);
    let result = batch.try_handoff(
        &account.address,
        &replacement,
        &50,
        &recovery_sig,
        &replacement_sig,
    );
    assert!(
        result.is_err(),
        "old-key authorization survived recovery: {result:?}"
    );
    assert_eq!(account.epoch(), 0);
    assert_eq!(account.counter(), 0);
}

#[test]
fn counter_authority_rejects_empty_external_and_composite_contexts() {
    use soroban_sdk::auth::{ContractContext, ContractExecutable, CreateContractHostFnContext};
    let env = Env::default();
    let (account, _, keys) = setup(&env);
    let payload = BytesN::from_array(&env, &[8; 32]);
    let signature: Val = sign(&env, &keys.active, &payload, AUTH_CONTEXT).into_val(&env);
    let allowed = Context::Contract(ContractContext {
        contract: account.address.clone(),
        fn_name: Symbol::new(&env, "protected"),
        args: vec![&env],
    });
    assert_eq!(
        env.try_invoke_contract_check_auth::<Error>(
            &account.address,
            &payload,
            signature,
            &vec![&env, allowed.clone()],
        ),
        Ok(())
    );
    for contexts in [
        vec![&env],
        vec![&env, allowed.clone(), allowed],
        vec![
            &env,
            Context::Contract(ContractContext {
                contract: Address::generate(&env),
                fn_name: Symbol::new(&env, "protected"),
                args: vec![&env],
            }),
        ],
        vec![
            &env,
            Context::Contract(ContractContext {
                contract: account.address.clone(),
                fn_name: Symbol::new(&env, "recover"),
                args: vec![&env],
            }),
        ],
        vec![
            &env,
            Context::Contract(ContractContext {
                contract: account.address.clone(),
                fn_name: Symbol::new(&env, "protected"),
                args: (1u32,).into_val(&env),
            }),
        ],
        vec![
            &env,
            Context::CreateContractHostFn(CreateContractHostFnContext {
                executable: ContractExecutable::Wasm(BytesN::from_array(&env, &[1; 32])),
                salt: BytesN::from_array(&env, &[2; 32]),
            }),
        ],
    ] {
        assert_eq!(
            env.try_invoke_contract_check_auth::<Error>(
                &account.address,
                &payload,
                signature,
                &contexts,
            ),
            Err(Ok(Error::UnsupportedAuthContext))
        );
    }
}
