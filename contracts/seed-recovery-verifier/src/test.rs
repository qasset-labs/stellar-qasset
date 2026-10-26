#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, MockAuthInvoke},
    vec, xdr, IntoVal, Symbol, TryIntoVal, Val,
};

fn setup(env: &Env) -> SeedRecoveryVerifierClient<'_> {
    let owner = Address::generate(env);
    let key = BytesN::from_array(env, &[1; 32]);
    // Constructor-only mocks. Authorization tests below run in enforcing mode.
    env.mock_all_auths();
    let id = env.register(SeedRecoveryVerifier, (&owner, &key, 7u32));
    assert_eq!(env.auths().len(), 1);
    assert_eq!(env.auths()[0].0, owner);
    env.set_auths(&[]);
    let client = SeedRecoveryVerifierClient::new(env, &id);
    assert_eq!(client.config().owner, owner);
    client
}

fn forged_proof(env: &Env, binding: &BytesN<32>, fill: u8) -> RecoveryProof {
    RecoveryProof {
        binding: binding.clone(),
        proof: Bytes::from_slice(env, &[fill; 256]),
    }
}

#[test]
fn constructor_sets_immutable_configuration_and_disabled_status() {
    let env = Env::default();
    let recovery = setup(&env);
    let config = recovery.config();
    assert_eq!(config.protected_pubkey, BytesN::from_array(&env, &[1; 32]));
    assert_eq!(config.derivation_index, 7);
    assert!(!recovery.backend_available());
}

#[test]
fn public_initializer_and_constructor_cannot_rebind_deployed_instance() {
    let env = Env::default();
    let recovery = setup(&env);
    let before = recovery.config();
    let attacker = Address::generate(&env);
    let key = BytesN::from_array(&env, &[2; 32]);
    // Even an authenticated caller cannot invoke either initialization path.
    env.mock_all_auths();
    for name in ["initialize", "__constructor"] {
        let result = env.try_invoke_contract::<(), Error>(
            &recovery.address,
            &Symbol::new(&env, name),
            (&attacker, &key, 42u32).into_val(&env),
        );
        assert!(result.is_err());
    }
    assert_eq!(recovery.config(), before);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn constructor_rejects_an_already_hardened_account_index() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let key = BytesN::from_array(&env, &[1; 32]);
    env.register(SeedRecoveryVerifier, (&owner, &key, 1u32 << 31));
}

#[test]
#[should_panic]
fn constructor_without_owner_authorization_is_rejected() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let key = BytesN::from_array(&env, &[1; 32]);
    // No mocks and no signed authorization entries for the owner.
    env.register(SeedRecoveryVerifier, (&owner, &key, 0u32));
}

#[test]
fn matching_or_modified_bindings_never_authorize_placeholder_proofs() {
    let env = Env::default();
    let recovery = setup(&env);
    let payload = BytesN::from_array(&env, &[4; 32]);
    for (binding, fill) in [
        (payload.clone(), 0),
        (payload.clone(), 255),
        (BytesN::from_array(&env, &[5; 32]), 0),
    ] {
        let proof = forged_proof(&env, &binding, fill);
        assert_eq!(
            env.try_invoke_contract_check_auth::<Error>(
                &recovery.address,
                &payload,
                proof.into_val(&env),
                &vec![&env],
            ),
            Err(Ok(Error::BackendUnavailable))
        );
    }
}

#[soroban_sdk::contract]
pub struct ProtectedAction;

#[soroban_sdk::contractimpl]
impl ProtectedAction {
    pub fn spend(env: Env, account: Address) {
        account.require_auth();
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "spent"), &true);
    }

    pub fn spent(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "spent"))
            .unwrap_or(false)
    }
}

#[test]
fn forged_credentials_fail_through_real_require_auth_without_auth_mocks() {
    use xdr::WriteXdr;
    let env = Env::default();
    let recovery = setup(&env);
    let target_id = env.register(ProtectedAction, ());
    let target = ProtectedActionClient::new(&env, &target_id);
    let invocation: xdr::SorobanAuthorizedInvocation = (&MockAuthInvoke {
        contract: &target_id,
        fn_name: "spend",
        args: (&recovery.address,).into_val(&env),
        sub_invokes: &[],
    })
        .into();

    // The former exploit used arbitrary proof bytes, the correct PUBLIC hash,
    // and a fresh public nonce. No mnemonic, private key, or auth mocking here.
    for (nonce, fill) in [(100i64, 0u8), (101i64, 255u8)] {
        let expiration = 100;
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(env.ledger().network_id().to_array()),
                nonce,
                signature_expiration_ledger: expiration,
                invocation: invocation.clone(),
            });
        let encoded = preimage.to_xdr(xdr::Limits::none()).unwrap();
        let hash = env.crypto().sha256(&Bytes::from_slice(&env, &encoded));
        let binding = BytesN::from_array(&env, &hash.to_array());
        let signature: Val = forged_proof(&env, &binding, fill).into_val(&env);
        env.set_auths(&[xdr::SorobanAuthorizationEntry {
            root_invocation: invocation.clone(),
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: (&recovery.address).into(),
                nonce,
                signature_expiration_ledger: expiration,
                signature: signature.try_into_val(&env).unwrap(),
            }),
        }]);
        assert!(target.try_spend(&recovery.address).is_err());
        assert!(!target.spent());
    }
}
