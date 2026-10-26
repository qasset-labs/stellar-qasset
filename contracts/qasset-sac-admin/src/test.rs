#![cfg(test)]
//! Every authorization these tests rely on for a security claim is a real ML-DSA-65
//! signature over the host's real Soroban authorization payload, supplied with
//! `set_auths`. `mock_auths` is used in exactly two places, each for one exact call: the
//! classic issuer's consent to `set_admin` during setup (the issuer's own Ed25519 account
//! authentication is not what is under test), and the stale-authority test, where the
//! point is that even a genuine credential from the previous administrator no longer
//! authorizes anything.

extern crate std;

use super::*;
use ml_dsa::{ExpandedSigningKey, Seed};
use soroban_sdk::{
    auth::{ContractContext, ContractExecutable, CreateContractHostFnContext},
    testutils::{Address as _, IssuerFlags, Ledger as _, MockAuth, MockAuthInvoke},
    token::StellarAssetClient,
    vec, xdr, Address, BytesN, IntoVal, TryIntoVal, Val,
};

fn key(seed: u8) -> ExpandedSigningKey<MlDsa65> {
    ExpandedSigningKey::from_seed(&Seed::from([seed; 32]))
}

fn public(env: &Env, key: &ExpandedSigningKey<MlDsa65>) -> Bytes {
    Bytes::from_slice(env, key.verifying_key().encode().as_slice())
}

fn sign(env: &Env, key: &ExpandedSigningKey<MlDsa65>, digest: &[u8; 32], context: &[u8]) -> Bytes {
    Bytes::from_slice(
        env,
        key.sign_deterministic(digest, context)
            .unwrap()
            .encode()
            .as_slice(),
    )
}

struct Signing<'a> {
    key: &'a ExpandedSigningKey<MlDsa65>,
    context: &'a [u8],
    nonce: i64,
    expiry: u32,
    network_id: [u8; 32],
}

/// Builds a genuine Soroban authorization entry for `account` (the admin contract),
/// signing the exact payload the host recomputes: SHA-256 of the XDR
/// `HashIdPreimageSorobanAuthorization { network_id, nonce, expiry, invocation }`.
fn entry(
    env: &Env,
    account: &Address,
    invoke: &MockAuthInvoke,
    s: &Signing,
) -> xdr::SorobanAuthorizationEntry {
    use xdr::WriteXdr;
    let invocation: xdr::SorobanAuthorizedInvocation = invoke.into();
    let preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(s.network_id),
            nonce: s.nonce,
            signature_expiration_ledger: s.expiry,
            invocation: invocation.clone(),
        });
    let encoded = preimage.to_xdr(xdr::Limits::none()).unwrap();
    let digest = env
        .crypto()
        .sha256(&Bytes::from_slice(env, &encoded))
        .to_bytes()
        .to_array();
    let signature: Val = sign(env, s.key, &digest, s.context).into_val(env);
    xdr::SorobanAuthorizationEntry {
        root_invocation: invocation,
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: account.into(),
            nonce: s.nonce,
            signature_expiration_ledger: s.expiry,
            signature: signature.try_into_val(env).unwrap(),
        }),
    }
}

struct Fixture {
    env: Env,
    issuer_admin: Address,
    sac: Address,
    admin: Address,
    operator: ExpandedSigningKey<MlDsa65>,
    holder: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        let issuer_admin = Address::generate(&env);
        let asset = env.register_stellar_asset_contract_v2(issuer_admin.clone());
        // New holders must start unauthorized so rejection checks prove no state change.
        asset.issuer().set_flag(IssuerFlags::RequiredFlag);
        // set_authorized(.., false) requires the issuer's revocable flag.
        asset.issuer().set_flag(IssuerFlags::RevocableFlag);
        let sac = asset.address();
        let operator = key(11);
        let admin = env.register(QAssetSacAdmin, (&sac, public(&env, &operator)));
        hand_over(&env, &issuer_admin, &sac, &admin);
        let holder = Address::generate(&env);
        Fixture {
            env,
            issuer_admin,
            sac,
            admin,
            operator,
            holder,
        }
    }

    fn sac_client(&self) -> StellarAssetClient<'_> {
        StellarAssetClient::new(&self.env, &self.sac)
    }

    fn signing<'a>(&'a self, key: &'a ExpandedSigningKey<MlDsa65>, nonce: i64) -> Signing<'a> {
        Signing {
            key,
            context: AUTH_CONTEXT,
            nonce,
            expiry: self.env.ledger().sequence() + 100,
            network_id: self.env.ledger().network_id().to_array(),
        }
    }

    fn set_authorized_invoke(&self, id: &Address, authorize: bool) -> MockAuthInvoke<'_> {
        MockAuthInvoke {
            contract: &self.sac,
            fn_name: "set_authorized",
            args: (id, authorize).into_val(&self.env),
            sub_invokes: &[],
        }
    }

    fn authorize(&self, id: &Address, authorize: bool, s: &Signing) -> bool {
        let invoke = MockAuthInvoke {
            contract: &self.sac,
            fn_name: "set_authorized",
            args: (id, authorize).into_val(&self.env),
            sub_invokes: &[],
        };
        self.env
            .set_auths(&[entry(&self.env, &self.admin, &invoke, s)]);
        let ok = self.sac_client().try_set_authorized(id, &authorize).is_ok();
        self.env.set_auths(&[]);
        ok
    }

    fn is_authorized(&self, id: &Address) -> bool {
        self.sac_client().authorized(id)
    }
}

/// The classic issuer's consent to the handover, mocked for exactly this one call.
fn hand_over(env: &Env, issuer_admin: &Address, sac: &Address, admin: &Address) {
    env.mock_auths(&[MockAuth {
        address: issuer_admin,
        invoke: &MockAuthInvoke {
            contract: sac,
            fn_name: "set_admin",
            args: (admin,).into_val(env),
            sub_invokes: &[],
        },
    }]);
    StellarAssetClient::new(env, sac).set_admin(admin);
    env.set_auths(&[]);
}

#[test]
fn handover_makes_the_contract_the_sac_administrator() {
    let f = Fixture::new();
    assert_eq!(f.sac_client().admin(), f.admin);
    let client = QAssetSacAdminClient::new(&f.env, &f.admin);
    assert_eq!(client.sac(), f.sac);
    assert_eq!(client.operator_key(), public(&f.env, &f.operator));
    assert_eq!(
        client.protected_function(),
        Symbol::new(&f.env, "set_authorized")
    );
}

#[test]
fn handover_requires_the_current_administrators_authorization() {
    let env = Env::default();
    let issuer_admin = Address::generate(&env);
    let sac = env
        .register_stellar_asset_contract_v2(issuer_admin.clone())
        .address();
    let admin = env.register(QAssetSacAdmin, (&sac, public(&env, &key(11))));
    env.set_auths(&[]);
    assert!(StellarAssetClient::new(&env, &sac)
        .try_set_admin(&admin)
        .is_err());
    assert_eq!(StellarAssetClient::new(&env, &sac).admin(), issuer_admin);
}

#[test]
fn valid_ml_dsa_authorization_sets_and_clears_trustline_authorization() {
    let f = Fixture::new();
    assert!(f.authorize(&f.holder, true, &f.signing(&f.operator, 1)));
    assert!(f.is_authorized(&f.holder));
    assert!(f.authorize(&f.holder, false, &f.signing(&f.operator, 2)));
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn missing_authorization_is_rejected() {
    let f = Fixture::new();
    f.env.set_auths(&[]);
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_err());
}

#[test]
fn corrupted_signature_is_rejected() {
    let f = Fixture::new();
    let invoke = f.set_authorized_invoke(&f.holder, true);
    let mut e = entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 1));
    if let xdr::SorobanCredentials::Address(c) = &mut e.credentials {
        if let xdr::ScVal::Bytes(b) = &mut c.signature {
            let mut v = b.to_vec();
            v[100] ^= 0x01;
            *b = v.try_into().unwrap();
        }
    }
    f.env.set_auths(&[e]);
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_err());
    f.env.set_auths(&[]);
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn signature_from_an_unregistered_ml_dsa_key_is_rejected() {
    let f = Fixture::new();
    let intruder = key(99);
    assert!(!f.authorize(&f.holder, true, &f.signing(&intruder, 1)));
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn signature_under_another_contracts_domain_context_is_rejected() {
    // A valid signature by the right key, but produced for the recovery candidate's
    // domain context, must not authorize SAC administration.
    let f = Fixture::new();
    let mut s = f.signing(&f.operator, 1);
    s.context = b"qasset-pq-auth-v1";
    assert!(!f.authorize(&f.holder, true, &s));
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn signature_for_another_network_is_rejected() {
    let f = Fixture::new();
    let mut s = f.signing(&f.operator, 1);
    s.network_id = [7u8; 32];
    assert!(!f.authorize(&f.holder, true, &s));
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn credential_for_different_arguments_does_not_authorize_the_call() {
    let f = Fixture::new();
    let other = Address::generate(&f.env);
    let signed_for_other = f.set_authorized_invoke(&other, true);
    f.env.set_auths(&[entry(
        &f.env,
        &f.admin,
        &signed_for_other,
        &f.signing(&f.operator, 1),
    )]);
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_err());
    f.env.set_auths(&[]);
    assert!(!f.is_authorized(&f.holder));
    assert!(!f.is_authorized(&other));
}

#[test]
fn valid_signature_for_mint_is_rejected_by_the_context_policy() {
    // The signature is genuine and the host would accept it; only this contract's policy
    // stops a SAC administrator signature from minting.
    let f = Fixture::new();
    let invoke = MockAuthInvoke {
        contract: &f.sac,
        fn_name: "mint",
        args: (&f.holder, 1_000i128).into_val(&f.env),
        sub_invokes: &[],
    };
    f.env
        .set_auths(&[entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 1))]);
    assert!(f.sac_client().try_mint(&f.holder, &1_000).is_err());
    f.env.set_auths(&[]);
}

#[test]
fn valid_signature_for_set_admin_is_rejected_by_the_context_policy() {
    let f = Fixture::new();
    let attacker = Address::generate(&f.env);
    let invoke = MockAuthInvoke {
        contract: &f.sac,
        fn_name: "set_admin",
        args: (&attacker,).into_val(&f.env),
        sub_invokes: &[],
    };
    f.env
        .set_auths(&[entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 1))]);
    assert!(f.sac_client().try_set_admin(&attacker).is_err());
    f.env.set_auths(&[]);
    assert_eq!(f.sac_client().admin(), f.admin);
}

#[test]
fn valid_signature_for_a_different_sac_is_rejected() {
    // A second SAC also administered by this same contract: the contract is bound to its
    // configured SAC and must refuse the other one even with a valid signature.
    let f = Fixture::new();
    let other_issuer = Address::generate(&f.env);
    let other_asset = f
        .env
        .register_stellar_asset_contract_v2(other_issuer.clone());
    other_asset.issuer().set_flag(IssuerFlags::RequiredFlag);
    let other_sac = other_asset.address();
    hand_over(&f.env, &other_issuer, &other_sac, &f.admin);
    let invoke = MockAuthInvoke {
        contract: &other_sac,
        fn_name: "set_authorized",
        args: (&f.holder, true).into_val(&f.env),
        sub_invokes: &[],
    };
    f.env
        .set_auths(&[entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 1))]);
    assert!(StellarAssetClient::new(&f.env, &other_sac)
        .try_set_authorized(&f.holder, &true)
        .is_err());
    f.env.set_auths(&[]);
    assert!(!StellarAssetClient::new(&f.env, &other_sac).authorized(&f.holder));
}

#[test]
fn replayed_authorization_entry_is_rejected() {
    let f = Fixture::new();
    let invoke = f.set_authorized_invoke(&f.holder, true);
    let e = entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 5));
    f.env.set_auths(core::slice::from_ref(&e));
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_ok());
    f.env.set_auths(&[e]);
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_err());
    f.env.set_auths(&[]);
}

#[test]
fn expired_authorization_entry_is_rejected() {
    let f = Fixture::new();
    let mut s = f.signing(&f.operator, 1);
    s.expiry = f.env.ledger().sequence() + 5;
    let invoke = f.set_authorized_invoke(&f.holder, true);
    let e = entry(&f.env, &f.admin, &invoke, &s);
    f.env
        .ledger()
        .set_sequence_number(f.env.ledger().sequence() + 10);
    f.env.set_auths(&[e]);
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_err());
    f.env.set_auths(&[]);
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn previous_administrators_authority_is_stale_after_handover() {
    let f = Fixture::new();
    f.env.mock_auths(&[MockAuth {
        address: &f.issuer_admin,
        invoke: &f.set_authorized_invoke(&f.holder, true),
    }]);
    assert!(f.sac_client().try_set_authorized(&f.holder, &true).is_err());
    f.env.set_auths(&[]);
    assert!(!f.is_authorized(&f.holder));
}

#[contract]
pub struct Relay;

#[contractimpl]
impl Relay {
    /// Requires the admin's authorization for itself, then calls the SAC: the admin's
    /// credential would have to cover a two-context tree.
    pub fn admin_then_set(env: Env, admin: Address, sac: Address, id: Address) {
        admin.require_auth();
        StellarAssetClient::new(&env, &sac).set_authorized(&id, &true);
    }

    /// Calls the SAC without requiring anything itself.
    pub fn forward(env: Env, sac: Address, id: Address) {
        StellarAssetClient::new(&env, &sac).set_authorized(&id, &true);
    }
}

#[test]
fn nested_authorization_tree_is_rejected() {
    let f = Fixture::new();
    let relay = f.env.register(Relay, ());
    let sub = [MockAuthInvoke {
        contract: &f.sac,
        fn_name: "set_authorized",
        args: (&f.holder, true).into_val(&f.env),
        sub_invokes: &[],
    }];
    let root = MockAuthInvoke {
        contract: &relay,
        fn_name: "admin_then_set",
        args: (&f.admin, &f.sac, &f.holder).into_val(&f.env),
        sub_invokes: &sub,
    };
    f.env
        .set_auths(&[entry(&f.env, &f.admin, &root, &f.signing(&f.operator, 1))]);
    assert!(RelayClient::new(&f.env, &relay)
        .try_admin_then_set(&f.admin, &f.sac, &f.holder)
        .is_err());
    f.env.set_auths(&[]);
    assert!(!f.is_authorized(&f.holder));
}

#[test]
fn relayed_submission_carries_exactly_the_signed_operation_and_nothing_else() {
    // Authority comes from the signature, not from who submits: a relay may deliver the
    // signed set_authorized call, but cannot change its arguments.
    let f = Fixture::new();
    let relay = f.env.register(Relay, ());
    let other = Address::generate(&f.env);
    let invoke = f.set_authorized_invoke(&f.holder, true);
    f.env
        .set_auths(&[entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 1))]);
    assert!(RelayClient::new(&f.env, &relay)
        .try_forward(&f.sac, &other)
        .is_err());
    assert!(!f.is_authorized(&other));
    f.env
        .set_auths(&[entry(&f.env, &f.admin, &invoke, &f.signing(&f.operator, 2))]);
    assert!(RelayClient::new(&f.env, &relay)
        .try_forward(&f.sac, &f.holder)
        .is_ok());
    f.env.set_auths(&[]);
    assert!(f.is_authorized(&f.holder));
}

/// Calls `__check_auth` directly with a signature that is valid for `payload`, so each
/// rejection below is caused by the context policy alone.
fn check(
    f: &Fixture,
    payload: &[u8; 32],
    signature: &Bytes,
    contexts: Vec<Context>,
) -> Result<(), Error> {
    f.env
        .try_invoke_contract_check_auth::<Error>(
            &f.admin,
            &BytesN::from_array(&f.env, payload),
            signature.into_val(&f.env),
            &contexts,
        )
        .map_err(|e| e.unwrap())
}

#[test]
fn context_policy_rejects_everything_but_one_direct_protected_call() {
    let f = Fixture::new();
    let payload = [42u8; 32];
    let good = sign(&f.env, &f.operator, &payload, AUTH_CONTEXT);
    let call = |contract: &Address, name: &str, args: soroban_sdk::Vec<Val>| {
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(&f.env, name),
            args,
        })
    };
    let protected = call(&f.sac, "set_authorized", (&f.holder, true).into_val(&f.env));

    assert_eq!(
        check(&f, &payload, &good, vec![&f.env, protected.clone()]),
        Ok(())
    );
    assert_eq!(
        check(&f, &payload, &good, vec![&f.env]),
        Err(Error::UnsupportedAuthContext)
    );
    assert_eq!(
        check(
            &f,
            &payload,
            &good,
            vec![&f.env, protected.clone(), protected.clone()]
        ),
        Err(Error::UnsupportedAuthContext)
    );
    for name in ["mint", "clawback", "set_admin", "transfer"] {
        assert_eq!(
            check(
                &f,
                &payload,
                &good,
                vec![
                    &f.env,
                    call(&f.sac, name, (&f.holder, true).into_val(&f.env))
                ]
            ),
            Err(Error::UnsupportedAuthContext),
            "{name}"
        );
    }
    assert_eq!(
        check(
            &f,
            &payload,
            &good,
            vec![
                &f.env,
                call(
                    &Address::generate(&f.env),
                    "set_authorized",
                    (&f.holder, true).into_val(&f.env)
                )
            ]
        ),
        Err(Error::UnsupportedAuthContext)
    );
    assert_eq!(
        check(
            &f,
            &payload,
            &good,
            vec![
                &f.env,
                call(
                    &f.sac,
                    "set_authorized",
                    (&f.holder, true, 1u32).into_val(&f.env)
                )
            ]
        ),
        Err(Error::UnsupportedAuthContext)
    );
    assert_eq!(
        check(
            &f,
            &payload,
            &good,
            vec![
                &f.env,
                call(
                    &f.admin,
                    "set_authorized",
                    (&f.holder, true).into_val(&f.env)
                )
            ]
        ),
        Err(Error::UnsupportedAuthContext),
        "self-delegation to this contract's own address"
    );
    let create = Context::CreateContractHostFn(CreateContractHostFnContext {
        executable: ContractExecutable::Wasm(BytesN::from_array(&f.env, &[1u8; 32])),
        salt: BytesN::from_array(&f.env, &[2u8; 32]),
    });
    assert_eq!(
        check(&f, &payload, &good, vec![&f.env, create]),
        Err(Error::UnsupportedAuthContext)
    );
}

#[test]
fn signature_checks_apply_after_the_context_check() {
    let f = Fixture::new();
    let payload = [42u8; 32];
    let protected = Context::Contract(ContractContext {
        contract: f.sac.clone(),
        fn_name: Symbol::new(&f.env, "set_authorized"),
        args: (&f.holder, true).into_val(&f.env),
    });
    let ctx = vec![&f.env, protected];
    let wrong_payload = sign(&f.env, &f.operator, &[43u8; 32], AUTH_CONTEXT);
    assert_eq!(
        check(&f, &payload, &wrong_payload, ctx.clone()),
        Err(Error::InvalidSignature)
    );
    let short = Bytes::from_slice(&f.env, &[0u8; 64]);
    assert_eq!(
        check(&f, &payload, &short, ctx.clone()),
        Err(Error::BadSignatureLength)
    );
    let wrong_key = sign(&f.env, &key(12), &payload, AUTH_CONTEXT);
    assert_eq!(
        check(&f, &payload, &wrong_key, ctx),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn constructor_rejects_a_malformed_operator_key() {
    let env = Env::default();
    let sac = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(QAssetSacAdmin, (&sac, Bytes::from_slice(&env, &[0u8; 32])))
    }));
    assert!(result.is_err());
}

#[test]
fn instance_lease_is_bounded_and_renewed_after_valid_authorization() {
    use soroban_sdk::testutils::storage::Instance;
    let f = Fixture::new();
    let target = f.env.storage().max_ttl().min(TTL_TARGET);
    f.env.as_contract(&f.admin, || {
        let ttl = f.env.storage().instance().get_ttl();
        assert!(ttl >= target - 1 && ttl <= target);
    });
    f.env
        .ledger()
        .set_sequence_number(f.env.ledger().sequence() + target / 2 + 1);
    assert!(f.authorize(&f.holder, true, &f.signing(&f.operator, 60)));
    f.env.as_contract(&f.admin, || {
        let ttl = f.env.storage().instance().get_ttl();
        assert!(ttl >= target - 1 && ttl <= target);
    });
}
