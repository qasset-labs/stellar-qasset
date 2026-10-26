#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Env, IntoVal};

fn setup(env: &Env) -> (QAssetRegistryClient<'_>, Address, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let asset = Address::generate(env);
    let contract_id = env.register(QAssetRegistry, (admin.clone(),));
    let client = QAssetRegistryClient::new(env, &contract_id);
    client.register_asset(&asset, &admin);
    (client, admin, asset)
}

fn classical(env: &Env) -> Signer {
    classical_weighted(env, 1)
}

fn pq(env: &Env) -> Signer {
    pq_weighted(env, 1)
}

fn classical_weighted(env: &Env, weight: u32) -> Signer {
    Signer {
        address: Address::generate(env),
        algo: SignerAlgo::Ed25519,
        weight,
    }
}

fn pq_weighted(env: &Env, weight: u32) -> Signer {
    Signer {
        address: Address::generate(env),
        algo: SignerAlgo::MlDsa65,
        weight,
    }
}

fn set_all_roles(_env: &Env, client: &QAssetRegistryClient, asset: &Address, quorum: &Quorum) {
    for role in Role::ALL {
        client.set_role_quorum(asset, &role, quorum);
    }
}

#[test]
fn revision_checked_updates_reject_a_stale_writer_without_changing_policy_or_events() {
    let env = Env::default();
    let (client, _, asset) = setup(&env);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    let revision = client.policy_assessment(&asset).policy_revision;
    client.set_role_quorum_if_revision(&asset, &Role::Freeze, &quorum, &revision);
    assert_eq!(env.events().all().events().len(), 1);
    assert_eq!(
        client.policy_assessment(&asset).policy_revision,
        revision + 1
    );
    assert_eq!(
        client.try_set_role_quorum_if_revision(&asset, &Role::Mint, &quorum, &revision),
        Err(Ok(Error::RevisionConflict))
    );
    // The SDK exposes events from the most recent invocation, not a cumulative log.
    assert!(env.events().all().events().is_empty());
    assert_eq!(
        client.policy_assessment(&asset).policy_revision,
        revision + 1
    );
    assert!(client.get_role_quorum(&asset, &Role::Mint).is_none());
    client.set_role_quorum_if_revision(&asset, &Role::Mint, &quorum, &(revision + 1));
    assert_eq!(
        client.policy_assessment(&asset).policy_revision,
        revision + 2
    );
}

#[test]
fn revision_checked_update_requires_the_tenant_administrator() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register(QAssetRegistry, (admin.clone(),));
    let client = QAssetRegistryClient::new(&env, &id);
    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &id,
            fn_name: "register_asset",
            args: (asset.clone(), admin.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    client.register_asset(&asset, &admin);
    env.mock_auths(&[]);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    assert!(client
        .try_set_role_quorum_if_revision(&asset, &Role::Freeze, &quorum, &0)
        .is_err());
    assert_eq!(client.policy_assessment(&asset).policy_revision, 0);
}

// ============================================================
// QS0 — classical only
// ============================================================

#[test]
fn qs0_when_no_pq_signer_registered_anywhere() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let all_classical = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), classical(&env)],
        threshold: 2,
    };
    set_all_roles(&env, &client, &asset, &all_classical);

    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs0);
    // Every one of the 8 roles is reported weak, all for the same reason.
    let weak = client.list_weak_paths(&asset);
    assert_eq!(weak.len(), 8);
    for w in weak.iter() {
        assert_eq!(w.reason, WeakPathReason::ThresholdMeetableClassically);
    }
}

#[test]
fn qs0_and_all_weak_unregistered_when_nothing_registered_at_all() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs0);
    let weak = client.list_weak_paths(&asset);
    assert_eq!(weak.len(), 8);
    for w in weak.iter() {
        assert_eq!(w.reason, WeakPathReason::Unregistered);
    }
}

// ============================================================
// The core security property: a PQ signer's mere PRESENCE in a quorum does not make that
// role safe if the threshold can still be met by classical signers alone. This is exactly
// the gap a naive "does this role have a PQ signer configured?" checklist would miss, and
// the whole reason the control graph counts classical-vs-PQ against the threshold instead
// of just checking presence.
// ============================================================

#[test]
fn role_stays_weak_if_threshold_meetable_by_classical_signers_alone_even_with_a_pq_signer_present()
{
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // Register every OTHER role as fully PQ-required first, so the only weak path left after
    // this is the one deliberately introduced below — isolates the property under test instead
    // of also counting the other 7 roles' unrelated "Unregistered" weakness.
    let safe = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    for role in Role::ALL {
        if role != Role::Treasury {
            client.set_role_quorum(&asset, &role, &safe);
        }
    }

    // 2-of-3: two classical signers, one PQ signer. Threshold is 2, and there are 2 classical
    // signers — so the quorum can be met by the two classical signers alone, without the PQ
    // signer ever being needed. A naive "has a PQ signer" check would call this role safe; the
    // control graph must not.
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), classical(&env), pq(&env)],
        threshold: 2,
    };
    client.set_role_quorum(&asset, &Role::Treasury, &quorum);

    let weak = client.list_weak_paths(&asset);
    assert_eq!(weak.len(), 1);
    assert_eq!(weak.get(0).unwrap().role, Role::Treasury);
    assert_eq!(
        weak.get(0).unwrap().reason,
        WeakPathReason::ThresholdMeetableClassically
    );
}

#[test]
fn role_becomes_safe_once_threshold_cannot_be_met_by_classical_signers_alone() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // Same 3 signers as above (2 classical + 1 PQ), but threshold raised to 3 — now EVERY
    // possible way to reach the threshold must include the PQ signer.
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), classical(&env), pq(&env)],
        threshold: 3,
    };
    client.set_role_quorum(&asset, &Role::Treasury, &quorum);

    let weak = client.list_weak_paths(&asset);
    // Treasury itself is now safe, but the other 7 roles are still unregistered (weak).
    assert!(weak.iter().all(|w| w.role != Role::Treasury));
    assert_eq!(weak.len(), 7);
}

// ============================================================
// QS1 — PQ adoption started, but the highest-impact roles are still weak
// ============================================================

#[test]
fn qs1_when_pq_signer_exists_but_a_highest_impact_role_is_still_weak() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // Every role fully PQ-protected...
    let pq_required = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), pq(&env)],
        threshold: 2,
    };
    for role in Role::ALL {
        client.set_role_quorum(&asset, &role, &pq_required);
    }
    // ...except Treasury (a HIGHEST_IMPACT role), which is left classically meetable.
    let weak_treasury = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), pq(&env)],
        threshold: 1,
    };
    client.set_role_quorum(&asset, &Role::Treasury, &weak_treasury);

    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs1);
}

// ============================================================
// QS2 — highest-impact roles protected, but a lower-impact role is still weak
// ============================================================

#[test]
fn qs2_when_highest_impact_roles_protected_but_another_role_is_weak() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let pq_required = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), pq(&env)],
        threshold: 2,
    };
    for role in Role::ALL {
        client.set_role_quorum(&asset, &role, &pq_required);
    }
    // Weaken a non-highest-impact role (Mint).
    let weak_mint = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), pq(&env)],
        threshold: 1,
    };
    client.set_role_quorum(&asset, &Role::Mint, &weak_mint);

    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs2);
}

// ============================================================
// QS3 — every critical role PQ-required, but a highest-impact role is single-key
// ============================================================

#[test]
fn qs3_when_every_role_pq_required_but_highest_impact_single_key() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // Single PQ signer per role, threshold 1 — PQ-required (no classical-only path), but a
    // single key is a point of failure for the 3 highest-impact roles.
    let single_pq = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    for role in Role::ALL {
        client.set_role_quorum(&asset, &role, &single_pq);
    }

    assert_eq!(client.list_weak_paths(&asset).len(), 0);
    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs3);
}

// ============================================================
// QS4 — every critical role PQ-required, highest-impact roles are genuine multisig
// ============================================================

#[test]
fn qs4_when_every_role_pq_required_and_highest_impact_roles_are_multisig() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let single_pq = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    for role in Role::ALL {
        client.set_role_quorum(&asset, &role, &single_pq);
    }
    // Raise the 3 highest-impact roles to genuine 2-of-2 PQ multisig.
    let pq_multisig = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env), pq(&env)],
        threshold: 2,
    };
    for role in Role::HIGHEST_IMPACT {
        client.set_role_quorum(&asset, &role, &pq_multisig);
    }

    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs4);
}

// ============================================================
// require_min_qs — the cross-contract enforcement gate
// ============================================================

#[test]
fn forged_algorithm_metadata_cannot_satisfy_verified_gate() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);
    // Neither address has a PQ authentication contract; these are only administrator labels.
    let forged = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env), pq(&env)],
        threshold: 2,
    };
    set_all_roles(&env, &client, &asset, &forged);
    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs4);
    assert_eq!(
        client.try_quantum_security_level(&asset),
        Err(Ok(Error::UnverifiedPolicy))
    );
    for min in [
        QsLevel::Qs0,
        QsLevel::Qs1,
        QsLevel::Qs2,
        QsLevel::Qs3,
        QsLevel::Qs4,
    ] {
        assert_eq!(
            client.try_require_min_qs(&asset, &min),
            Err(Ok(Error::UnverifiedPolicy))
        );
    }
    assert_eq!(
        client.policy_assessment(&asset).verification,
        VerificationStatus::Unverified
    );
}

#[test]
fn unregistered_assets_cannot_satisfy_verified_gate() {
    let env = Env::default();
    let (client, _admin, _asset) = setup(&env);
    let unknown = Address::generate(&env);
    assert_eq!(
        client.try_require_min_qs(&unknown, &QsLevel::Qs0),
        Err(Ok(Error::UnverifiedPolicy))
    );
    assert_eq!(
        client.try_policy_assessment(&unknown),
        Err(Ok(Error::AssetNotRegistered))
    );
}

// ============================================================
// Input validation
// ============================================================

#[test]
fn set_role_quorum_rejects_zero_threshold() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let bad = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env)],
        threshold: 0,
    };
    let result = client.try_set_role_quorum(&asset, &Role::Mint, &bad);
    assert!(result.is_err());
}

#[test]
fn set_role_quorum_rejects_threshold_exceeding_total_signer_weight() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let bad = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env)],
        threshold: 2,
    };
    let result = client.try_set_role_quorum(&asset, &Role::Mint, &bad);
    assert!(result.is_err());
}

#[test]
fn deployment_initializes_atomically_without_a_callable_initializer() {
    let env = Env::default();
    let (client, admin, asset) = setup(&env);
    let attacker = Address::generate(&env);
    assert!(env
        .try_invoke_contract::<(), Error>(
            &client.address,
            &Symbol::new(&env, "initialize"),
            soroban_sdk::vec![&env, attacker.into_val(&env)],
        )
        .is_err());
    assert_eq!(client.asset_admin(&asset), admin);
}

#[test]
fn set_role_quorum_rejects_duplicate_signer_address() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let addr = Address::generate(&env);
    let bad = Quorum {
        signers: soroban_sdk::vec![
            &env,
            Signer {
                address: addr.clone(),
                algo: SignerAlgo::Ed25519,
                weight: 1,
            },
            Signer {
                address: addr,
                algo: SignerAlgo::MlDsa65,
                weight: 1,
            },
        ],
        threshold: 1,
    };
    let result = client.try_set_role_quorum(&asset, &Role::Mint, &bad);
    assert!(result.is_err());
}

#[test]
fn set_role_quorum_rejects_more_than_max_signers() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let mut signers = soroban_sdk::Vec::new(&env);
    for _ in 0..21 {
        signers.push_back(classical(&env));
    }
    let bad = Quorum {
        signers,
        threshold: 1,
    };
    let result = client.try_set_role_quorum(&asset, &Role::Mint, &bad);
    assert!(result.is_err());
}

#[test]
fn set_role_quorum_rejects_zero_weight_signer() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let bad = Quorum {
        signers: soroban_sdk::vec![&env, classical_weighted(&env, 0)],
        threshold: 1,
    };
    let result = client.try_set_role_quorum(&asset, &Role::Mint, &bad);
    assert!(result.is_err());
}

// ============================================================
// Observability: a quorum change emits an event an off-chain scanner can watch, instead of
// requiring it to poll every asset's every role to notice a downgrade.
// ============================================================

#[test]
fn set_role_quorum_emits_an_event_on_every_change() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    client.set_role_quorum(&asset, &Role::Treasury, &quorum);

    let events = env.events().all();
    assert_eq!(events.events().len(), 1);
}

// ============================================================
// Weighted signers — Stellar's real weight/threshold multisig model, not unweighted m-of-n
// ============================================================

#[test]
fn role_is_weak_when_a_single_high_weight_classical_signer_alone_meets_the_threshold() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // One classical signer of weight 3 and one PQ signer of weight 1, threshold 3: the
    // classical signer alone already reaches the threshold, so the PQ signer is decorative.
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, classical_weighted(&env, 3), pq_weighted(&env, 1)],
        threshold: 3,
    };
    client.set_role_quorum(&asset, &Role::Treasury, &quorum);

    let weak = client.list_weak_paths(&asset);
    let treasury = weak.iter().find(|w| w.role == Role::Treasury).unwrap();
    assert_eq!(
        treasury.reason,
        WeakPathReason::ThresholdMeetableClassically
    );
    assert_eq!(treasury.classical_weight, 3);
    assert_eq!(treasury.post_quantum_weight, 1);
}

#[test]
fn role_becomes_safe_once_the_pq_signers_weight_is_required_to_reach_the_threshold() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // Same signers as above, but the threshold is raised to 4 — the classical signer's weight
    // of 3 alone is no longer enough; the PQ signer's weight is now load-bearing.
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, classical_weighted(&env, 3), pq_weighted(&env, 1)],
        threshold: 4,
    };
    client.set_role_quorum(&asset, &Role::Treasury, &quorum);

    let weak = client.list_weak_paths(&asset);
    assert!(weak.iter().all(|w| w.role != Role::Treasury));
}

#[test]
fn qs4_is_denied_when_a_single_signers_weight_alone_meets_the_threshold_despite_threshold_being_2()
{
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    // Every role fully PQ-required with a plain single-signer quorum (would be QS3 on its own).
    let single_pq = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    for role in Role::ALL {
        client.set_role_quorum(&asset, &role, &single_pq);
    }

    // A naive "threshold >= 2" multisig check would call this QS4: threshold is 2. But one of
    // the two signers has weight 3, which alone already reaches threshold 2 — this is still a
    // single point of failure, not genuine multisig, and must NOT be reported as QS4.
    let fake_multisig = Quorum {
        signers: soroban_sdk::vec![&env, pq_weighted(&env, 3), pq_weighted(&env, 1)],
        threshold: 2,
    };
    for role in Role::HIGHEST_IMPACT {
        client.set_role_quorum(&asset, &role, &fake_multisig);
    }

    assert_eq!(client.list_weak_paths(&asset).len(), 0);
    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs3);
}

#[test]
fn qs4_when_highest_impact_roles_require_every_signers_weight_together() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);

    let single_pq = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    for role in Role::ALL {
        client.set_role_quorum(&asset, &role, &single_pq);
    }

    // Two weight-1 PQ signers, threshold 2 — neither signer's weight alone reaches the
    // threshold, so both are genuinely required. This is real multisig.
    let genuine_multisig = Quorum {
        signers: soroban_sdk::vec![&env, pq_weighted(&env, 1), pq_weighted(&env, 1)],
        threshold: 2,
    };
    for role in Role::HIGHEST_IMPACT {
        client.set_role_quorum(&asset, &role, &genuine_multisig);
    }

    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs4);
}

// Authorization tests deliberately use exact invocation mocks rather than mock_all_auths.
fn strict_setup(env: &Env) -> (QAssetRegistryClient<'_>, Address, Address, Address) {
    let registrar = Address::generate(env);
    let tenant = Address::generate(env);
    let asset = Address::generate(env);
    let id = env.register(QAssetRegistry, (registrar.clone(),));
    let client = QAssetRegistryClient::new(env, &id);
    let invoke = MockAuthInvoke {
        contract: &id,
        fn_name: "register_asset",
        args: (asset.clone(), tenant.clone()).into_val(env),
        sub_invokes: &[],
    };
    client
        .mock_auths(&[
            MockAuth {
                address: &registrar,
                invoke: &invoke,
            },
            MockAuth {
                address: &tenant,
                invoke: &invoke,
            },
        ])
        .register_asset(&asset, &tenant);
    env.mock_auths(&[]);
    (client, registrar, tenant, asset)
}

#[test]
fn tenant_updates_require_the_exact_asset_admin_authorization() {
    let env = Env::default();
    let (client, registrar, tenant, asset) = strict_setup(&env);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    assert!(client
        .try_set_role_quorum(&asset, &Role::Mint, &quorum)
        .is_err());
    let invoke = MockAuthInvoke {
        contract: &client.address,
        fn_name: "set_role_quorum",
        args: (asset.clone(), Role::Mint, quorum.clone()).into_val(&env),
        sub_invokes: &[],
    };
    // The registry's root registrar is expressly unable to bypass the tenant's authority.
    assert!(client
        .mock_auths(&[MockAuth {
            address: &registrar,
            invoke: &invoke
        }])
        .try_set_role_quorum(&asset, &Role::Mint, &quorum)
        .is_err());
    assert!(client.get_role_quorum(&asset, &Role::Mint).is_none());
    client
        .mock_auths(&[MockAuth {
            address: &tenant,
            invoke: &invoke,
        }])
        .set_role_quorum(&asset, &Role::Mint, &quorum);
    assert_eq!(client.policy_assessment(&asset).policy_revision, 1);
}

#[test]
fn registration_requires_registrar_and_incoming_admin_consent() {
    let env = Env::default();
    let registrar = Address::generate(&env);
    let tenant = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register(QAssetRegistry, (registrar.clone(),));
    let client = QAssetRegistryClient::new(&env, &id);
    let invoke = MockAuthInvoke {
        contract: &id,
        fn_name: "register_asset",
        args: (asset.clone(), tenant.clone()).into_val(&env),
        sub_invokes: &[],
    };
    assert!(client
        .mock_auths(&[MockAuth {
            address: &registrar,
            invoke: &invoke
        }])
        .try_register_asset(&asset, &tenant)
        .is_err());
    assert!(client
        .mock_auths(&[MockAuth {
            address: &tenant,
            invoke: &invoke
        }])
        .try_register_asset(&asset, &tenant)
        .is_err());
    assert_eq!(
        client.try_asset_admin(&asset),
        Err(Ok(Error::AssetNotRegistered))
    );
}

#[test]
fn registrar_cannot_overwrite_a_registered_tenant() {
    let env = Env::default();
    let (client, registrar, tenant, asset) = strict_setup(&env);
    let invoke = MockAuthInvoke {
        contract: &client.address,
        fn_name: "register_asset",
        args: (asset.clone(), registrar.clone()).into_val(&env),
        sub_invokes: &[],
    };
    assert_eq!(
        client
            .mock_auths(&[MockAuth {
                address: &registrar,
                invoke: &invoke
            }])
            .try_register_asset(&asset, &registrar),
        Err(Ok(Error::AssetAlreadyRegistered))
    );
    assert_eq!(client.asset_admin(&asset), tenant);
}

#[test]
fn tenant_transfer_requires_both_parties_and_revokes_the_old_admin() {
    let env = Env::default();
    let (client, _registrar, old_admin, asset) = strict_setup(&env);
    let new_admin = Address::generate(&env);
    let invoke = MockAuthInvoke {
        contract: &client.address,
        fn_name: "transfer_asset_admin",
        args: (asset.clone(), new_admin.clone()).into_val(&env),
        sub_invokes: &[],
    };
    assert!(client
        .mock_auths(&[MockAuth {
            address: &old_admin,
            invoke: &invoke
        }])
        .try_transfer_asset_admin(&asset, &new_admin)
        .is_err());
    assert!(client
        .mock_auths(&[MockAuth {
            address: &new_admin,
            invoke: &invoke
        }])
        .try_transfer_asset_admin(&asset, &new_admin)
        .is_err());
    assert_eq!(client.asset_admin(&asset), old_admin);
    client
        .mock_auths(&[
            MockAuth {
                address: &old_admin,
                invoke: &invoke,
            },
            MockAuth {
                address: &new_admin,
                invoke: &invoke,
            },
        ])
        .transfer_asset_admin(&asset, &new_admin);
    assert_eq!(client.policy_assessment(&asset).policy_revision, 1);
    assert_eq!(client.asset_admin(&asset), new_admin);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    let set = MockAuthInvoke {
        contract: &client.address,
        fn_name: "set_role_quorum",
        args: (asset.clone(), Role::Mint, quorum.clone()).into_val(&env),
        sub_invokes: &[],
    };
    assert!(client
        .mock_auths(&[MockAuth {
            address: &old_admin,
            invoke: &set
        }])
        .try_set_role_quorum(&asset, &Role::Mint, &quorum)
        .is_err());
    client
        .mock_auths(&[MockAuth {
            address: &new_admin,
            invoke: &set,
        }])
        .set_role_quorum(&asset, &Role::Mint, &quorum);
    assert_eq!(client.policy_assessment(&asset).policy_revision, 2);
}

#[test]
fn weight_overflow_inputs_are_rejected_before_they_can_wrap() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);
    let overflowing = Quorum {
        signers: soroban_sdk::vec![&env, pq_weighted(&env, u32::MAX), classical(&env)],
        threshold: 1,
    };
    assert_eq!(
        client.try_set_role_quorum(&asset, &Role::Mint, &overflowing),
        Err(Ok(Error::SignerWeightTooHigh))
    );
    assert!(client.get_role_quorum(&asset, &Role::Mint).is_none());
    let bounded = Quorum {
        signers: soroban_sdk::vec![&env, classical_weighted(&env, 255), pq_weighted(&env, 255)],
        threshold: 510,
    };
    client.set_role_quorum(&asset, &Role::Mint, &bounded);
    assert!(!client
        .list_weak_paths(&asset)
        .iter()
        .any(|w| w.role == Role::Mint));
}

#[test]
fn snapshot_records_observation_ledger_and_mutation_revision() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);
    env.ledger().set_sequence_number(123);
    let first = client.policy_assessment(&asset);
    assert_eq!(first.ledger_sequence, 123);
    assert_eq!(first.policy_revision, 0);
    assert_eq!(first.verification, VerificationStatus::Unverified);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env)],
        threshold: 1,
    };
    client.set_role_quorum(&asset, &Role::Mint, &quorum);
    assert_eq!(client.policy_assessment(&asset).policy_revision, 1);
}

#[test]
fn permissionless_keeper_extends_policy_and_quorum_lifetime() {
    use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    client.set_role_quorum(&asset, &Role::Mint, &quorum);
    let target = env.storage().max_ttl().min(TTL_TARGET);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + target * 3 / 4);
    env.mock_auths(&[]);
    client.keep_alive(&asset);
    env.as_contract(&client.address, || {
        assert!(env.storage().instance().get_ttl() >= target - 1);
        assert!(env.storage().persistent().get_ttl(&asset_key(&asset)) >= target - 1);
        assert!(
            env.storage()
                .persistent()
                .get_ttl(&role_key(&env, &asset, Role::Mint))
                >= target - 1
        );
    });
    assert_eq!(client.policy_assessment(&asset).policy_revision, 1);
}

#[contract]
struct ProtectedOperation;

#[contractimpl]
impl ProtectedOperation {
    pub fn execute(env: Env, registry: Address, asset: Address) {
        QAssetRegistryClient::new(&env, &registry).require_min_qs(&asset, &QsLevel::Qs4);
        env.storage()
            .instance()
            .set(&symbol_short!("EXECUTED"), &true);
    }

    pub fn executed(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&symbol_short!("EXECUTED"))
            .unwrap_or(false)
    }
}

#[test]
fn cross_contract_gate_blocks_state_change_despite_declared_qs4() {
    let env = Env::default();
    let (registry, _admin, asset) = setup(&env);
    let fake_pq_multisig = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env), pq(&env)],
        threshold: 2,
    };
    set_all_roles(&env, &registry, &asset, &fake_pq_multisig);
    assert_eq!(registry.declared_security_level(&asset), QsLevel::Qs4);
    let protected_id = env.register(ProtectedOperation, ());
    let protected = ProtectedOperationClient::new(&env, &protected_id);
    assert!(protected.try_execute(&registry.address, &asset).is_err());
    assert!(!protected.executed());
}

#[test]
fn qs4_requires_two_pq_addresses_even_after_all_classical_signers_are_compromised() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);
    let hybrid = Quorum {
        signers: soroban_sdk::vec![&env, classical(&env), pq(&env)],
        threshold: 2,
    };
    set_all_roles(&env, &client, &asset, &hybrid);
    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs3);
    // Two distinct PQ addresses must still be necessary after adding all classical weight.
    let two_pq_required = Quorum {
        signers: soroban_sdk::vec![
            &env,
            classical_weighted(&env, 2),
            pq_weighted(&env, 3),
            pq(&env)
        ],
        threshold: 6,
    };
    for role in Role::HIGHEST_IMPACT {
        client.set_role_quorum(&asset, &role, &two_pq_required);
    }
    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs4);
    // Classical(2) plus one PQ(3) reaches five: the second PQ becomes unnecessary at T=5.
    let one_pq_enough = Quorum {
        threshold: 5,
        ..two_pq_required
    };
    client.set_role_quorum(&asset, &Role::Governance, &one_pq_enough);
    assert_eq!(client.declared_security_level(&asset), QsLevel::Qs3);
}

#[test]
fn reenrollment_rejects_orphaned_role_declarations_without_resetting_them() {
    let env = Env::default();
    let (client, _registrar, asset) = setup(&env);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env), pq(&env)],
        threshold: 2,
    };
    client.set_role_quorum(&asset, &Role::Governance, &quorum);
    // Deliberately construct inconsistent state. This is not a claim that normal archival
    // deletes persistent entries: it exercises defensive handling of orphaned declarations.
    env.as_contract(&client.address, || {
        env.storage().persistent().remove(&asset_key(&asset));
    });
    let replacement = Address::generate(&env);
    assert_eq!(
        client.try_register_asset(&asset, &replacement),
        Err(Ok(Error::OrphanedPolicy))
    );
    assert_eq!(
        client.try_asset_admin(&asset),
        Err(Ok(Error::AssetNotRegistered))
    );
    let retained = client.get_role_quorum(&asset, &Role::Governance).unwrap();
    assert_eq!(retained.threshold, quorum.threshold);
    assert_eq!(retained.signers, quorum.signers);
}

// Independent coalition oracle: enumerate every subset that can authorize, rather than
// reproducing the contract's classical-weight/largest-PQ-weight shortcut.
fn minimum_pq_signers_by_enumeration(weights: &[u32], pq_mask: u32, threshold: u32) -> u32 {
    let mut minimum = u32::MAX;
    for coalition in 0..(1u32 << weights.len()) {
        let mut weight = 0;
        let mut pq_count = 0;
        for (index, signer_weight) in weights.iter().enumerate() {
            if coalition & (1 << index) != 0 {
                weight += signer_weight;
                if pq_mask & (1 << index) != 0 {
                    pq_count += 1;
                }
            }
        }
        if weight >= threshold {
            minimum = minimum.min(pq_count);
        }
    }
    minimum
}

#[test]
fn exhaustive_small_quorums_match_independent_authorizing_coalition_oracle() {
    let mut checked_policies = 0;
    for size in 1..=3usize {
        for pq_mask in 0..(1u32 << size) {
            for weight_mask in 0..(1u32 << size) {
                let env = Env::default();
                let (client, _admin, asset) = setup(&env);
                let mut weights = [0u32; 3];
                let mut signers = Vec::new(&env);
                let mut total_weight = 0;
                for (index, weight) in weights.iter_mut().enumerate().take(size) {
                    *weight = 1 + ((weight_mask >> index) & 1);
                    total_weight += *weight;
                    let algo = if pq_mask & (1 << index) != 0 {
                        match index {
                            0 => SignerAlgo::MlDsa44,
                            1 => SignerAlgo::MlDsa65,
                            _ => SignerAlgo::MlDsa87,
                        }
                    } else if index % 2 == 0 {
                        SignerAlgo::Ed25519
                    } else {
                        SignerAlgo::Secp256r1
                    };
                    signers.push_back(Signer {
                        address: Address::generate(&env),
                        algo,
                        weight: *weight,
                    });
                }
                for threshold in 1..=total_weight {
                    let quorum = Quorum {
                        signers: signers.clone(),
                        threshold,
                    };
                    set_all_roles(&env, &client, &asset, &quorum);
                    let minimum =
                        minimum_pq_signers_by_enumeration(&weights[..size], pq_mask, threshold);
                    // Every role has the same quorum here; the existing transition tests cover
                    // QS2, where roles differ. These expectations come from actual coalitions.
                    let expected = if pq_mask == 0 {
                        QsLevel::Qs0
                    } else if minimum == 0 {
                        QsLevel::Qs1
                    } else if minimum == 1 {
                        QsLevel::Qs3
                    } else {
                        QsLevel::Qs4
                    };
                    assert_eq!(
                        client.declared_security_level(&asset),
                        expected,
                        "size={size}, pq_mask={pq_mask}, weight_mask={weight_mask}, threshold={threshold}"
                    );
                    let weak_paths = client.list_weak_paths(&asset);
                    assert_eq!(weak_paths.len(), if minimum == 0 { 8 } else { 0 });
                    for weak in weak_paths.iter() {
                        assert_eq!(weak.reason, WeakPathReason::ThresholdMeetableClassically);
                        assert_eq!(weak.threshold, threshold);
                    }
                    checked_policies += 1;
                }
            }
        }
    }
    assert_eq!(checked_policies, 342);
}

#[test]
fn rejected_quorum_replacements_preserve_existing_policy_and_revision() {
    let env = Env::default();
    let (client, _admin, asset) = setup(&env);
    let good = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env), pq(&env)],
        threshold: 2,
    };
    client.set_role_quorum(&asset, &Role::Mint, &good);
    let original_revision = client.policy_assessment(&asset).policy_revision;
    let repeated_address = good.signers.get(0).unwrap().address;
    let mut too_many = Vec::new(&env);
    for _ in 0..21 {
        too_many.push_back(classical(&env));
    }
    let invalid_updates = [
        (
            Quorum {
                threshold: 0,
                ..good.clone()
            },
            Error::ZeroThreshold,
        ),
        (
            Quorum {
                signers: soroban_sdk::vec![&env, classical_weighted(&env, 0), pq(&env)],
                threshold: 1,
            },
            Error::ZeroSignerWeight,
        ),
        (
            Quorum {
                signers: soroban_sdk::vec![&env, pq_weighted(&env, 256)],
                threshold: 1,
            },
            Error::SignerWeightTooHigh,
        ),
        (
            Quorum {
                signers: soroban_sdk::vec![
                    &env,
                    Signer {
                        address: repeated_address.clone(),
                        algo: SignerAlgo::Ed25519,
                        weight: 1,
                    },
                    Signer {
                        address: repeated_address,
                        algo: SignerAlgo::MlDsa65,
                        weight: 1,
                    }
                ],
                threshold: 1,
            },
            Error::DuplicateSigner,
        ),
        (
            Quorum {
                threshold: 3,
                ..good.clone()
            },
            Error::ThresholdUnreachable,
        ),
        (
            Quorum {
                signers: Vec::new(&env),
                threshold: 1,
            },
            Error::ThresholdUnreachable,
        ),
        (
            Quorum {
                signers: too_many,
                threshold: 1,
            },
            Error::TooManySigners,
        ),
    ];
    for (bad, expected_error) in invalid_updates {
        assert_eq!(
            client.try_set_role_quorum(&asset, &Role::Mint, &bad),
            Err(Ok(expected_error))
        );
        let retained = client.get_role_quorum(&asset, &Role::Mint).unwrap();
        assert_eq!(retained.threshold, good.threshold);
        assert_eq!(retained.signers, good.signers);
        assert_eq!(
            client.policy_assessment(&asset).policy_revision,
            original_revision
        );
    }
}

#[test]
fn one_tenant_cannot_modify_another_tenants_policy() {
    let env = Env::default();
    let (client, registrar, first_admin, first_asset) = strict_setup(&env);
    let second_admin = Address::generate(&env);
    let second_asset = Address::generate(&env);
    let registration = MockAuthInvoke {
        contract: &client.address,
        fn_name: "register_asset",
        args: (second_asset.clone(), second_admin.clone()).into_val(&env),
        sub_invokes: &[],
    };
    client
        .mock_auths(&[
            MockAuth {
                address: &registrar,
                invoke: &registration,
            },
            MockAuth {
                address: &second_admin,
                invoke: &registration,
            },
        ])
        .register_asset(&second_asset, &second_admin);
    let quorum = Quorum {
        signers: soroban_sdk::vec![&env, pq(&env)],
        threshold: 1,
    };
    let update = MockAuthInvoke {
        contract: &client.address,
        fn_name: "set_role_quorum",
        args: (second_asset.clone(), Role::Mint, quorum.clone()).into_val(&env),
        sub_invokes: &[],
    };
    assert!(client
        .mock_auths(&[MockAuth {
            address: &first_admin,
            invoke: &update,
        }])
        .try_set_role_quorum(&second_asset, &Role::Mint, &quorum)
        .is_err());
    assert_eq!(client.policy_assessment(&second_asset).policy_revision, 0);
    assert!(client.get_role_quorum(&second_asset, &Role::Mint).is_none());
    client
        .mock_auths(&[MockAuth {
            address: &second_admin,
            invoke: &update,
        }])
        .set_role_quorum(&second_asset, &Role::Mint, &quorum);
    assert_eq!(client.policy_assessment(&second_asset).policy_revision, 1);
    assert_eq!(client.policy_assessment(&first_asset).policy_revision, 0);
    assert!(client.get_role_quorum(&first_asset, &Role::Mint).is_none());
}
