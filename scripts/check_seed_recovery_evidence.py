#!/usr/bin/env python3
"""Reproducible LOCAL evidence for original-seed recovery, PUBLIC fixtures only.

No RPC, user seed input, ZK proof, contract authorization, or quantum attack.
The scalar is derived from a published fixture to model an already exposed scalar.
"""

from dataclasses import replace
import datetime as dt
import hashlib
import json
from pathlib import Path
import platform
import sys

import nacl
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from nacl.signing import VerifyKey
from stellar_sdk import Account, Address, StrKey, TransactionBuilder

import check_recovery_relation as relation
from recovery_statement import CurrentPolicy, RecoveryStatement, LEAF, ROOT, check_policy_preconditions

REPO = Path(__file__).resolve().parents[1]
PASSPHRASE = "Test SDF Network ; September 2015"
ORDER = relation.SUBGROUP_ORDER


def recover_full_clamped_scalar(reduced: int) -> int:
    """Invert the clamping domain's injective map modulo the subgroup order.

    This is ordinary arithmetic given a scalar, NOT a discrete-log algorithm.
    a = 2^254 + 8*r, 0 <= r < 2^251; since this range is smaller than l, the
    modular equation has at most one valid r. Shor's output also reveals full a.
    """
    if type(reduced) is not int or not 0 <= reduced < ORDER:
        raise ValueError("Noncanonical reduced scalar")
    offset = ((reduced - (1 << 254)) * pow(8, -1, ORDER)) % ORDER
    if offset >= 1 << 251:
        raise ValueError("Scalar has no RFC8032 clamped representative")
    return (1 << 254) + 8 * offset


def scalar_only_signature(reduced_scalar: bytes, public_key: bytes, message: bytes) -> bytes:
    """PUBLIC-fixture attack demonstration: Ed25519 signing without the seed.

    The attacker chooses a nonce. RFC8032's original secret nonce prefix is not
    needed to forge an ordinary signature. Never use this as a wallet signer.
    """
    if len(reduced_scalar) != 32 or len(public_key) != 32:
        raise ValueError("Invalid public fixture scalar/key length")
    scalar = int.from_bytes(reduced_scalar, "little")
    if not 0 < scalar < ORDER:
        raise ValueError("Noncanonical or zero fixture scalar")
    if crypto_scalarmult_ed25519_base_noclamp(reduced_scalar) != public_key:
        raise ValueError("Scalar does not match public key")
    nonce = int.from_bytes(hashlib.sha512(b"qasset-public-scalar-attack-v1" + reduced_scalar + message).digest(), "little") % ORDER
    if nonce == 0:
        raise ValueError("Degenerate fixture nonce")
    r_point = crypto_scalarmult_ed25519_base_noclamp(nonce.to_bytes(32, "little"))
    challenge = int.from_bytes(hashlib.sha512(r_point + public_key + message).digest(), "little") % ORDER
    response = (nonce + challenge * scalar) % ORDER
    return r_point + response.to_bytes(32, "little")


def public_fixture_statement(public_key: bytes, account_index: int | None = None) -> RecoveryStatement:
    """Backend/parameter IDs below are explicit DRAFT placeholders, never approved."""
    return RecoveryStatement(
        network_id=hashlib.sha256(PASSPHRASE.encode()).digest(),
        parent_contract=Address.from_raw_contract(bytes([0x51]) * 32).address,
        protected_public_key=public_key,
        relation=LEAF if account_index is None else ROOT,
        account_index=account_index,
        policy_epoch=7,
        policy_hash=hashlib.sha256(b"public-fixture-model-policy-v1").digest(),
        replacement_algorithm="ML-DSA-65",
        replacement_public_key=bytes([0x42]) * 1952,
        valid_until_ledger=1200,
        verifier_id=hashlib.sha256(b"DRAFT-unapproved-backend").digest(),
        parameters_id=hashlib.sha256(b"DRAFT-no-security-parameters-selected").digest(),
    )


def public_fixture_policy(statement: RecoveryStatement) -> CurrentPolicy:
    return CurrentPolicy(statement.network_id, statement.parent_contract, statement.protected_public_key,
                         statement.relation, statement.account_index, statement.policy_epoch,
                         statement.policy_hash, statement.verifier_id, statement.parameters_id, True, True)


def relation_matches(statement: RecoveryStatement, witness: bytes) -> bool:
    """Ordinary local witness check. Calling this does NOT create or verify ZK."""
    if type(witness) is not bytes:
        return False
    if statement.relation == LEAF and len(witness) == 32:
        leaf = witness
    elif statement.relation == ROOT and len(witness) == 64:
        leaf = relation.slip10_ed25519(witness, (44, 148, statement.account_index))
    else:
        return False
    return relation.ed25519_public_key(leaf) == statement.protected_public_key


def run() -> dict:
    fixtures = json.loads((REPO / "docs/recovery-relation-vectors.json").read_text())
    if fixtures.get("public_test_vectors_only") is not True or nacl.__version__ != "1.6.2":
        raise ValueError("Use pinned dependencies and published test fixtures only")
    if len(fixtures["vectors"]) != 5 or any([a["index"] for a in v["accounts"]] != [0, 1, 9] for v in fixtures["vectors"]):
        raise ValueError("Expected five official fixture groups at indices 0, 1 and 9")
    cases = []
    for vector in fixtures["vectors"]:
        root = relation.mnemonic_to_seed(vector["mnemonic"], vector["passphrase"])
        for account in vector["accounts"]:
            leaf = relation.slip10_ed25519(root, (44, 148, account["index"]))
            public = relation.decode_public_strkey(account["address"])
            full = int.from_bytes(relation.expanded_clamped_scalar(leaf), "little")
            reduced = (full % ORDER).to_bytes(32, "little")
            statement = public_fixture_statement(public)
            root_statement = public_fixture_statement(public, account["index"])
            tx = (TransactionBuilder(Account(account["address"], 0), PASSPHRASE, base_fee=100)
                  .append_bump_sequence_op(2).add_time_bounds(0, 1900000000).build())
            signature = scalar_only_signature(reduced, public, tx.hash())
            VerifyKey(public).verify(tx.hash(), signature)
            # An S... secret encodes the exact leaf witness, not just its scalar.
            public_fixture_secret = StrKey.encode_ed25519_secret_seed(leaf)
            decoded_seed = StrKey.decode_ed25519_secret_seed(public_fixture_secret)
            checks = {
                "official_public_key_matches": relation.ed25519_public_key(leaf) == public,
                "root_relation_matches": relation_matches(root_statement, root),
                "leaf_relation_matches": relation_matches(statement, leaf),
                "full_clamped_scalar_is_recoverable_from_reduced_scalar": recover_full_clamped_scalar(full % ORDER) == full,
                "scalar_alone_forges_classic_stellar_transaction_signature": True,
                "reduced_scalar_bytes_fail_leaf_relation": not relation_matches(statement, reduced),
                "full_scalar_bytes_fail_leaf_relation": not relation_matches(statement, full.to_bytes(32, "little")),
                "wrong_leaf_fails": not relation_matches(statement, bytes([leaf[0] ^ 1]) + leaf[1:]),
                "wrong_root_fails": not relation_matches(root_statement, bytes([root[0] ^ 1]) + root[1:]),
                "wrong_account_index_fails": not relation_matches(replace(root_statement, account_index=account["index"] + 1), root),
                "stolen_S_secret_supplies_valid_leaf_witness": relation_matches(statement, decoded_seed),
                "leaf_witness_is_not_a_root_witness": not relation_matches(root_statement, leaf),
                "root_witness_is_not_a_leaf_witness": not relation_matches(statement, root),
            }
            if not all(checks.values()):
                raise AssertionError("Public-fixture evidence check failed")
            cases.append({"fixture": vector["id"], "account_index": account["index"],
                          "public_address": account["address"], "checks": checks,
                          "unsubmitted_classic_transaction_hash": tx.hash_hex(),
                          "scalar_only_signature_hex": signature.hex()})
    statement = public_fixture_statement(relation.decode_public_strkey(fixtures["vectors"][0]["accounts"][0]["address"]), 0)
    mutations = {
        "network_id": bytes([0x12]) * 32,
        "parent_contract": Address.from_raw_contract(bytes([0x52]) * 32).address,
        "protected_public_key": relation.decode_public_strkey(fixtures["vectors"][0]["accounts"][1]["address"]),
        "relation": LEAF,
        "account_index": 1,
        "policy_epoch": 8,
        "policy_hash": bytes([0x13]) * 32,
        "replacement_public_key": bytes([0x14]) * 1952,
        "valid_until_ledger": 1201,
        "verifier_id": bytes([0x15]) * 32,
        "parameters_id": bytes([0x16]) * 32,
    }
    binding_checks = {}
    for field, value in mutations.items():
        changed = replace(statement, **({"relation": LEAF, "account_index": None} if field == "relation" else {field: value}))
        binding_checks[field] = changed.digest() != statement.digest()
    policy = public_fixture_policy(statement)
    check_policy_preconditions(statement, policy, 1000)
    guard_checks = {}
    for name, changed_policy, ledger in [
        ("stale_epoch", replace(policy, epoch=8), 1000),
        ("revoked_eligibility", replace(policy, eligible=False), 1000),
        ("classical_bypass_still_active", replace(policy, classical_authority_retired=False), 1000),
        ("expired_request", policy, 1201),
        ("excessive_expiry_window", policy, 199),
    ]:
        try:
            check_policy_preconditions(statement, changed_policy, ledger)
        except ValueError:
            guard_checks[name] = True
        else:
            raise AssertionError("Model policy precondition failed open")
    if not all(binding_checks.values()):
        raise AssertionError("A statement field mutation did not change its digest")
    inputs = ["scripts/check_seed_recovery_evidence.py", "scripts/recovery_statement.py",
              "scripts/check_recovery_relation.py", "docs/recovery-relation-vectors.json"]
    return {
        "schema": "qasset-original-seed-evidence-v1", "status": "passed",
        "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "Local public-fixture relation/counterexample checks and draft statement/policy model; not a ZK proof or on-chain recovery",
        "python_version": platform.python_version(), "pynacl_version": nacl.__version__,
        "source_sha256": {p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in inputs},
        "case_count": len(cases), "relation_and_counterexample_checks": sum(len(c["checks"]) for c in cases),
        "cases": cases, "statement_binding_mutation_checks": binding_checks, "policy_model_rejections": guard_checks,
        "draft_statement": {"digest_algorithm": "SHA512", "digest_hex": statement.digest().hex(),
                            "canonical_xdr_hex": statement.to_xdr_bytes().hex(),
                            "backend_ids_are_unapproved_placeholders": True},
        "network_requests": 0, "submitted_transactions": 0,
        "limits": ["Finite examples cannot establish seed-preimage hardness or a security theorem.",
                   "Scalars were derived from public seeds, not recovered by a quantum computer.",
                   "Failed use of scalar bytes as seeds does not rule out efficient seed-inversion algorithms.",
                   "Policy guards are a local model, not implemented authorization on Stellar.",
                   "Statement serialization does not establish proof-system transcript binding.",
                   "No proof backend is approved or enabled by this script."]}


def main():
    output = REPO / "docs/seed-recovery-evidence.json"
    output.write_text(json.dumps({"schema": "qasset-original-seed-evidence-v1", "status": "in_progress"}, indent=2) + "\n")
    try:
        result = run()
    except Exception as error:
        output.write_text(json.dumps({"schema": "qasset-original-seed-evidence-v1", "status": "failed",
                                     "error_type": type(error).__name__}, indent=2) + "\n")
        print("FAIL: original-seed evidence checks; no witness values printed", file=sys.stderr)
        return 1
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: {result['case_count']} public accounts, {result['relation_and_counterexample_checks']} relation/counterexample checks, "
          f"{len(result['statement_binding_mutation_checks'])} binding mutations, {len(result['policy_model_rejections'])} policy-model rejections")
    print("No ZK proof, seed-inversion hardness proof, quantum attack, or on-chain recovery is established by these checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
