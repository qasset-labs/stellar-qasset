"""Adversarial tests for LOCAL research evidence, not a production proof verifier."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from stellar_sdk import scval, xdr

import check_recovery_relation as relation
import check_seed_recovery_evidence as evidence
from recovery_statement import LEAF, ROOT, RecoveryStatement, check_policy_preconditions


class SeedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vectors = json.loads((Path(__file__).resolve().parents[1] / "docs/recovery-relation-vectors.json").read_text())
        cls.fixture = vectors["vectors"][0]
        cls.root = relation.mnemonic_to_seed(cls.fixture["mnemonic"], cls.fixture["passphrase"])
        cls.leaf = relation.slip10_ed25519(cls.root, (44, 148, 0))
        cls.public = relation.decode_public_strkey(cls.fixture["accounts"][0]["address"])
        cls.statement = evidence.public_fixture_statement(cls.public, 0)
        cls.policy = evidence.public_fixture_policy(cls.statement)

    def test_scalar_only_signature_verifies_but_changed_message_and_key_fail(self):
        full = int.from_bytes(relation.expanded_clamped_scalar(self.leaf), "little")
        reduced = (full % relation.SUBGROUP_ORDER).to_bytes(32, "little")
        message = hashlib.sha256(b"public-fixture-unsubmitted-stellar-action").digest()
        signature = evidence.scalar_only_signature(reduced, self.public, message)
        VerifyKey(self.public).verify(message, signature)
        with self.assertRaises(BadSignatureError):
            VerifyKey(self.public).verify(hashlib.sha256(message).digest(), signature)
        other = relation.decode_public_strkey(self.fixture["accounts"][1]["address"])
        with self.assertRaises(BadSignatureError):
            VerifyKey(other).verify(message, signature)

    def test_clamp_inverse_covers_boundaries_and_rejects_invalid_residues(self):
        for offset in (0, 1, 7, (1 << 250), (1 << 251) - 2, (1 << 251) - 1):
            full = (1 << 254) + 8 * offset
            self.assertEqual(evidence.recover_full_clamped_scalar(full % relation.SUBGROUP_ORDER), full)
        for invalid in (-1, 0, relation.SUBGROUP_ORDER, True, 0.0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.recover_full_clamped_scalar(invalid)

    def test_scalar_signer_rejects_key_mismatch_and_noncanonical_scalar(self):
        wrong_public = relation.decode_public_strkey(self.fixture["accounts"][1]["address"])
        reduced = (int.from_bytes(relation.expanded_clamped_scalar(self.leaf), "little") % relation.SUBGROUP_ORDER).to_bytes(32, "little")
        for scalar, public in ((reduced, wrong_public), (bytes(32), self.public),
                               (relation.SUBGROUP_ORDER.to_bytes(32, "little"), self.public)):
            with self.assertRaises(ValueError):
                evidence.scalar_only_signature(scalar, public, b"public-fixture")

    def test_relation_cannot_substitute_root_leaf_or_scalar(self):
        root_statement = self.statement
        leaf_statement = replace(root_statement, relation=LEAF, account_index=None)
        self.assertTrue(evidence.relation_matches(root_statement, self.root))
        self.assertTrue(evidence.relation_matches(leaf_statement, self.leaf))
        for candidate in (self.leaf, self.root[:32], relation.expanded_clamped_scalar(self.leaf)):
            self.assertFalse(evidence.relation_matches(root_statement, candidate))
        for candidate in (self.root, relation.expanded_clamped_scalar(self.leaf), bytes(32)):
            self.assertFalse(evidence.relation_matches(leaf_statement, candidate))

    def test_leaf_relation_cannot_claim_a_root_path(self):
        with self.assertRaises(ValueError):
            replace(self.statement, relation=LEAF)
        with self.assertRaises(ValueError):
            replace(self.statement, account_index=None)
        leaf = replace(self.statement, relation=LEAF, account_index=None)
        self.assertNotEqual(leaf.digest(), self.statement.digest())

    def test_statement_rejects_invalid_types_ranges_and_point_encodings(self):
        invalid_changes = [
            {"account_index": True}, {"account_index": 1 << 31}, {"policy_epoch": 1 << 64},
            {"policy_epoch": False}, {"valid_until_ledger": -1}, {"valid_until_ledger": 1 << 32},
            {"network_id": bytearray(32)}, {"policy_hash": bytes(31)},
            {"protected_public_key": bytes(32)}, {"protected_public_key": b"\x01" + bytes(31)},
            {"parent_contract": self.fixture["accounts"][0]["address"]},
            {"replacement_public_key": bytes(1951)}, {"replacement_algorithm": "Ed25519"},
            {"operation": "upgrade"}, {"relation": "arbitrary-HD-path"},
        ]
        for changes in invalid_changes:
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                replace(self.statement, **changes)

    def test_xdr_encoding_has_typed_path_epoch_and_full_replacement_key(self):
        decoded = xdr.SCVal.from_xdr_bytes(self.statement.to_xdr_bytes())
        values = decoded.vec.sc_vec
        self.assertEqual(len(values), 14)
        self.assertEqual(values[5].type, xdr.SCValType.SCV_U32)
        self.assertEqual(values[6].type, xdr.SCValType.SCV_U64)
        self.assertEqual(scval.from_bytes(values[10]), self.statement.replacement_public_key)
        leaf = replace(self.statement, relation=LEAF, account_index=None)
        self.assertEqual(xdr.SCVal.from_xdr_bytes(leaf.to_xdr_bytes()).vec.sc_vec[5].type, xdr.SCValType.SCV_VOID)

    def test_every_current_policy_identity_must_match(self):
        other_key = relation.decode_public_strkey(self.fixture["accounts"][1]["address"])
        for field, value in (("network_id", bytes(32)), ("parent_contract", "other-contract"),
                             ("protected_public_key", other_key), ("relation", LEAF),
                             ("account_index", 1), ("epoch", 8), ("policy_hash", bytes(32)),
                             ("verifier_id", bytes(32)), ("parameters_id", bytes(32))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_policy_preconditions(self.statement, replace(self.policy, **{field: value}), 1000)

    def test_revoked_owner_or_classical_bypass_cannot_pass_model_preconditions(self):
        for field in ("eligible", "classical_authority_retired"):
            for false_value in (False, 0, 1, "true"):
                with self.subTest(field=field, value=false_value), self.assertRaises(ValueError):
                    check_policy_preconditions(self.statement, replace(self.policy, **{field: false_value}), 1000)

    def test_expiry_model_boundaries_and_overflow(self):
        for expiry in (1000, 2000):
            check_policy_preconditions(replace(self.statement, valid_until_ledger=expiry), self.policy, 1000)
        for expiry in (999, 2001):
            with self.assertRaises(ValueError):
                check_policy_preconditions(replace(self.statement, valid_until_ledger=expiry), self.policy, 1000)
        check_policy_preconditions(replace(self.statement, valid_until_ledger=(1 << 32) - 1), self.policy, (1 << 32) - 1)
        for ledger in (-1, True, 1 << 32):
            with self.assertRaises(ValueError):
                check_policy_preconditions(self.statement, self.policy, ledger)


if __name__ == "__main__":
    unittest.main()
