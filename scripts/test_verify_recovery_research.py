"""Reject malformed or mismatched requests before the expensive research proof."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stellar_sdk import scval, xdr

from check_seed_recovery_evidence import public_fixture_policy
from recovery_statement import LEAF
from verify_recovery_research import (
    LEAF_PUBLIC, ResearchBackend, ResearchProofRejected, ResearchRejection, RecoveryState,
    consume_research_recovery, parse_statement, replacement_possession_digest,
)

ROOT = Path(__file__).resolve().parents[1]


class StrictRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((ROOT / "docs/seed-proof-research.json").read_text())
        cls.raw = bytes.fromhex(cls.record["statement"]["canonical_xdr_hex"])
        cls.statement = parse_statement(cls.raw)
        cls.backend = ResearchBackend("sep5-root", 8, cls.statement.verifier_id,
                                      cls.statement.parameters_id, Path("/unused/test-verifier"), "00" * 32)
        cls.state = RecoveryState(public_fixture_policy(cls.statement), bytes(1952))

    def reject_without_process(self, state=None, raw=None):
        with patch("verify_recovery_research.subprocess.run", side_effect=AssertionError("Unexpected native process")):
            with self.assertRaises(ValueError):
                consume_research_recovery(state or self.state, self.raw if raw is None else raw,
                                          Path("/unused/proof"), bytes(3309), 1000, self.backend,
                                          Path("/unused/fixture-helper"))

    def test_canonical_record_is_exactly_roundtripped(self):
        self.assertEqual(self.statement.to_xdr_bytes(), self.raw)
        self.assertEqual(self.statement.digest().hex(), self.record["statement"]["digest_sha512_hex"])

    def test_trailing_bytes_truncation_and_size_bound_reject(self):
        for raw in (self.raw + b"\0", self.raw[:-1], b"", bytes(8193), bytearray(self.raw)):
            with self.subTest(kind=type(raw).__name__, size=len(raw)), self.assertRaises(ResearchRejection):
                parse_statement(raw)

    def test_field_count_and_type_confusion_reject(self):
        original = xdr.SCVal.from_xdr_bytes(self.raw).vec.sc_vec
        for fields in (original[:-1], original + [scval.to_void()],
                       [scval.to_symbol("same-value-wrong-type"), *original[1:]]):
            with self.assertRaises(ResearchRejection):
                parse_statement(scval.to_vec(fields).to_xdr_bytes())

    def test_unknown_domain_rejects(self):
        fields = xdr.SCVal.from_xdr_bytes(self.raw).vec.sc_vec
        fields[0] = scval.to_string("another-protocol")
        with self.assertRaises(ResearchRejection):
            parse_statement(scval.to_vec(fields).to_xdr_bytes())

    def test_changed_valid_key_cannot_be_bound_to_fixed_circuit(self):
        changed = replace(self.statement, protected_public_key=LEAF_PUBLIC)
        with self.assertRaises(ResearchRejection):
            self.backend.check_relation(changed)
        self.reject_without_process(raw=changed.to_xdr_bytes())

    def test_changed_path_or_relation_rejects_before_backend(self):
        for changed in (replace(self.statement, account_index=1),
                        replace(self.statement, relation=LEAF, account_index=None)):
            self.reject_without_process(raw=changed.to_xdr_bytes())

    def test_wrong_verifier_parameters_and_round_count_reject(self):
        for changed in (replace(self.statement, verifier_id=bytes(32)),
                        replace(self.statement, parameters_id=bytes(32))):
            self.reject_without_process(raw=changed.to_xdr_bytes())
        for invalid in (1, 438, True):
            with self.assertRaises(ResearchRejection):
                replace(self.backend, rounds=invalid).check_relation(self.statement)

    def test_stale_epoch_revocation_and_unretired_policy_reject(self):
        for field, value in (("epoch", 8), ("eligible", False), ("classical_authority_retired", False)):
            state = replace(self.state, policy=replace(self.state.policy, **{field: value}))
            self.reject_without_process(state=state)

    def test_consumed_or_overflow_epoch_rejects_before_crypto(self):
        self.reject_without_process(state=replace(self.state, consumed=True))
        self.reject_without_process(state=replace(self.state, policy=replace(self.state.policy, epoch=(1 << 64) - 1)))

    def test_noop_rotation_and_malformed_possession_signature_reject(self):
        self.reject_without_process(state=replace(self.state, active_public_key=self.statement.replacement_public_key))
        with patch("verify_recovery_research.subprocess.run", side_effect=AssertionError("Unexpected native process")):
            with self.assertRaises(ValueError):
                consume_research_recovery(self.state, self.raw, Path("/unused/proof"), bytes(3308),
                                          1000, self.backend, Path("/unused/helper"))

    def test_failed_possession_is_atomic_and_never_calls_proof_verifier(self):
        before = self.state
        failed = subprocess.CompletedProcess([], 1, "", "signature rejected")
        with patch("verify_recovery_research.subprocess.run", return_value=failed), \
                patch.object(ResearchBackend, "verify", side_effect=AssertionError("PoP failure reached proof verifier")):
            with self.assertRaises(ResearchRejection):
                consume_research_recovery(self.state, self.raw, Path("/unused/proof"), bytes(3309),
                                          1000, self.backend, Path("/unused/helper"))
        self.assertEqual(self.state, before)
        self.assertFalse(self.state.consumed)

    def test_possession_digest_changes_with_replacement_or_epoch(self):
        original = replacement_possession_digest(self.statement)
        for changed in (replace(self.statement, policy_epoch=8),
                        replace(self.statement, replacement_public_key=bytes(1952))):
            self.assertNotEqual(original, replacement_possession_digest(changed))

    def test_research_record_cannot_assert_production_approval(self):
        changed = json.loads(json.dumps(self.record))
        changed["statement"]["backend_approved"] = True
        with self.assertRaises(ResearchRejection):
            ResearchBackend.from_record(changed, Path("/unused/binary"))

    def test_only_wellformed_exact_verifier_rejection_has_proof_rejection_type(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, proof = Path(directory) / "binary", Path(directory) / "proof"
            binary.write_bytes(b"not-executed-negative-test-fixture")
            proof.write_bytes(b"not-a-real-proof")
            backend = replace(self.backend, binary=binary,
                              binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
            response = {"valid": False, "message_digest_hex": self.statement.digest().hex(),
                        "relation_mode": "sep5-root", "rounds": 8}
            for code, data, is_proof_rejection in (
                (1, response, True), (2, response, False),
                (1, {**response, "message_digest_hex": "00" * 64}, False),
            ):
                result = subprocess.CompletedProcess([], code, json.dumps(data), "")
                with patch("verify_recovery_research.subprocess.run", return_value=result):
                    with self.assertRaises(ResearchRejection) as rejection:
                        backend.verify(self.statement, proof)
                self.assertEqual(isinstance(rejection.exception, ResearchProofRejected), is_proof_rejection)


if __name__ == "__main__":
    unittest.main()
