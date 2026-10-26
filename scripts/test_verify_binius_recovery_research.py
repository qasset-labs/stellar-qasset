"""Binius adapter rejection/control tests; no mocked cryptographic acceptance."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from check_seed_recovery_evidence import public_fixture_statement
from verify_binius_recovery_research import BiniusResearchBackend, SCALAR
from verify_recovery_research import LEAF_PUBLIC, ResearchProofRejected, ResearchRejection, ROOT_PUBLIC


class BiniusAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.binary = folder / "binary"
        self.binary.write_bytes(b"operator trusted test binary")
        self.proof = folder / "proof"
        self.proof.write_bytes(b"test rejection input")
        self.statement = public_fixture_statement(LEAF_PUBLIC)
        self.backend = BiniusResearchBackend(self.statement.verifier_id, self.statement.parameters_id,
                                             self.binary, hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def response(self, code=2, **changes):
        value = {"valid": False, "backend": "binius64-115108-zk-96-log-inv-rate1",
                 "relation": "rfc8032-leaf-clamped-seed-v1", "public_scalar_hex": SCALAR.hex(),
                 "action_digest_sha512_hex": self.statement.digest().hex()}
        value.update(changes)
        return subprocess.CompletedProcess([], code, json.dumps(value), "")

    def test_key_relation_and_parameters_rejected_before_native(self):
        for statement in [replace(self.statement, protected_public_key=ROOT_PUBLIC),
                          replace(self.statement, verifier_id=bytes(32)),
                          replace(self.statement, parameters_id=bytes(32))]:
            with self.subTest(statement=statement), self.assertRaises(ResearchRejection):
                self.backend.check_relation(statement)

    def test_exact_identity_required_for_native_proof_rejection(self):
        with patch("verify_binius_recovery_research.subprocess.run", return_value=self.response()):
            with self.assertRaises(ResearchProofRejected):
                self.backend.verify(self.statement, self.proof)

    def test_wrong_action_response_is_not_proof_rejection(self):
        with patch("verify_binius_recovery_research.subprocess.run", return_value=self.response(action_digest_sha512_hex=bytes(64).hex())):
            with self.assertRaises(ResearchRejection) as caught:
                self.backend.verify(self.statement, self.proof)
            self.assertNotIsInstance(caught.exception, ResearchProofRejected)

    def test_failed_process_is_not_proof_rejection(self):
        with patch("verify_binius_recovery_research.subprocess.run", return_value=self.response(code=7)):
            with self.assertRaises(ResearchRejection) as caught:
                self.backend.verify(self.statement, self.proof)
            self.assertNotIsInstance(caught.exception, ResearchProofRejected)

    def test_malformed_native_response_rejected(self):
        result = subprocess.CompletedProcess([], 2, "garbage", "")
        with patch("verify_binius_recovery_research.subprocess.run", return_value=result):
            with self.assertRaises(ResearchRejection):
                self.backend.verify(self.statement, self.proof)

    def test_binary_mutation_rejected(self):
        self.binary.write_bytes(b"changed")
        with self.assertRaises(ResearchRejection):
            self.backend.verify(self.statement, self.proof)

    def test_empty_proof_rejected_before_native(self):
        self.proof.write_bytes(b"")
        with self.assertRaises(ResearchRejection):
            self.backend.verify(self.statement, self.proof)

    def test_research_record_cannot_assert_approval(self):
        record = {"status": "passed_binius_leaf_functional_experiment_only", "security_approved": False, "source_sha256": {},
                  "statement": {"backend_approved": False, "parameters": {"approved": True, "public_clamped_scalar_hex": SCALAR.hex()}}}
        with self.assertRaises(ResearchRejection):
            BiniusResearchBackend.from_record(record, self.binary)


if __name__ == "__main__":
    unittest.main()
