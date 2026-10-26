"""Bounded evidence-integrity regressions; these do not simulate proof acceptance."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_verifier_port_evidence as port


class VerifierPortEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="qasset-port-evidence-test-")
        cls.package = Path(cls.temporary.name) / "package"
        shutil.copytree(port.ROOT / "tools/binius-verifier-port", cls.package,
                        ignore=shutil.ignore_patterns("target", "__pycache__", ".git"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.restore = {}

    def tearDown(self):
        for path, original in self.restore.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)

    def change(self, name, raw):
        path = self.package / name
        if path not in self.restore:
            self.restore[path] = path.read_bytes() if path.exists() else None
        path.write_bytes(raw)

    def change_json(self, name, record):
        self.change(name, (json.dumps(record) + "\n").encode())

    def mutate_wasm_record(self, mutate):
        record = port.read(self.package, "evidence/wasm-results.json")
        mutate(record)
        self.change_json("evidence/wasm-results.json", record)
        research = port.read(self.package, "evidence/research.json")
        research["wasm"] = record
        self.change_json("evidence/research.json", research)

    def test_changed_source_is_rejected(self):
        original = (self.package / "guest/src/lib.rs").read_bytes()
        self.change("guest/src/lib.rs", original + b"\n// changed after execution\n")
        with self.assertRaisesRegex(ValueError, "source inventory/hash"):
            port.check(self.package)

    def test_unrecorded_source_is_rejected(self):
        self.change("guest/src/unrecorded.rs", b"// unrecorded compiler input\n")
        with self.assertRaisesRegex(ValueError, "source inventory/hash"):
            port.check(self.package)

    def test_record_cannot_promote_security_approval(self):
        research = port.read(self.package, "evidence/research.json")
        research["security_approved"] = True
        self.change_json("evidence/research.json", research)
        with self.assertRaisesRegex(ValueError, "incomplete/overstated"):
            port.check(self.package)

    def test_accepted_changed_action_is_not_a_passing_negative(self):
        self.mutate_wasm_record(lambda record: record["checks"][1].update(result=1, expected=1, passed=True))
        with self.assertRaisesRegex(ValueError, "Wasm trap/error/result"):
            port.check(self.package)

    def test_trap_is_not_a_passing_proof_rejection(self):
        self.mutate_wasm_record(lambda record: record["checks"][1].update(error="out of bounds memory access", passed=True))
        with self.assertRaisesRegex(ValueError, "Wasm trap/error/result"):
            port.check(self.package)

    def test_missing_artifacts_have_explicit_limited_scope(self):
        result = port.check(self.package)
        self.assertEqual(result["status"], "passed_source_and_record_consistency_only")
        self.assertEqual(result["retained_artifacts_checked"], [])
        self.assertEqual(len(result["ignored_artifacts_missing"]), 5)
        self.assertIs(result["proof_execution_rerun"], False)
        self.assertIs(result["security_approved"], False)
        with self.assertRaisesRegex(ValueError, "required ignored artifacts"):
            port.check(self.package, require_artifacts=True)


if __name__ == "__main__":
    unittest.main()
