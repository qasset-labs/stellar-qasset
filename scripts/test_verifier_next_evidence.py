"""Integrity regressions only; historical records are never fake proof execution."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import check_verifier_next_evidence as next_evidence


class VerifierNextEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="qasset-next-evidence-test-")
        cls.package = Path(cls.directory.name) / "package"
        shutil.copytree(next_evidence.ROOT / "tools/binius-verifier-next", cls.package,
                        ignore=shutil.ignore_patterns("target", "__pycache__", ".git"))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.restore = {}

    def tearDown(self):
        for path, original in self.restore.items():
            path.write_bytes(original)

    def change_json(self, name, record):
        path = self.package / name
        self.restore.setdefault(path, path.read_bytes())
        path.write_text(json.dumps(record) + "\n")

    def test_source_mutation_rejects_even_with_python_optimization(self):
        path = self.package / "guest/src/lib.rs"
        self.restore[path] = path.read_bytes()
        path.write_bytes(self.restore[path] + b"\n// changed after execution\n")
        result = subprocess.run([sys.executable, "-O", str(next_evidence.ROOT / "scripts/check_verifier_next_evidence.py"),
                                 "--package", str(self.package)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source inventory/hash/lineage mismatch", result.stdout)

    def test_wasm_trap_cannot_count_as_a_proof_rejection(self):
        wasm = next_evidence.read(self.package, "evidence/final-optimized-results.json")
        wasm["checks"][1]["runtime_error"] = "out of fuel"
        self.change_json("evidence/final-optimized-results.json", wasm)
        research = next_evidence.read(self.package, "evidence/research.json")
        research["wasm"] = wasm
        self.change_json("evidence/research.json", research)
        with self.assertRaisesRegex(ValueError, "Wasm trap/rejection/result"):
            next_evidence.check(self.package)

    def test_matching_but_wrong_arithmetic_outputs_are_rejected(self):
        arithmetic = next_evidence.read(self.package, "evidence/final-arithmetic-results.json")
        for result in arithmetic["results"]:
            result["output_sha256"] = "00" * 32
        self.change_json("evidence/final-arithmetic-results.json", arithmetic)
        research = next_evidence.read(self.package, "evidence/research.json")
        research["arithmetic"] = arithmetic
        self.change_json("evidence/research.json", research)
        with self.assertRaisesRegex(ValueError, "arithmetic equivalence"):
            next_evidence.check(self.package)

    def test_missing_artifacts_are_explicit_and_raw_fit_is_not_contract_approval(self):
        result = next_evidence.check(self.package)
        self.assertEqual(result["status"], "passed_source_and_record_consistency_only")
        self.assertEqual(len(result["ignored_artifacts_missing"]), 4)
        self.assertIs(result["fresh_proof_execution"], False)
        self.assertIs(result["security_approved"], False)
        self.assertIs(result["soroban_compatible"], False)
        with self.assertRaisesRegex(ValueError, "required ignored successor artifacts"):
            next_evidence.check(self.package, require_artifacts=True)
        limits = next_evidence.read(next_evidence.ROOT, "docs/verifier-network-limits.json")
        for row in limits["response"]["updated_entry"]:
            if "contract_max_size_bytes" in row:
                row["contract_max_size_bytes"] = result["raw_module_bytes"] - 1
        with self.assertRaisesRegex(ValueError, "raw module exceeds"):
            next_evidence.check(self.package, limits=limits)


if __name__ == "__main__":
    unittest.main()
