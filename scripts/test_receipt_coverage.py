"""Offline completeness checks for the actual public historical demo receipts."""
import copy
import json
from pathlib import Path
import unittest

from receipt_coverage import require_coverage


class CaptureCompletenessTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.policy = json.loads((root / "docs/testnet-deployment.json").read_text())
        self.pq = json.loads((root / "docs/recovery-testnet.json").read_text())

    def test_both_real_journals_have_every_required_operation(self):
        require_coverage(self.policy["transactions"], self.policy["contracts"],
                         [("qasset_registry", "register_asset")] + [("qasset_registry", "set_role_quorum")] * 12)
        require_coverage(self.pq["transactions"], {"pq_recovery_demo": self.pq["contract"]},
                         [("pq_recovery_demo", "protected"), ("pq_recovery_demo", "recover"), ("pq_recovery_demo", "protected")])

    def test_missing_creation_or_mutation_cannot_be_reported_as_complete(self):
        records = self.pq["transactions"]
        for index in range(len(records)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                require_coverage(records[:index] + records[index + 1:], {"pq_recovery_demo": self.pq["contract"]},
                                 [("pq_recovery_demo", "protected"), ("pq_recovery_demo", "recover"), ("pq_recovery_demo", "protected")])

    def test_duplicate_or_reordered_receipts_cannot_fill_a_capture_gap(self):
        records = copy.deepcopy(self.pq["transactions"])
        for invalid in [records + [records[1]], [records[0], records[2], records[1], records[3]]]:
            with self.assertRaises(ValueError):
                require_coverage(invalid, {"pq_recovery_demo": self.pq["contract"]},
                                 [("pq_recovery_demo", "protected"), ("pq_recovery_demo", "recover"), ("pq_recovery_demo", "protected")])


if __name__ == "__main__":
    unittest.main()
