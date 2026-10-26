"""Reject dishonest positive/negative claims before publishing an assessment."""
import copy
import json
import unittest
from unittest.mock import patch

from qasset_authority_analyzer import ROOT, STATUSES, assess, collect


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deployment = json.loads((ROOT / "deployments/testnet/qasset-poc.json").read_text())
        cls.snapshot = json.loads((ROOT / "evidence/qasset-authority-inputs.json").read_text())

    def test_pending_issuer_lock_never_claims_restricted_classic_mint(self):
        # Keep the pending-gate regression tied to the preserved historical run.
        unlocked = json.loads((ROOT / "deployments/testnet/history/qasset-poc-unlocked.json").read_text())
        snapshot = json.loads((ROOT / "evidence/history/qasset-authority-inputs-unlocked.json").read_text())
        paths = assess(unlocked, snapshot)
        self.assertTrue(all(p["status"] in STATUSES for p in paths))
        qctl = next(p for p in paths if p["asset"] == "QCTL" and p["path"] == "issuer.classic_mint")
        self.assertEqual(qctl["status"], "INCONCLUSIVE")
        self.assertEqual(next(p for p in paths if p["asset"] == "QEXP" and p["path"] == "issuer.classic_mint")["status"], "EXPOSED")

    def test_failed_positive_cannot_be_reported_as_passed(self):
        edited = copy.deepcopy(self.deployment)
        next(o for o in edited["observations"] if o["label"] == "ml_dsa_set_authorized")["observed"] = "FAILED"
        with self.assertRaisesRegex(ValueError, "positive claim"):
            assess(edited, self.snapshot)

    def test_successful_negative_cannot_be_reported_as_rejected(self):
        edited = copy.deepcopy(self.deployment)
        next(o for o in edited["observations"] if o["label"] == "operator_mint")["observed"] = "SUCCESS"
        with self.assertRaisesRegex(ValueError, "rejection claim"):
            assess(edited, self.snapshot)

    def test_changed_local_artifact_fails_before_any_live_read(self):
        edited = copy.deepcopy(self.deployment)
        next(iter(edited["artifacts"].values()))["sha256"] = "0" * 64
        with patch("qasset_authority_analyzer.rpc", side_effect=AssertionError("unexpected network call")):
            with self.assertRaisesRegex(ValueError, "local artifact differs"):
                collect(edited)


if __name__ == "__main__":
    unittest.main()
