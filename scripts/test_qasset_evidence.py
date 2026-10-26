"""Tamper and staleness checks against the recorded disposable Testnet inputs."""
import copy
import contextlib
import io
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from verify_qasset_evidence import BASE, digest, input_bytes, verify
import verify_qasset_evidence
from stellar_sdk import xdr


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((BASE / "evidence/qasset-authority-assessment.json").read_text())

    def setUp(self):
        self.assessment = copy.deepcopy(self.fixture)

    def rehash(self):
        body = {k: v for k, v in self.assessment.items() if k != "assessment_sha256"}
        self.assessment["assessment_sha256"] = digest(body)

    def test_untouched_recorded_fixture_passes(self):
        result = verify(self.assessment)
        self.assertTrue(result["consistent"])
        self.assertEqual(result["paths_checked"], len(self.fixture["paths"]))
        self.assertEqual(result["scope"], "offline consistency only")

    def test_edited_status_fails_body_hash(self):
        self.assessment["paths"][0]["status"] = "INCONCLUSIVE"
        with self.assertRaisesRegex(ValueError, "checksum"):
            verify(self.assessment)

    def test_edited_status_with_recomputed_body_hash_still_fails(self):
        self.assessment["paths"][0]["status"] = "INCONCLUSIVE"
        self.rehash()
        with self.assertRaisesRegex(ValueError, "does not recompute"):
            verify(self.assessment)

    def test_edited_transaction_hash_with_recomputed_body_hash_fails(self):
        row = next(r for r in self.assessment["paths"] if any(c.get("hash") for c in r["citations"]))
        row["citations"][0]["hash"] = "0" * 64
        self.rehash()
        with self.assertRaises(ValueError):
            verify(self.assessment)

    def test_removed_citation_fails(self):
        row = next(r for r in self.assessment["paths"] if r["status"] == "TESTED_PASS")
        row["citations"] = []
        self.rehash()
        with self.assertRaisesRegex(ValueError, "lacks citation"):
            verify(self.assessment)

    def test_injected_status_fails(self):
        self.assessment["paths"][0]["status"] = "QUANTUM_SAFE"
        self.rehash()
        with self.assertRaisesRegex(ValueError, "unknown status"):
            verify(self.assessment)

    def test_altered_input_hash_fails(self):
        first = next(iter(self.assessment["inputs"]))
        self.assessment["inputs"][first]["sha256"] = "0" * 64
        self.rehash()
        with self.assertRaisesRegex(ValueError, "input hash mismatch"):
            verify(self.assessment)

    def test_bumped_policy_revision_marks_only_affected_paths_stale(self):
        revisions = {code: a["policy_revision"] for code, a in self.assessment["assets"].items()}
        revisions["QEXP"] += 1
        result = verify(self.assessment, current_revisions=revisions)
        self.assertFalse(result["fresh"])
        self.assertEqual(len(result["stale_paths"]), sum(p["asset"] == "QEXP" for p in self.fixture["paths"]))
        self.assertEqual({p["asset"] for p in result["stale_paths"]}, {"QEXP"})
        self.assertEqual({p["status"] for p in result["stale_paths"]}, {"STALE"})

    def test_removed_authority_path_fails(self):
        self.assessment["paths"].pop()
        self.rehash()
        with self.assertRaisesRegex(ValueError, "paths removed"):
            verify(self.assessment)

    def test_command_exits_nonzero_for_a_changed_revision_fixture(self):
        revisions = {code: value["policy_revision"] for code, value in self.assessment["assets"].items()}
        revisions["QEXP"] += 1
        with patch.object(verify_qasset_evidence, "check_live", return_value=(revisions, [])), \
                patch.object(verify_qasset_evidence, "network_call", return_value={"sequence": self.assessment["ledger_sequence_read"]}), \
                patch("sys.argv", ["verify_qasset_evidence.py"]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(verify_qasset_evidence.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual({p["status"] for p in report["stale_paths"]}, {"STALE"})

    def test_declared_policy_cannot_be_promoted_to_tested(self):
        row = next(r for r in self.assessment["paths"] if r["path"] == "registry.policy")
        row["status"] = "TESTED_PASS"
        row["citations"] = next(r["citations"] for r in self.assessment["paths"] if r["status"] == "TESTED_PASS" and r["citations"])
        self.rehash()
        with self.assertRaises(ValueError):
            verify(self.assessment)

    def test_decoded_snapshot_edit_fails_even_after_both_hashes_are_recomputed(self):
        with tempfile.TemporaryDirectory(prefix="qasset-evidence-test-") as directory:
            root = Path(directory)
            for name in self.assessment["inputs"]:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(input_bytes(BASE, name, self.assessment["inputs"][name]))
            path = root / self.assessment["snapshot_input"]
            snapshot = json.loads(path.read_text())
            snapshot["assets"]["QEXP"]["reads"]["sac_admin"]["value"] = snapshot["assets"]["QCTL"]["reads"]["sac_admin"]["value"]
            path.write_text(json.dumps(snapshot))
            data = path.read_bytes()
            import hashlib
            self.assessment["inputs"][self.assessment["snapshot_input"]] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            self.rehash()
            with self.assertRaisesRegex(ValueError, "edited decoded read value"):
                verify(self.assessment, root=root)


class LockedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((BASE / "evidence/history/qasset-authority-assessment-locked-revision3.json").read_text())

    def edited_input(self, input_key, mutate):
        """Rewrite both checksums so assertions exercise independent semantic checks."""
        temporary = tempfile.TemporaryDirectory(prefix="qasset-locked-evidence-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        assessment = copy.deepcopy(self.fixture)
        for name in assessment["inputs"]:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(input_bytes(BASE, name, assessment["inputs"][name]))
        path = root / assessment[input_key]
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data))
        encoded = path.read_bytes()
        assessment["inputs"][assessment[input_key]] = {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
        assessment["assessment_sha256"] = digest({k: v for k, v in assessment.items() if k != "assessment_sha256"})
        return assessment, root

    def test_real_locked_fixture_includes_the_post_lock_success_citation(self):
        self.assertTrue(verify(self.fixture)["fresh"])
        row = next(p for p in self.fixture["paths"] if p["asset"] == "QCTL" and p["path"] == "sac.set_authorized")
        self.assertEqual(len(row["citations"]), 2)
        classic = next(p for p in self.fixture["paths"] if p["asset"] == "QCTL" and p["path"] == "issuer.classic_mint")
        self.assertEqual(classic["status"], "TESTED_REJECT")
        self.assertEqual(classic["citations"][0]["kind"], "submission_rejection")

    def test_missing_post_lock_action_cannot_be_hidden_by_rehashing(self):
        def mutate(deployment):
            deployment["observations"] = [o for o in deployment["observations"] if o["label"] != "ml_dsa_after_lock"]
        assessment, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "missing post-lock"):
            verify(assessment, root=root)

    def test_lock_without_explicit_gate_is_rejected(self):
        assessment, root = self.edited_input("deployment_input", lambda d: d["lock_gate"].update(environment_enabled=False))
        with self.assertRaisesRegex(ValueError, "explicit gate"):
            verify(assessment, root=root)

    def test_retained_positive_weight_signer_invalidates_a_lock_claim(self):
        def mutate(snapshot):
            snapshot["assets"]["QCTL"]["issuer"]["signers"][0]["weight"] = 1
        assessment, root = self.edited_input("snapshot_input", mutate)
        with self.assertRaisesRegex(ValueError, "positive-weight signer"):
            verify(assessment, root=root)

    def test_relabelled_pre_lock_success_cannot_claim_post_lock_authorization(self):
        def mutate(deployment):
            before = next(o for o in deployment["observations"] if o["asset"] == "QCTL" and o["label"] == "ml_dsa_set_authorized")
            after = next(o for o in deployment["observations"] if o["label"] == "ml_dsa_after_lock")
            for field in ("hash", "envelope_xdr", "receipt", "simulation"):
                after[field] = copy.deepcopy(before[field])
        assessment, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "did not occur after"):
            verify(assessment, root=root)

    def test_balance_error_cannot_be_reported_as_post_lock_authentication_rejection(self):
        def mutate(deployment):
            rejection = next(o for o in deployment["observations"] if o["label"] == "classic_mint_after_lock")
            result = xdr.TransactionResult.from_xdr(rejection["response"]["errorResultXdr"])
            result.result.code = xdr.TransactionResultCode.txINSUFFICIENT_BALANCE
            rejection["response"]["errorResultXdr"] = result.to_xdr()
        assessment, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "not bad authentication"):
            verify(assessment, root=root)

    def test_relocated_unlocked_evidence_still_verifies_offline(self):
        historical = json.loads((BASE / "evidence/history/qasset-authority-assessment-unlocked.json").read_text())
        self.assertTrue(verify(historical)["consistent"])


class RemediationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((BASE / "evidence/qasset-authority-assessment.json").read_text())

    edited_input = LockedEvidenceTests.edited_input

    def test_budget_failure_cannot_replace_policy_rejection_even_with_recomputed_hashes(self):
        def mutate(deployment):
            for o in deployment["observations"]:
                if o["label"] == "operator_mint":
                    o["expected_error"] = "Budget"
                    o["result"]["error"] = "HostError: Error(Budget, ExceededLimit)"
        a, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "different reason"):
            verify(a, root=root)

    def test_wrong_network_credential_cannot_be_relabelled_as_a_replay(self):
        def mutate(deployment):
            wrong = next(o for o in deployment["observations"] if o["label"] == "wrong_network_signature")
            replay = next(o for o in deployment["observations"] if o["label"] == "replayed_entry")
            replay["envelope_xdr"] = wrong["envelope_xdr"]
        a, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "replay differs"):
            verify(a, root=root)

    def test_unsigned_payment_is_not_evidence_of_an_issuer_key_being_disabled(self):
        def mutate(deployment):
            from stellar_sdk import TransactionEnvelope
            o = next(o for o in deployment["observations"] if o["label"] == "classic_mint_after_lock")
            tx = TransactionEnvelope.from_xdr(o["envelope_xdr"], verify_qasset_evidence.NETWORK)
            tx.signatures = []
            o["envelope_xdr"] = tx.to_xdr()
        a, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "requires the issuer signature"):
            verify(a, root=root)

    def test_mint_probe_requires_a_valid_operator_signature(self):
        def mutate(deployment):
            from stellar_sdk import scval
            o = next(o for o in deployment["observations"] if o["label"] == "operator_mint")
            tx = verify_qasset_evidence.envelope(o["envelope_xdr"])[0]
            op = (tx.transaction.inner_transaction_envelope.transaction if hasattr(tx.transaction, "inner_transaction_envelope")
                  else tx.transaction).operations[0]
            op.auth[0].credentials.address.signature = scval.to_bytes(bytes(3309))
            o["envelope_xdr"] = tx.to_xdr()
        a, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "credential signature"):
            verify(a, root=root)

    def test_raw_rpc_ledgers_must_lie_in_the_claimed_assessment_interval(self):
        a, root = self.edited_input("snapshot_input", lambda s: s.update(ledger_start=1, ledger_end=1))
        a.update(ledger_range=[1, 1], ledger_sequence_read=1)
        a["assessment_sha256"] = digest({k: v for k, v in a.items() if k != "assessment_sha256"})
        with self.assertRaisesRegex(ValueError, "raw response ledger"):
            verify(a, root=root)

    def test_future_timestamp_is_rejected_after_rehashing(self):
        a = copy.deepcopy(self.fixture)
        a["generated_at_utc"] = "2099-01-01T00:00:00+00:00"
        a["assessment_sha256"] = digest({k: v for k, v in a.items() if k != "assessment_sha256"})
        with self.assertRaisesRegex(ValueError, "future assessment timestamp"):
            verify(a)

    def test_v2_requires_the_tool_version_and_rejects_schema_downgrades(self):
        if self.fixture["schema"] != "qasset-authority-assessment-v2":
            self.fail("primary evidence must use the versioned v2 schema")
        for field in ("tool", "schema"):
            a = copy.deepcopy(self.fixture)
            if field == "tool":
                del a["tool"]
            else:
                a["schema"] = "qasset-authority-assessment-v1"
            a["assessment_sha256"] = digest({k: v for k, v in a.items() if k != "assessment_sha256"})
            with self.assertRaises(ValueError):
                verify(a)

    def test_authority_change_returns_structured_stale_paths(self):
        v = verify_qasset_evidence
        with patch.object(v, "check_live", side_effect=v.ConfigurationChanged("issuer threshold changed", "QEXP")), \
                patch("sys.argv", ["verify_qasset_evidence.py"]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(v.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "STALE")
        self.assertEqual({p["asset"] for p in report["stale_paths"]}, {"QEXP"})

    def test_missing_live_receipt_is_inconclusive_and_does_not_claim_freshness(self):
        v = verify_qasset_evidence
        def rpc(method, params=None):
            if method == "getNetwork":
                return {"passphrase": v.NETWORK}
            if method == "getTransaction":
                return {"status": "NOT_FOUND"}
            raise AssertionError(method)
        with patch.object(v, "network_call", side_effect=rpc), \
                patch("sys.argv", ["verify_qasset_evidence.py"]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(v.main(), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "INCONCLUSIVE")
        self.assertIsNone(report["fresh"])
        self.assertEqual(len(report["inconclusive_paths"]), len(self.fixture["paths"]))

    def test_contract_error_must_be_present_in_raw_diagnostics(self):
        def mutate(deployment):
            o = next(o for o in deployment["observations"] if o["label"] == "operator_mint")
            o["result"]["events"] = []
        a, root = self.edited_input("deployment_input", mutate)
        with self.assertRaisesRegex(ValueError, "contract error diagnostic"):
            verify(a, root=root)

    def test_wrong_issuer_cannot_be_hidden_by_rehashing_the_deployment(self):
        def mutate(deployment):
            deployment["assets"]["QEXP"]["issuer"] = deployment["assets"]["QCTL"]["issuer"]
        a, root = self.edited_input("deployment_input", mutate)
        with self.assertRaises(ValueError):
            verify(a, root=root)

    def test_changed_recorded_threshold_does_not_match_the_assessment_configuration(self):
        a, root = self.edited_input("snapshot_input", lambda s: s["assets"]["QEXP"]["issuer"]["thresholds"].update(med_threshold=9))
        with self.assertRaisesRegex(ValueError, "configuration binding"):
            verify(a, root=root)


if __name__ == "__main__":
    unittest.main()
