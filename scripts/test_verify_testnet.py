#!/usr/bin/env python3
"""Offline adversarial evidence checks. Uses public recorded envelopes; never signs or calls RPC."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stellar_sdk import Address, TransactionEnvelope, scval

import verify_testnet as verifier

ROOT = Path(__file__).resolve().parents[1]


class ReceiptScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "docs/testnet-deployment.json").read_text())
        cls.recovery = json.loads((ROOT / "docs/recovery-testnet.json").read_text())

    def setUp(self):
        self.policy = copy.deepcopy(type(self).policy)
        self.recovery = copy.deepcopy(type(self).recovery)
        # Any accidental networking in these tests must fail immediately.
        self.network = patch.object(verifier, "rpc", side_effect=AssertionError("offline test called RPC"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def rejected(self):
        with self.assertRaises((verifier.EvidenceError, ValueError)):
            verifier.verify_scenario(self.policy, self.recovery)

    def test_real_public_receipts_bind_all_21_actions_without_network(self):
        result = verifier.verify_scenario(self.policy, self.recovery)
        self.assertEqual(len(result), 21)
        self.assertEqual(len({r["hash"] for r in result}), 21)
        self.assertEqual([r["action"] for r in result[-4:]], [
            "deployment", "initial_key_authorizes", "backup_key_recovers_to_replacement", "replacement_key_authorizes"])

    def test_relabelled_success_does_not_prove_recovery(self):
        self.recovery["transactions"][1]["label"] = "backup_key_recovers_to_replacement"
        self.rejected()

    def test_original_duplicate_receipt_exploit_is_rejected(self):
        real = self.recovery["transactions"][1]
        self.policy["transactions"] = [copy.deepcopy(real) for _ in range(17)]
        self.rejected()

    def test_unrelated_existing_success_cannot_replace_recovery(self):
        replacement = copy.deepcopy(self.policy["transactions"][0])
        replacement["label"] = "backup_key_recovers_to_replacement"
        self.recovery["transactions"][2] = replacement
        self.rejected()

    def test_transaction_hash_must_match_network_specific_envelope(self):
        self.recovery["transactions"][2]["hash"] = "00" * 32
        self.rejected()

    def test_claimed_contract_id_cannot_be_rebound_to_existing_other_contract(self):
        self.recovery["contract"]["id"] = self.policy["contracts"]["qasset_registry"]["id"]
        self.rejected()

    def test_constructor_enrolled_backup_must_match_recorded_backup(self):
        self.recovery["public_key_sha256"]["recovery"] = "ab" * 32
        self.rejected()

    def test_canonical_recovery_intent_is_recomputed(self):
        for field, value in [("digest", "ab" * 32), ("epoch", 1), ("valid_until_ledger", 1)]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.recovery)
                changed["recovery_intent"][field] = value
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_scenario(self.policy, changed)

    def test_recovery_cannot_be_moved_before_original_action(self):
        self.recovery["transactions"][1], self.recovery["transactions"][2] = (
            self.recovery["transactions"][2], self.recovery["transactions"][1])
        self.rejected()

    def test_receipt_ledger_cannot_be_detached_from_rpc_result(self):
        self.recovery["transactions"][2]["ledger"] += 100
        self.rejected()

    def test_metadata_command_function_and_arguments_match_actual_mutation(self):
        original = copy.deepcopy(self.policy)
        for flag, changed in [("--id", self.recovery["contract"]["id"]),
                              ("--role", "Mint"), ("--quorum", '{"signers": [], "threshold": 0}')]:
            with self.subTest(flag=flag):
                self.policy = copy.deepcopy(original)
                command = self.policy["transactions"][5]["command"]
                command[command.index(flag) + 1] = changed
                self.rejected()
        self.policy = copy.deepcopy(original)
        command = self.policy["transactions"][5]["command"]
        command[command.index("--") + 1] = "transfer_asset_admin"
        self.rejected()

    def test_pq_authorization_root_must_match_action_and_address(self):
        record = self.recovery["transactions"][1]
        _, op = verifier.decode_receipt(record, self.recovery["fee_payer"])
        account = self.recovery["contract"]["id"]
        expected = verifier.invocation(account, "protected", [])
        verifier.verify_invocation_auth(op, expected, account=account, ledger=record["ledger"])
        for function, args in [("recover", []), ("protected", [scval.to_uint32(1)])]:
            with self.subTest(function=function):
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_invocation_auth(op, verifier.invocation(account, function, args),
                                                   account=account, ledger=record["ledger"])
        tampered = copy.deepcopy(op)
        tampered.auth = []
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_invocation_auth(tampered, expected, account=account, ledger=record["ledger"])
        tampered = copy.deepcopy(op)
        tampered.auth[0].credentials.address.address = Address(self.policy["public_identities"]["admin"]).to_xdr_sc_address()
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_invocation_auth(tampered, expected, account=account, ledger=record["ledger"])

    def test_constructor_configuration_is_bound_beyond_byte_length(self):
        record = self.recovery["transactions"][0]
        _, op = verifier.decode_receipt(record, self.recovery["fee_payer"])
        values = op.host_function.create_contract_v2.constructor_args
        expected = copy.deepcopy(values)
        verifier.verify_create(op, self.recovery["contract"], self.recovery["fee_payer"], expected, constructor_auth=True)
        expected[2] = scval.to_bytes(bytes(1952))
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_create(op, self.recovery["contract"], self.recovery["fee_payer"], expected, constructor_auth=True)


class LocalArtifactBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qasset-evidence-offline-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wasm_dir = self.root / "artifacts"
        self.wasm_dir.mkdir()
        names = ["Cargo.toml", "Cargo.lock", "tools/pq-demo/Cargo.toml", "tools/pq-demo/Cargo.lock", "tools/pq-demo/src/main.rs"]
        for contract in ["qasset-registry", "seed-recovery-verifier", "pq-recovery-demo"]:
            names.extend([f"contracts/{contract}/Cargo.toml", f"contracts/{contract}/src/lib.rs"])
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("offline input: " + name)
        self.validation = {"status": "passed", "source_sha256": {
            name: verifier.digest((self.root / name).read_bytes()) for name in names}, "wasm_artifacts": []}
        contracts = {}
        for name in ["qasset_registry", "seed_recovery_verifier", "pq_recovery_demo"]:
            data = ("offline WASM fixture: " + name).encode()
            (self.wasm_dir / (name + ".wasm")).write_bytes(data)
            entry = {"name": name + ".wasm", "sha256": verifier.digest(data), "bytes": len(data)}
            self.validation["wasm_artifacts"].append(entry)
            contracts[name] = {"wasm_sha256": entry["sha256"], "wasm_bytes": len(data)}
        self.policy = {"contracts": {k: v for k, v in contracts.items() if k != "pq_recovery_demo"},
                       "source_sha256": {"Cargo.lock": self.validation["source_sha256"]["Cargo.lock"]}}
        self.recovery = {"contract": contracts["pq_recovery_demo"], "source_sha256": {}}

    def check(self):
        return verifier.verify_local_artifacts(self.root, self.wasm_dir, self.validation, self.policy, self.recovery)

    def test_matching_local_sources_and_all_three_artifacts_pass(self):
        self.assertTrue(self.check()["source_manifest_match"])
        self.assertTrue(self.check()["local_wasm_match"])

    def test_changed_rust_source_or_crate_manifest_or_lock_is_rejected(self):
        for name in ["contracts/pq-recovery-demo/src/lib.rs", "contracts/qasset-registry/Cargo.toml", "Cargo.lock"]:
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b" changed")
                with self.assertRaises(verifier.EvidenceError):
                    self.check()
                path.write_bytes(original)

    def test_mutating_json_hash_to_match_other_build_is_not_enough(self):
        self.recovery["contract"]["wasm_sha256"] = "ab" * 32
        with self.assertRaises(verifier.EvidenceError):
            self.check()

    def test_current_artifact_replacement_or_missing_wasm_is_rejected(self):
        path = self.wasm_dir / "pq_recovery_demo.wasm"
        path.write_bytes(b"another build")
        with self.assertRaises(verifier.EvidenceError):
            self.check()
        path.unlink()
        with self.assertRaises(verifier.EvidenceError):
            self.check()

    def test_deleted_manifest_is_not_silently_removed_from_input_glob(self):
        (self.root / "contracts/pq-recovery-demo/Cargo.toml").unlink()
        with self.assertRaises(verifier.EvidenceError):
            self.check()

    def test_duplicate_validation_artifact_is_not_silently_collapsed(self):
        self.validation["wasm_artifacts"].append(copy.deepcopy(self.validation["wasm_artifacts"][0]))
        with self.assertRaises(verifier.EvidenceError):
            self.check()

    def test_incomplete_or_unpassed_local_validation_is_rejected(self):
        self.validation["status"] = "in_progress"
        with self.assertRaises(verifier.EvidenceError):
            self.check()
        self.validation["status"] = "passed"
        del self.validation["source_sha256"]["contracts/pq-recovery-demo/Cargo.toml"]
        with self.assertRaises(verifier.EvidenceError):
            self.check()


if __name__ == "__main__":
    unittest.main()
