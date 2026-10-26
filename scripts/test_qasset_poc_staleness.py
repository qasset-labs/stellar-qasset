"""Offline guards for the bounded live registry-staleness demonstration."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from stellar_sdk import Keypair
from qasset_poc_staleness import ROOT, check_fresh_registry, load_deployer


class FreshRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((ROOT / "deployments/testnet/qasset-poc-locked.json").read_text())

    def test_real_creation_receipt_binds_the_fresh_registry(self):
        check_fresh_registry(self.record)

    def test_existing_contract_cannot_replace_the_creation_target(self):
        edited = copy.deepcopy(self.record)
        edited["registry"]["id"] = edited["assets"]["QEXP"]["admin"]
        with self.assertRaisesRegex(ValueError, "freshly created"):
            check_fresh_registry(edited)

    def test_relabelled_invocation_cannot_claim_registry_creation(self):
        edited = copy.deepcopy(self.record)
        replacement = copy.deepcopy(next(o for o in edited["observations"] if o["label"] == "register_policy"))
        replacement["label"] = "deploy_registry"
        edited["observations"] = [replacement]
        with self.assertRaisesRegex(ValueError, "not contract creation"):
            check_fresh_registry(edited)


class PrivateDeployerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="qasset-staleness-key-test-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "accounts.json"
        self.key = Keypair.random()
        descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"deployer": self.key.secret}, stream)

    def test_private_file_is_bound_to_the_recorded_deployer(self):
        self.assertEqual(load_deployer(self.path, self.key.public_key).public_key, self.key.public_key)
        with self.assertRaisesRegex(ValueError, "does not match"):
            load_deployer(self.path, Keypair.random().public_key)

    def test_shared_permissions_symlinks_and_hardlinks_are_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_deployer(self.path, self.key.public_key)
        self.path.chmod(0o600)
        link = self.path.parent / "link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            load_deployer(link, self.key.public_key)
        hardlink = self.path.parent / "hardlink"
        os.link(self.path, hardlink)
        with self.assertRaises(ValueError):
            load_deployer(self.path, self.key.public_key)


if __name__ == "__main__":
    unittest.main()
