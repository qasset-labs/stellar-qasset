"""Offline checks of the irreversible-operation gate; no network or signing mocks."""
import unittest
import json
from stellar_sdk import Account, FeeBumpTransactionEnvelope, Keypair, TransactionBuilder
from qasset_poc_testnet import ROOT, PASSPHRASE, issuer_lock_allowed, prepare_and_sign


class IssuerLockTests(unittest.TestCase):
    def test_only_exact_environment_value_enables_a_fresh_issuer_lock(self):
        state = {"account_id": "fresh", "signers": [{"key": "fresh", "weight": 1}]}
        for value in (None, "yes", "1", "TRUE", "YES "):
            environment = {} if value is None else {"QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK": value}
            self.assertFalse(issuer_lock_allowed(environment, "fresh", {"fresh"}, state))
        self.assertTrue(issuer_lock_allowed({"QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK": "YES"}, "fresh", {"fresh"}, state))

    def test_enabled_gate_still_refuses_existing_wrong_or_multisigner_issuers(self):
        enabled = {"QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK": "YES"}
        good = {"account_id": "fresh", "signers": [{"key": "fresh", "weight": 1}]}
        for created, state in [(set(), good), ({"fresh"}, {**good, "account_id": "existing"}),
                               ({"fresh"}, {**good, "signers": []}),
                               ({"fresh"}, {**good, "signers": [{"key": "other", "weight": 0}]}),
                               ({"fresh"}, {**good, "signers": [{"key": "fresh", "weight": 0}]})]:
            with self.assertRaises(RuntimeError):
                issuer_lock_allowed(enabled, "fresh", created, state)


class FeeAssemblyTests(unittest.TestCase):
    def test_recorded_large_resource_fee_roundtrips_in_a_signed_fee_bump(self):
        simulation = json.loads((ROOT / "evidence/attempts/qasset-upload-simulation.json").read_text())
        key = Keypair.random()
        # This tests serialization and fee preservation only, not contract execution.
        tx = (TransactionBuilder(Account(key.public_key, 0), PASSPHRASE, 100)
              .append_upload_contract_wasm_op(b"fee assembly fixture").set_timeout(300).build())
        result = prepare_and_sign(tx, simulation, key)
        decoded = FeeBumpTransactionEnvelope.from_xdr(result.to_xdr(), PASSPHRASE)
        inner = decoded.transaction.inner_transaction_envelope
        fee = int(simulation["minResourceFee"])
        self.assertGreater(fee, 0xffffffff)
        self.assertEqual(inner.transaction.soroban_data.resource_fee.int64, fee)
        self.assertEqual(decoded.transaction.fee, fee + 200)
        self.assertEqual(len(inner.signatures), 1)
        self.assertEqual(len(decoded.signatures), 1)


if __name__ == "__main__":
    unittest.main()
