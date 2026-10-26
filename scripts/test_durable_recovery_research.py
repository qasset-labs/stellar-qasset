"""Persistence and fail-closed control tests; positive crypto runs separately."""

from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from check_seed_recovery_evidence import public_fixture_policy
from durable_recovery_research import DurableRecoveryStore, decode_state, encode_state, MAX_REVISION
from verify_recovery_research import RecoveryState, ResearchRejection, parse_statement

ROOT = Path(__file__).resolve().parents[1]


class DurableRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "model.sqlite"
        record = json.loads((ROOT / "docs/seed-proof-research.json").read_text())
        self.statement = parse_statement(bytes.fromhex(record["statement"]["canonical_xdr_hex"]))
        self.state = RecoveryState(public_fixture_policy(self.statement), bytes(1952))
        self.store = DurableRecoveryStore.create(self.path, self.state, 1000)

    def test_canonical_state_roundtrip_full_unsigned_epoch(self):
        state = replace(self.state, policy=replace(self.state.policy, epoch=(1 << 64) - 1))
        self.assertEqual(decode_state(encode_state(state)), state)

    def test_unknown_or_coerced_state_fields_rejected(self):
        for field, value in [("eligible", 1), ("epoch", True), ("account_index", True),
                             ("network_id", "ff"), ("extra", "unknown")]:
            state = json.loads(encode_state(self.state))
            state["policy"][field] = value
            with self.subTest(field=field), self.assertRaises(ResearchRejection):
                decode_state(json.dumps(state, sort_keys=True, separators=(",", ":")))

    def test_noncanonical_json_rejected(self):
        with self.assertRaises(ResearchRejection):
            decode_state(json.dumps(json.loads(encode_state(self.state)), indent=2))

    def test_existing_database_never_reset(self):
        self.store.change_model_inputs(eligible=False)
        with self.assertRaises(FileExistsError):
            DurableRecoveryStore.create(self.path, self.state, 1000)
        self.assertFalse(self.store.snapshot()[2].policy.eligible)
        self.assertEqual(self.store.snapshot()[0], 1)

    def test_aba_and_noop_increment_revision(self):
        self.store.change_model_inputs(eligible=False)
        self.store.change_model_inputs(eligible=True)
        self.assertEqual(self.store.snapshot(), (2, 1000, self.state))
        self.store.change_model_inputs()
        self.assertEqual(self.store.snapshot()[0], 3)

    def test_ledger_monotonic_and_typed(self):
        self.store.change_model_inputs(ledger=1001)
        for bad in [1000, -1, True, 1 << 32]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.store.change_model_inputs(ledger=bad)
        self.assertEqual(self.store.snapshot()[:2], (1, 1001))

    def test_flags_strict(self):
        with self.assertRaises(ResearchRejection):
            self.store.change_model_inputs(eligible=1)
        self.assertEqual(self.store.snapshot()[0], 0)

    def test_revision_overflow_rolls_back(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE model SET revision=?", (MAX_REVISION,))
        with self.assertRaises(ResearchRejection):
            self.store.change_model_inputs(eligible=False)
        self.assertEqual(self.store.snapshot(), (MAX_REVISION, 1000, self.state))

    def test_crypto_failure_never_writes_state_or_receipt(self):
        with patch("durable_recovery_research.consume_research_recovery", side_effect=ResearchRejection("reject")):
            with self.assertRaises(ResearchRejection):
                self.store.recover(self.statement.to_xdr_bytes(), Path("unused"), bytes(3309), None, Path("unused"))
        self.assertEqual(self.store.snapshot(), (0, 1000, self.state))
        self.assertEqual(self.store.receipt_count(), 0)

    def test_missing_database_is_not_silently_created(self):
        missing = Path(self.temp.name) / "missing.sqlite"
        with self.assertRaises(sqlite3.OperationalError):
            DurableRecoveryStore(missing).snapshot()
        self.assertFalse(missing.exists())

    def test_empty_model_rejected(self):
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM model")
        with self.assertRaises(ResearchRejection):
            self.store.snapshot()

    def test_reopened_store_sees_revocation(self):
        self.store.change_model_inputs(eligible=False, classical_authority_retired=False)
        state = DurableRecoveryStore(self.path).snapshot()[2]
        self.assertFalse(state.policy.eligible)
        self.assertFalse(state.policy.classical_authority_retired)


if __name__ == "__main__":
    unittest.main()
