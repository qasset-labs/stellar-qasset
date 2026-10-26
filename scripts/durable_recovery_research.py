"""Transactional PUBLIC-FIXTURE recovery model, never an on-chain authority.

The caller, database, binaries and proof files are operator-trusted local inputs.
SQLite persistence cannot prevent filesystem rollback or a malicious operator.
No caller-created preverified ticket can bypass the actual crypto verifiers.
"""

from contextlib import closing
from dataclasses import asdict, replace
import hashlib
import json
import logging
from pathlib import Path
import sqlite3

from recovery_statement import CurrentPolicy, check_policy_preconditions, unsigned
from verify_recovery_research import (
    RecoveryState, ResearchBackend, ResearchRejection, consume_research_recovery,
    parse_statement,
)

LOG = logging.getLogger(__name__)
MAX_REVISION = (1 << 63) - 1
BYTE_FIELDS = {"network_id", "protected_public_key", "policy_hash", "verifier_id", "parameters_id"}
SCHEMA = """
CREATE TABLE model (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 schema_version INTEGER NOT NULL CHECK(schema_version=1),
 revision INTEGER NOT NULL CHECK(revision>=0),
 ledger INTEGER NOT NULL CHECK(ledger BETWEEN 0 AND 4294967295),
 state TEXT NOT NULL
);
CREATE TABLE receipts (
 revision INTEGER PRIMARY KEY,
 statement_sha512 TEXT NOT NULL UNIQUE,
 previous_state_sha256 TEXT NOT NULL,
 current_state_sha256 TEXT NOT NULL,
 ledger INTEGER NOT NULL
);
"""


class RecoveryConflict(ResearchRejection):
    """A verified snapshot became stale; it cannot overwrite newer state."""


def encode_state(state: RecoveryState) -> str:
    """Use canonical JSON for full u64 epochs, beyond SQLite signed integers."""
    policy = asdict(state.policy)
    for name in BYTE_FIELDS:
        policy[name] = policy[name].hex()
    return json.dumps({"policy": policy, "active_public_key": state.active_public_key.hex(),
                       "consumed": state.consumed}, sort_keys=True, separators=(",", ":"))


def decode_state(raw: str) -> RecoveryState:
    """Validate persisted types and all policy structure; no coercions."""
    try:
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"policy", "active_public_key", "consumed"}:
            raise ValueError("Invalid state fields")
        policy = value["policy"]
        if type(policy) is not dict or set(policy) != set(CurrentPolicy.__dataclass_fields__):
            raise ValueError("Invalid policy fields")
        for name in BYTE_FIELDS:
            if type(policy[name]) is not str:
                raise ValueError("Invalid stored bytes")
            policy[name] = bytes.fromhex(policy[name])
        for flag in ["eligible", "classical_authority_retired"]:
            if type(policy[flag]) is not bool:
                raise ValueError("Invalid policy boolean")
        state = RecoveryState(CurrentPolicy(**policy), bytes.fromhex(value["active_public_key"]), value["consumed"])
        # Reuse the typed statement constructor to validate point/path/IDs/ranges.
        from recovery_statement import RecoveryStatement
        RecoveryStatement(state.policy.network_id, state.policy.parent_contract,
                          state.policy.protected_public_key, state.policy.relation,
                          state.policy.account_index, state.policy.epoch, state.policy.policy_hash,
                          "ML-DSA-65", state.active_public_key, 0,
                          state.policy.verifier_id, state.policy.parameters_id)
        if encode_state(state) != raw:
            raise ValueError("Noncanonical stored state")
        return state
    except (ValueError, TypeError, KeyError) as error:
        raise ResearchRejection("Invalid persisted research state") from error


class DurableRecoveryStore:
    """One local account. All writers must use this adapter's revision rules."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def _connect(self):
        # URI mode=rw prevents read/recover from silently creating an empty DB.
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True,
                             timeout=120, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    @classmethod
    def create(cls, path: Path, state: RecoveryState, ledger: int):
        unsigned(ledger, 32, "local ledger")
        encoded = encode_state(state)
        decode_state(encoded)
        # Exclusive creation never resets an existing consumed database.
        with Path(path).open("xb"):
            pass
        store = cls(path)
        with closing(store._connect()) as db:
            db.executescript("BEGIN IMMEDIATE;" + SCHEMA)
            try:
                db.execute("INSERT INTO model VALUES (1,1,0,?,?)", (ledger, encoded))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return store

    @staticmethod
    def _load(db):
        rows = db.execute("SELECT singleton,schema_version,revision,ledger,state FROM model").fetchall()
        if len(rows) != 1:
            raise ResearchRejection("Expected exactly one persisted model")
        singleton, version, revision, ledger, raw = rows[0]
        if singleton != 1 or version != 1 or type(revision) is not int or not 0 <= revision <= MAX_REVISION:
            raise ResearchRejection("Invalid schema or revision")
        unsigned(ledger, 32, "persisted ledger")
        return revision, ledger, raw, decode_state(raw)

    def snapshot(self):
        with closing(self._connect()) as db:
            revision, ledger, _, state = self._load(db)
            return revision, ledger, state

    def receipt_count(self):
        with closing(self._connect()) as db:
            return db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]

    @staticmethod
    def _next_revision(revision):
        if revision == MAX_REVISION:
            raise ResearchRejection("Revision cannot increment")
        return revision + 1

    def change_model_inputs(self, *, ledger=None, eligible=None, classical_authority_retired=None):
        """Operator-only fixture controls, NOT an authenticated product API.

        Every call increments revision, even a no-op, preventing ABA reuse.
        The ledger is a monotonic local input, never a network observation.
        """
        if ledger is not None:
            unsigned(ledger, 32, "local ledger")
        for flag in [eligible, classical_authority_retired]:
            if flag is not None and type(flag) is not bool:
                raise ResearchRejection("Invalid fixture policy flag")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                revision, current_ledger, _, state = self._load(db)
                new_ledger = current_ledger if ledger is None else ledger
                if new_ledger < current_ledger:
                    raise ResearchRejection("Local ledger cannot go backwards")
                policy = replace(state.policy,
                                 eligible=state.policy.eligible if eligible is None else eligible,
                                 classical_authority_retired=(state.policy.classical_authority_retired
                                     if classical_authority_retired is None else classical_authority_retired))
                db.execute("UPDATE model SET revision=?,ledger=?,state=? WHERE singleton=1",
                           (self._next_revision(revision), new_ledger, encode_state(replace(state, policy=policy))))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def recover(self, raw_statement: bytes, proof: Path, possession_signature: bytes,
                backend: ResearchBackend, fixture_verifier: Path):
        revision, ledger, state = self.snapshot()
        snapshot_raw = encode_state(state)
        # These real verifiers run outside the write lock. No positive callback.
        updated, verification = consume_research_recovery(
            state, raw_statement, proof, possession_signature, ledger, backend, fixture_verifier)
        statement = parse_statement(raw_statement)
        LOG.info("proof_and_possession_verified")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                current_revision, current_ledger, current_raw, current_state = self._load(db)
                if current_revision != revision or current_raw != snapshot_raw:
                    raise RecoveryConflict("Policy, ledger or consumption changed during verification")
                # Read inside the write transaction, never use caller's old ledger.
                check_policy_preconditions(statement, current_state.policy, current_ledger)
                if current_state.consumed:
                    raise ResearchRejection("Recovery permission already consumed")
                next_revision = self._next_revision(current_revision)
                updated_raw = encode_state(updated)
                changed = db.execute("UPDATE model SET revision=?,state=? WHERE singleton=1 AND revision=? AND state=?",
                                     (next_revision, updated_raw, revision, snapshot_raw))
                if changed.rowcount != 1:
                    raise RecoveryConflict("Atomic state comparison failed")
                db.execute("INSERT INTO receipts VALUES (?,?,?,?,?)",
                           (next_revision, statement.digest().hex(),
                            hashlib.sha256(snapshot_raw.encode()).hexdigest(),
                            hashlib.sha256(updated_raw.encode()).hexdigest(), current_ledger))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return updated, verification
