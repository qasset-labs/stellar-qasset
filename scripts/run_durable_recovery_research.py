#!/usr/bin/env python3
"""PUBLIC-FIXTURE real-proof process races, persistence and rollback experiment.

No RPC/deployment. Eight-round proofs are insecure. Pausing a worker happens
only AFTER actual native proof and replacement PoP verification have succeeded.
"""

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
import logging
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time

from check_seed_recovery_evidence import public_fixture_policy
from durable_recovery_research import DurableRecoveryStore
from verify_recovery_research import (
    RecoveryState, ResearchBackend, parse_statement, replacement_possession_digest,
)

ROOT = Path(__file__).resolve().parents[1]


def fixture(args):
    record = json.loads((ROOT / "docs/seed-proof-research.json").read_text())
    backend = ResearchBackend.from_record(record, args.proof_binary)
    statement = parse_statement(bytes.fromhex(record["statement"]["canonical_xdr_hex"]))
    def helper(*parts):
        result = subprocess.run([str(args.fixture_helper.resolve()), *parts],
                                text=True, capture_output=True, check=True, timeout=60)
        return bytes.fromhex(result.stdout.strip())
    active = helper("public-key", "active")
    if helper("public-key", "replacement") != statement.replacement_public_key:
        raise RuntimeError("Fixture replacement mismatch")
    signature = helper("sign", "replacement", replacement_possession_digest(statement).hex(), "RECOVERY")
    return statement, RecoveryState(public_fixture_policy(statement), active), signature, backend


class ProcessBarrier(logging.Handler):
    def emit(self, record):
        if record.getMessage() == "proof_and_possession_verified":
            print(json.dumps({"phase": "real_proof_and_pop_verified"}), flush=True)
            if sys.stdin.readline().strip() != "commit":
                raise RuntimeError("Parent did not release research barrier")


def worker(args):
    statement, _, signature, backend = fixture(args)
    logger = logging.getLogger("durable_recovery_research")
    logger.setLevel(logging.INFO)
    logger.addHandler(ProcessBarrier())
    try:
        state, _ = DurableRecoveryStore(args.worker).recover(
            statement.to_xdr_bytes(), args.proof, signature, backend, args.fixture_helper)
        print(json.dumps({"result": "committed", "epoch": state.policy.epoch,
                          "consumed": state.consumed}), flush=True)
    except Exception as error:
        print(json.dumps({"result": "rejected", "error_type": type(error).__name__,
                          "error": str(error)}), flush=True)
        return 2
    return 0


def main(args):
    output = args.output
    evidence = {"schema": "qasset-durable-recovery-research-v1", "status": "in_progress",
                "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "checks": [],
                "proof_security": "INSECURE_EIGHT_ROUNDS_UNAUDITED_RESEARCH_ONLY",
                "network_requests": 0, "submitted_transactions": 0,
                "retirement_eligibility_and_ledger_are_local_fixture_inputs": True}
    def save():
        output.write_text(json.dumps(evidence, indent=2) + "\n")
    def check(label, details):
        evidence["checks"].append({"label": label, "passed": True, "details": details})
        save()
        print("PASS:", label, flush=True)
    sources = ["scripts/run_durable_recovery_research.py", "scripts/durable_recovery_research.py",
               "scripts/verify_recovery_research.py", "scripts/recovery_statement.py",
               "scripts/check_seed_recovery_evidence.py", "docs/seed-proof-research.json",
               "tools/pq-demo/src/main.rs", "tools/pq-demo/Cargo.toml", "tools/pq-demo/Cargo.lock"]
    initial = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
    save()
    children = []
    try:
        statement, state, _, _ = fixture(args)
        proof_hash = hashlib.sha256(args.proof.read_bytes()).hexdigest()
        proof_record = json.loads((ROOT / "docs/seed-proof-research.json").read_text())
        if proof_hash != proof_record["proof_sha256"]:
            raise RuntimeError("Public fixture proof hash mismatch")
        evidence.update({"source_sha256": initial, "proof_sha256": proof_hash,
                         "proof_verifier_binary_sha256": hashlib.sha256(args.proof_binary.read_bytes()).hexdigest(),
                         "fixture_helper_binary_sha256": hashlib.sha256(args.fixture_helper.read_bytes()).hexdigest(),
                         "statement_sha512": statement.digest().hex(), "initial_epoch": state.policy.epoch})
        save()
        def start(db):
            command = [sys.executable, "-u", str(Path(__file__).resolve()), "--worker", str(db),
                       "--proof", str(args.proof.resolve()), "--proof-binary", str(args.proof_binary.resolve()),
                       "--fixture-helper", str(args.fixture_helper.resolve())]
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            children.append(child)
            return child
        def ready(child):
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=180):
                    raise RuntimeError("Timed out awaiting real native verification")
            line = child.stdout.readline()
            if json.loads(line).get("phase") != "real_proof_and_pop_verified":
                raise RuntimeError("Worker failed before real cryptography barrier: " + line)
        def finish(child, release=True):
            if release:
                child.stdin.write("commit\n")
                child.stdin.flush()
            stdout, stderr = child.communicate(timeout=180)
            result = json.loads(stdout.strip())
            if ((result.get("result") == "committed" and child.returncode != 0)
                    or (result.get("result") == "rejected" and child.returncode != 2)):
                raise RuntimeError("Worker result/exit mismatch: " + stderr)
            return result
        with tempfile.TemporaryDirectory(prefix="qasset-durable-fixtures-") as directory:
            folder = Path(directory)
            def create(name):
                return DurableRecoveryStore.create(folder / (name + ".sqlite"), state, 1000)
            duplicate = create("duplicate")
            pair = [start(duplicate.path), start(duplicate.path)]
            for child in pair:
                ready(child)
            # Both processes have independently verified the actual proof+PoP.
            for child in pair:
                child.stdin.write("commit\n")
                child.stdin.flush()
            results = [finish(child, release=False) for child in pair]
            if sorted(r["result"] for r in results) != ["committed", "rejected"]:
                raise RuntimeError("Expected exactly one concurrent recovery winner")
            loser = next(r for r in results if r["result"] == "rejected")
            if loser["error_type"] != "RecoveryConflict" or duplicate.receipt_count() != 1:
                raise RuntimeError("Race did not reject specifically through snapshot conflict")
            revision, ledger, updated = DurableRecoveryStore(duplicate.path).snapshot()
            if (revision, ledger, updated.policy.epoch, updated.consumed, updated.policy.eligible,
                    updated.active_public_key) != (1, 1000, state.policy.epoch + 1, True, False, statement.replacement_public_key):
                raise RuntimeError("Incorrect durable winning state")
            check("two_real_proof_processes_exactly_one_atomic_commit", results)
            replay = finish(start(duplicate.path), release=False)
            if replay["result"] != "rejected" or replay["error_type"] != "ResearchRejection" or duplicate.receipt_count() != 1:
                raise RuntimeError("Persisted consumption was reused")
            check("new_process_replay_rejected_after_reopen", replay)
            try:
                DurableRecoveryStore.create(duplicate.path, state, 1000)
            except FileExistsError:
                check("initialization_cannot_reset_consumed_database", "exclusive creation rejected")
            else:
                raise RuntimeError("Existing consumption was reset")
            for name in ["revoke", "retirement", "expiry", "aba"]:
                store = create(name)
                child = start(store.path)
                ready(child)
                if name == "revoke":
                    store.change_model_inputs(eligible=False)
                elif name == "retirement":
                    store.change_model_inputs(classical_authority_retired=False)
                elif name == "expiry":
                    store.change_model_inputs(ledger=statement.valid_until_ledger + 1)
                else:
                    store.change_model_inputs(eligible=False)
                    store.change_model_inputs(eligible=True)
                result = finish(child)
                if result.get("error_type") != "RecoveryConflict" or store.receipt_count() != 0 or store.snapshot()[2].consumed:
                    raise RuntimeError("Stale verified snapshot survived " + name)
                check(name + "_during_real_verification_blocks_commit", result)
            rollback = create("rollback")
            # Database-level fault AFTER UPDATE: abort receipt insert, not crypto.
            with sqlite3.connect(rollback.path) as db:
                db.execute("CREATE TRIGGER reject_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT, 'fixture receipt failure'); END")
            child = start(rollback.path)
            ready(child)
            result = finish(child)
            if result.get("error_type") != "IntegrityError" or rollback.snapshot() != (0, 1000, state) or rollback.receipt_count() != 0:
                raise RuntimeError("State escaped a failed receipt transaction")
            check("receipt_failure_rolls_back_rotation_and_consumption", result)
            with sqlite3.connect(rollback.path) as db:
                db.execute("DROP TRIGGER reject_receipt")
            child = start(rollback.path)
            ready(child)
            result = finish(child)
            if result.get("result") != "committed" or rollback.receipt_count() != 1:
                raise RuntimeError("Recovery could not retry after a rollback")
            check("fresh_real_verification_commits_after_rolled_back_attempt", result)
        if hashlib.sha256(args.proof.read_bytes()).hexdigest() != proof_hash:
            raise RuntimeError("Trusted proof fixture changed during experiment")
        if any(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != h for p, h in initial.items()):
            raise RuntimeError("Experiment sources changed during execution")
        evidence.update({"status": "passed_durable_local_research_only", "real_proof_successes_before_commit": 8,
                         "sqlite_version": sqlite3.sqlite_version,
                         "limits": ["Local trusted SQLite model only; not a Stellar contract or transaction.",
                                    "Proof uses insecure eight-round research parameters; no cryptographic security certification.",
                                    "Retirement, eligibility and ledger are operator-controlled fixture assumptions.",
                                    "All writers must use the adapter; malicious operator, disk rollback, compromised binaries and untrusted proof-file mutation are outside this model.",
                                    "Concurrency and rollback tests are controlled processes and SQL aborts; power-loss durability is not experimentally tested.",
                                    "Receipts bind requests and model states, not independent proof certificates or network observations."]})
        save()
    except Exception as error:
        evidence.update({"status": "failed", "error_type": type(error).__name__, "error": str(error)})
        save()
        raise
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--proof", type=Path, default=ROOT / "target/seed-recovery-research/proof.postcard")
    parser.add_argument("--proof-binary", type=Path, default=ROOT / "tools/seed-recovery-research/target/release/qasset-zk-seed-research")
    parser.add_argument("--fixture-helper", type=Path, default=ROOT / "tools/pq-demo/target/release/qasset-pq-demo-tool")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/durable-recovery-research.json")
    arguments = parser.parse_args()
    if arguments.worker:
        raise SystemExit(worker(arguments))
    main(arguments)
