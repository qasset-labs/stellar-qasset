#!/usr/bin/env python3
"""PUBLIC-FIXTURE local recovery ceremony with real proof and replacement PoP.

The proof uses insecure research parameters. Policy flags are explicit local
assumptions. No RPC, real-wallet inputs, deployments, or transaction submission.
"""

import argparse
from dataclasses import replace
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess

from check_seed_recovery_evidence import public_fixture_policy
from verify_recovery_research import (
    LEAF_PUBLIC, ResearchBackend, ResearchProofRejected, RecoveryState, consume_research_recovery,
    parse_statement, replacement_possession_digest,
)

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, default=ROOT / "target/seed-recovery-research/proof.postcard")
    parser.add_argument("--proof-binary", type=Path, default=ROOT / "tools/seed-recovery-research/target/release/qasset-zk-seed-research")
    parser.add_argument("--fixture-helper", type=Path, default=ROOT / "tools/pq-demo/target/release/qasset-pq-demo-tool")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/recovery-ceremony-research.json")
    args = parser.parse_args()
    record_path = ROOT / "docs/seed-proof-research.json"
    record = json.loads(record_path.read_text())
    evidence = {"schema": "qasset-local-recovery-ceremony-research-v1", "status": "in_progress",
                "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "checks": [],
                "network_requests": 0, "submitted_transactions": 0,
                "policy_flags_are_fixture_assumptions": True, "state_transition_is_in_memory_only": True,
                "proof_security": "INSECURE_EIGHT_ROUNDS_UNAUDITED_RESEARCH_ONLY"}

    def save():
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")

    def helper(*parts, expect_failure=False):
        result = subprocess.run([str(args.fixture_helper.resolve()), *parts], text=True, capture_output=True, timeout=60)
        if expect_failure:
            if result.returncode != 1:
                raise RuntimeError("Expected real ML-DSA rejection")
        elif result.returncode != 0:
            raise RuntimeError("Public-fixture helper failed")
        return result.stdout.strip()

    def check(label, kind):
        evidence["checks"].append({"label": label, "kind": kind, "passed": True})

    save()
    try:
        sources = ["scripts/run_recovery_ceremony_research.py", "scripts/verify_recovery_research.py",
                   "tools/pq-demo/src/main.rs", "tools/pq-demo/Cargo.toml", "tools/pq-demo/Cargo.lock",
                   "scripts/recovery_statement.py", "docs/seed-proof-research.json"]
        initial = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
        proof_hash = hashlib.sha256(args.proof.read_bytes()).hexdigest()
        if proof_hash != record["proof_sha256"]:
            raise RuntimeError("Proof does not match the recorded source experiment")
        backend = ResearchBackend.from_record(record, args.proof_binary)
        statement = parse_statement(bytes.fromhex(record["statement"]["canonical_xdr_hex"]))
        state = RecoveryState(public_fixture_policy(statement), bytes.fromhex(helper("public-key", "active")))
        if bytes.fromhex(helper("public-key", "replacement")) != statement.replacement_public_key:
            raise RuntimeError("Fixture replacement key differs from the recorded statement")
        signature = bytes.fromhex(helper("sign", "replacement", replacement_possession_digest(statement).hex(), "RECOVERY"))
        raw = statement.to_xdr_bytes()
        evidence.update({"source_sha256": initial, "proof_sha256": proof_hash,
                         "proof_record_sha256": initial["docs/seed-proof-research.json"],
                         "proof_verifier_binary_sha256": hashlib.sha256(args.proof_binary.read_bytes()).hexdigest(),
                         "fixture_helper_binary_sha256": hashlib.sha256(args.fixture_helper.read_bytes()).hexdigest(),
                         "initial_epoch": state.policy.epoch, "statement_sha512": statement.digest().hex()})
        save()
        for label, candidate_state, candidate_raw, candidate_sig in [
            ("wrong_public_anchor", state, replace(statement, protected_public_key=LEAF_PUBLIC).to_xdr_bytes(), signature),
            ("wrong_root_path", state, replace(statement, account_index=1).to_xdr_bytes(), signature),
            ("stale_epoch", replace(state, policy=replace(state.policy, epoch=8)), raw, signature),
            ("revoked_eligibility", replace(state, policy=replace(state.policy, eligible=False)), raw, signature),
            ("classical_authority_still_active", replace(state, policy=replace(state.policy, classical_authority_retired=False)), raw, signature),
            ("trailing_xdr_bytes", state, raw + b"\0", signature),
            ("forged_replacement_possession", state, raw, bytes(3309)),
        ]:
            try:
                consume_research_recovery(candidate_state, candidate_raw, args.proof, candidate_sig, 1000,
                                          backend, args.fixture_helper)
            except ValueError:
                check(label, "real_ml_dsa_rejection" if label == "forged_replacement_possession" else "typed_request_or_policy_model_rejection")
            else:
                raise RuntimeError("Invalid request unexpectedly returned a new state")
        print("Checking an old proof against a newly signed, otherwise-current epoch request...", flush=True)
        changed = replace(statement, policy_epoch=8)
        newer_state = replace(state, policy=replace(state.policy, epoch=8))
        newer_pop = bytes.fromhex(helper("sign", "replacement", replacement_possession_digest(changed).hex(), "RECOVERY"))
        helper("verify", changed.replacement_public_key.hex(), replacement_possession_digest(changed).hex(), newer_pop.hex(), "RECOVERY")
        try:
            consume_research_recovery(newer_state, changed.to_xdr_bytes(), args.proof, newer_pop, 1000,
                                      backend, args.fixture_helper)
        except ResearchProofRejected:
            check("old_proof_rejected_for_otherwise_current_new_epoch", "real_proof_rejection_after_valid_replacement_possession")
        else:
            raise RuntimeError("Proof was transferable to a changed request")
        print("Consuming the exact request with the real original-root proof and replacement signature...", flush=True)
        updated, verification = consume_research_recovery(state, raw, args.proof, signature, 1000,
                                                          backend, args.fixture_helper)
        if not (updated.consumed and updated.policy.epoch == state.policy.epoch + 1
                and updated.policy.eligible is False and updated.active_public_key == statement.replacement_public_key):
            raise RuntimeError("Incorrect model transition")
        check("exact_original_root_proof_and_possession_rotate_model_key", "real_proof_and_ml_dsa_with_local_state_transition")
        try:
            consume_research_recovery(updated, raw, args.proof, signature, 1000, backend, args.fixture_helper)
        except ValueError:
            check("second_consumption_rejected", "local_consumed_state_rejection")
        else:
            raise RuntimeError("Recovery permission was reused")
        action = hashlib.sha256(b"qasset-research-post-recovery-action-v1" + updated.policy.epoch.to_bytes(8, "big")
                                + updated.policy.parent_contract.encode("ascii")).hexdigest()
        replacement_sig = helper("sign", "replacement", action, "AUTH")
        helper("verify", updated.active_public_key.hex(), action, replacement_sig, "AUTH")
        check("replacement_key_signature_verifies_after_model_rotation", "real_ml_dsa_verification")
        old_sig = helper("sign", "active", action, "AUTH")
        helper("verify", updated.active_public_key.hex(), action, old_sig, "AUTH", expect_failure=True)
        check("old_active_key_signature_fails_under_replacement_key", "real_ml_dsa_verification")
        if state.consumed or state.policy.epoch != statement.policy_epoch:
            raise RuntimeError("Input model state mutated")
        if any(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != h for p, h in initial.items()):
            raise RuntimeError("Ceremony inputs changed while checks ran")
        evidence.update({"status": "passed_local_research_ceremony_only", "final_epoch": updated.policy.epoch,
                         "final_consumed": updated.consumed, "final_recovery_eligibility": updated.policy.eligible,
                         "replacement_key_sha256": hashlib.sha256(updated.active_public_key).hexdigest(),
                         "real_proof_verification": verification,
                         "limits": ["The backend uses deliberately insecure eight-round proof parameters.",
                                    "Retirement and eligibility are explicit local fixture assumptions, not observed network facts.",
                                    "The model updates in memory; it is not an on-chain recovery transaction or custody guarantee.",
                                    "No complete asset adapter, pending-authority/cache lifecycle, or independent cryptographic audit is implemented."]})
        save()
        print(f"PASS: {len(evidence['checks'])} ceremony checks; local research only.")
    except Exception as error:
        evidence.update({"status": "failed", "error_type": type(error).__name__, "error": str(error)})
        save()
        raise


if __name__ == "__main__":
    main()
