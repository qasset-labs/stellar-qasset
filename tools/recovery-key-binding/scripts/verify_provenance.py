#!/usr/bin/env python3
"""Check local source/record/artifact consistency; no fresh cryptographic execution."""
import hashlib
import json
from pathlib import Path
from run import sources

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    provenance = json.loads((ROOT/"provenance.json").read_text())
    record = json.loads((ROOT/"evidence/research.json").read_text())
    actual = sources()
    require(provenance["source_sha256"] == actual == record["source_sha256"], "source inventory/hash mismatch")
    require(provenance["source_count"] == len(actual), "source count mismatch")
    require(provenance["security_approved"] is record["security_approved"] is False, "unapproved security flag changed")
    require(provenance["execution_record_sha256"] == hashlib.sha256((ROOT/"evidence/research.json").read_bytes()).hexdigest(), "execution record hash mismatch")
    require(record["status"] == "passed_native_and_raw_wasm_key_binding_only", "execution did not pass")
    require(record["commands"] and all(row["exit_code"] == 0 for row in record["commands"]), "failed command recorded")
    require(record["stellar_rpc_requests"] == 0 and record["submitted_transactions"] == 0, "unexpected external activity")
    require(record["native_test_count"] == 6 and record["independent_positive_vectors"] == 18, "native/vector coverage mismatch")
    require(record["wasm"] == json.loads((ROOT/"evidence/wasm.json").read_text()), "nested Wasm report mismatch")
    wasm_record = record["wasm"]
    require(wasm_record["status"] == "passed_raw_wasm_key_binding_only" and wasm_record["security_approved"] is False, "Wasm security/status mismatch")
    require(wasm_record["wasm_sha256"] == record["wasm_sha256"] and wasm_record["wasm_bytes"] == record["wasm_bytes"], "nested Wasm artifact identity mismatch")
    require(wasm_record["imports"] == [], "unexpected Wasm import")
    checks = wasm_record["checks"]
    require([row["id"] for row in checks] == list(range(26)) and all(type(row["id"]) is int for row in checks), "unique ordered case IDs mismatch")
    require(all(row["passed"] is True and row["error"] is None
                and type(row["result"]) is int and type(row["expected"]) is int
                and row["result"] == row["expected"] == (1 if row["id"] < 18 else -1 if row["id"] == 25 else 0)
                for row in checks), "actual Wasm result/rejection/trap mismatch")
    dependency = provenance["curve25519_dalek"]
    require(dependency["version"] == "4.1.3" and dependency["modified"] is False
            and dependency["default_features"] is False and dependency["precomputed_tables"] is False,
            "unreviewed dependency configuration")
    wasm = ROOT/"target/wasm32v1-none/release/qasset_recovery_key_binding_wasm.wasm"
    if wasm.exists():
        require(len(wasm.read_bytes()) == record["wasm_bytes"], "retained Wasm size mismatch")
        require(hashlib.sha256(wasm.read_bytes()).hexdigest() == record["wasm_sha256"], "retained Wasm hash mismatch")
        status = "passed_source_record_and_retained_artifact_hashes"
    else:
        status = "passed_source_record_consistency_only_artifact_missing"
    print(json.dumps({"status":status,"source_count":len(actual),"proof_execution_rerun":False,"security_approved":False}))


if __name__ == "__main__":
    main()
