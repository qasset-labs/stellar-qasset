#!/usr/bin/env python3
"""Check retained port sources/records and available artifacts; never rerun proofs.

Hashes establish local consistency, not independent attestation or production security.
Absent ignored artifacts produce an explicit source/record-only result.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PIN = "115108d5a661d95c0b474b6ab02558bfe6c6bec7"
STATUS = "passed_raw_wasm_fixed_fixture_only_not_soroban_contract"
GOLDEN = [394127921, 1463445479, 3541783]
EXCLUDED = {"target", "__pycache__", ".git", "evidence"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def path_under(base, name):
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts
            and str(relative) == name, "unsafe manifest path")
    result = base / name
    require(result.resolve().is_relative_to(base.resolve()), "escaping manifest path")
    return result


def read(base, name):
    return json.loads(path_under(base, name).read_text())


def check(package, require_artifacts=False):
    provenance = read(package, "provenance.json")
    pins = read(package, "pins.json")
    research = read(package, "evidence/research.json")
    reproduction = read(package, "evidence/reproduction.json")
    native = read(package, "evidence/native-results.json")
    wasm = read(package, "evidence/wasm-results.json")
    inspection = read(package, "evidence/wasm-inspection.json")
    original = read(package, "evidence/original-native-transcript-vector.json")
    expected = provenance["source_sha256"]
    actual = {str(p.relative_to(package)): digest(p) for p in sorted(package.rglob("*"))
              if p.is_file() and not set(p.relative_to(package).parts) & EXCLUDED
              and p.name != "provenance.json"}
    require(actual == expected, "package source inventory/hash mismatch")
    require(provenance["source_count"] == len(actual) == research["source_count"],
            "source count mismatch")
    for record in [provenance, pins]:
        require(record["upstream_revision"] == PIN, "upstream revision mismatch")
        require(record["security_approved"] is False, "unapproved security flag changed")
    for relative, origin in provenance["vendor_origin"].items():
        name = "vendor/binius64/" + relative
        require(name in actual and actual[name] == origin["local_sha256"], "vendor hash mismatch")
        require(origin["modified"] is (origin["upstream_sha256"] != origin["local_sha256"]),
                "vendor modification classification mismatch")
    vendor_inventory = {name.removeprefix("vendor/binius64/") for name in actual
                        if name.startswith("vendor/binius64/")}
    require(vendor_inventory == set(provenance["vendor_origin"]), "vendor origin inventory mismatch")
    require(research["source_sha256"] == expected == reproduction["source_sha256"],
            "execution record source lineage mismatch")
    require(research["provenance_sha256"] == digest(package / "provenance.json"),
            "execution provenance hash mismatch")
    for record in [research, reproduction]:
        require(record["status"] == STATUS and record["security_approved"] is False,
                "incomplete/overstated execution record")
        require(record["stellar_rpc_requests"] == 0 and record["submitted_transactions"] == 0,
                "unexpected external activity")
    require(reproduction["commands"] and all(row["exit_code"] == 0 for row in reproduction["commands"]),
            "record contains unsuccessful command")
    require(research["native"] == native and research["wasm"] == wasm
            and research["inspection"] == inspection, "nested evidence mismatch")
    require(pins["upstream_security_bits"] == 96 and pins["fri_queries"] == 232
            and pins["log_inverse_rate"] == 1, "unreviewed parameter change")
    require(original["upstream_revision"] == PIN and original["challenger_modified"] is False
            and original["vector"] == GOLDEN, "original challenger evidence mismatch")
    for record in [native, wasm]:
        require(record["all_passed"] is True and record["transcript_vector_passed"] is True
                and record["transcript_vector"] == GOLDEN, "cross-target challenger mismatch")
    native_names = ["canonical", "changed_action", "corrupt", "trailing", "truncated", "empty"]
    require([row["name"] for row in native["checks"]] == native_names, "native case coverage mismatch")
    for index, row in enumerate(native["checks"]):
        require(row["passed"] is True and row["accepted"] is (index == 0), "native case result mismatch")
        reason = None if index == 0 else "trailing_or_unread_proof" if index == 3 else "verification_failed"
        require(row["error"] == reason, "native failure was not expected proof rejection")
    require(native["padded_constraints_passed"] is True
            and native["padded_constraints_sha256"] == "0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938",
            "padded constraint identity mismatch")
    wasm_names = ["canonical", "changed_action", "corrupted_proof", "trailing_proof", "truncated_proof",
                  "empty_proof", "changed_scalar", "padded_constraints_match_native_identity", "unclamped_scalar"]
    require([row["name"] for row in wasm["checks"]] == wasm_names, "Wasm case coverage mismatch")
    for index, row in enumerate(wasm["checks"]):
        accepted = int(index in (0, 7))
        require(row["id"] == index and row["expected"] == row["result"] == accepted
                and row["passed"] is True and row["error"] is None, "Wasm trap/error/result mismatch")
        require(0 <= row["allocated_end"] <= row["linear_memory_bytes"] <= 40 * 1024 * 1024,
                "Wasm memory bounds mismatch")
        require(row["phase"] == (0 if index in (6, 8) else 3), "guard and proof rejection misclassified")
    require(inspection["float_operator_count"] == 0 and inspection["float_operators"] == []
            and inspection["imports"] == []
            and inspection["no_float_simd_threads_validation"] == "passed", "Wasm inspection mismatch")
    memories = inspection["memories"]
    require(len(memories) == 1 and memories[0]["maximum_pages"] == 640
            and memories[0]["initial_pages"] <= 640 and memories[0]["memory64"] is False
            and memories[0]["shared"] is False, "linear memory declaration mismatch")
    artifacts = research["artifacts"]
    wasm_meta = artifacts["target/bin/qasset_binius_wasm_fixture.wasm"]
    require(wasm_meta["sha256"] == wasm["wasm_sha256"] == reproduction["wasm_sha256"]
            and wasm_meta["bytes"] == wasm["wasm_bytes"] == inspection["bytes"], "Wasm artifact lineage mismatch")
    for name, pin_key in [("target/fixtures/proof.bin", "proof_sha256"),
                          ("target/fixtures/fixed-setup.bin", "setup_sha256")]:
        require(artifacts[name]["sha256"] == pins[pin_key] == reproduction[pin_key], "fixture identity mismatch")
    require(pins["proof_sha256"] == read(ROOT, "docs/binius-seed-research.json")["proof_sha256"],
            "port proof differs from canonical recovery evidence")
    checked, missing = [], []
    for name, metadata in artifacts.items():
        require(name.startswith("target/"), "unexpected artifact location")
        path = path_under(package, name)
        if path.exists():
            require(path.stat().st_size == metadata["bytes"] and digest(path) == metadata["sha256"],
                    "retained artifact hash/size mismatch: " + name)
            checked.append(name)
        else:
            missing.append(name)
    require(not require_artifacts or not missing, "required ignored artifacts are missing")
    return {"status": "passed_source_records_and_retained_artifact_hashes" if not missing
            else "passed_source_and_record_consistency_only", "source_count": len(actual),
            "retained_artifacts_checked": checked, "ignored_artifacts_missing": missing,
            "proof_execution_rerun": False, "security_approved": False,
            "scope": "Local consistency only; no independent attestation, fresh execution, Soroban metering or production security approval."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=ROOT / "tools/binius-verifier-port")
    parser.add_argument("--require-artifacts", action="store_true")
    args = parser.parse_args()
    try:
        result = check(args.package.resolve(), args.require_artifacts)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        raise SystemExit(1) from error
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
