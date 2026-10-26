#!/usr/bin/env python3
"""Check successor source/record/artifact consistency; no fresh proof execution."""
import argparse
import hashlib
import json
from pathlib import Path

from check_verifier_port_evidence import digest, path_under, read, require

ROOT = Path(__file__).resolve().parents[1]
PIN = "115108d5a661d95c0b474b6ab02558bfe6c6bec7"
STATUS = "passed_compact_raw_external_fixture_only_not_soroban_contract"
GOLDEN = [394127921, 1463445479, 3541783]
PROOF = "e383a3cc44c30b0028b764e11130bdb27454221e0d67a5b82d90abe70047f461"
SETUP = "0d1a3b775ce006e07df6af3aa1491d2d7c29202e11985fd6045ef398cb3be424"
ORIGINAL_SETUP = "4d6fd19ea0092a261ed7041985b679ecad4b45f9cc6452a7a717979be7c35ef3"
CONSTRAINTS = "0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938"


def check(package, require_artifacts=False, limits=None):
    provenance = read(package, "provenance.json")
    pins = read(package, "pins.json")
    research = read(package, "evidence/research.json")
    execution = read(package, "evidence/final-run.json")
    wasm = read(package, "evidence/final-optimized-results.json")
    raw = read(package, "evidence/final-raw-results.json")
    arithmetic = read(package, "evidence/final-arithmetic-results.json")
    transcode = read(package, "evidence/lossless-transcode.json")
    actual = {str(p.relative_to(package)): digest(p) for p in sorted(package.rglob("*"))
              if p.is_file() and not set(p.relative_to(package).parts) & {"target", "evidence", "__pycache__", ".git"}
              and p.name != "provenance.json" and p.suffix not in {".stdout", ".stderr", ".wasm"}}
    require(actual == provenance["source_sha256"] == research["source_sha256"] == execution["source_sha256"],
            "successor source inventory/hash/lineage mismatch")
    require(provenance["source_count"] == len(actual) == research["source_count"], "source count mismatch")
    require(research["provenance_sha256"] == digest(package / "provenance.json"), "provenance identity mismatch")
    for record in [pins, provenance]:
        require(record["upstream_revision"] == PIN and record["security_approved"] is False, "upstream/security identity mismatch")
    for record in [provenance, research, execution]:
        require(record["security_approved"] is False and record["soroban_compatible"] is False,
                "raw successor cannot promote security or Soroban compatibility")
    for record in [research, execution]:
        require(record["status"] == STATUS and record["stellar_rpc_requests"] == 0
                and record["submitted_transactions"] == 0, "incomplete or externally active record")
    require(execution["commands"] and all(row["exit_code"] == 0 for row in execution["commands"]), "failed execution command")
    for relative, origin in provenance["vendor_origin"].items():
        require(actual.get("vendor/binius64/" + relative) == origin["local_sha256"], "vendor local identity mismatch")
        require(origin["modified_from_upstream"] is (origin["upstream_sha256"] != origin["local_sha256"]), "vendor modification classification mismatch")
    require({name.removeprefix("vendor/binius64/") for name in actual if name.startswith("vendor/binius64/")}
            == set(provenance["vendor_origin"]), "vendor origin inventory mismatch")
    require(pins["proof_sha256"] == PROOF and pins["compact_setup_sha256"] == SETUP
            and pins["original_setup_sha256"] == ORIGINAL_SETUP and pins["padded_constraints_sha256"] == CONSTRAINTS
            and pins["program_source_sha256"] == actual["external-input/src/native.rs"], "fixed relation identity mismatch")
    require(pins["upstream_security_bits"] == 96 and pins["fri_queries"] == 232
            and pins["log_inverse_rate"] == 1, "unreviewed proof parameter change")
    require(research["setup"] == {"bytes": 1286664, "sha256": SETUP}, "compact setup record mismatch")
    require(transcode["byte_exact_expansion_equal"] is True and transcode["security_approved"] is False
            and transcode["original_sha256"] == ORIGINAL_SETUP and transcode["compact_sha256"] == SETUP
            and transcode["original_bytes"] == 2714051 and transcode["compact_bytes"] == 1286664,
            "lossless transcode evidence mismatch")
    require(research["wasm"] == wasm and research["arithmetic"] == arithmetic, "nested successor evidence mismatch")
    native = research["native"]
    require(native["all_passed"] is True and native["padded_constraints_passed"] is True
            and native["padded_constraints_sha256"] == CONSTRAINTS and native["padded_count"] == 131072
            and native["retained_unpadded_count"] == 0 and native["unpadded_count_metadata"] == 82373,
            "retained/padded constraint identity mismatch")
    require([row["name"] for row in native["checks"]] == ["canonical", "changed_action", "corrupt", "trailing", "truncated", "empty"], "native case coverage mismatch")
    for index, row in enumerate(native["checks"]):
        reason = None if index == 0 else "trailing_or_unread_proof" if index == 3 else "verification_failed"
        require(row["passed"] is True and row["accepted"] is (index == 0) and row["error"] == reason,
                "native failure/result misclassified")
    names = ["canonical", "changed_action", "corrupted_proof", "trailing_proof", "truncated_proof", "empty_proof",
             "changed_scalar", "padded_constraints_match_native_identity", "unclamped_scalar",
             "changed_preprocessing", "trailing_preprocessing", "truncated_preprocessing"]
    for report in [wasm, raw]:
        require(report["all_passed"] is True and report["transcript_vector_passed"] is True
                and report["transcript_vector"] == GOLDEN and report["setup_sha256"] == SETUP
                and report["proof_sha256"] == PROOF, "raw Wasm protocol identity mismatch")
        require([row["name"] for row in report["checks"]] == names
                and [row["id"] for row in report["checks"]] == list(range(12)), "Wasm case inventory mismatch")
        for index, row in enumerate(report["checks"]):
            expected = int(index in (0, 7))
            reason = "preprocessing_identity_or_decode_failed" if index >= 9 else "trailing_or_unread_proof" if index == 3 else "verification_failed" if index in (1, 2, 4, 5) else ""
            require(type(row["result"]) is int and row["result"] == row["expected"] == expected
                    and row["passed"] is True and row["runtime_error"] is None and row["rejection_code"] == reason
                    and row["repeat_result"] == 0, "Wasm trap/rejection/result mismatch")
            require(row["phase"] == (1 if index >= 9 else 0 if index in (6, 8) else 3), "Wasm guard/proof rejection misclassified")
            require(0 <= row["allocated_end"] <= row["linear_memory_bytes"] <= 41943040, "Wasm memory bound mismatch")
        require([row["name"] for row in report["bounds"]] == ["empty_setup", "oversize_setup", "oversize_proof", "verify_without_input", "input_slot_can_be_prepared_once"]
                and all(row["passed"] is True for row in report["bounds"])
                and all(row["result"] == 0 for row in report["bounds"][:3]), "input slot/bounds coverage mismatch")
    require(native["transcript_vector"] == GOLDEN and native["transcript_vector_passed"] is True, "native challenger mismatch")
    inspection = research["inspection"]
    require(inspection["imports"] == [] and inspection["float_operator_count"] == 0 and inspection["float_operators"] == []
            and inspection["no_float_simd_threads_validation"] == "passed", "Wasm inspection mismatch")
    memories = inspection["memories"]
    require(len(memories) == 1 and memories[0]["maximum_pages"] == 640 and memories[0]["initial_pages"] <= 640
            and memories[0]["memory64"] is False and memories[0]["shared"] is False, "declared memory mismatch")
    artifact = research["artifact"]
    require(artifact["bytes"] == wasm["wasm_bytes"] == inspection["bytes"] == execution["wasm_bytes"]
            and artifact["sha256"] == wasm["wasm_sha256"] == execution["wasm_sha256"], "successor artifact identity mismatch")
    snapshot = read(ROOT, "docs/verifier-network-limits.json") if limits is None else limits
    caps = [row["contract_max_size_bytes"] for row in snapshot["response"]["updated_entry"] if "contract_max_size_bytes" in row]
    require(snapshot["status"] == "passed_read_only_partial_snapshot" and snapshot["read_only"] is True
            and len(caps) == 1 and type(caps[0]) is int and 0 < artifact["bytes"] <= caps[0],
            "raw module exceeds or lacks recorded partial network code cap")
    require(arithmetic["all_passed"] is True and arithmetic["vectors"] == 646
            and arithmetic["reference_sha256"] == digest(package / "reference/inverse-original-native.txt"), "arithmetic reference mismatch")
    reference_rows = (package / "reference/inverse-original-native.txt").read_text().splitlines()
    require(len(reference_rows) == 646 and all(len(row.split()) == 3 for row in reference_rows),
            "arithmetic reference vector count mismatch")
    expected_output_hash = hashlib.sha256(("\n".join(row.split()[1] for row in reference_rows) + "\n").encode()).hexdigest()
    rows = arithmetic["results"]
    require([row["name"] for row in rows] == ["original_wasm_table", "compact_wasm_squaring"]
            and all(row["all_passed"] is True and row["failures"] == [] and row["vectors"] == 646 for row in rows)
            and rows[0]["output_sha256"] == rows[1]["output_sha256"] == expected_output_hash,
            "arithmetic equivalence mismatch")
    expected_artifacts = {artifact["path"]: (artifact["bytes"], artifact["sha256"]),
                          "target/bin/qasset_binius_external_input.raw.wasm": (raw["wasm_bytes"], raw["wasm_sha256"]),
                          "target/fixtures/fixed-setup.bin": (1286664, SETUP), "target/fixtures/proof.bin": (539888, PROOF)}
    checked, missing = [], []
    for name, (size, sha) in expected_artifacts.items():
        require(name.startswith("target/"), "unexpected artifact location")
        path = path_under(package, name)
        if path.exists():
            require(path.stat().st_size == size and digest(path) == sha, "retained successor artifact mismatch: " + name)
            checked.append(name)
        else:
            missing.append(name)
    require(not require_artifacts or not missing, "required ignored successor artifacts are missing")
    return {"status": "passed_source_records_and_retained_artifact_hashes" if not missing else "passed_source_and_record_consistency_only",
            "source_count": len(actual), "raw_module_bytes": artifact["bytes"], "recorded_partial_code_cap_bytes": caps[0],
            "raw_module_margin_bytes": caps[0] - artifact["bytes"], "artifacts_checked": checked, "ignored_artifacts_missing": missing,
            "fresh_proof_execution": False, "security_approved": False, "soroban_compatible": False,
            "scope": "Local source/record/hash consistency only; raw size fit is not a Soroban contract ABI, successful SDK verification, current network guarantee or security attestation."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=ROOT / "tools/binius-verifier-next")
    parser.add_argument("--require-artifacts", action="store_true")
    args = parser.parse_args()
    try:
        result = check(args.package.resolve(), args.require_artifacts)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        raise SystemExit(1) from error
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
