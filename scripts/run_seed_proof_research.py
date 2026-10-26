#!/usr/bin/env python3
"""Opt-in, off-chain, INSECURE reduced-round original-seed proof experiment.

Uses published fixtures only and an attributed, pinned upstream ZKBoo circuit.
Builds a research binary, generates a proof, then invokes a separate verifier
process with only the proof and a public statement digest. No Stellar RPC/signing.
"""

import argparse
from dataclasses import replace
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

import check_recovery_relation as relation
from check_seed_recovery_evidence import public_fixture_statement

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/seed-recovery-research"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_sources():
    return ["tools/seed-recovery-research/Cargo.toml", "tools/seed-recovery-research/Cargo.lock",
            "tools/seed-recovery-research/src/main.rs", "tools/seed-recovery-research/upstream-pins.json",
            "scripts/run_seed_proof_research.py", "scripts/recovery_statement.py",
            "scripts/check_seed_recovery_evidence.py", "scripts/check_recovery_relation.py",
            "docs/recovery-relation-vectors.json"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--rounds", type=int, choices=range(1, 17), default=8)
    parser.add_argument("--relation", choices=["leaf", "sep5-root"], default="sep5-root")
    parser.add_argument("--target-dir", type=Path, default=TOOL / "target")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--fixture-signer", type=Path, default=ROOT / "tools/pq-demo/target/release/qasset-pq-demo-tool")
    parser.add_argument("--report-path", type=Path, default=ROOT / "docs/seed-proof-research.json")
    args = parser.parse_args()
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="qasset-seed-proof-public-"))
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": "qasset-original-seed-proof-research-v1", "status": "in_progress",
              "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "security": "INSECURE_REDUCED_ROUNDS_UNAUDITED_RESEARCH_ONLY",
              "stellar_rpc_requests": 0, "submitted_transactions": 0,
              "cargo_dependency_network_access_disabled": args.offline}

    def save():
        args.report_path.parent.mkdir(parents=True, exist_ok=True)
        args.report_path.write_text(json.dumps(report, indent=2) + "\n")

    def run(command, timeout=600):
        result = subprocess.run(list(map(str, command)), cwd=ROOT, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Research command failed: " + str(command[0]) + "; " + result.stderr[-2500:])
        return result

    save()
    try:
        sources = {p: sha(ROOT / p) for p in tool_sources()}
        pins = json.loads((TOOL / "upstream-pins.json").read_text())
        backend_id = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).digest()
        parameters = {"rounds": args.rounds, "hash": "BLAKE3-256", "proof_format": "postcard-1.1.3",
                      "research_mode": args.relation, "approved": False}
        parameters_id = hashlib.sha256(json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode()).digest()
        replacement = bytes.fromhex(run([args.fixture_signer.resolve(), "public-key", "replacement"]).stdout.strip())
        if len(replacement) != 1952:
            raise ValueError("Fixture helper did not return an ML-DSA-65 public key")
        if args.relation == "leaf":
            public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            statement = public_fixture_statement(public)
        else:
            fixtures = json.loads((ROOT / "docs/recovery-relation-vectors.json").read_text())
            public = relation.decode_public_strkey(fixtures["vectors"][0]["accounts"][0]["address"])
            statement = public_fixture_statement(public, 0)
        statement = replace(statement, replacement_public_key=replacement,
                            verifier_id=backend_id, parameters_id=parameters_id)
        statement_record = {"canonical_xdr_hex": statement.to_xdr_bytes().hex(),
                            "digest_sha512_hex": statement.digest().hex(),
                            "public_key_hex": public.hex(), "relation": statement.relation,
                            "account_index": statement.account_index,
                            "verifier_id_hex": backend_id.hex(), "parameters_id_hex": parameters_id.hex(),
                            "parameters": parameters, "backend_approved": False,
                            "replacement_key_possession_established_by_this_experiment": False}
        (output / "statement.json").write_text(json.dumps(statement_record, indent=2) + "\n")
        report.update({"source_sha256": sources, "upstream_pins": pins, "statement": statement_record,
                       "python_version": platform.python_version(), "artifact_directory": str(output)})
        save()
        print("Building pinned research backend...", flush=True)
        build = ["cargo", "build", "--release", "--locked", "--manifest-path", TOOL / "Cargo.toml",
                 "--target-dir", args.target_dir.resolve()]
        if args.offline:
            build.append("--offline")
        run(build)
        binary = args.target_dir.resolve() / "release/qasset-zk-seed-research"
        report["binary_sha256"] = sha(binary)
        report["rustc"] = run(["rustc", "-Vv"]).stdout.strip()
        report["cargo"] = run(["cargo", "-V"]).stdout.strip()
        report["build_environment"] = {name: {"set": name in os.environ,
                                                "value_sha256": hashlib.sha256(os.environ[name].encode()).hexdigest() if name in os.environ else None}
                                         for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_BOOTSTRAP", "RUSTC_WRAPPER"]}
        save()
        proof_file, raw_report = output / "proof.postcard", output / "backend-result.json"
        print(f"Proving {args.relation} with {args.rounds} INSECURE research rounds...", flush=True)
        started = time.monotonic()
        run([binary, "prove", statement.digest().hex(), proof_file, raw_report, args.rounds, args.relation])
        report["proof"] = json.loads(raw_report.read_text())
        report["prove_and_adversarial_checks_elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["proof_sha256"] = sha(proof_file)
        save()
        print("Verifying in a separate process, then changing the recovery request...", flush=True)
        verification = run([binary, "verify", statement.digest().hex(), proof_file, args.rounds, args.relation])
        report["separate_verifier"] = json.loads(verification.stdout)
        changed = replace(statement, policy_epoch=statement.policy_epoch + 1)
        rejection = subprocess.run([str(binary), "verify", changed.digest().hex(), str(proof_file),
                                    str(args.rounds), args.relation], cwd=ROOT, text=True, capture_output=True, timeout=600)
        changed_result = json.loads(rejection.stdout)
        report["changed_epoch_separate_verifier"] = {"exit_code": rejection.returncode, **changed_result}
        checks = report["proof"]["checks"]
        if not checks or not all(v is True for v in checks.values()):
            raise RuntimeError("A backend functional check failed; do not interpret reduced-round failures as secure behavior")
        if report["separate_verifier"].get("valid") is not True or rejection.returncode != 1 or changed_result.get("valid") is not False:
            raise RuntimeError("Separate-process functional verification or changed-statement rejection failed")
        if any(sha(ROOT / p) != value for p, value in sources.items()):
            raise RuntimeError("Research inputs changed during execution")
        report["limits"] = [
            "Only reduced-round functional behavior was exercised; security is intentionally inadequate.",
            "Upstream's 438-round claim is not independently established quantum security, and is not used here.",
            "Public fixture witnesses do not demonstrate privacy for a real user's secret.",
            "The raw root witness is not a proof of mnemonic entropy, checksum, or wallet provenance.",
            "No Soroban verifier, authority transition, original-seed recovery transaction, or current ownership check is implemented.",
            "Successful message mutations do not constitute a proof of chosen-message or quantum extraction security.",
            "The verifier accepts an explicit public digest; a production adapter must derive it from authoritative current state.",
            "All fixtures are public and the backend is unaudited; do not use with real secrets or assets."]
        report["status"] = "passed_functional_experiment_only_not_secure"
        save()
        print("PASS: actual off-chain proof and separate verifier; INSECURE research parameters.", flush=True)
        print("Report:", args.report_path)
    except Exception as error:
        report.update({"status": "failed", "error_type": type(error).__name__, "error": str(error)})
        save()
        raise


if __name__ == "__main__":
    main()
