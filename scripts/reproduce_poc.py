#!/usr/bin/env python3
"""Build and validate the reference PoC from source. Does not create accounts or submit transactions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="use cached Cargo dependencies; every Cargo command remains locked")
    parser.add_argument("--live", action="store_true", help="also recheck current Testnet evidence; read-only")
    parser.add_argument("--report", type=Path, default=Path(tempfile.gettempdir()) / "qasset-poc-reproduction.json")
    args = parser.parse_args()
    report = {"schema": "qasset-poc-reproduction-v1", "status": "IN_PROGRESS", "commands": []}

    def run(command, expected=0):
        environment = dict(os.environ)
        environment.setdefault("CARGO_BUILD_JOBS", "2")
        completed = subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True)
        report["commands"].append({"command": command, "exit_code": completed.returncode,
            "expected_exit_code": expected, "stdout": completed.stdout, "stderr": completed.stderr})
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{completed.returncode}: {' '.join(command)}", flush=True)
        if completed.returncode != expected:
            raise RuntimeError(completed.stdout + completed.stderr)
        return completed.stdout

    try:
        rust = run(["rustc", "--version"]).strip()
        if not rust.startswith("rustc 1.94.1 "):
            raise RuntimeError("reference Wasm reproduction requires Rust 1.94.1 with wasm32v1-none installed")
        lock = ["--locked"] + (["--offline"] if args.offline else [])
        run(["cargo", "test", "--workspace", *lock])
        run(["cargo", "build", "--workspace", "--release", "--target", "wasm32v1-none", *lock])
        for tool in ("qasset-sac-signer", "qasset-evidence-crypto"):
            manifest = str(ROOT / "tools" / tool / "Cargo.toml")
            run(["cargo", "test", "--manifest-path", manifest, *lock])
            run(["cargo", "build", "--manifest-path", manifest, "--release", *lock])
        deployment = json.loads((ROOT / "deployments/testnet/qasset-poc.json").read_text())
        for name, expected in deployment["artifacts"].items():
            data = (ROOT / name).read_bytes()
            if {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} != expected:
                raise RuntimeError(f"fresh build differs from reference deployment: {name}")
        run([sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"])
        run([sys.executable, "scripts/verify_qasset_evidence.py", "--offline"])
        run([sys.executable, "-c", "import sys; sys.path.insert(0, 'scripts'); "
             "from check_seed_recovery_evidence import run; r = run(); "
             "print(r['status'], r['case_count'], r['relation_and_counterexample_checks'])"])
        for checker in ("check_recovery_relation.py",
                        "check_verifier_port_evidence.py", "check_verifier_next_evidence.py"):
            run([sys.executable, "scripts/" + checker])
        run([sys.executable, "scripts/check_proof_transport_research.py", "--proof",
             "evidence/research-fixtures/compact-proof.postcard", "--output",
             str(args.report.with_name(args.report.stem + "-proof-transport.json"))])
        if args.live:
            run([sys.executable, "scripts/verify_qasset_evidence.py"])
            run([sys.executable, "scripts/verify_qasset_evidence.py", "--assessment",
                 "evidence/history/qasset-authority-assessment-revisioned-before-bump.json"], expected=1)
        report["status"] = "PASS"
    except (RuntimeError, OSError, ValueError) as error:
        report.update(status="FAIL", error=str(error))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.report)}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
