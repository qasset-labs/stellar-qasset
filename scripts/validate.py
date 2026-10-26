#!/usr/bin/env python3
"""Run reproducible local checks and write public reviewer evidence."""

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target")
    parser.add_argument("--helper-target-dir", type=Path, default=ROOT / "tools/pq-demo/target")
    parser.add_argument("--research-target-dir", type=Path, default=ROOT / "tools/seed-recovery-research/target")
    parser.add_argument("--scalar-target-dir", type=Path, default=ROOT / "tools/scalar-seed-research/target")
    parser.add_argument("--compact-target-dir", type=Path, default=ROOT / "tools/compact-seed-research/target")
    parser.add_argument("--binius-target-dir", type=Path, default=ROOT / "tools/binius-seed-research/target")
    parser.add_argument("--port-target-dir", type=Path, default=ROOT / "tools/binius-verifier-port/target/build")
    parser.add_argument("--next-target-dir", type=Path, default=ROOT / "tools/binius-verifier-next/target/build")
    parser.add_argument("--binding-target-dir", type=Path, default=ROOT / "tools/recovery-key-binding/target")
    parser.add_argument("--sdk-target-dir", type=Path, default=ROOT / "target/soroban-verifier-build")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    flags = ["--locked"] + (["--offline"] if args.offline else [])
    target = ["--target-dir", str(args.target_dir)]
    helper = ["--manifest-path", "tools/pq-demo/Cargo.toml"]
    research = ["--manifest-path", "tools/seed-recovery-research/Cargo.toml"]
    scalar = ["--manifest-path", "tools/scalar-seed-research/Cargo.toml"]
    compact = ["--manifest-path", "tools/compact-seed-research/Cargo.toml"]
    binius = ["--manifest-path", "tools/binius-seed-research/Cargo.toml"]
    rate_study = ["--manifest-path", "tools/binius-seed-research/rate-study/Cargo.toml"]
    commands = [
        ["cargo", "fmt", "--all", "--", "--check"],
        ["cargo", "fmt", *helper, "--", "--check"],
        ["cargo", "fmt", *research, "--", "--check"],
        ["cargo", "fmt", *scalar, "--", "--check"],
        ["cargo", "fmt", *binius, "--", "--check"],
        ["cargo", "fmt", *rate_study, "--", "--check"],
        ["cargo", "fmt", *compact, "--package", "qasset-compact-seed-research", "--", "--check"],
        ["rustfmt", "--edition", "2021", "--check", "tools/compact-seed-research/vendor/shorstop/src/qasset_leaf_seed.rs"],
        ["cargo", "test", "--workspace", *flags, *target],
        ["cargo", "test", *helper, *flags, "--target-dir", str(args.helper_target_dir)],
        ["cargo", "test", *scalar, *flags, "--target-dir", str(args.scalar_target_dir)],
        ["cargo", "test", *binius, "--release", *flags, "--target-dir", str(args.binius_target_dir)],
        ["cargo", "test", *rate_study, "--release", *flags, "--target-dir", str(args.binius_target_dir)],
        ["cargo", "clippy", "--workspace", "--all-targets", *flags, *target, "--", "-D", "warnings"],
        ["cargo", "clippy", *helper, "--all-targets", *flags, "--target-dir", str(args.helper_target_dir), "--", "-D", "warnings"],
        ["cargo", "clippy", *research, "--release", *flags, "--target-dir", str(args.research_target_dir), "--", "-D", "warnings"],
        ["cargo", "clippy", *scalar, "--release", *flags, "--target-dir", str(args.scalar_target_dir), "--", "-D", "warnings"],
        ["cargo", "clippy", *compact, "--package", "qasset-compact-seed-research", "--no-deps", "--release", *flags, "--target-dir", str(args.compact_target_dir), "--", "-D", "warnings"],
        ["cargo", "clippy", *binius, "--release", *flags, "--no-deps", "--target-dir", str(args.binius_target_dir), "--", "-D", "warnings"],
        ["cargo", "clippy", *rate_study, "--release", *flags, "--no-deps", "--target-dir", str(args.binius_target_dir), "--", "-D", "warnings"],
        ["cargo", "build", "--workspace", *flags, "--target", "wasm32v1-none", "--release", *target],
        ["cargo", "build", *helper, *flags, "--release", "--target-dir", str(args.helper_target_dir)],
        [sys.executable, "scripts/check_recovery_relation.py"],
        [sys.executable, "scripts/check_seed_recovery_evidence.py"],
        [sys.executable, "tools/compact-seed-research/verify_provenance.py"],
        [sys.executable, "tools/binius-seed-research/verify_provenance.py"],
        [sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"],
    ]
    for package in ["guest", "host-runner", "wasm-fixture", "inspect"]:
        commands.append(["cargo", "fmt", "--manifest-path", f"tools/binius-verifier-port/{package}/Cargo.toml", "--", "--check"])
    port = ["--manifest-path", "tools/binius-verifier-port/guest/Cargo.toml"]
    port_target = ["--target-dir", str(args.port_target_dir)]
    commands.extend([
        ["cargo", "test", *port, *flags, *port_target, "--lib"],
        ["cargo", "check", *port, *flags, *port_target, "--lib", "--release", "--target", "wasm32v1-none"],
        ["cargo", "clippy", *port, *flags, *port_target, "--lib", "--no-deps", "--", "-D", "warnings"],
        [sys.executable, "scripts/check_verifier_port_evidence.py"],
        [sys.executable, "tools/binius-preprocessing-reference/prepare.py", "--selftest"],
    ])
    for package in ["guest", "host-runner", "external-input", "inspect", "arithmetic-check"]:
        commands.append(["cargo", "fmt", "--manifest-path", f"tools/binius-verifier-next/{package}/Cargo.toml", "--", "--check"])
    commands.extend([
        ["cargo", "test", "--manifest-path", "tools/binius-verifier-next/guest/Cargo.toml", *flags, "--target-dir", str(args.next_target_dir), "--lib"],
        ["cargo", "test", "--manifest-path", "tools/binius-verifier-next/host-runner/Cargo.toml", *flags, "--release", "--target-dir", str(args.next_target_dir)],
        [sys.executable, "scripts/check_verifier_next_evidence.py"],
        ["cargo", "fmt", "--manifest-path", "tools/recovery-key-binding/Cargo.toml", "--all", "--", "--check"],
        ["cargo", "test", "--manifest-path", "tools/recovery-key-binding/Cargo.toml", "-p", "qasset-recovery-key-binding", *flags, "--target-dir", str(args.binding_target_dir), "--lib"],
        ["cargo", "clippy", "--manifest-path", "tools/recovery-key-binding/Cargo.toml", "-p", "qasset-recovery-key-binding", *flags, "--all-targets", "--target-dir", str(args.binding_target_dir), "--", "-D", "warnings"],
        ["cargo", "check", "--manifest-path", "tools/recovery-key-binding/Cargo.toml", "-p", "qasset-recovery-key-binding", *flags, "--target", "wasm32v1-none", "--target-dir", str(args.binding_target_dir), "--lib"],
        [sys.executable, "tools/recovery-key-binding/scripts/verify_provenance.py"],
    ])
    for package in ["", "/compact", "/host-runner"]:
        commands.append(["cargo", "fmt", "--manifest-path", f"tools/binius-soroban-research{package}/Cargo.toml", "--", "--check"])
    commands.extend([
        ["cargo", "clippy", "--manifest-path", "tools/binius-soroban-research/compact/Cargo.toml", *flags, "--lib", "--release", "--target", "wasm32v1-none", "--target-dir", str(args.sdk_target_dir), "--no-deps", "--", "-D", "warnings"],
        ["cargo", "clippy", "--manifest-path", "tools/binius-soroban-research/host-runner/Cargo.toml", *flags, *target, "--no-deps", "--", "-D", "warnings"],
    ])
    evidence = {"schema": "qasset-local-validation-v2", "status": "in_progress",
                "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "scope": "Local execution of first-party code; not an independent audit or production assurance.",
                "checks": [], "source_sha256": {}, "wasm_artifacts": []}
    output = ROOT / "docs/validation.json"

    def save():
        output.write_text(json.dumps(evidence, indent=2) + "\n")

    # Invalidate an older successful record before spawning any tool.
    save()
    sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "README.md", ROOT / ".gitignore",
               *sorted((ROOT / "contracts").glob("**/*.rs")), *sorted((ROOT / "contracts").glob("*/Cargo.toml")),
               *sorted(p for p in (ROOT / "contracts/pq-recovery-demo/test-vectors").rglob("*") if p.is_file()),
               ROOT / "tools/pq-demo/Cargo.toml", ROOT / "tools/pq-demo/Cargo.lock", ROOT / "tools/pq-demo/src/main.rs",
               *[ROOT / "tools/seed-recovery-research" / p for p in ["Cargo.toml", "Cargo.lock", "src/main.rs", "upstream-pins.json", "README.md", "LICENSE"]],
               *[ROOT / "tools/scalar-seed-research" / p for p in ["Cargo.toml", "Cargo.lock", "src/main.rs", "fixtures.json", "upstream-pins.json", "README.md", "LICENSE"]],
               *sorted(p for p in (ROOT / "tools/compact-seed-research").rglob("*") if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts),
               *sorted(p for p in (ROOT / "tools/binius-seed-research").rglob("*") if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts),
               *sorted(p for folder in ["binius-verifier-port", "binius-preprocessing-reference", "binius-verifier-next", "recovery-key-binding", "binius-soroban-research"] for p in (ROOT / "tools" / folder).rglob("*") if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts),
               *sorted((ROOT / "scripts").glob("*.py")), *sorted((ROOT / "scripts").glob("requirements*.txt")),
               *sorted((ROOT / "docs").glob("*.md")),
               *sorted(p for folder in ["compact-loader-review", "sdk-host-diagnostics"] for p in (ROOT / "docs" / folder).rglob("*") if p.is_file()),
               *[ROOT / "docs" / p for p in ["verifier-next-research.json", "binius-soroban-research.json", "verifier-network-limits.json", "dependency-audit.json"]],
               ROOT / "docs/recovery-relation-vectors.json",
               ROOT / "docs/seed-proof-research.json", ROOT / "docs/seed-proof-network-limits.json",
               ROOT / "docs/RECOVERY_EVIDENCE.md", ROOT / "docs/RECOVERY_SECURITY_ARGUMENT.md",
               ROOT / "docs/SCALAR_RECOVERY_EVIDENCE.md", ROOT / "docs/SCALAR_RECOVERY_REVIEW.md",
               ROOT / "docs/COMPACT_BACKEND_REVIEW.md", ROOT / "docs/COMPACT_BACKEND_NEXT_GATE.md",
               ROOT / "docs/DURABLE_RECOVERY_EVIDENCE.md", ROOT / "docs/BINIUS_RECOVERY_EVIDENCE.md",
               ROOT / "docs/BINIUS_SECURITY_REVIEW.md", ROOT / "docs/VERIFIER_PORT_EVIDENCE.md",
               ROOT / "docs/PROOF_MAILBOX_EVIDENCE.md", ROOT / "docs/verifier-port-research.json", ROOT / "docs/proof-mailbox-research.json",
               *sorted(p for folder in ["preprocessing-reference-checks", "verifier-port-optimization"] for p in (ROOT / "docs" / folder).rglob("*") if p.is_file()),
               *[ROOT / "docs" / p for p in ["scalar-leaf438-research.json", "scalar-root438-research.json", "scalar-root8-research.json", "recovery-ceremony-research.json", "compact-seed-research.json", "durable-recovery-research.json", "proof-transport-research.json", "binius-seed-research.json"]]]

    def snapshot():
        return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}

    initial_sources = snapshot()
    evidence["source_sha256"] = initial_sources
    # Bind the separately executed expensive experiment to these inputs. This
    # checks its recorded lineage; routine validation does not reverify its proof.
    research_record = json.loads((ROOT / "docs/seed-proof-research.json").read_text())
    if research_record.get("status") != "passed_functional_experiment_only_not_secure":
        raise RuntimeError("The separate seed-proof functional experiment has not passed")
    for relative, expected in research_record["source_sha256"].items():
        source = (ROOT / relative).resolve()
        if not source.is_relative_to(ROOT.resolve()) or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Seed-proof experiment source changed; rerun the opt-in experiment")
    if (not research_record["proof"]["checks"]
            or not all(v is True for v in research_record["proof"]["checks"].values())
            or research_record["separate_verifier"].get("valid") is not True
            or research_record["changed_epoch_separate_verifier"].get("valid") is not False):
        raise RuntimeError("Seed-proof experiment recorded a failed functional check")
    evidence["seed_proof_evidence_scope"] = "Recorded source/functional-status lineage checked; expensive proof verification is separate and reduced rounds are insecure."
    for filename, expected_status in [
        ("scalar-leaf438-research.json", "passed_scalar_exposed_functional_experiment_only"),
        ("scalar-root438-research.json", "passed_scalar_exposed_functional_experiment_only"),
        ("scalar-root8-research.json", "passed_scalar_exposed_functional_experiment_only"),
        ("recovery-ceremony-research.json", "passed_local_research_ceremony_only"),
        ("compact-seed-research.json", "passed_preimage_primitive_functional_experiment_only"),
        ("durable-recovery-research.json", "passed_durable_local_research_only"),
        ("proof-transport-research.json", "passed_lossless_encoding_measurement_only"),
        ("binius-seed-research.json", "passed_binius_leaf_functional_experiment_only"),
        ("proof-mailbox-research.json", "passed_staged_transport_only_not_recovery"),
        ("verifier-port-research.json", "passed_raw_wasm_fixed_fixture_only_not_soroban_contract"),
        ("verifier-next-research.json", "completed_research_with_sdk_feasibility_blockers"),
        ("binius-soroban-research.json", "completed_actual_sdk_measurement_only_not_recovery"),
    ]:
        record = json.loads((ROOT / "docs" / filename).read_text())
        if record.get("status") != expected_status:
            raise RuntimeError("Missing successful research execution: " + filename)
        for relative, expected in record["source_sha256"].items():
            source = (ROOT / relative).resolve()
            if not source.is_relative_to(ROOT.resolve()) or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
                raise RuntimeError("Research record input changed: " + filename + ":" + relative)
        if filename == "binius-seed-research.json":
            if (record.get("security_approved") is not False
                    or record["statement"].get("backend_approved") is not False
                    or len(record.get("checks", [])) != 13
                    or any(check.get("passed") is not True for check in record["checks"])
                    or record["separate_verifier"].get("valid") is not True
                    or record["wrong_witness_measurement"].get("proof_generated") is not False):
                raise RuntimeError("Binius experiment has incomplete or mislabeled evidence")
        if filename == "durable-recovery-research.json":
            if (len(record.get("checks", [])) != 9
                    or any(check.get("passed") is not True for check in record["checks"])
                    or record.get("real_proof_successes_before_commit") != 8):
                raise RuntimeError("Durable experiment has incomplete checks")
        if filename == "proof-transport-research.json":
            if (len(record.get("encodings", [])) != 2
                    or any(check.get("roundtrip_equal") is not True for check in record["encodings"])):
                raise RuntimeError("Transport experiment has incomplete round trips")
    evidence["additional_research_evidence_scope"] = "Execution-record status and source lineage checked; native proof experiments are not rerun or certified by routine validation."
    evidence["toolchain"] = {}
    for name, command in [("rustc", ["rustc", "-Vv"]), ("cargo", ["cargo", "-V"]),
                          ("stellar_cli", ["stellar", "--version"])]:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
        evidence["toolchain"][name] = result.stdout.strip()
    evidence["toolchain"]["python"] = sys.version
    evidence["toolchain"]["python_packages"] = {name: importlib.metadata.version(name) for name in
                                                 ["PyNaCl", "stellar-sdk", "python-docx"]}
    import os
    build_names = ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_BOOTSTRAP", "RUSTC_WRAPPER",
                   "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"]
    build_names += sorted(k for k in os.environ if k.startswith("CARGO_PROFILE_RELEASE_"))
    evidence["build_environment"] = {name: {"set": name in os.environ,
                                            "value_sha256": hashlib.sha256(os.environ[name].encode()).hexdigest() if name in os.environ else None}
                                       for name in build_names}
    evidence["provenance_limit"] = "Locked dependency/checksum and tool versions are recorded; this is not a hermetic build attestation. Python transitive wheels are not hash-locked."
    save()
    for command in commands:
        print("Running:", " ".join(command), flush=True)
        start = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        transcript = result.stdout + result.stderr
        entry = {"command": command, "result": "passed" if result.returncode == 0 else "failed",
                 "exit_code": result.returncode, "elapsed_seconds": round(time.monotonic() - start, 2),
                 "output_sha256": hashlib.sha256(transcript.encode()).hexdigest(), "output": transcript[-20000:]}
        counts = re.findall(r"test result: ok\. (\d+) passed", transcript)
        counts += re.findall(r"Ran (\d+) tests", transcript)
        if counts:
            entry["tests_passed"] = sum(map(int, counts))
        evidence["checks"].append(entry)
        save()
        if result.returncode:
            evidence["status"] = "failed"
            save()
            print(transcript, file=sys.stderr)
            raise SystemExit(result.returncode)
        if snapshot() != initial_sources:
            raise RuntimeError("Validation inputs changed while checks were running; rerun on a stable source snapshot")
    for wasm in sorted((args.target_dir / "wasm32v1-none/release").glob("*.wasm")):
        if wasm.stem not in ["qasset_registry", "seed_recovery_verifier", "pq_recovery_demo", "recovery_proof_mailbox"]:
            continue
        evidence["wasm_artifacts"].append({"name": wasm.name, "bytes": wasm.stat().st_size,
                                           "sha256": hashlib.sha256(wasm.read_bytes()).hexdigest()})
    evidence["limitations"] = ["Registry scores remain declarations and verified enforcement rejects them.",
                                "Legacy-seed ZK recovery remains disabled.",
                                "ML-DSA demo requires prior PQ-key enrollment and uses public fixture keys.",
                                "Testnet results are recorded separately; local tests do not establish deployment.",
                                "Proof mailbox stores sealed unverified bytes only; raw verifier port is not a deployable Soroban backend.",
                                "Successor raw size fit and mathematical key binding do not close actual SDK code/CPU, complete account lifecycle or independent quantum-security gates."]
    evidence["status"] = "passed"
    save()
    print("All local checks passed:", output)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        destination = ROOT / "docs/validation.json"
        record = json.loads(destination.read_text()) if destination.exists() else {}
        record.update({"status": "failed", "failure": str(error)})
        destination.write_text(json.dumps(record, indent=2) + "\n")
        raise
