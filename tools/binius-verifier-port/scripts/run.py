#!/usr/bin/env python3
"""Reproduce fixed public fixtures locally. Never calls Stellar RPC."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SETUP = "4d6fd19ea0092a261ed7041985b679ecad4b45f9cc6452a7a717979be7c35ef3"
PROOF = "e383a3cc44c30b0028b764e11130bdb27454221e0d67a5b82d90abe70047f461"


def source_manifest():
    excluded = {"target", "__pycache__", ".git", "evidence"}
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(ROOT.rglob("*"))
        if p.is_file() and not set(p.relative_to(ROOT).parts) & excluded
        and p.name != "provenance.json"
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/build")
    args = parser.parse_args()
    out = ROOT / "target/port-evidence"
    out.mkdir(parents=True, exist_ok=True)
    record = {
        "status": "in_progress", "security_approved": False,
        "stellar_rpc_requests": 0, "submitted_transactions": 0,
        "hermetic_build": False, "commands": [],
    }

    def save():
        path = out / "run.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(path)

    save()  # Invalid inputs and failed tools must supersede earlier successful reports.
    try:
        fixtures = ROOT / "target/fixtures"
        fixtures.mkdir(parents=True, exist_ok=True)
        for source, name, expected, limit in [
            (args.setup, "fixed-setup.bin", SETUP, 3 * 1024 * 1024),
            (args.proof, "proof.bin", PROOF, 1024 * 1024),
        ]:
            if source.stat().st_size > limit:
                raise ValueError("oversize fixed fixture")
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("wrong fixed public fixture hash: " + name)
            destination = fixtures / name
            if source.resolve() != destination.resolve():
                destination.write_bytes(raw)
        target = args.target_dir.resolve()
        env = os.environ.copy()
        record["inherited_rustflags_removed"] = {
            key: bool(env.pop(key, ""))
            for key in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"]
        }
        env["CARGO_TARGET_DIR"] = str(target)
        env["QASSET_RESEARCH_FIXTURE_DIR"] = str(fixtures.resolve())
        record["source_sha256"] = source_manifest()
        record["versions"] = {"python": sys.version}
        save()

        def run(command, label, timeout=600):
            result = subprocess.run(command, cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=timeout)
            (out / (label + ".stdout")).write_text(result.stdout)
            (out / (label + ".stderr")).write_text(result.stderr)
            record["commands"].append({"argv": command, "exit_code": result.returncode})
            save()
            if source_manifest() != record["source_sha256"]:
                raise RuntimeError("source changed during reproduction")
            if result.returncode:
                raise RuntimeError("command failed: " + label)
            return result.stdout

        for key, command in [
            ("rustc", ["rustc", "+1.94.1", "--version"]),
            ("cargo", ["cargo", "+1.94.1", "--version"]),
            ("node", ["node", "--version"]),
        ]:
            record["versions"][key] = run(command, "version-" + key).strip()
        commands = [
            ["cargo", "+1.94.1", "test", "--locked", "--offline", "--manifest-path", str(ROOT / "guest/Cargo.toml"), "--lib"],
            ["cargo", "+1.94.1", "rustc", "--locked", "--offline", "--release", "--manifest-path", str(ROOT / "wasm-fixture/Cargo.toml"), "--lib", "--target", "wasm32v1-none", "--", "-C", "link-arg=--max-memory=41943040"],
            ["cargo", "+1.94.1", "build", "--locked", "--offline", "--release", "--manifest-path", str(ROOT / "host-runner/Cargo.toml")],
            ["cargo", "+1.94.1", "build", "--locked", "--offline", "--release", "--manifest-path", str(ROOT / "inspect/Cargo.toml")],
        ]
        for i, command in enumerate(commands):
            run(command, "build-" + str(i))
        wasm = target / "wasm32v1-none/release/qasset_binius_wasm_fixture.wasm"
        native = json.loads(run([str(target / "release/qasset-binius-port-host"), str(fixtures / "fixed-setup.bin"), str(fixtures / "proof.bin")], "native"))
        inspection = json.loads(run([str(target / "release/qasset-wasm-inspect"), str(wasm)], "inspection"))
        run(["node", str(ROOT / "test_wasm.mjs"), str(wasm), str(out / "wasm.json")], "wasm", 120)
        wasm_report = json.loads((out / "wasm.json").read_text())
        memories = inspection["memories"]
        bounded = (len(memories) == 1 and memories[0]["maximum_pages"] == 640
                   and memories[0]["initial_pages"] <= 640
                   and not memories[0]["memory64"] and not memories[0]["shared"])
        if not (native["all_passed"] and wasm_report["all_passed"] and bounded
                and len(wasm_report["checks"]) == 9
                and all(row["error"] is None for row in wasm_report["checks"])
                and not inspection["float_operator_count"] and not inspection["imports"]
                and inspection["no_float_simd_threads_validation"] == "passed"):
            raise RuntimeError("native, Wasm, memory bound or inspection check failed")
        record.update(status="passed_raw_wasm_fixed_fixture_only_not_soroban_contract",
                      wasm_sha256=hashlib.sha256(wasm.read_bytes()).hexdigest(),
                      setup_sha256=SETUP, proof_sha256=PROOF)
        save()
        print(json.dumps(record, indent=2))
    except BaseException as error:
        record.update(status="failed", error_type=type(error).__name__, error=str(error))
        save()
        raise


if __name__ == "__main__":
    main()
