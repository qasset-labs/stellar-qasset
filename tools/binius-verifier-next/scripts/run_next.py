#!/usr/bin/env python3
"""Reproduce fixed public-fixture compact verifier experiments without Stellar RPC."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SETUP = "0d1a3b775ce006e07df6af3aa1491d2d7c29202e11985fd6045ef398cb3be424"
PROOF = "e383a3cc44c30b0028b764e11130bdb27454221e0d67a5b82d90abe70047f461"
SOURCE = "bc30461161691a58b975f888548586ebe721713ffcf1d6ac70460b0c85510945"


def source_manifest():
    excluded = {"target", "__pycache__", ".git", "evidence"}
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(ROOT.rglob("*")) if p.is_file()
            and not set(p.relative_to(ROOT).parts) & excluded
            and p.name != "provenance.json"
            and p.suffix not in {".stdout", ".stderr", ".wasm"}}


def main():
    parser = argparse.ArgumentParser()
    setup_group = parser.add_mutually_exclusive_group(required=True)
    setup_group.add_argument("--setup", type=Path)
    setup_group.add_argument("--original-setup", type=Path)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/build")
    args = parser.parse_args()
    out = ROOT / "target/next-evidence"
    out.mkdir(parents=True, exist_ok=True)
    record = {"status": "in_progress", "security_approved": False,
              "soroban_compatible": False, "stellar_rpc_requests": 0,
              "submitted_transactions": 0, "hermetic_build": False, "commands": []}

    def save():
        temporary = out / "run.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(out / "run.json")

    save()
    try:
        fixtures = ROOT / "target/fixtures"
        fixtures.mkdir(parents=True, exist_ok=True)
        target = args.target_dir.resolve()
        env = os.environ.copy()
        record["inherited_rustflags_removed"] = {
            key: bool(env.pop(key, "")) for key in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"]}
        env["CARGO_TARGET_DIR"] = str(target)
        record["source_sha256"] = source_manifest()
        record["versions"] = {"python": sys.version}
        save()

        def run(command, label, timeout=600):
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                    text=True, timeout=timeout)
            (out / (label + ".stdout")).write_text(result.stdout)
            (out / (label + ".stderr")).write_text(result.stderr)
            record["commands"].append({"argv": command, "exit_code": result.returncode})
            save()
            if source_manifest() != record["source_sha256"]:
                raise RuntimeError("source changed during reproduction")
            if result.returncode:
                raise RuntimeError("command failed: " + label)
            return result.stdout

        if args.original_setup:
            run([sys.executable, str(ROOT / "transcode.py"), str(args.original_setup.resolve()),
                 str(fixtures / "fixed-setup.bin")], "lossless-transcode")
            setup = fixtures / "fixed-setup.bin"
        else:
            setup = args.setup
        for source, name, expected, limit in [
            (setup, "fixed-setup.bin", SETUP, 2 * 1024 * 1024),
            (args.proof, "proof.bin", PROOF, 1024 * 1024),
        ]:
            if source.stat().st_size > limit:
                raise ValueError("oversize fixed public fixture")
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("wrong public fixture SHA256: " + name)
            destination = fixtures / name
            if source.resolve() != destination.resolve():
                destination.write_bytes(raw)
        for relative in ["external-input/src/native.rs", "host-runner/src/native.rs"]:
            if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != SOURCE:
                raise ValueError("source identity constant does not match provenance source")
        for key, command in [("rustc", ["rustc", "+1.94.1", "--version"]),
                             ("cargo", ["cargo", "+1.94.1", "--version"]),
                             ("stellar", ["stellar", "--version"]),
                             ("node", ["node", "--version"])]:
            record["versions"][key] = run(command, "version-" + key).strip()
        for package in ["guest", "external-input", "host-runner", "inspect", "arithmetic-check"]:
            run(["cargo", "+1.94.1", "fmt", "--manifest-path", str(ROOT / package / "Cargo.toml"),
                 "--", "--check"], "fmt-" + package)
        run(["cargo", "+1.94.1", "test", "--locked", "--offline", "--manifest-path",
             str(ROOT / "guest/Cargo.toml"), "--lib"], "guest-test")
        for package in ["host-runner", "inspect"]:
            run(["cargo", "+1.94.1", "build", "--locked", "--offline", "--release",
                 "--manifest-path", str(ROOT / package / "Cargo.toml")], "build-" + package)
        run([str(target / "release/qasset-binius-port-host"), str(fixtures / "fixed-setup.bin"),
             str(fixtures / "proof.bin")], "native-verifier")
        run(["cargo", "+1.94.1", "rustc", "--locked", "--offline", "--release",
             "--manifest-path", str(ROOT / "external-input/Cargo.toml"), "--lib", "--target",
             "wasm32v1-none", "--", "-C", "link-arg=--max-memory=41943040"], "external-build")
        raw = target / "wasm32v1-none/release/qasset_binius_external_input.wasm"
        optimized = out / "qasset_binius_external_input.optimized.wasm"
        run(["stellar", "contract", "optimize", "--wasm", str(raw), "--wasm-out", str(optimized)],
            "binaryen-optimize")
        inspect = json.loads(run([str(target / "release/qasset-wasm-inspect"), str(optimized)],
                                 "optimized-inspection"))
        if inspect["bytes"] > 131072 or inspect["imports"] or inspect["float_operator_count"]:
            raise RuntimeError("raw standalone module size/import/float check failed")
        if inspect["no_float_simd_threads_validation"] != "passed":
            raise RuntimeError("Wasm validation failed")
        memories = inspect["memories"]
        if not (len(memories) == 1 and memories[0]["maximum_pages"] == 640
                and not memories[0]["shared"] and not memories[0]["memory64"]):
            raise RuntimeError("wrong actual memory limit")
        for name, module in [("raw", raw), ("optimized", optimized)]:
            path = out / (name + "-results.json")
            run(["node", str(ROOT / "test_external.mjs"), str(module), str(fixtures / "fixed-setup.bin"),
                 str(fixtures / "proof.bin"), str(path)], "node-" + name, 120)
            result = json.loads(path.read_text())
            if not (result["all_passed"] and len(result["checks"]) == 12
                    and len(result["bounds"]) == 5
                    and all(row["runtime_error"] is None for row in result["checks"])):
                raise RuntimeError("actual raw input verifier tests failed")
        arithmetic = target / "wasm32v1-none/release/qasset_ghash_arithmetic_check.wasm"
        copies = []
        for mode, flags in [("table", []), ("squaring", ["--features", "compact"])]:
            run(["cargo", "+1.94.1", "rustc", "--locked", "--offline", "--release",
                 "--manifest-path", str(ROOT / "arithmetic-check/Cargo.toml"), "--lib", "--target",
                 "wasm32v1-none", *flags, "--", "-C", "link-arg=--max-memory=41943040"], "arithmetic-" + mode)
            copy = out / ("arithmetic-" + mode + ".wasm")
            copy.write_bytes(arithmetic.read_bytes())
            copies.append(copy)
        run(["node", str(ROOT / "test_arithmetic.mjs"), *map(str, copies),
             str(ROOT / "reference/inverse-original-native.txt"), str(out / "arithmetic-results.json")],
            "arithmetic-comparison", 120)
        arithmetic_result = json.loads((out / "arithmetic-results.json").read_text())
        if not arithmetic_result["all_passed"] or arithmetic_result["vectors"] != 646:
            raise RuntimeError("arithmetic equivalence checks failed")
        record.update(status="passed_compact_raw_external_fixture_only_not_soroban_contract",
                      setup_sha256=SETUP, proof_sha256=PROOF,
                      wasm_sha256=hashlib.sha256(optimized.read_bytes()).hexdigest(),
                      wasm_bytes=optimized.stat().st_size)
        save()
        print(json.dumps(record, indent=2))
    except BaseException as error:
        record.update(status="failed", error_type=type(error).__name__, error=str(error))
        save()
        raise


if __name__ == "__main__":
    main()
