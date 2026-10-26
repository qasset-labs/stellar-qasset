#!/usr/bin/env python3
"""Check pinned native dependencies and the retained failed Soroban build probe."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
PIN = "115108d5a661d95c0b474b6ab02558bfe6c6bec7"


def main():
    # Cargo parses and validates both TOML files, including transitive Git pins.
    # Python3.10 has no stdlib TOML reader; no extra Python package is required.
    version = subprocess.run(["rustc", "-Vv"], text=True, capture_output=True, check=True, timeout=30)
    hosts = [line.split(": ", 1)[1] for line in version.stdout.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1:
        raise ValueError("Could not identify the native build host")
    result = subprocess.run(["cargo", "metadata", "--manifest-path", str(ROOT / "Cargo.toml"),
                             "--locked", "--offline", "--format-version", "1", "--filter-platform", hosts[0]],
                            text=True, capture_output=True, check=True, timeout=120)
    metadata = json.loads(result.stdout)
    packages = [package for package in metadata["packages"] if package["name"].startswith("binius-")]
    if not packages:
        raise ValueError("No resolved Binius dependencies")
    for package in packages:
        if not package.get("source", "").endswith("#" + PIN):
            raise ValueError("Unexpected Binius resolution: " + package["name"])
    probe = ROOT / "wasm-probe"
    report = json.loads((probe / "build-probe.json").read_text())
    if (report.get("upstream_revision") != PIN or report.get("exit_code") != 101
            or report.get("status") != "upstream_verifier_does_not_compile_unmodified_for_soroban_target"):
        raise ValueError("Expected exact failed-build evidence, not a successful port claim")
    for relative, expected in report["inputs_sha256"].items():
        path = (probe / relative).resolve()
        if not path.is_relative_to(probe.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Changed Wasm build input: " + relative)
    tree = probe / "rand-core-feature-tree.txt"
    if hashlib.sha256(tree.read_bytes()).hexdigest() != report["rand_core_feature_tree_sha256"]:
        raise ValueError("Changed upstream feature-tree evidence")
    study = ROOT / "rate-study"
    rate = json.loads((study / "provenance.json").read_text())
    if (rate.get("status") != "passed_existing_parameter_comparison_only_no_fitting_proof"
            or rate.get("security_approved") is not False or rate.get("checks", {}).get("all_passed") is not True):
        raise ValueError("Rate comparison lacks successful research-only evidence")
    for relative, expected in rate["source_sha256"].items():
        path = (study / relative).resolve()
        if not path.is_relative_to(study.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Changed rate-comparison input: " + relative)
    if {row["rate"] for row in rate["measurements"]} != {2, 3, 4, 5}:
        raise ValueError("Incomplete rate matrix")
    print("PASS: rate comparison input hashes; no fitting proof or security approval")
    print("PASS: exact Binius pins and failed-build input hashes; no Wasm/crypto approval")


if __name__ == "__main__":
    main()
