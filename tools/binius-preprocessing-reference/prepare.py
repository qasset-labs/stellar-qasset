#!/usr/bin/env python3
"""Reproduce fixed Binius preprocessing from committed objects, without a second vendor tree."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parent
PIN = "115108d5a661d95c0b474b6ab02558bfe6c6bec7"
TREE = "a1438c59bd15d013754247eeff104dcd7c7c2451"
TOOLCHAIN = "1.94.1"
ARTIFACT_SHA256 = "4d6fd19ea0092a261ed7041985b679ecad4b45f9cc6452a7a717979be7c35ef3"
ARTIFACT_BYTES = 2714051
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PROOF_BYTES = 256 * 1024 * 1024
HOST_INPUTS = ("Cargo.toml", "Cargo.lock", "src/main.rs", "src/native.rs", "src/frozen.rs", "setup.sha256")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(name: str) -> str:
    # Check the original components before any normalizing Path operation.
    clean = name[:-1] if name.endswith("/") else name
    if not clean or clean.startswith("/") or "\\" in clean or ":" in clean:
        raise ValueError("unsafe archive name")
    if any(part in ("", ".", "..", ".git") for part in clean.split("/")):
        raise ValueError("unsafe archive component")
    return clean


def extract_archive(archive: Path, destination: Path, expected: dict[str, str]) -> None:
    """Write only bounded regular files matching the exact committed inventory."""
    if destination.exists():
        raise ValueError("archive destination must be fresh")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds byte bound")
    destination.mkdir()
    seen: set[str] = set()
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents if parent.as_posix() != "."}
    total = 0
    count = 0
    with tarfile.open(archive, "r|") as stream:
        for member in stream:
            count += 1
            if count > 2048:
                raise ValueError("too many archive members")
            name = safe_name(member.name)
            if member.isdir():
                if name not in directories:
                    raise ValueError("unapproved archive directory")
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise ValueError("archive links and special files are forbidden")
            if name not in expected or name in seen:
                raise ValueError("unapproved or duplicate archive file")
            if member.size < 0 or member.size > MAX_FILE_BYTES:
                raise ValueError("archive file exceeds byte bound")
            total += member.size
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("expanded archive exceeds byte bound")
            handle = stream.extractfile(member)
            if handle is None:
                raise ValueError("archive file unavailable")
            data = handle.read(member.size + 1)
            if len(data) != member.size or hashlib.sha256(data).hexdigest() != expected[name]:
                raise ValueError("committed archive content mismatch")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as out:
                out.write(data)
            seen.add(name)
    if seen != set(expected):
        raise ValueError("archive inventory incomplete")


def check_inventory(directory: Path, expected: dict[str, str]) -> None:
    files = {}
    for item in directory.rglob("*"):
        if item.is_symlink():
            raise ValueError("unexpected symlink in materialized source")
        if item.is_file():
            files[item.relative_to(directory).as_posix()] = sha(item)
    if files != expected:
        raise ValueError("materialized source inventory/hash mismatch")


def input_inventory() -> dict[str, str]:
    manifest_path = ROOT / "source-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest["upstream_commit"] != PIN or manifest["upstream_tree"] != TREE:
        raise ValueError("reference source pin mismatch")
    actual = {"source-manifest.json": sha(manifest_path)}
    for name, expected in manifest["source_sha256"].items():
        safe_name(name)
        actual[name] = sha(ROOT / name)
        if actual[name] != expected:
            raise ValueError("reference input hash mismatch: " + name)
    return actual


def extractor_selftest(directory: Path) -> list[str]:
    """Adversarial tests for the archive trust boundary; no outside path is written."""
    payload = b"committed fixture"
    expected = {"safe/file": hashlib.sha256(payload).hexdigest()}
    cases = [("valid", "safe/file", tarfile.REGTYPE, "", payload, True),
             ("parent_traversal", "../escape", tarfile.REGTYPE, "", payload, False),
             ("absolute_path", "/escape", tarfile.REGTYPE, "", payload, False),
             ("symlink", "safe/file", tarfile.SYMTYPE, "../escape", b"", False),
             ("hardlink", "safe/file", tarfile.LNKTYPE, "../escape", b"", False),
             ("fifo", "safe/file", tarfile.FIFOTYPE, "", b"", False),
             ("wrong_content", "safe/file", tarfile.REGTYPE, "", b"wrong", False),
             ("unapproved_file", "safe/other", tarfile.REGTYPE, "", payload, False),
             ("backslash_path", "safe\\file", tarfile.REGTYPE, "", payload, False)]
    passed = []
    for label, name, kind, link, data, accept in cases:
        archive = directory / (label + ".tar")
        with tarfile.open(archive, "w") as output:
            member = tarfile.TarInfo(name)
            member.type, member.linkname, member.size = kind, link, len(data)
            output.addfile(member, io.BytesIO(data))
        rejected = False
        try:
            extract_archive(archive, directory / label, expected)
        except (ValueError, tarfile.TarError):
            rejected = True
        if rejected == accept:
            raise AssertionError("extractor regression: " + label)
        passed.append(label)
    # Duplicate regular entries and missing inventories must also fail.
    for label, count in (("duplicate", 2), ("missing", 0)):
        archive = directory / (label + ".tar")
        with tarfile.open(archive, "w") as output:
            for _ in range(count):
                member = tarfile.TarInfo("safe/file")
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
        try:
            extract_archive(archive, directory / label, expected)
        except ValueError:
            passed.append(label)
        else:
            raise AssertionError("extractor regression: " + label)
    return passed


def main() -> int:
    target = ROOT / "target"
    target.mkdir(exist_ok=True)
    output = target / "reproduction.json"
    report = {"status": "in_progress", "upstream_commit": PIN, "started_at_unix": time.time(),
              "security_approved": False, "commands": [], "fresh_build_performed": False}

    def write() -> None:
        temporary = output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, output)

    write()  # Invalidate any older pass before parsing arguments or invoking tools.
    def terminated(_signum: int, _frame: object) -> None:
        raise RuntimeError("reproduction terminated")
    signal.signal(signal.SIGTERM, terminated)
    baseline: dict[str, str] | None = None
    work: Path | None = None
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--upstream-git-dir", type=Path, help="existing checkout containing the pinned Git object")
        parser.add_argument("--prepare-only", action="store_true", help="archive/validate/patch/copy; do not build")
        parser.add_argument("--selftest", action="store_true", help="run archive boundary tests only")
        parser.add_argument("--proof", type=Path, help="retained canonical public-fixture proof for 12 verifier checks")
        parser.add_argument("--cargo-target-dir", type=Path, help="optional reusable Cargo artifact cache")
        args = parser.parse_args()
        baseline = input_inventory()
        report["source_sha256"] = baseline
        work = Path(tempfile.mkdtemp(prefix="work-", dir=target))
        report["work_directory"] = str(work)
        log_directory = work / "logs"
        log_directory.mkdir()
        write()

        prepared_inputs: dict[Path, str] = {}
        prepared_vendor: tuple[Path, dict[str, str]] | None = None

        def stable() -> None:
            if input_inventory() != baseline:
                raise ValueError("reference inputs changed during reproduction")
            for filename, expected in prepared_inputs.items():
                if sha(filename) != expected:
                    raise ValueError("prepared input changed during reproduction: " + str(filename))
            if prepared_vendor is not None:
                check_inventory(*prepared_vendor)

        def tool(label: str, command: list[str], cwd: Path = work, env: dict[str, str] | None = None,
                 expected_generated_artifact: Path | None = None) -> str:
            stable()
            report["current_step"] = label
            write()
            begin = time.monotonic()
            result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=1800)
            stdout = log_directory / (label + ".stdout")
            stderr = log_directory / (label + ".stderr")
            stdout.write_bytes(result.stdout)
            stderr.write_bytes(result.stderr)
            report["commands"].append({"step": label, "command": command, "exit_code": result.returncode,
                                       "seconds": time.monotonic() - begin,
                                       "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)})
            write()
            if result.returncode == 0 and expected_generated_artifact is not None:
                if expected_generated_artifact.stat().st_size != ARTIFACT_BYTES or sha(expected_generated_artifact) != ARTIFACT_SHA256:
                    raise ValueError("generated artifact does not match pinned bytes")
                prepared_inputs[expected_generated_artifact] = ARTIFACT_SHA256
            stable()
            if result.returncode:
                raise RuntimeError(label + " failed; see " + str(stderr))
            return result.stdout.decode("utf-8")

        if args.selftest:
            report["archive_boundary_checks"] = extractor_selftest(work)
            stable()
            report["status"] = "passed_archive_boundary_selftests_only"
            write()
            print(json.dumps({"status": report["status"], "checks": len(report["archive_boundary_checks"]), "report": str(output)}))
            return 0
        if args.upstream_git_dir is None:
            raise ValueError("--upstream-git-dir is required unless --selftest is selected")
        upstream = args.upstream_git_dir.resolve()
        git_env = {key: value for key, value in os.environ.items()
                   if key not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR")
                   and not key.startswith("GIT_CONFIG_")}
        git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_SYSTEM": os.devnull})
        git = ["git", "--no-optional-locks", "-C", str(upstream)]
        resolved = tool("git-commit", git + ["rev-parse", "--verify", PIN + "^{commit}"], env=git_env).strip()
        tree = tool("git-tree", git + ["rev-parse", PIN + "^{tree}"], env=git_env).strip()
        if resolved != PIN or tree != TREE:
            raise ValueError("Git object identity mismatch")
        archive = work / "committed-source.tar"
        tool("git-archive", git + ["archive", "--format=tar", "--output=" + str(archive), PIN], env=git_env)
        report["git_archive_sha256"] = sha(archive)
        with gzip.open(ROOT / "evidence/provenance.json.gz", "rb") as handle:
            raw = handle.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("provenance exceeds byte bound")
        provenance = json.loads(raw)
        if provenance["upstream_commit"] != PIN or len(provenance["vendor_inventory"]) != 647:
            raise ValueError("historical provenance identity mismatch")
        original = {row["path"]: row["upstream_sha256"] for row in provenance["vendor_inventory"]}
        patched = {row["path"]: row["local_sha256"] for row in provenance["vendor_inventory"]}
        vendor = work / "vendor"
        extract_archive(archive, vendor, original)
        check_inventory(vendor, original)
        patch = ROOT / "trusted-constructors.patch"
        patch_env = dict(git_env)
        # Do not discover an enclosing user's repository when this package is installed in one.
        patch_env["GIT_CEILING_DIRECTORIES"] = str(work.parent)
        tool("patch-check", ["git", "apply", "--check", "--directory=vendor", str(patch)], env=patch_env)
        tool("patch-apply", ["git", "apply", "--directory=vendor", str(patch)], env=patch_env)
        check_inventory(vendor, patched)
        for name in HOST_INPUTS:
            destination = work / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        (work / "fixed-setup.bin").write_bytes(b"")  # Build the exporter before it generates the artifact.
        prepared_inputs.update({work / name: baseline[name] for name in HOST_INPUTS})
        prepared_inputs[work / "fixed-setup.bin"] = hashlib.sha256(b"").hexdigest()
        prepared_vendor = (vendor, patched)
        report.update({"prepared_vendor_files": 647, "modified_vendor_files": provenance["modified_files"],
                       "archive_paths_checked": True, "prepared_source_hashes_verified": True})
        stable()
        if args.prepare_only:
            report["prepared_input_sha256"] = {str(path.relative_to(work)): digest for path, digest in prepared_inputs.items()}
            report["status"] = "prepared_from_committed_objects_not_built"
            write()
            print(json.dumps({"status": report["status"], "work_directory": str(work), "report": str(output)}))
            return 0
        rustc = tool("rustc-version", ["rustup", "run", TOOLCHAIN, "rustc", "--version"]).strip()
        cargo = tool("cargo-version", ["rustup", "run", TOOLCHAIN, "cargo", "--version"]).strip()
        if not rustc.startswith("rustc " + TOOLCHAIN + " ") or not cargo.startswith("cargo " + TOOLCHAIN + " "):
            raise ValueError("exact toolchain version required")
        cache = (args.cargo_target_dir.resolve() if args.cargo_target_dir else target / "cargo")
        env = dict(os.environ)
        env["CARGO_BUILD_JOBS"] = "2"
        env.pop("CARGO_BUILD_TARGET", None)
        env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        env.pop("RUSTFLAGS", None)
        command = ["rustup", "run", TOOLCHAIN, "cargo", "build", "--release", "--locked", "--offline",
                   "--manifest-path", str(work / "Cargo.toml"), "--target-dir", str(cache)]
        tool("build-exporter", command, env=env)
        binary = cache / "release/qasset-binius-preprocess-probe"
        exporter = work / "native-exporter"
        shutil.copy2(binary, exporter)
        prepared_inputs[exporter] = sha(binary)
        stable()
        generated = work / "fixed-setup.bin"
        exported = json.loads(tool("export-fixed-setup", [str(exporter), "export", str(generated)],
                                   env=env, expected_generated_artifact=generated))
        if generated.stat().st_size != ARTIFACT_BYTES or sha(generated) != ARTIFACT_SHA256:
            raise ValueError("regenerated fixed setup does not match pinned bytes")
        if not exported["repeat_export_equal"] or not exported["loaded_reexport_equal"]:
            raise ValueError("deterministic export/roundtrip check failed")
        tool("build-fixed-verifier", command, env=env)
        verifier = work / "native-verifier"
        shutil.copy2(binary, verifier)
        prepared_inputs[verifier] = sha(binary)
        stable()
        report.update({"fresh_build_performed": True, "export": exported,
                       "fixed_artifact_sha256": sha(generated), "native_binary_sha256": sha(verifier)})
        report["status"] = "passed_fixed_artifact_regeneration_only"
        if args.proof is not None:
            proof = args.proof.resolve()
            historical = json.loads((ROOT / "evidence/result.json").read_text())
            if proof.stat().st_size > MAX_PROOF_BYTES or sha(proof) != historical["proof_sha256"]:
                raise ValueError("proof must match the retained canonical public-fixture proof")
            local_proof = work / "proof.bin"
            shutil.copyfile(proof, local_proof)
            if sha(local_proof) != historical["proof_sha256"]:
                raise ValueError("proof changed during copy")
            prepared_inputs[local_proof] = historical["proof_sha256"]
            params = [str(local_proof), historical["public_scalar_hex"], historical["canonical_action_sha512_hex"]]
            verified = json.loads(tool("verify-canonical-proof", [str(verifier), "verify"] + params, env=env))
            checks = json.loads(tool("verify-boundary-checks", [str(verifier), "selfcheck"] + params, env=env))
            if not verified["valid"] or not checks["all_passed"] or checks["count"] != 12:
                raise ValueError("canonical proof or boundary checks failed")
            report.update({"status": "passed_fresh_native_preprocessing_reproduction_only",
                           "native_verification": verified, "native_checks": checks})
        stable()
        report.pop("current_step", None)
        report["prepared_input_sha256"] = {str(path.relative_to(work)): digest for path, digest in prepared_inputs.items()}
        report["finished_at_unix"] = time.time()
        write()
        print(json.dumps({"status": report["status"], "work_directory": str(work), "report": str(output)}))
        return 0
    except BaseException as error:
        if isinstance(error, SystemExit) and error.code == 0:
            report["status"] = "help_requested_no_reproduction"
            write()
            return 0
        report.update({"status": "failed", "error_type": type(error).__name__, "error": str(error), "finished_at_unix": time.time()})
        write()
        if isinstance(error, KeyboardInterrupt):
            return 130
        print("Reproduction failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
