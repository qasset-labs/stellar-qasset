#!/usr/bin/env python3
"""Reproduce PUBLIC key-binding fixtures; no RPC, signing, deployment or real seeds."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sources():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(ROOT.rglob("*")) if p.is_file()
            and not set(p.relative_to(ROOT).parts) & {"target", "evidence", "__pycache__", ".git"}
            and p.name != "provenance.json"}


def main():
    out = ROOT / "evidence"
    out.mkdir(exist_ok=True)
    record = {"status":"in_progress","scope":"Public mathematical scalar/key binding only, not seed proof or recovery authorization",
              "security_approved":False,"stellar_rpc_requests":0,"submitted_transactions":0,"commands":[],"hermetic_build":False}

    def save():
        (out / "research.json").write_text(json.dumps(record,indent=2)+"\n")

    save()
    try:
        before = sources()
        record["source_sha256"] = before
        env = os.environ.copy()
        removed = ["RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_TARGET"]
        record["removed_build_overrides"] = {k:bool(env.pop(k,"")) for k in removed}
        env["CARGO_TARGET_DIR"] = str(ROOT / "target")
        save()

        def run(command, label):
            result = subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=600)
            (out / (label+".stdout")).write_text(result.stdout)
            (out / (label+".stderr")).write_text(result.stderr)
            record["commands"].append({"argv":command,"exit_code":result.returncode})
            save()
            if result.returncode or before != sources():
                raise RuntimeError("command failed or source changed: "+label)
            return result.stdout

        record["versions"] = {name:run(command,"version-"+name).strip() for name,command in [
            ("rustc",["rustc","-Vv"]),("cargo",["cargo","-V"]),("node",["node","--version"]),
            ("python",[sys.executable,"--version"])]}
        run([sys.executable,"scripts/generate_vectors.py","--check"],"independent-vectors")
        run(["cargo","fmt","--all","--","--check"],"fmt")
        run(["cargo","test","--locked","--offline","-p","qasset-recovery-key-binding","--lib"],"native-tests")
        run(["cargo","clippy","--locked","--offline","-p","qasset-recovery-key-binding","--all-targets","--","-D","warnings"],"native-clippy")
        run(["cargo","check","--locked","--offline","-p","qasset-recovery-key-binding","--lib","--target","wasm32v1-none"],"nostd-check")
        run(["cargo","clippy","--locked","--offline","--release","-p","qasset-recovery-key-binding-wasm","--target","wasm32v1-none","--","-D","warnings"],"wasm-clippy")
        run(["cargo","build","--locked","--offline","--release","-p","qasset-recovery-key-binding-wasm","--target","wasm32v1-none"],"wasm-build")
        wasm = ROOT / "target/wasm32v1-none/release/qasset_recovery_key_binding_wasm.wasm"
        run(["node","test_wasm.mjs",str(wasm),str(out/"wasm.json")],"wasm-execution")
        actual = json.loads((out/"wasm.json").read_text())
        if actual["status"] != "passed_raw_wasm_key_binding_only" or len(actual["checks"]) != 26:
            raise RuntimeError("actual Wasm checks did not pass")
        record.update({"status":"passed_native_and_raw_wasm_key_binding_only","wasm":actual,
                       "wasm_sha256":hashlib.sha256(wasm.read_bytes()).hexdigest(),"wasm_bytes":wasm.stat().st_size,
                       "native_test_count":6,"independent_positive_vectors":18})
        save()
        lock = (ROOT / "Cargo.lock").read_text()
        dalek = next(part for part in lock.split("[[package]]") if 'name = "curve25519-dalek"' in part)
        checksum = re.search(r'checksum = "([0-9a-f]{64})"', dalek).group(1)
        provenance = {"schema":"qasset-recovery-key-binding-source-v1","security_approved":False,
                      "source_count":len(before),"source_sha256":before,
                      "curve25519_dalek":{"version":"4.1.3","registry_checksum":checksum,"modified":False,
                          "license":"BSD-3-Clause","default_features":False,"precomputed_tables":False},
                      "execution_record_sha256":hashlib.sha256((out/"research.json").read_bytes()).hexdigest()}
        (ROOT/"provenance.json").write_text(json.dumps(provenance,indent=2)+"\n")
        print(json.dumps({k:record[k] for k in ["status","wasm_bytes","wasm_sha256","native_test_count","independent_positive_vectors"]},indent=2))
    except BaseException as error:
        record.update(status="failed",error_type=type(error).__name__,error=str(error))
        save()
        raise


if __name__ == "__main__":
    main()
