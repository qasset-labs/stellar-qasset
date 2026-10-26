#!/usr/bin/env python3
"""Check local hashes recorded for this attributed research source snapshot."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
record = json.loads((root / "provenance.json").read_text())
for relative, expected in record["local_files_sha256"].items():
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise SystemExit(f"Missing or escaping file: {relative}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"Changed file: {relative}")
source_inventory = {
    str(path.relative_to(root))
    for path in root.rglob("*")
    if path.is_file()
    and "target" not in path.relative_to(root).parts
    and "__pycache__" not in path.relative_to(root).parts
    and (path.suffix in {".rs", ".toml", ".py"} or path.name == "Cargo.lock")
}
if source_inventory != set(record["source_inventory"]):
    raise SystemExit("Unexpected, removed, or newly added source inputs")
for relative in record["compiler_consumed_local_sources"]:
    if relative not in record["local_files_sha256"]:
        raise SystemExit(f"Unrecorded compiler input: {relative}")
print(f"Verified {len(record['local_files_sha256'])} local file hashes; upstream pin {record['upstream_commit']}.")
