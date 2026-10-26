#!/usr/bin/env python3
"""Measure lossless encodings of the retained PUBLIC research proof, not a backend."""

import argparse
import datetime as dt
import hashlib
import json
import lzma
from pathlib import Path
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, default=ROOT / "target/compact-seed-research/proof.postcard")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/proof-transport-research.json")
    args = parser.parse_args()
    sources = ["scripts/check_proof_transport_research.py", "docs/compact-seed-research.json",
               "docs/seed-proof-network-limits.json"]
    initial = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
    record = {"schema": "qasset-proof-transport-research-v1", "status": "in_progress",
              "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source_sha256": initial, "network_requests": 0, "submitted_transactions": 0}
    def save():
        args.output.write_text(json.dumps(record, indent=2) + "\n")
    save()
    try:
        compact = json.loads((ROOT / "docs/compact-seed-research.json").read_text())
        if not 1 <= args.proof.stat().st_size <= 256 * 1024 * 1024:
            raise ValueError("Public fixture size rejected")
        proof = args.proof.read_bytes()
        if hashlib.sha256(proof).hexdigest() != compact["proof_sha256"]:
            raise ValueError("This is not the recorded public fixture")
        # Historical measurements, explicitly NOT a live network query.
        snapshot = json.loads((ROOT / "docs/seed-proof-network-limits.json").read_text())
        settings = snapshot["response"]["updated_entry"]
        limits = [row["contract_bandwidth_v0"]["tx_max_size_bytes"] for row in settings
                  if "contract_bandwidth_v0" in row]
        entry_limits = [row["contract_data_entry_size_bytes"] for row in settings
                        if "contract_data_entry_size_bytes" in row]
        if (len(limits) != 1 or len(entry_limits) != 1
                or any(type(value) is not int or value <= 0 for value in limits + entry_limits)):
            raise RuntimeError("Invalid or ambiguous historical limit fields")
        limit, entry_limit = limits[0], entry_limits[0]
        record.update({"proof_sha256": hashlib.sha256(proof).hexdigest(), "input_bytes": len(proof),
                       "recorded_whole_transaction_limit_bytes": limit,
                       "recorded_ledger_entry_limit_bytes": entry_limit,
                       "raw_upload_transaction_lower_bound_ignoring_overhead": (len(proof) + limit - 1) // limit,
                       "raw_ledger_entry_lower_bound_ignoring_overhead": (len(proof) + entry_limit - 1) // entry_limit,
                       "zlib_runtime_version": zlib.ZLIB_RUNTIME_VERSION, "encodings": []})
        for name, encode, decode in [("zlib_level_9", lambda value: zlib.compress(value, 9), zlib.decompress),
                                     ("xz_preset_6", lambda value: lzma.compress(value, preset=6), lzma.decompress)]:
            start = time.monotonic()
            encoded = encode(proof)
            elapsed = time.monotonic() - start
            if decode(encoded) != proof:
                raise RuntimeError("Lossless roundtrip failed")
            record["encodings"].append({"name": name, "bytes": len(encoded),
                                        "sha256": hashlib.sha256(encoded).hexdigest(),
                                        "encode_seconds": round(elapsed, 6), "roundtrip_equal": True,
                                        "times_recorded_whole_transaction_cap": len(encoded) / limit})
            save()
        if any(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != h for p, h in initial.items()):
            raise RuntimeError("Probe sources changed during execution")
        record.update({"status": "passed_lossless_encoding_measurement_only",
                       "scope": "Encoding only, no proof/security/parameter change, Soroban decoder, verifier port or submitted transaction. Caps are historical Testnet observations with CLI26/protocol29 compatibility warning, not current network guarantees."})
        save()
        print(json.dumps({"status": record["status"], "encodings": record["encodings"]}, indent=2))
    except Exception as error:
        record.update({"status": "failed", "error_type": type(error).__name__, "error": str(error)})
        save()
        raise


if __name__ == "__main__":
    main()
