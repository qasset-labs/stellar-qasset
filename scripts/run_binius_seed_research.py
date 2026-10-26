#!/usr/bin/env python3
"""PUBLIC-FIXTURE Binius leaf experiment, canonical binding and local handoff.

No RPC/deployment/user secrets. Native proof security is NOT certified.
"""

import argparse
from dataclasses import replace
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import time
import zlib

from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from stellar_sdk import Account, DecoratedSignature, Network, SorobanDataBuilder, TransactionBuilder, scval

from check_seed_recovery_evidence import public_fixture_policy, public_fixture_statement
from durable_recovery_research import DurableRecoveryStore
from verify_binius_recovery_research import BiniusResearchBackend, SCALAR, fingerprint
from verify_recovery_research import (
    LEAF_PUBLIC, RecoveryState, ResearchProofRejected, consume_research_recovery,
    replacement_possession_digest,
)

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/binius-seed-research"
COMPILED = ["tools/binius-seed-research/" + name for name in ["Cargo.toml", "Cargo.lock", "src/main.rs", "pins.json"]]
SOURCES = COMPILED + [
    "scripts/run_binius_seed_research.py", "scripts/verify_binius_recovery_research.py",
    "scripts/recovery_statement.py", "scripts/verify_recovery_research.py",
    "scripts/durable_recovery_research.py", "scripts/check_seed_recovery_evidence.py",
    "tools/pq-demo/src/main.rs", "tools/pq-demo/Cargo.toml", "tools/pq-demo/Cargo.lock",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invocation_measurement(proof: bytes, statement, pop: bytes):
    """Serialize a HYPOTHETICAL interface. No implemented contract is asserted."""
    from stellar_sdk import StrKey
    source = StrKey.encode_ed25519_public_key(LEAF_PUBLIC)
    envelope = (TransactionBuilder(Account(source, 0), Network.TESTNET_NETWORK_PASSPHRASE, 100)
                .append_invoke_contract_function_op(statement.parent_contract, "recover_research",
                    [scval.to_bytes(statement.to_xdr_bytes()), scval.to_bytes(SCALAR),
                     scval.to_bytes(proof), scval.to_bytes(pop)])
                .add_time_bounds(0, 0)
                .set_soroban_data(SorobanDataBuilder().build())
                .build())
    # A placeholder accounts for one outer signature's encoded size. Never signs.
    envelope.signatures.append(DecoratedSignature(bytes(4), bytes(64)))
    encoded = envelope.to_xdr_object().to_xdr_bytes()
    settings = json.loads((ROOT / "docs/seed-proof-network-limits.json").read_text())["response"]["updated_entry"]
    limits = [row["contract_bandwidth_v0"]["tx_max_size_bytes"] for row in settings if "contract_bandwidth_v0" in row]
    if len(limits) != 1 or type(limits[0]) is not int or limits[0] <= 0:
        raise ValueError("Ambiguous historical bandwidth cap")
    compressed = zlib.compress(proof, 9)
    return {"raw_proof_bytes": len(proof), "hypothetical_invocation_envelope_bytes": len(encoded),
            "statement_bytes": len(statement.to_xdr_bytes()), "replacement_pop_bytes": len(pop),
            "outer_signature_is_all_zero_placeholder": True,
            "recorded_testnet_whole_transaction_cap": limits[0],
            "fits_recorded_bandwidth_cap_only": len(encoded) <= limits[0],
            "lossless_zlib9_proof_bytes": len(compressed),
            "lossless_zlib9_roundtrip_equal": zlib.decompress(compressed) == proof,
            "scope": "Exact XDR size for a hypothetical undeployed recover_research interface, empty footprint and one placeholder outer signature. No signed/submitted/valid contract transaction, live cap, simulation, CPU/memory cost, fee or full authorization-footprint estimate. Compression requires an unimplemented decoder."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--target-dir", type=Path, default=TOOL / "target")
    parser.add_argument("--fixture-helper", type=Path, default=ROOT / "tools/pq-demo/target/release/qasset-pq-demo-tool")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/binius-seed-research")
    parser.add_argument("--report", type=Path, default=ROOT / "docs/binius-seed-research.json")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {"schema": "qasset-binius-leaf-research-v1", "status": "in_progress",
              "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "security_approved": False, "stellar_rpc_requests": 0, "submitted_transactions": 0,
              "checks": []}
    def save():
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    def run(command, *, expected=0, bounded=False, timeout=600):
        env = os.environ.copy()
        if bounded:
            env["RAYON_NUM_THREADS"] = "2"
        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
        result = subprocess.run(list(map(str, command)), text=True, capture_output=True, cwd=ROOT,
                                timeout=timeout, env=env, preexec_fn=limits if bounded else None)
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f"Command {command[0]} exited {result.returncode}, expected {expected}: " + result.stderr[-3000:])
        return result
    def helper(*parts):
        return run([args.fixture_helper.resolve(), *parts]).stdout.strip()
    def check(label, detail=None):
        report["checks"].append({"label": label, "passed": True, "detail": detail})
        save()
        print("PASS:", label, flush=True)
    save()
    try:
        initial = {p: sha(ROOT / p) for p in SOURCES}
        # Fixed independent Python SHA512 + libsodium checks of public RFC fixture.
        expanded = bytearray(hashlib.sha512(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).digest()[:32])
        expanded[0] &= 248
        expanded[31] = (expanded[31] & 127) | 64
        if bytes(expanded) != SCALAR or crypto_scalarmult_ed25519_base_noclamp(SCALAR) != LEAF_PUBLIC:
            raise RuntimeError("Independent public fixture binding failed")
        params = {"approved": False, "backend": "Binius64-Iron-Spartan-ZK", "proof_format": "raw-transcript",
                  "binius_revision": "115108d5a661d95c0b474b6ab02558bfe6c6bec7", "log_inv_rate": 1,
                  "upstream_query_phase_security_bits": 96, "hash_suite": "SHA256",
                  "field": "binary-GF-2^128", "public_clamped_scalar_hex": SCALAR.hex(),
                  "scalar_exposure_requires_prior_finalized_classical_retirement": True}
        statement = replace(public_fixture_statement(LEAF_PUBLIC),
                            replacement_public_key=bytes.fromhex(helper("public-key", "replacement")),
                            verifier_id=fingerprint(initial), parameters_id=fingerprint(params))
        statement_record = {"canonical_xdr_hex": statement.to_xdr_bytes().hex(),
                            "digest_sha512_hex": statement.digest().hex(),
                            "public_key_hex": LEAF_PUBLIC.hex(), "relation": statement.relation,
                            "account_index": None, "verifier_id_hex": statement.verifier_id.hex(),
                            "parameters_id_hex": statement.parameters_id.hex(), "parameters": params,
                            "backend_approved": False}
        (args.output_dir / "statement.json").write_text(json.dumps(statement_record, indent=2) + "\n")
        report.update({"source_sha256": initial, "statement": statement_record,
                       "fixture_helper_binary_sha256": sha(args.fixture_helper),
                       "artifact_directory": str(args.output_dir.resolve()),
                       "resource_bounds": {"native_proof_process_address_space_bytes": 4 * 1024**3,
                                           "native_proof_process_wall_timeout_seconds": 600, "rayon_threads": 2, "excludes_cargo_build_and_fixed_size_ml_dsa_helper": True}})
        save()
        if args.prepare_only:
            print(statement.digest().hex())
            return
        build = ["cargo", "build", "--release", "--locked", "--manifest-path", TOOL / "Cargo.toml",
                 "--target-dir", args.target_dir.resolve()]
        if args.offline:
            build.append("--offline")
        print("Building exact-pin research tool...", flush=True)
        run(build)
        binary = args.target_dir.resolve() / "release/qasset-binius-seed-research"
        report["binary_sha256"] = sha(binary)
        report["toolchain"] = {"rustc": run(["rustc", "-Vv"]).stdout.strip(), "cargo": run(["cargo", "-V"]).stdout.strip()}
        report["build_environment"] = {name: {"set": name in os.environ, "value_sha256": hashlib.sha256(os.environ[name].encode()).hexdigest() if name in os.environ else None}
                                       for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_BOOTSTRAP", "RUSTC_WRAPPER"]}
        save()
        proof_path, native_report = args.output_dir / "proof.bin", args.output_dir / "backend-result.json"
        def native_prove(wrong=False):
            path = args.output_dir / "wrong-witness.bin" if wrong else proof_path
            result_path = args.output_dir / "wrong-witness-result.json" if wrong else native_report
            command = [binary, "prove", statement.digest().hex(), path, result_path]
            if wrong:
                command.append("wrong-witness")
            command = ["/usr/bin/time", "-v", *command]
            for stale in [path, result_path]:
                stale.unlink(missing_ok=True)
            started = time.monotonic()
            result = run(command, bounded=True, expected=None if wrong else 0)
            if wrong and result.returncode != 0:
                # Exact known upstream failure for this unsatisfied assignment.
                # An arbitrary process failure/OOM never counts as this check.
                if result.returncode != 101 or "outer witness generation should not fail: WitnessError" not in result.stderr or path.exists():
                    raise RuntimeError("Unexpected wrong-witness execution failure: " + result.stderr[-2500:])
                (args.output_dir / "wrong-witness-stderr.txt").write_text(result.stderr)
                measurement = {"wrong_private_witness": True, "proof_generated": False,
                               "rejection_phase": "upstream_prover_outer_witness_generation",
                               "native_exit_code": result.returncode,
                               "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
                               "action_digest_sha512_hex": statement.digest().hex(), "public_scalar_hex": SCALAR.hex(),
                               "scope": "Actual unsatisfied-witness prover abort; NOT verifier rejection of an adversarially generated proof."}
            else:
                measurement = json.loads(result_path.read_text())
            rss = re.search(r"Maximum resident set size \(kbytes\): (\d+)", result.stderr)
            measurement["process_peak_rss_kib"] = int(rss[1]) if rss else None
            measurement["process_elapsed_seconds"] = round(time.monotonic() - started, 6)
            if measurement["action_digest_sha512_hex"] != statement.digest().hex() or measurement["public_scalar_hex"] != SCALAR.hex():
                raise RuntimeError("Native measurement identity differs")
            return measurement, path
        print("Generating actual leaf proof with canonical recovery binding...", flush=True)
        measurement, _ = native_prove()
        if measurement.get("verifier_accepted") is not True or measurement.get("wrong_private_witness") is not False:
            raise RuntimeError("Actual native proof generation failed")
        report["native_measurement"] = measurement
        report["proof_sha256"] = sha(proof_path)
        check("actual_leaf_proof_generated_and_verified", measurement["proof_bytes"])
        print("Generating malicious wrong-seed proof with identical public inputs...", flush=True)
        malicious, wrong_path = native_prove(True)
        report["wrong_witness_measurement"] = malicious
        if malicious.get("wrong_private_witness") is not True:
            raise RuntimeError("Missing wrong-witness result")
        if malicious.get("proof_generated") is False:
            check("wrong_private_seed_aborted_by_real_prover_before_proof", malicious["rejection_phase"])
        elif malicious.get("verifier_accepted") is False:
            check("malicious_wrong_private_seed_proof_rejected_with_same_public_inputs")
        else:
            raise RuntimeError("Wrong witness was not rejected")
        backend = BiniusResearchBackend(statement.verifier_id, statement.parameters_id, binary, report["binary_sha256"])
        verification = backend.verify(statement, proof_path)
        report["separate_verifier"] = verification
        check("separate_native_verifier_accepts_without_seed_input")
        for name, path, scalar, action, expected in [
            ("changed_action_native_rejection", proof_path, SCALAR, bytes([statement.digest()[0] ^ 1]) + statement.digest()[1:], 2),
        ]:
            result = run([binary, "verify", path, scalar.hex(), action.hex()], expected=expected, bounded=True)
            response = json.loads(result.stdout)
            if response.get("valid") is not False or response.get("public_scalar_hex") != scalar.hex() or response.get("action_digest_sha512_hex") != action.hex():
                raise RuntimeError("Not an explicit matching native proof rejection")
            check(name)
        original = proof_path.read_bytes()
        for name, value in [("trailing", original + b"\0"), ("truncated", original[:-1]),
                            ("corrupted", bytes([original[0] ^ 1]) + original[1:]), ("empty", b"")]:
            path = args.output_dir / (name + ".bin")
            path.write_bytes(value)
            response = json.loads(run([binary, "verify", path, SCALAR.hex(), statement.digest().hex()], expected=2, bounded=True).stdout)
            if response.get("valid") is not False:
                raise RuntimeError("Invalid encoding accepted")
            check(name + "_proof_native_rejection")
        for name, scalar in [("unclamped_scalar", bytes([SCALAR[0] | 1]) + SCALAR[1:]),
                             ("different_clamped_scalar", SCALAR[:1] + bytes([SCALAR[1] ^ 1]) + SCALAR[2:])]:
            result = run([binary, "verify", proof_path, scalar.hex(), statement.digest().hex()], expected=1, bounded=True)
            if ("clamped encoding" not in result.stderr if name == "unclamped_scalar" else "independent fixture public key" not in result.stderr):
                raise RuntimeError("Unexpected scalar guard failure")
            check(name + "_guard_rejection")
        policy = public_fixture_policy(statement)
        state = RecoveryState(policy, bytes.fromhex(helper("public-key", "active")))
        pop = bytes.fromhex(helper("sign", "replacement", replacement_possession_digest(statement).hex(), "RECOVERY"))
        changed = replace(statement, policy_epoch=statement.policy_epoch + 1)
        changed_state = replace(state, policy=replace(policy, epoch=changed.policy_epoch))
        changed_pop = bytes.fromhex(helper("sign", "replacement", replacement_possession_digest(changed).hex(), "RECOVERY"))
        try:
            consume_research_recovery(changed_state, changed.to_xdr_bytes(), proof_path, changed_pop, 1000,
                                      backend, args.fixture_helper)
        except ResearchProofRejected:
            check("old_proof_rejects_new_epoch_after_valid_new_replacement_pop")
        else:
            raise RuntimeError("Old proof transferred to new epoch")
        with tempfile.TemporaryDirectory(prefix="qasset-binius-model-") as directory:
            store = DurableRecoveryStore.create(Path(directory) / "model.sqlite", state, 1000)
            updated, _ = store.recover(statement.to_xdr_bytes(), proof_path, pop, backend, args.fixture_helper)
            if (not updated.consumed or updated.policy.eligible or updated.policy.epoch != policy.epoch + 1
                    or updated.active_public_key != statement.replacement_public_key or store.receipt_count() != 1):
                raise RuntimeError("Incorrect durable fixture handoff")
            check("real_binius_proof_and_ml_dsa_pop_commit_local_handoff")
            try:
                DurableRecoveryStore(store.path).recover(statement.to_xdr_bytes(), proof_path, pop, backend, args.fixture_helper)
            except ValueError:
                if store.receipt_count() != 1:
                    raise RuntimeError("Replay changed receipts")
                check("durable_replay_rejected_after_reopen")
            else:
                raise RuntimeError("Local replay accepted")
        report["transport"] = invocation_measurement(original, statement, pop)
        if sha(proof_path) != report["proof_sha256"] or any(sha(ROOT / p) != h for p, h in initial.items()):
            raise RuntimeError("Proof or experiment sources changed during execution")
        report.update({"status": "passed_binius_leaf_functional_experiment_only",
                       "limits": ["Public RFC8032 fixture, leaf-only relation; SEP5 derivation may be performed privately offline, but is not proved by this circuit.",
                                  "Scalar disclosure permits classical forgery; finalized retirement of every effective classical/reused-key authority must precede any disclosure.",
                                  "Upstream96-bit query configuration is not128-bit/PQ security, complete soundness, quantum knowledge extraction or quantumZK certification.",
                                  "Native code uses std and cannot currently compile directly for Soroban wasm32v1-none; no deployed verifier or metered resources.",
                                  "Policy, retirement and ledger are local fixture assumptions; SQLite does not provide on-chain authority or filesystem anti-rollback.",
                                  "Witness memory erasure and a private-user deployment are not assessed; no real user secrets are accepted.",
                                  "The wrong-seed experiment aborts inside the upstream prover before emitting a proof; it does not demonstrate verifier rejection of an adversarially generated wrong-witness proof.",
                                  "Passing transcript mutation tests is functional evidence, not a QROM signature-of-knowledge theorem."]})
        save()
        print("PASS: native functional evidence only; no production security or Soroban activation.", flush=True)
    except Exception as error:
        report.update({"status": "failed", "error_type": type(error).__name__, "error": str(error)})
        save()
        raise


if __name__ == "__main__":
    main()
