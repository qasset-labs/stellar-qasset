#!/usr/bin/env python3
"""Repeat one declaration on the run's fresh Testnet registry and prove evidence staleness.

The old assessment and deployment stay immutable. A separate updated deployment
records the new receipt and revision for subsequent evidence collection.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

from stellar_sdk import Account, Address, Keypair, TransactionBuilder, scval, xdr
from qasset_poc_testnet import HORIZON, PASSPHRASE, ROOT, now, prepare_and_sign, read, request, rpc
from verify_qasset_evidence import check_live, envelope, verify


def load_deployer(path, expected):
    path = path.resolve(strict=True) if not path.is_symlink() else path
    if path.is_relative_to(ROOT):
        raise ValueError("private account file must be outside the repository")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1):
            raise ValueError("account file must be owner-held, singly linked and mode 0600")
        key = Keypair.from_secret(json.load(stream)["deployer"])
    if key.public_key != expected:
        raise ValueError("private deployer does not match the recorded registry administrator")
    return key


def check_fresh_registry(deployment):
    """Bind the target to this record's successful registry creation, never an older registry."""
    candidates = [o for o in deployment["observations"] if o["label"] == "deploy_registry"]
    if len(candidates) != 1 or candidates[0]["observed"] != "SUCCESS":
        raise ValueError("a fresh registry creation receipt is required")
    observation = candidates[0]
    _, transaction = envelope(observation["envelope_xdr"])
    if len(transaction.operations) != 1:
        raise ValueError("registry creation must be a single operation")
    operation = transaction.operations[0]
    if operation.host_function.type != xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2:
        raise ValueError("recorded registry operation is not contract creation")
    creation = operation.host_function.create_contract_v2
    admin = deployment["registry"]["admin"]
    if (transaction.source.account_id != admin
            or creation.constructor_args != [Address(admin).to_xdr_sc_val()]
            or creation.executable.wasm_hash.hash.hex() != deployment["registry"]["wasm_sha256"]):
        raise ValueError("registry creation administrator or code mismatch")
    meta = xdr.TransactionMeta.from_xdr(observation["receipt"]["resultMetaXdr"])
    returned = meta.v4.soroban_meta if meta.v4 is not None else meta.v3.soroban_meta
    if scval.from_address(returned.return_value).address != deployment["registry"]["id"]:
        raise ValueError("target registry is not the freshly created instance")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assessment", required=True, type=Path)
    parser.add_argument("--accounts", required=True, type=Path, help="private account file outside repository")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--updated-deployment", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.updated_deployment.exists():
        parser.error("output exists; preserve previous results and choose new paths")
    assessment = json.loads(args.assessment.read_text())
    verify(assessment)
    deployment_path = ROOT / assessment["deployment_input"]
    deployment = json.loads(deployment_path.read_text())
    snapshot = json.loads((ROOT / assessment["snapshot_input"]).read_text())
    check_fresh_registry(deployment)
    key = load_deployer(args.accounts, deployment["registry"]["admin"])
    revisions, hashes = check_live(deployment, snapshot)
    before_verification = verify(assessment, current_revisions=revisions)
    if not before_verification["fresh"]:
        raise ValueError("assessment must be fresh before demonstrating a revision change")
    if rpc("getNetwork")["passphrase"] != PASSPHRASE:
        raise ValueError("only Testnet is permitted")
    asset = deployment["assets"]["QEXP"]
    before = revisions["QEXP"]
    result = {"schema": "qasset-poc-staleness-v1", "status": "in_progress", "recorded_at_utc": now(),
              "network": "testnet", "network_passphrase": PASSPHRASE, "registry": deployment["registry"]["id"],
              "asset": "QEXP", "sac": asset["sac"], "before_revision": before,
              "assessment_input": str(args.assessment.resolve().relative_to(ROOT)),
              "assessment_sha256": assessment["assessment_sha256"],
              "pre_mutation_verification": {**before_verification, "transactions_rechecked": len(hashes),
                                            "current_policy_revisions": revisions}}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")

    save()
    try:
        signer = scval.to_struct({"address": Address(asset["admin"]).to_xdr_sc_val(),
                                  "algo": scval.to_enum("MlDsa65", None), "weight": scval.to_uint32(1)})
        quorum = scval.to_struct({"signers": scval.to_vec([signer]), "threshold": scval.to_uint32(1)})
        current = request(f"{HORIZON}/accounts/{key.public_key}")
        if not deployment["registry"].get("revision_checked_writes"):
            raise ValueError("revision demonstration requires the revision-checked registry release")
        tx = (TransactionBuilder(Account(key.public_key, int(current["sequence"])), PASSPHRASE, 100)
              .append_invoke_contract_function_op(deployment["registry"]["id"], "set_role_quorum_if_revision",
                  [Address(asset["sac"]).to_xdr_sc_val(), scval.to_enum("Freeze", None), quorum, scval.to_uint64(before)])
              .set_timeout(300).build())
        recording = rpc("simulateTransaction", {"transaction": tx.to_xdr(), "authMode": "record"})
        if recording.get("error"):
            raise ValueError("registry source authorization recording failed")
        auths = [xdr.SorobanAuthorizationEntry.from_xdr(a) for a in recording["results"][0].get("auth", [])]
        if any(a.credentials.type != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT for a in auths):
            raise ValueError("only the recorded transaction source may authorize this declaration")
        tx.transaction.operations[0].auth = auths
        simulation = rpc("simulateTransaction", {"transaction": tx.to_xdr(), "authMode": "enforce"})
        if simulation.get("error"):
            raise ValueError("registry mutation rejected in enforced simulation")
        signed = prepare_and_sign(tx, simulation, key)
        result.update(hash=signed.hash_hex(), envelope_xdr=signed.to_xdr(), simulation=simulation)
        save()
        response = rpc("sendTransaction", {"transaction": signed.to_xdr()})
        result["submission"] = response
        save()
        if response["status"] not in ("PENDING", "DUPLICATE"):
            raise ValueError("registry mutation rejected before inclusion")
        for _ in range(50):
            receipt = rpc("getTransaction", {"hash": signed.hash_hex()})
            if receipt["status"] != "NOT_FOUND":
                break
            time.sleep(1)
        result["receipt"] = receipt
        save()
        if receipt["status"] != "SUCCESS":
            raise ValueError("registry mutation was not confirmed successful")
        policy = read(key.public_key, deployment["registry"]["id"], "policy_assessment", [Address(asset["sac"]).to_xdr_sc_val()])
        after = policy["value"]["policy_revision"]
        if after != before + 1:
            raise ValueError("registry revision did not increment exactly once")
        result.update(after_revision=after, policy_read=policy)
        updated = copy.deepcopy(deployment)
        updated["observations"].append({"id": f"observation-{len(updated['observations']) + 1:03d}",
            "label": "staleness_declaration", "asset": "QEXP", "kind": "transaction", "expected": "SUCCESS",
            "observed": "SUCCESS", "hash": signed.hash_hex(), "envelope_xdr": signed.to_xdr(),
            "receipt": receipt, "simulation": simulation})
        updated["assets"]["QEXP"].update(policy_revision=after, policy_read=policy)
        updated["previous_end_ledger"] = updated["end_ledger"]
        updated["end_ledger"] = receipt["ledger"]
        updated["previous_deployment"] = {"path": str(deployment_path.relative_to(ROOT)),
            "sha256": hashlib.sha256(deployment_path.read_bytes()).hexdigest()}
        args.updated_deployment.parent.mkdir(parents=True, exist_ok=True)
        args.updated_deployment.write_text(json.dumps(updated, indent=2) + "\n")
        completed = subprocess.run([sys.executable, str(ROOT / "scripts/verify_qasset_evidence.py"),
            "--assessment", str(args.assessment)], text=True, capture_output=True, timeout=180)
        result["verifier_exit_code"] = completed.returncode
        result["verifier_report"] = json.loads(completed.stdout)
        report = result["verifier_report"]
        if (completed.returncode != 1 or not report.get("consistent") or report.get("fresh")
                or not report.get("stale_paths")
                or {p["asset"] for p in report["stale_paths"]} != {"QEXP"}
                or {p["status"] for p in report["stale_paths"]} != {"STALE"}):
            raise ValueError("separate verifier did not report only the affected asset as STALE")
        result["status"] = "completed"
        save()
        print(json.dumps({"status": "completed", "hash": signed.hash_hex(), "before_revision": before,
                          "after_revision": after, "stale_paths": len(report["stale_paths"]), "verifier_exit_code": 1}))
    except Exception:
        result["status"] = "failed"
        save()
        raise


if __name__ == "__main__":
    main()
