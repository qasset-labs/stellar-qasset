#!/usr/bin/env python3
"""Recheck the specific public demo receipts against local reviewed artifacts; never sign/send."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

from stellar_sdk import Account, Address, Keypair, TransactionBuilder, TransactionEnvelope, scval, xdr

from testnet_demo import PASSPHRASE, ROOT, RPC, ROLES, CRITICAL, rpc


class EvidenceError(ValueError):
    """Public evidence does not establish the supported demo scenario."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def same_values(actual, expected):
    return [v.to_xdr() for v in actual] == [v.to_xdr() for v in expected]


def invocation(contract, function, args):
    return xdr.InvokeContractArgs(Address(contract).to_xdr_sc_address(), xdr.SCSymbol(function.encode()), args)


def verify_invocation_auth(op, expected, *, account=None, ledger=None):
    require(len(op.auth) == 1, "Expected exactly one invocation authorization")
    auth = op.auth[0]
    require(not auth.root_invocation.sub_invocations, "Unexpected authorization subtree")
    root = auth.root_invocation.function
    require(root.type == xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
            "Wrong authorization root kind")
    require(root.contract_fn.to_xdr() == expected.to_xdr(), "Authorization payload does not match invocation")
    if account is None:
        require(auth.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT,
                "Metadata invocation must use recorded source-account authority")
        return None
    require(auth.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS,
            "PQ action lacks address credentials")
    cred = auth.credentials.address
    require(Address.from_xdr_sc_address(cred.address).address == account, "Wrong custom-account authorization address")
    signature = scval.from_bytes(cred.signature)
    require(len(signature) == 3309 and any(signature), "Wrong ML-DSA signature encoding/length")
    require(cred.signature_expiration_ledger.uint32 >= ledger, "Authorization already expired at inclusion")
    preimage = xdr.HashIDPreimage(
        type=xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
        soroban_authorization=xdr.HashIDPreimageSorobanAuthorization(
            xdr.Hash(hashlib.sha256(PASSPHRASE.encode()).digest()), cred.nonce,
            cred.signature_expiration_ledger, auth.root_invocation))
    return {"nonce": cred.nonce.int64, "payload_sha256": digest(preimage.to_xdr_bytes())}


def decode_receipt(record, fee_address):
    raw = record["rpc_receipt"]
    require(record.get("status") == "SUCCESS" and raw.get("status") == "SUCCESS", "Receipt is not SUCCESS")
    require(raw.get("ledger") == record["ledger"], "Recorded/RPC receipt ledger mismatch")
    envelope = TransactionEnvelope.from_xdr(raw["envelopeXdr"], PASSPHRASE)
    require(envelope.hash_hex() == record["hash"], "Receipt envelope does not hash to recorded transaction")
    require(envelope.transaction.source.account_id == fee_address, "Unexpected transaction source")
    require(len(envelope.transaction.operations) == 1, "Unexpected transaction operation count")
    require(len(envelope.signatures) == 1, "Unexpected envelope signature count")
    signature = envelope.signatures[0]
    require(signature.signature_hint == Keypair.from_public_key(fee_address).signature_hint(), "Wrong fee signature hint")
    Keypair.from_public_key(fee_address).verify(envelope.hash(), signature.signature)
    op = envelope.transaction.operations[0]
    require(op.source is None, "Unexpected operation source override")
    require(hasattr(op, "host_function"), "Expected an InvokeHostFunction operation")
    return envelope, op


def verify_create(op, contract, owner, expected_args, *, constructor_auth):
    host = op.host_function
    require(host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2, "Expected constructor deployment")
    create = host.create_contract_v2
    require(create.executable.type == xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM,
            "Deployment is not reviewed WASM")
    require(create.executable.wasm_hash.hash.hex() == contract["wasm_sha256"], "Constructor selects another WASM")
    preimage = create.contract_id_preimage
    require(preimage.type == xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS,
            "Unexpected deployment preimage")
    require(Address.from_xdr_sc_address(preimage.from_address.address).address == owner,
            "Wrong deployment owner/preimage")
    full = xdr.HashIDPreimage(
        type=xdr.EnvelopeType.ENVELOPE_TYPE_CONTRACT_ID,
        contract_id=xdr.HashIDPreimageContractID(xdr.Hash(hashlib.sha256(PASSPHRASE.encode()).digest()), preimage))
    actual_id = Address.from_raw_contract(bytes.fromhex(digest(full.to_xdr_bytes()))).address
    require(actual_id == contract["id"], "Deployment does not create recorded contract ID")
    require(same_values(create.constructor_args, expected_args), "Constructor configuration differs from recorded scope")
    require(len(op.auth) == 1, "Expected owner deployment authorization")
    auth = op.auth[0]
    require(auth.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT,
            "Wrong deployment authorization credentials")
    function = auth.root_invocation.function
    require(function.type == xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN,
            "Wrong deployment authorization root")
    require(function.create_contract_v2_host_fn.to_xdr() == create.to_xdr(), "Deployment auth root differs")
    children = auth.root_invocation.sub_invocations
    require(len(children) == int(constructor_auth), "Wrong constructor authorization subtree")
    if constructor_auth:
        child = children[0]
        require(not child.sub_invocations, "Unexpected nested constructor authorization")
        require(child.function.type == xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
                "Wrong constructor authorization kind")
        expected = invocation(contract["id"], "__constructor", expected_args)
        require(child.function.contract_fn.to_xdr() == expected.to_xdr(), "Constructor owner consent differs")


def quorum(signers, threshold):
    return scval.to_struct({"signers": scval.to_vec([
        scval.to_struct({"address": scval.to_address(address), "algo": scval.to_enum(algo, None),
                         "weight": scval.to_uint32(1)}) for address, algo in signers]),
        "threshold": scval.to_uint32(threshold)})


def policy_actions(policy):
    ids = policy["public_identities"]
    asset = scval.to_address(ids["label"])
    classical, pq_a, pq_b = (ids["admin"], "Ed25519"), (ids["outsider"], "MlDsa65"), (ids["label"], "MlDsa65")
    actions = [("register_asset", [asset, scval.to_address(ids["admin"])])]
    def add(role, signers, threshold):
        actions.append(("set_role_quorum", [asset, scval.to_enum(role, None), quorum(signers, threshold)]))
    add("Treasury", [classical, pq_a], 1)
    for role in CRITICAL:
        add(role, [classical, pq_a], 2)
    for role in ROLES:
        if role not in CRITICAL:
            add(role, [pq_a], 1)
    for role in CRITICAL:
        add(role, [classical, pq_a, pq_b], 3)
    return actions


def command_tail(record):
    command = record["command"]
    require(command[:2] in [["contract", "deploy"], ["contract", "invoke"]], "Unknown metadata command scope")
    require(command[command.index("--rpc-url") + 1] == RPC, "Command RPC differs")
    require(command[command.index("--network-passphrase") + 1] == PASSPHRASE, "Command network differs")
    require(command[command.index("--source-account") + 1] == "qasset-reviewer-admin", "Wrong command source")
    split = command.index("--")
    tail = command[split + 1:]
    return command, tail


def verify_scenario(policy, recovery):
    """Pure offline binding of stored public envelopes to the supported two demos."""
    for record in [policy, recovery]:
        require(record["status"] == "passed", "Demo did not pass")
        require(record["network_passphrase"] == PASSPHRASE and record["rpc_url"] == RPC,
                "Unsupported network evidence")
    require(policy["schema"] == "qasset-testnet-demo-v1" and recovery["schema"] == "qasset-pq-recovery-baseline-v1",
            "Unsupported evidence schema")
    all_records = policy["transactions"] + recovery["transactions"]
    hashes = [r["hash"] for r in all_records]
    require(len(hashes) == len(set(hashes)), "Duplicate transaction hashes")
    fee = recovery["fee_payer"]
    require(fee == policy["public_identities"]["admin"], "Demo fee identities disagree")
    require(set(policy["contracts"]) == {"qasset_registry", "seed_recovery_verifier"}, "Unknown metadata contract scope")
    pc = policy["contracts"]
    pq = recovery["contract"]
    require(len({pc["qasset_registry"]["id"], pc["seed_recovery_verifier"]["id"], pq["id"]}) == 3,
            "Contract identities overlap")
    summaries = []
    creates, uploads, action_index = [], set(), 0
    expected_actions = policy_actions(policy)
    last_ledger, last_sequence = -1, -1
    for record in policy["transactions"]:
        envelope, op = decode_receipt(record, fee)
        require(record["ledger"] >= last_ledger and envelope.transaction.sequence > last_sequence,
                "Metadata receipt order is not chronological")
        last_ledger, last_sequence = record["ledger"], envelope.transaction.sequence
        command, tail = command_tail(record)
        host = op.host_function
        if command[1] == "deploy":
            name = Path(command[command.index("--wasm") + 1]).stem
            require(name in pc and action_index == 0, "Unknown or late metadata deployment")
            if host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM:
                require(name not in uploads and name not in creates, "Duplicate/late WASM upload")
                require(not op.auth and digest(host.wasm) == pc[name]["wasm_sha256"], "WASM upload differs")
                uploads.add(name)
                label = name + ":upload"
            else:
                require(name not in creates, "Duplicate contract creation")
                expected = [scval.to_address(fee)]
                expected_tail = ["--admin", fee]
                if name == "seed_recovery_verifier":
                    public = Address("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6").to_xdr_sc_address().account_id.account_id.ed25519.uint256
                    expected += [scval.to_bytes(public), scval.to_uint32(0)]
                    expected_tail = ["--owner", fee, "--protected-pubkey", public.hex(), "--derivation-index", "0"]
                require(tail == expected_tail, "Deployment command constructor differs")
                verify_create(op, pc[name], fee, expected, constructor_auth=name == "seed_recovery_verifier")
                creates.append(name)
                label = name + ":create"
        else:
            require(set(creates) == set(pc), "Mutation precedes both contract deployments")
            require(action_index < len(expected_actions), "Unexpected extra metadata mutation")
            function, expected_args = expected_actions[action_index]
            require(host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT, "Wrong metadata host function")
            expected = invocation(pc["qasset_registry"]["id"], function, expected_args)
            require(host.invoke_contract.to_xdr() == expected.to_xdr(), "Metadata invocation differs from scenario")
            require(command[command.index("--id") + 1] == pc["qasset_registry"]["id"], "Command contract differs")
            require(command[command.index("--send") + 1] == "yes" and tail[0] == function,
                    "Recorded command does not submit the expected function")
            # Decode command arguments into canonical typed values, independently of its label.
            require(len(tail[1:]) % 2 == 0, "Malformed command parameters")
            parameters = dict(zip(tail[1::2], tail[2::2]))
            require(len(parameters) * 2 == len(tail[1:]), "Duplicate command parameter flags")
            if function == "register_asset":
                require(set(parameters) == {"--asset", "--admin"}, "Unknown enrollment parameters")
                cmd_args = [scval.to_address(parameters["--asset"]), scval.to_address(parameters["--admin"])]
            else:
                require(set(parameters) == {"--asset", "--role", "--quorum"}, "Unknown quorum parameters")
                q = json.loads(parameters["--quorum"])
                require(set(q) == {"signers", "threshold"}, "Unknown quorum fields")
                require(all(set(s) == {"address", "algo", "weight"} and s["weight"] == 1 for s in q["signers"]),
                        "Unexpected fixture signer/weight")
                cmd_args = [scval.to_address(parameters["--asset"]), scval.to_enum(parameters["--role"], None),
                            quorum([(s["address"], s["algo"]) for s in q["signers"]], q["threshold"])]
            require(same_values(cmd_args, expected_args), "Command parameters differ from envelope/scenario")
            verify_invocation_auth(op, expected)
            action_index += 1
            label = function
        summaries.append({"hash": record["hash"], "ledger": record["ledger"], "scope": "metadata", "action": label})
    require(len(creates) == 2 and action_index == len(expected_actions), "Incomplete metadata scenario")
    labels = ["deployment", "initial_key_authorizes", "backup_key_recovers_to_replacement", "replacement_key_authorizes"]
    require([r.get("label") for r in recovery["transactions"]] == labels, "Missing, reordered or relabelled recovery stages")
    keys = recovery["public_key_sha256"]
    require(set(keys) == {"active", "recovery", "replacement"} and len(set(keys.values())) == 3,
            "Invalid recorded PQ key identities")
    nonces, digest_seen = set(), None
    last_ledger, last_sequence = -1, -1
    for index, record in enumerate(recovery["transactions"]):
        envelope, op = decode_receipt(record, fee)
        require(record["ledger"] > last_ledger and envelope.transaction.sequence > last_sequence,
                "Recovery stages are not in ledger/sequence order")
        last_ledger, last_sequence = record["ledger"], envelope.transaction.sequence
        if index == 0:
            create = op.host_function.create_contract_v2
            require(create is not None and len(create.constructor_args) == 3, "Missing PQ constructor configuration")
            initial, backup = [scval.from_bytes(v) for v in create.constructor_args[1:]]
            require(len(initial) == len(backup) == 1952, "Wrong enrolled PQ key lengths")
            require(digest(initial) == keys["active"] and digest(backup) == keys["recovery"],
                    "Constructor does not enroll recorded active/recovery keys")
            verify_create(op, pq, fee, [scval.to_address(fee), scval.to_bytes(initial), scval.to_bytes(backup)], constructor_auth=True)
        elif index in [1, 3]:
            expected = invocation(pq["id"], "protected", [])
            require(op.host_function.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT and
                    op.host_function.invoke_contract.to_xdr() == expected.to_xdr(), "PQ action differs from recorded protected call")
            auth = verify_invocation_auth(op, expected, account=pq["id"], ledger=record["ledger"])
            require(auth["nonce"] not in nonces, "PQ action reuses an authorization nonce")
            nonces.add(auth["nonce"])
        else:
            require(op.host_function.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT, "Wrong recovery operation kind")
            args = op.host_function.invoke_contract.args
            require(len(args) == 5, "Wrong recovery argument count")
            epoch, replacement, expiry = scval.from_uint64(args[0]), scval.from_bytes(args[1]), scval.from_uint32(args[2])
            require(epoch == 0 and len(replacement) == 1952 and digest(replacement) == keys["replacement"], "Recovery key/epoch differs")
            require(record["ledger"] <= expiry <= record["ledger"] + 1000, "Recovery expiry outside supported window")
            for signature in args[3:]:
                data = scval.from_bytes(signature)
                require(len(data) == 3309 and any(data), "Wrong recovery signature/possession encoding")
            expected = invocation(pq["id"], "recover", args)
            require(op.host_function.invoke_contract.to_xdr() == expected.to_xdr() and not op.auth,
                    "Recovery invocation target/auth shape differs")
            statement = scval.to_vec([scval.to_string("qassetrecoverv1"),
                scval.to_bytes(hashlib.sha256(PASSPHRASE.encode()).digest()), scval.to_address(pq["id"]), *args[:3]])
            digest_seen = digest(statement.to_xdr_bytes())
            intent = recovery["recovery_intent"]
            require(intent["epoch"] == epoch and intent["valid_until_ledger"] == expiry and intent["digest"] == digest_seen,
                    "Canonical recovery digest does not match recorded intent")
        summaries.append({"hash": record["hash"], "ledger": record["ledger"], "scope": "pq_backup", "action": labels[index]})
    require(digest_seen is not None, "No action-bound recovery transition")
    return summaries


def verify_local_artifacts(root, wasm_dir, validation, policy, recovery):
    require(validation.get("status") == "passed", "Local validation has not passed")
    for name, expected in validation["source_sha256"].items():
        path = (root / name).resolve()
        require(path.is_relative_to(root.resolve()) and path.is_file(), "Invalid or missing validation input")
        require(digest(path.read_bytes()) == expected, f"Validated input changed: {name}")
    required = [root / "Cargo.toml", root / "Cargo.lock", root / "tools/pq-demo/Cargo.toml",
                root / "tools/pq-demo/Cargo.lock", root / "tools/pq-demo/src/main.rs",
                *sorted((root / "contracts").glob("**/*.rs")), *sorted((root / "contracts").glob("*/Cargo.toml"))]
    for name in ["qasset-registry", "seed-recovery-verifier", "pq-recovery-demo"]:
        required.extend([root / "contracts" / name / "Cargo.toml", root / "contracts" / name / "src/lib.rs"])
    for name in validation["source_sha256"]:
        if name.startswith("contracts/") and (name.endswith(".rs") or name.endswith("/Cargo.toml")):
            path = (root / name).resolve()
            require(path.is_relative_to(root.resolve()), "Invalid validation input path")
            required.append(path)
    required = sorted(set(required))
    require(bool(list((root / "contracts").glob("**/*.rs"))), "No local contract source found")
    for path in required:
        require(path.is_file(), f"Missing local reviewed input: {path}")
        require(validation["source_sha256"].get(str(path.relative_to(root))) == digest(path.read_bytes()),
                f"Current source/manifest differs from local validation: {path.relative_to(root)}")
    # Verify every source entry present in deployment evidence, not merely the Rust file names.
    for evidence in [policy, recovery]:
        for name, expected in evidence.get("source_sha256", {}).items():
            path = (root / name).resolve()
            require(path.is_relative_to(root.resolve()) and path.is_file(), "Invalid evidence source path")
            require(digest(path.read_bytes()) == expected, f"Deployment input changed: {name}")
    artifacts = {entry["name"]: entry for entry in validation["wasm_artifacts"]}
    expected_names = {name + ".wasm" for name in ["qasset_registry", "seed_recovery_verifier", "pq_recovery_demo"]}
    require(set(artifacts) == expected_names and len(validation["wasm_artifacts"]) == 3,
            "Local validation artifact set is incomplete, duplicated or unsupported")
    contracts = {**policy["contracts"], "pq_recovery_demo": recovery["contract"]}
    require(set(contracts) == {"qasset_registry", "seed_recovery_verifier", "pq_recovery_demo"}, "Unknown artifact scope")
    for name, contract in contracts.items():
        path = wasm_dir / (name + ".wasm")
        require(path.is_file(), f"Build the current reviewed WASM first: {path}")
        actual = digest(path.read_bytes())
        require(actual == contract["wasm_sha256"] == artifacts[path.name]["sha256"], "Local/validation/deployed WASM mismatch")
        require(path.stat().st_size == contract["wasm_bytes"] == artifacts[path.name]["bytes"], "WASM size mismatch")
    return {"source_manifest_match": True, "local_wasm_match": True,
            "source_inputs_checked": len(required), "artifact_names": sorted(artifacts[n + ".wasm"]["name"] for n in contracts)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasm-dir", type=Path, default=ROOT / "target/wasm32v1-none/release")
    args = parser.parse_args()
    policy = json.loads((ROOT / "docs/testnet-deployment.json").read_text())
    recovery = json.loads((ROOT / "docs/recovery-testnet.json").read_text())
    require(recovery.get("audit_disposition", {}).get("approved_for_current_candidate", True),
            "Historical pre-audit deployment is superseded; the patched candidate has not been redeployed")
    validation = json.loads((ROOT / "docs/validation.json").read_text())
    local = verify_local_artifacts(ROOT, args.wasm_dir, validation, policy, recovery)
    verify_scenario(policy, recovery)
    require(rpc("getNetwork")["passphrase"] == PASSPHRASE, "RPC is not Stellar Testnet")
    records = policy["transactions"] + recovery["transactions"]
    def check_receipt(record):
        result = rpc("getTransaction", {"hash": record["hash"]})
        require(result["status"] == "SUCCESS" and result["ledger"] == record["ledger"],
                "Receipt unavailable/mismatched; testnet history can expire")
        fresh = dict(record, rpc_receipt=result)
        return fresh
    with ThreadPoolExecutor(max_workers=4) as executor:
        fresh = list(executor.map(check_receipt, records))
    fresh_policy = dict(policy, transactions=fresh[:len(policy["transactions"])])
    fresh_recovery = dict(recovery, transactions=fresh[len(policy["transactions"]):])
    semantics = verify_scenario(fresh_policy, fresh_recovery)
    contracts = [*policy["contracts"].values(), recovery["contract"]]
    with tempfile.TemporaryDirectory(prefix="qasset-public-verification-") as temp:
        for index, contract in enumerate(contracts):
            wasm = Path(temp) / f"contract-{index}.wasm"
            command = ["stellar", "--config-dir", temp, "contract", "fetch", "--id", contract["id"],
                       "--out-file", str(wasm), "--rpc-url", RPC, "--network-passphrase", PASSPHRASE]
            env = {k: v for k, v in os.environ.items() if not k.startswith("STELLAR_") and k != "RUST_LOG"}
            subprocess.run(command, check=True, capture_output=True, timeout=90, env=env)
            require(digest(wasm.read_bytes()) == contract["wasm_sha256"], "Public contract WASM hash mismatch")
    fee_address = recovery["fee_payer"]
    request = urllib.request.Request("https://horizon-testnet.stellar.org/accounts/" + fee_address,
                                     headers={"User-Agent": "stellar-cli/26.0.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        sequence = int(json.load(response)["sequence"])
    def view(contract, function, params=None, error=None):
        tx = (TransactionBuilder(Account(fee_address, sequence), PASSPHRASE, base_fee=100)
              .append_invoke_contract_function_op(contract, function, params or [], auth=[]).set_timeout(300).build())
        result = rpc("simulateTransaction", {"transaction": tx.to_xdr(), "authMode": "enforce"})
        if error:
            require(error in result.get("error", ""), f"Expected {error} for {function}")
            return None
        require(not result.get("error"), str(result.get("error")))
        return xdr.SCVal.from_xdr(result["results"][0]["xdr"])
    pq_account = recovery["contract"]["id"]
    require(scval.from_uint64(view(pq_account, "epoch")) == 1, "Wrong recovery epoch")
    require(not scval.from_bool(view(pq_account, "recovery_enabled")), "Recovery not consumed")
    counter = scval.from_uint64(view(pq_account, "counter"))
    require(counter >= 2, "Expected operations before/after recovery")
    require(digest(scval.from_bytes(view(pq_account, "active_key"))) == recovery["public_key_sha256"]["replacement"], "Wrong active replacement key")
    registry = policy["contracts"]["qasset_registry"]["id"]
    asset = scval.to_address(policy["public_identities"]["label"])
    assessment = scval.from_struct(view(registry, "policy_assessment", [asset]))
    require(scval.from_uint32(assessment["declared_level"]) == 4, "Expected declared QS4")
    verification, _ = scval.from_enum(assessment["verification"])
    require(verification == "Unverified", "Metadata unexpectedly verified")
    view(registry, "require_min_qs", [asset, scval.to_uint32(4)], error="Contract, #10")
    legacy = policy["contracts"]["seed_recovery_verifier"]["id"]
    require(not scval.from_bool(view(legacy, "backend_available")), "Legacy verifier unexpectedly enabled")
    evidence = {"schema": "qasset-public-verification-v2", "status": "passed",
        "verified_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "network_info": rpc("getNetwork"), "latest_ledger": rpc("getLatestLedger"),
        "confirmed_receipts": [{"hash": r["hash"], "ledger": r["ledger"], "status": "SUCCESS"} for r in fresh],
        "receipt_semantics": semantics, "receipt_semantics_match": True, **local,
        "matched_contract_wasm": contracts,
        "current_state": {"declared_level": 4, "verification": verification, "legacy_seed_backend_available": False,
            "recovery_epoch": 1, "recovery_enabled": False, "counter": counter, "active_key_matches_replacement": True},
        "transactions_signed_or_sent": 0,
        "limitations": ["Point-in-time RPC-trusted testnet evidence; public fixtures, unaudited account.",
            "ML-DSA validity relies on SUCCESS under the matched reviewed WASM, not a second local ML-DSA verifier.",
            "Historical negative simulations are recorded separately and are not replayed by this read-only verifier.",
            "Local hashes bind reviewed inputs/artifacts; compiler/toolchain provenance is not a hermetic build proof."]}
    (ROOT / "docs/testnet-verification.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"PASS: {len(fresh)} unique semantically matched receipts; 3 local/on-chain WASMs; current state; no signing/sending.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        (ROOT / "docs/testnet-verification.json").write_text(json.dumps({"status": "failed", "error": str(error)}, indent=2) + "\n")
        raise
