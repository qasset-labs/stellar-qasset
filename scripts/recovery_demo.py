#!/usr/bin/env python3
"""Testnet-only pre-enrolled ML-DSA recovery baseline, using PUBLIC fixture keys.

This is not a zero-knowledge proof or recovery against an unenrolled legacy key.
The CLI keeps the fee-payer secret in its isolated configuration; this script
handles only public fixture signatures and public transaction data.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request

from stellar_sdk import Account, Address, SorobanServer, TransactionBuilder, TransactionEnvelope, scval, xdr
from stellar_sdk.auth import authorization_payload_hash, authorize_invocation
from stellar_sdk.soroban_rpc import SimulateTransactionResponse

from testnet_demo import ANSI, PASSPHRASE, ROOT, RPC, rpc, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasm-dir", type=Path, default=ROOT / "target/wasm32v1-none/release")
    parser.add_argument("--signer", type=Path, default=ROOT / "tools/pq-demo/target/release/qasset-pq-demo-tool")
    parser.add_argument("--config-dir", type=Path, default=ROOT / ".stellar/reviewer")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/recovery-testnet.json")
    parser.add_argument("--contract-id", help="Use an already deployed matching account still at epoch/counter zero")
    args = parser.parse_args()
    previous = json.loads(args.output.read_text()) if args.contract_id and args.output.exists() else {}
    config = args.config_dir.resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith("STELLAR_") and k != "RUST_LOG"}
    env["NO_COLOR"] = "1"
    evidence = {"schema": "qasset-pq-recovery-baseline-v1", "status": "in_progress",
                "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "network": "testnet", "network_passphrase": PASSPHRASE, "rpc_url": RPC,
                "capability": "one-time recovery with a previously registered, backup-derived ML-DSA-65 key",
                "checks": [], "transactions": [],
                "limitations": ["PUBLIC fixture keys: anybody can sign; never use real assets.",
                                "Requires prior registration of a PQ recovery public key; not legacy-seed ZK lifting.",
                                "Counter demonstration only; no asset/treasury policy adapter integrated.",
                                "RustCrypto ml-dsa 0.1.1 and this account have not received independent audit.",
                                "Account authorization uses ML-DSA; fee-payer envelope and network consensus are separate.",
                                "One recovery only; no general wallet lifecycle, key-loss service, or repeated recovery.",
                                "Keys share a root and are not independent security factors."]}
    if previous.get("contract", {}).get("id") == args.contract_id:
        evidence["transactions"] = [entry for entry in previous.get("transactions", []) if entry.get("label") == "deployment"]

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")

    def cli(parts, stdin=None):
        result = subprocess.run(["stellar", "--config-dir", str(config), *parts], cwd=ROOT, env=env,
                                input=stdin, text=True, capture_output=True, timeout=150)
        if result.returncode:
            raise RuntimeError(ANSI.sub("", result.stderr)[-6000:])
        return ANSI.sub("", result.stdout).strip(), ANSI.sub("", result.stderr).strip()

    def helper(parts):
        result = subprocess.run([str(args.signer.resolve()), *parts], text=True, capture_output=True,
                                cwd=ROOT, timeout=45)
        if result.returncode:
            raise RuntimeError(result.stderr[-3000:])
        return bytes.fromhex(result.stdout.strip())

    def receipt(tx_hash, label):
        for _ in range(45):
            result = rpc("getTransaction", {"hash": tx_hash})
            if result["status"] != "NOT_FOUND":
                break
            time.sleep(1)
        if result["status"] != "SUCCESS":
            raise RuntimeError(f"{label}: {tx_hash}: {result['status']}")
        evidence["transactions"].append({"label": label, "hash": tx_hash, "status": "SUCCESS",
                                          "ledger": result["ledger"], "rpc_receipt": result,
                                          "explorer": f"https://stellar.expert/explorer/testnet/tx/{tx_hash}"})
        save()

    def fee_account():
        request = urllib.request.Request("https://horizon-testnet.stellar.org/accounts/" + fee_address,
                                         headers={"User-Agent": "stellar-cli/26.0.0"})
        with urllib.request.urlopen(request, timeout=30) as result:
            sequence = int(json.load(result)["sequence"])
        return Account(fee_address, sequence)

    def transaction(function, params=None, auth=None):
        return (TransactionBuilder(fee_account(), PASSPHRASE, base_fee=100)
                .append_invoke_contract_function_op(contract_id, function, params or [], auth=auth)
                .set_timeout(300).build())

    def simulate(tx, label, expected_error=None):
        result = rpc("simulateTransaction", {"transaction": tx.to_xdr(), "authMode": "enforce"})
        if expected_error:
            if expected_error not in result.get("error", ""):
                raise RuntimeError(f"{label}: expected {expected_error}, got {result.get('error', 'success')}")
            evidence["checks"].append({"label": label, "kind": "rejected_rpc_simulation", "passed": True,
                                        "error": result["error"], "latest_ledger": result["latestLedger"]})
        else:
            if result.get("error"):
                raise RuntimeError(f"{label}: {result['error']}")
            resources = xdr.SorobanTransactionData.from_xdr(result["transactionData"]).resources
            evidence["checks"].append({"label": label, "kind": "successful_rpc_simulation", "passed": True,
                                        "instructions": resources.instructions.uint32,
                                        "min_resource_fee_stroops": result["minResourceFee"],
                                        "envelope_bytes_before_resource_assembly": len(tx.to_xdr_object().to_xdr_bytes()),
                                        "latest_ledger": result["latestLedger"]})
        save()
        return result

    def submit(tx, simulation, label):
        assembled = SorobanServer(RPC).prepare_transaction(tx, SimulateTransactionResponse.model_validate(simulation))
        signed, _ = cli(["tx", "sign", "--sign-with-key", "qasset-reviewer-admin",
                         "--network-passphrase", PASSPHRASE, "--rpc-url", RPC], stdin=assembled.to_xdr())
        signed_tx = TransactionEnvelope.from_xdr(signed, PASSPHRASE)
        tx_hash = signed_tx.hash_hex()
        response = rpc("sendTransaction", {"transaction": signed})
        if response["status"] not in ["PENDING", "DUPLICATE"]:
            raise RuntimeError(f"{label}: send rejected: {response}")
        receipt(tx_hash, label)
        print(f"Confirmed {label}: {tx_hash}", flush=True)

    def read(function):
        result = simulate(transaction(function), "read_" + function)
        return xdr.SCVal.from_xdr(result["results"][0]["xdr"])

    def protected(role):
        invocation = xdr.SorobanAuthorizedInvocation(
            function=xdr.SorobanAuthorizedFunction(
                type=xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
                contract_fn=xdr.InvokeContractArgs(Address(contract_id).to_xdr_sc_address(), xdr.SCSymbol(b"protected"), [])),
            sub_invocations=[])

        def signer(preimage):
            digest = authorization_payload_hash(preimage)
            return scval.to_bytes(helper(["sign", role, digest.hex(), "AUTH"]))

        # Every call has a fresh nonce; old-key rejection cannot be confused with replay rejection.
        entry = authorize_invocation(signer, contract_id, rpc("getLatestLedger")["sequence"] + 100,
                                     invocation, PASSPHRASE)
        return transaction("protected", auth=[entry])

    try:
        network = rpc("getNetwork")
        if network["passphrase"] != PASSPHRASE:
            raise RuntimeError("Refusing network other than Testnet")
        evidence["network_info"] = network
        fee_address, _ = cli(["keys", "address", "qasset-reviewer-admin"])
        evidence["fee_payer"] = fee_address
        keys = {role: helper(["public-key", role]) for role in ["active", "recovery", "replacement"]}
        if any(len(key) != 1952 for key in keys.values()) or len(set(keys.values())) != 3:
            raise RuntimeError("Wrong public keys from fixture signer")
        evidence["public_key_sha256"] = {role: hashlib.sha256(key).hexdigest() for role, key in keys.items()}
        wasm = args.wasm_dir / "pq_recovery_demo.wasm"
        if args.contract_id:
            contract_id, diagnostic = args.contract_id, ""
        else:
            deployed, diagnostic = cli(["contract", "deploy", "--wasm", str(wasm), "--source-account", "qasset-reviewer-admin",
                                        "--rpc-url", RPC, "--network-passphrase", PASSPHRASE, "--cost", "--",
                                        "--owner", fee_address, "--initial-key", keys["active"].hex(),
                                        "--recovery-key", keys["recovery"].hex()])
            contract_id = deployed.splitlines()[-1]
        if not re.fullmatch(r"C[A-Z2-7]{55}", contract_id):
            raise RuntimeError("Invalid deployed contract id")
        evidence["contract"] = {"id": contract_id, "wasm_sha256": sha(wasm), "wasm_bytes": wasm.stat().st_size,
                                 "explorer": f"https://stellar.expert/explorer/testnet/contract/{contract_id}"}
        for tx_hash in dict.fromkeys(re.findall(r"(?:/tx/|[Tt]ransaction hash[: ]+)([0-9a-f]{64})", diagnostic)):
            receipt(tx_hash, "deployment")
        downloaded = config / "pq_recovery_demo.fetched.wasm"
        cli(["contract", "fetch", "--id", contract_id, "--out-file", str(downloaded),
             "--rpc-url", RPC, "--network-passphrase", PASSPHRASE])
        if sha(downloaded) != sha(wasm):
            raise RuntimeError("On-chain WASM does not match local build")
        evidence["contract"]["onchain_wasm_matches"] = True
        evidence["source_sha256"] = {str(path.relative_to(ROOT)): sha(path) for path in
                                     [ROOT / "Cargo.toml", ROOT / "Cargo.lock",
                                      *sorted((ROOT / "contracts/pq-recovery-demo").glob("**/*.rs")),
                                      ROOT / "tools/pq-demo/Cargo.toml", ROOT / "tools/pq-demo/Cargo.lock",
                                      ROOT / "tools/pq-demo/src/main.rs", ROOT / "scripts/recovery_demo.py"]}
        save()
        print(f"Deployed PQ baseline: {contract_id}", flush=True)
        if scval.from_uint64(read("epoch")) != 0 or scval.from_uint64(read("counter")) != 0:
            raise RuntimeError("Demo requires an account at epoch and counter zero; deploy a fresh account")
        tx = protected("active")
        submit(tx, simulate(tx, "initial_key_authorizes"), "initial_key_authorizes")
        expiry = rpc("getLatestLedger")["sequence"] + 200
        args_values = [scval.to_uint64(0), scval.to_bytes(keys["replacement"]), scval.to_uint32(expiry)]
        digest_result = simulate(transaction("recovery_digest", args_values), "canonical_recovery_digest")
        chain_digest = scval.from_bytes(xdr.SCVal.from_xdr(digest_result["results"][0]["xdr"]))
        statement = scval.to_vec([scval.to_string("qassetrecoverv1"),
                                  scval.to_bytes(hashlib.sha256(PASSPHRASE.encode()).digest()),
                                  Address(contract_id).to_xdr_sc_val(), *args_values])
        local_digest = hashlib.sha256(statement.to_xdr_bytes()).digest()
        if chain_digest != local_digest:
            raise RuntimeError("Independent client digest differs from the contract")
        evidence["recovery_intent"] = {"epoch": 0, "valid_until_ledger": expiry, "digest": local_digest.hex(),
                                        "client_and_contract_digest_match": True}
        sig_recovery = helper(["sign", "recovery", local_digest.hex(), "RECOVERY"])
        sig_replacement = helper(["sign", "replacement", local_digest.hex(), "RECOVERY"])
        recovery_params = [*args_values, scval.to_bytes(sig_recovery), scval.to_bytes(sig_replacement)]
        simulate(transaction("recover", [*args_values, scval.to_bytes(bytes(3309)), scval.to_bytes(sig_replacement)]),
                 "forged_recovery_signature_rejected", "Contract, #3")
        wrong_pop = helper(["sign", "active", local_digest.hex(), "RECOVERY"])
        simulate(transaction("recover", [*args_values, scval.to_bytes(sig_recovery), scval.to_bytes(wrong_pop)]),
                 "wrong_replacement_possession_rejected", "Contract, #3")
        if scval.from_uint64(read("epoch")) != 0 or scval.from_bytes(read("active_key")) != keys["active"]:
            raise RuntimeError("A rejected recovery changed state")
        tx = transaction("recover", recovery_params)
        submit(tx, simulate(tx, "backup_key_recovers_to_replacement"), "backup_key_recovers_to_replacement")
        simulate(transaction("recover", recovery_params), "recovery_replay_rejected", "Contract, #4")
        simulate(protected("active"), "old_key_rejected_with_fresh_nonce", "Contract, #3")
        simulate(transaction("protected"), "fee_payer_cannot_bypass_pq_auth", "Auth")
        tx = protected("replacement")
        submit(tx, simulate(tx, "replacement_key_authorizes"), "replacement_key_authorizes")
        if scval.from_uint64(read("epoch")) != 1 or scval.from_uint64(read("counter")) != 2:
            raise RuntimeError("Wrong final epoch or counter")
        if scval.from_bool(read("recovery_enabled")) or scval.from_bytes(read("active_key")) != keys["replacement"]:
            raise RuntimeError("Wrong final recovery/key state")
        evidence["final_state"] = {"epoch": 1, "counter": 2, "recovery_enabled": False,
                                    "active_key_matches_replacement": True}
        from receipt_coverage import require_coverage
        evidence["receipt_coverage"] = require_coverage(evidence["transactions"], {"pq_recovery_demo": evidence["contract"]},
            [("pq_recovery_demo", "protected"), ("pq_recovery_demo", "recover"), ("pq_recovery_demo", "protected")])
        evidence["status"] = "passed"
        save()
        print(f"Recovery baseline passed. Public evidence: {args.output}", flush=True)
    except Exception as error:
        evidence["status"] = "failed"
        evidence["failure"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
