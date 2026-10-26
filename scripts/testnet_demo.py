#!/usr/bin/env python3
"""Deploy and exercise the existing metadata prototype on Stellar Testnet only.

Uses fresh, isolated CLI identities and Friendbot. No real assets are issued and
PQ algorithm labels in this demo are deliberately unverified metadata.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RPC = "https://soroban-testnet.stellar.org"
PASSPHRASE = "Test SDF Network ; September 2015"
ROLES = ["Mint", "Burn", "Freeze", "Clawback", "Treasury", "Upgrade", "Governance", "Recovery"]
CRITICAL = ["Treasury", "Upgrade", "Governance"]
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def rpc(method, params=None):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(RPC, data=data, headers={"Content-Type": "application/json", "User-Agent": "stellar-cli/26.0.0"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                result = json.load(response)
            break
        except (TimeoutError, urllib.error.URLError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in [429, 500, 502, 503, 504]:
                raise
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
    if "error" in result:
        raise RuntimeError(f"RPC {method}: {result['error']}")
    return result["result"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasm-dir", type=Path, default=ROOT / "target/wasm32v1-none/release")
    parser.add_argument("--config-dir", type=Path, default=ROOT / ".stellar/reviewer")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/testnet-deployment.json")
    parser.add_argument("--finish-checks", action="store_true", help="Recheck existing recorded QS4 state and finish negative checks without redeploying")
    args = parser.parse_args()
    config = args.config_dir.resolve()
    config.mkdir(parents=True, exist_ok=True)
    config.chmod(0o700)
    # Never inherit another project's account, RPC, signing key, or log settings.
    env = {k: v for k, v in os.environ.items() if not k.startswith("STELLAR_") and k != "RUST_LOG"}
    env["NO_COLOR"] = "1"
    journal = {
        "schema": "qasset-testnet-demo-v1",
        "status": "in_progress",
        "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "network": "testnet", "rpc_url": RPC, "network_passphrase": PASSPHRASE,
        "capability": "administrator-declared policy analysis; not enforced PQ authorization or recovery",
        "transactions": [], "checks": [], "contracts": {},
        "limitations": [
            "Demo asset is only a metadata identity; this script issues no token.",
            "All declared algorithms are labels; the demo does not create PQ signing keys.",
            "Read queries and rejected calls are RPC simulations, not committed transactions.",
            "SeedRecoveryVerifier is unavailable and cannot authorize recovery.",
            "Testnet state is temporary and may expire or be reset; reverify before review.",
        ],
    }
    if args.finish_checks:
        journal = json.loads(args.output.read_text())
        levels = {check.get("expected_level") for check in journal.get("checks", []) if check.get("passed")}
        if not set(["Qs0", "Qs1", "Qs2", "Qs3", "Qs4"]).issubset(levels):
            raise RuntimeError("Finish-checks requires recorded successful transitions through QS0–QS4")
        journal["status"] = "in_progress"
        journal.pop("failure", None)

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(journal, indent=2) + "\n")

    def command(parts, *, expect_failure=None, record=True):
        completed = subprocess.run(["stellar", "--config-dir", str(config), *parts],
                                   cwd=ROOT, env=env, text=True, capture_output=True, timeout=150)
        stdout = ANSI.sub("", completed.stdout).strip()
        stderr = ANSI.sub("", completed.stderr).strip()
        if expect_failure is not None:
            if completed.returncode == 0 or expect_failure.casefold() not in (stdout + stderr).casefold():
                raise RuntimeError(f"Expected {expect_failure!r} rejection, got {completed.returncode}: {stdout}\n{stderr}")
            journal["checks"].append({"kind": "rejected_rpc_simulation", "command": parts,
                                      "expected_error": expect_failure, "passed": True,
                                      "diagnostic": stderr[-5000:]})
            save()
            return None
        if completed.returncode:
            raise RuntimeError(f"Command failed ({parts[0:3]}): {stdout}\n{stderr}")
        if record:
            hashes = re.findall(r"(?:/tx/|[Tt]ransaction hash[: ]+)([0-9a-f]{64})", stderr)
            for tx_hash in dict.fromkeys(hashes):
                receipt = rpc("getTransaction", {"hash": tx_hash})
                if receipt.get("status") != "SUCCESS":
                    raise RuntimeError(f"Unconfirmed transaction {tx_hash}: {receipt.get('status')}")
                journal["transactions"].append({"hash": tx_hash, "command": parts,
                                                "status": receipt["status"], "ledger": receipt["ledger"],
                                                "explorer": f"https://stellar.expert/explorer/testnet/tx/{tx_hash}",
                                                "rpc_receipt": receipt})
            journal.setdefault("command_results", []).append({"command": parts, "stdout": stdout,
                                                               "diagnostic": stderr[-8000:]})
            save()
        return stdout

    common = ["--rpc-url", RPC, "--network-passphrase", PASSPHRASE]
    try:
        network = rpc("getNetwork")
        if network.get("passphrase") != PASSPHRASE:
            raise RuntimeError("Refusing network other than Stellar Testnet")
        journal["network_info"] = network
        journal["start_ledger"] = rpc("getLatestLedger")
        journal["stellar_cli"] = command(["--version"], record=False)
        identities = {}
        for role in ["admin", "outsider", "label"]:
            alias = f"qasset-reviewer-{role}"
            # Generated secrets are stored by CLI under ignored .stellar, never in evidence.
            existing = subprocess.run(["stellar", "--config-dir", str(config), "keys", "address", alias],
                                      env=env, text=True, capture_output=True)
            if existing.returncode:
                command(["keys", "generate", alias, "--network", "testnet"], record=False)
            identities[role] = command(["keys", "address", alias], record=False).splitlines()[-1]
            if role != "label":
                # Friendbot errors for an already funded identity do not trigger key rotation.
                request = urllib.request.Request("https://horizon-testnet.stellar.org/accounts/" + identities[role],
                                                 headers={"User-Agent": "stellar-cli/26.0.0"})
                try:
                    with urllib.request.urlopen(request, timeout=30):
                        pass
                except urllib.error.HTTPError as error:
                    if error.code != 404:
                        raise
                    command(["keys", "fund", alias, "--network", "testnet"], record=False)
        journal["public_identities"] = identities
        journal["source_sha256"] = {str(p.relative_to(ROOT)): sha(p) for p in
                                    [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "contracts").glob("*/src/*.rs"))]}
        save()

        def deploy(name, constructor):
            wasm = args.wasm_dir / f"{name}.wasm"
            if not wasm.is_file():
                raise RuntimeError(f"Build the WASM first: {wasm}")
            if args.finish_checks:
                contract_id = journal["contracts"][name]["id"]
                fetched = config / f"{name}.rechecked.wasm"
                command(["contract", "fetch", "--id", contract_id, "--out-file", str(fetched), *common], record=False)
                if sha(fetched) != sha(wasm):
                    raise RuntimeError("Existing deployment differs from the local build")
                return contract_id
            result = command(["contract", "deploy", "--wasm", str(wasm), "--source-account", "qasset-reviewer-admin",
                              *common, "--cost", "--", *constructor])
            contract_id = result.splitlines()[-1].strip()
            if not re.fullmatch(r"C[A-Z2-7]{55}", contract_id):
                raise RuntimeError(f"Invalid deployed contract id: {result}")
            fetched = config / f"{name}.fetched.wasm"
            command(["contract", "fetch", "--id", contract_id, "--out-file", str(fetched), *common], record=False)
            if sha(fetched) != sha(wasm):
                raise RuntimeError("Downloaded contract differs from locally built WASM")
            journal["contracts"][name] = {"id": contract_id, "wasm_sha256": sha(wasm), "wasm_bytes": wasm.stat().st_size,
                                          "onchain_wasm_matches": True,
                                          "explorer": f"https://stellar.expert/explorer/testnet/contract/{contract_id}"}
            save()
            print(f"Deployed {name}: {contract_id}", flush=True)
            return contract_id

        registry = deploy("qasset_registry", ["--admin", identities["admin"]])
        # Public official SEP-5 vector 1 key, not a user secret or a proof witness.
        import base64
        vector_address = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"
        public_key = base64.b32decode(vector_address)[1:33].hex()
        recovery = deploy("seed_recovery_verifier", ["--owner", identities["admin"], "--protected-pubkey", public_key,
                                                     "--derivation-index", "0"])

        def invoke(contract, function, parameters=None, *, write=False, source="admin", error=None):
            parts = ["contract", "invoke", "--id", contract, "--source-account", f"qasset-reviewer-{source}",
                     *common, "--send", "yes" if write else "no", "--cost", "--", function]
            for key, value in (parameters or {}).items():
                parts.extend(["--" + key.replace("_", "-"), json.dumps(value) if isinstance(value, (dict, list)) else str(value)])
            result = command(parts, expect_failure=error)
            if error is not None:
                return None
            return json.loads(result)

        asset = identities["label"]
        if not args.finish_checks:
            invoke(registry, "register_asset", {"asset": asset, "admin": identities["admin"]}, write=True)

        def snapshot(level, weak):
            assessment = invoke(registry, "policy_assessment", {"asset": asset})
            paths = invoke(registry, "list_weak_paths", {"asset": asset})
            encoded_level = assessment["declared_level"]
            if encoded_level not in [int(level[-1]), level, {level: None}, {level: []}, [level]]:
                raise RuntimeError(f"Expected {level}, got {assessment}")
            if len(paths) != weak or "Unverified" not in json.dumps(assessment):
                raise RuntimeError(f"Wrong weak-path or verification result: {assessment}, {paths}")
            journal["checks"].append({"kind": "rpc_simulation_snapshot", "expected_level": level, "passed": True,
                                      "assessment": assessment, "weak_paths": paths})
            save()
            print(f"Verified {level}: {weak} declared weak paths; Unverified", flush=True)

        def signer(address, algo):
            return {"address": address, "algo": algo, "weight": 1}

        classical = signer(identities["admin"], "Ed25519")
        pq_a = signer(identities["outsider"], "MlDsa65")
        pq_b = signer(identities["label"], "MlDsa65")

        def set_role(role, signers, threshold):
            invoke(registry, "set_role_quorum", {"asset": asset, "role": role,
                   "quorum": {"signers": signers, "threshold": threshold}}, write=True)

        if not args.finish_checks:
            snapshot("Qs0", 8)
            set_role("Treasury", [classical, pq_a], 1)
            snapshot("Qs1", 8)
            for role in CRITICAL:
                set_role(role, [classical, pq_a], 2)
            snapshot("Qs2", 5)
            for role in ROLES:
                if role not in CRITICAL:
                    set_role(role, [pq_a], 1)
            snapshot("Qs3", 0)
            for role in CRITICAL:
                set_role(role, [classical, pq_a, pq_b], 3)
        snapshot("Qs4", 0)
        # These labels intentionally describe ordinary G-addresses: metadata cannot
        # establish the cryptographic algorithm actually used by an authority.
        invoke(registry, "require_min_qs", {"asset": asset, "min_level": 4}, error="Contract, #10")
        invoke(registry, "quantum_security_level", {"asset": asset}, error="Contract, #10")
        # --send=no uses recording simulation in the CLI. It does not establish
        # authentication rejection. Explicitly enforce auth with no credentials.
        from stellar_sdk import Account, TransactionBuilder, scval
        request = urllib.request.Request("https://horizon-testnet.stellar.org/accounts/" + identities["outsider"],
                                         headers={"User-Agent": "stellar-cli/26.0.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            sequence = int(json.load(response)["sequence"])
        quorum_value = scval.to_struct({
            "signers": scval.to_vec([scval.to_struct({"address": scval.to_address(identities["outsider"]),
                                                      "algo": scval.to_enum("MlDsa65", None), "weight": scval.to_uint32(1)})]),
            "threshold": scval.to_uint32(1),
        })
        unauthorized = (TransactionBuilder(Account(identities["outsider"], sequence), PASSPHRASE, base_fee=100)
                        .append_invoke_contract_function_op(registry, "set_role_quorum",
                            [scval.to_address(asset), scval.to_enum("Treasury", None), quorum_value], auth=[])
                        .set_timeout(300).build())
        enforced = rpc("simulateTransaction", {"transaction": unauthorized.to_xdr(), "authMode": "enforce"})
        if "auth" not in enforced.get("error", "").casefold():
            raise RuntimeError(f"Unauthorized update was not rejected in enforcement mode: {enforced}")
        journal["checks"].append({"kind": "rejected_rpc_simulation", "check": "unauthorized_tenant_update",
                                  "auth_mode": "enforce", "passed": True, "diagnostic": enforced["error"]})
        save()
        invoke(registry, "register_asset", {"asset": asset, "admin": identities["admin"]}, error="Contract, #7")
        invoke(registry, "set_role_quorum", {"asset": asset, "role": "Mint",
               "quorum": {"signers": [pq_a, pq_a], "threshold": 1}}, error="Contract, #8")
        invoke(registry, "set_role_quorum", {"asset": asset, "role": "Mint",
               "quorum": {"signers": [pq_a], "threshold": 2}}, error="Contract, #2")
        snapshot("Qs4", 0)
        if invoke(recovery, "backend_available") is not False:
            raise RuntimeError("Recovery availability changed unexpectedly")
        journal["checks"].append({"kind": "rpc_simulation", "check": "recovery_backend_unavailable", "passed": True,
                                  "config": invoke(recovery, "config")})
        journal["end_ledger"] = rpc("getLatestLedger")
        if not journal["transactions"]:
            raise RuntimeError("No independently confirmed transaction receipts captured")
        from receipt_coverage import require_coverage
        journal["receipt_coverage"] = require_coverage(journal["transactions"], journal["contracts"],
            [("qasset_registry", "register_asset")] + [("qasset_registry", "set_role_quorum")] * 12)
        journal["status"] = "passed"
        save()
        print(f"Demo passed. Public evidence: {args.output}")
    except Exception as error:
        journal["status"] = "failed"
        journal["failure"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
