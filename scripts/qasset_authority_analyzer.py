#!/usr/bin/env python3
"""Assess only the recorded disposable Testnet assets; registry policy is a declaration."""
import argparse
import hashlib
import json
from pathlib import Path

from stellar_sdk import Address, scval, xdr
from qasset_poc_testnet import ROOT, PASSPHRASE, HORIZON, now, read, request, rpc

STATUSES = {"DECLARED", "TESTED_PASS", "TESTED_REJECT", "EXPOSED", "UNCOVERED", "STALE", "INCONCLUSIVE"}
TOOL_VERSION = "2.0.0"
TOOL_SOURCES = ("scripts/qasset_authority_analyzer.py", "scripts/verify_qasset_evidence.py",
                "tools/qasset-evidence-crypto/src/main.rs", "tools/qasset-evidence-crypto/Cargo.lock",
                "tools/qasset-evidence-crypto/Cargo.toml", "scripts/requirements-poc.lock")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def file_hash(path):
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def instance(contract):
    key = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
        Address(contract).to_xdr_sc_address(), xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
        xdr.ContractDataDurability.PERSISTENT))
    result = rpc("getLedgerEntries", {"keys": [key.to_xdr()]})
    if len(result.get("entries", [])) != 1:
        raise RuntimeError(f"contract instance missing or archived: {contract}")
    entry = xdr.LedgerEntryData.from_xdr(result["entries"][0]["xdr"])
    executable = entry.contract_data.val.instance.executable
    digest = executable.wasm_hash.hash.hex() if executable.wasm_hash else None
    item = {"contract": contract, "key_xdr": key.to_xdr(), "result": result, "wasm_sha256": digest}
    if digest:
        code_key = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_CODE,
                               contract_code=xdr.LedgerKeyContractCode(xdr.Hash(bytes.fromhex(digest))))
        code_result = rpc("getLedgerEntries", {"keys": [code_key.to_xdr()]})
        code = xdr.LedgerEntryData.from_xdr(code_result["entries"][0]["xdr"]).contract_code.code
        if hashlib.sha256(code).hexdigest() != digest:
            raise RuntimeError("on-chain Wasm bytes differ from the executable hash")
        item.update(code_key_xdr=code_key.to_xdr(), code_result=code_result)
    return item


def collect(deployment):
    if deployment["network_passphrase"] != PASSPHRASE or deployment["network"] != "testnet":
        raise ValueError("only Testnet records are accepted")
    if deployment["status"] not in ("completed", "pending_issuer_lock"):
        raise ValueError("a failed or unfinished run cannot establish authority coverage")
    for path, expected in deployment["artifacts"].items():
        if file_hash(ROOT / path) != expected:
            raise ValueError(f"local artifact differs from deployment: {path}")
    source = deployment["accounts"]["deployer"]
    registry = deployment["registry"]["id"]
    snapshot = {"network": rpc("getNetwork"), "ledger_start": rpc("getLatestLedger")["sequence"],
                "registry_instance": instance(registry), "assets": {}}
    if snapshot["network"]["passphrase"] != PASSPHRASE:
        raise ValueError("RPC is not Testnet")
    if snapshot["registry_instance"]["wasm_sha256"] != deployment["registry"]["wasm_sha256"]:
        raise ValueError("live registry Wasm differs from the deployment record")
    expected_admin_hash = next(v["sha256"] for p, v in deployment["artifacts"].items() if p.endswith("qasset_sac_admin.wasm"))
    for code, asset in deployment["assets"].items():
        values = [Address(asset["sac"]).to_xdr_sc_val()]
        item = {"issuer": request(f"{HORIZON}/accounts/{asset['issuer']}"),
                "holder": request(f"{HORIZON}/accounts/{asset['holder']}"),
                "sac_instance": instance(asset["sac"]), "admin_instance": instance(asset["admin"]),
                "reads": {"sac_admin": read(source, asset["sac"], "admin"),
                          "configured_sac": read(source, asset["admin"], "sac"),
                          "operator_key": read(source, asset["admin"], "operator_key"),
                          "protected_function": read(source, asset["admin"], "protected_function"),
                          "policy": read(source, registry, "policy_assessment", values),
                          "registry_admin": read(source, registry, "asset_admin", values)}, "quorums": {}}
        for role in ("Freeze", "Mint", "Clawback"):
            item["quorums"][role] = read(source, registry, "get_role_quorum", values + [scval.to_enum(role, None)])
        # A second policy read detects a concurrent registry revision during collection.
        end_policy = read(source, registry, "policy_assessment", values)
        item["policy_end"] = end_policy
        if item["reads"]["policy"]["value"]["policy_revision"] != end_policy["value"]["policy_revision"]:
            raise ValueError("registry revision changed while collecting inputs; retry collection")
        if item["admin_instance"]["wasm_sha256"] != expected_admin_hash:
            raise ValueError("live admin executable differs from recorded Wasm")
        if (item["reads"]["sac_admin"]["value"] != asset["admin"]
                or item["reads"]["configured_sac"]["value"] != asset["sac"]
                or item["reads"]["protected_function"]["value"] != "set_authorized"
                or hashlib.sha256(bytes.fromhex(item["reads"]["operator_key"]["value"]["bytes_hex"])).hexdigest()
                   != deployment["operator_public_key_sha256"]):
            raise ValueError("live administrator binding or key differs from the run")
        snapshot["assets"][code] = item
    snapshot["ledger_end"] = rpc("getLatestLedger")["sequence"]
    return snapshot


def assess(deployment, snapshot):
    paths = []
    for code, asset in deployment["assets"].items():
        observed = snapshot["assets"][code]
        observations = {o["label"]: o for o in deployment["observations"] if o.get("asset") == code}

        def add(name, status, detail, label=None):
            row = {"asset": code, "path": name, "status": status, "detail": detail, "citations": []}
            labels = label if isinstance(label, tuple) else (label,)
            for cited_label in labels:
                if cited_label not in observations:
                    if cited_label is not None:
                        raise ValueError("claim requires its recorded observation")
                    continue
                observation = observations[cited_label]
                if status in ("TESTED_PASS", "EXPOSED") and observation["observed"] != "SUCCESS":
                    raise ValueError("positive claim requires a successful recorded transaction")
                if status == "TESTED_REJECT" and observation["observed"] not in ("REJECT", "FAILED"):
                    raise ValueError("rejection claim requires a recorded rejection")
                citation = {"observation_id": observation["id"], "kind": observation["kind"]}
                if observation["kind"] == "transaction":
                    citation["hash"] = observation["hash"]
                row["citations"].append(citation)
            if status not in STATUSES or (status.startswith("TESTED_") and not row["citations"]):
                raise ValueError("tested status requires a recorded observation")
            paths.append(row)

        issuer = observed["issuer"]
        ed_weight = sum(s["weight"] for s in issuer["signers"] if s["type"] == "ed25519_public_key")
        can_sign = ed_weight > 0 and ed_weight >= max(1, issuer["thresholds"]["med_threshold"])
        locked = deployment["lock_gate"]["state"] == "LOCKED" and code == "QCTL"
        if locked and (not deployment["lock_gate"]["environment_enabled"]
                       or not deployment["lock_gate"]["issuer_created_this_run"]
                       or any(s["weight"] for s in issuer["signers"])):
            raise ValueError("locked issuer claim requires the gate and zero weight for every signer")
        add("issuer.classic_signers", "EXPOSED" if can_sign else "UNCOVERED",
            "Live issuer signer weights, thresholds and flags are in the input snapshot; classic Ed25519 authority remains." if can_sign
            else "Live issuer has no sufficient Ed25519 weight; other signer types are outside this narrow analyzer.")
        mint = observations.get("classic_mint")
        locked_mint = observations.get("classic_mint_after_lock")
        if mint and mint["kind"] == "transaction" and mint["observed"] == "SUCCESS":
            add("issuer.classic_mint", "EXPOSED", "Classic issuer Payment succeeded after SAC handover.", "classic_mint")
        elif (deployment["lock_gate"]["state"] == "LOCKED" and not can_sign and locked_mint
              and locked_mint["observed"] in ("FAILED", "REJECT")):
            add("issuer.classic_mint", "TESTED_REJECT", "Classic issuer Payment rejected after this run's gated lock.", "classic_mint_after_lock")
        else:
            add("issuer.classic_mint", "INCONCLUSIVE", "Restricted-issuer demonstration pending: the lock and post-lock payment were not run.")
        add("issuer.trustline_flags", "EXPOSED" if can_sign else "UNCOVERED",
            "Classic issuer SetTrustLineFlags remains a separate authorization path." if can_sign
            else "No positive-weight issuer signer remains; a separate post-lock SetTrustLineFlags attempt was not run.",
            "classic_trustline_flags" if "classic_trustline_flags" in observations else None)
        add("sac.admin", "TESTED_PASS", "Confirmed handover transaction and live SAC admin agree with the fixed custom account.", "handover")
        add("sac.set_authorized", "TESTED_PASS",
            "ML-DSA-65 credential accepted in Wasm (unaudited ml-dsa 0.1.1); holder trustline authorized."
            + (" A second transaction succeeded after the issuer lock." if locked else ""),
            ("ml_dsa_set_authorized", "ml_dsa_after_lock") if locked else "ml_dsa_set_authorized")
        add("sac.mint", "TESTED_REJECT", "Genuine operator credential rejected by the administrator's function policy in enforced simulation.", "operator_mint")
        for name in ("clawback", "set_admin"):
            add("sac." + name, "UNCOVERED", "Matched administrator source refuses this function; no live negative probe was run for this function.")
        add("admin.upgrade", "UNCOVERED", "Matched build has no upgrade entry point; no separate live upgrade probe was run.")
        for label in ("corrupted_signature", "wrong_network_signature", "replayed_entry"):
            add("auth." + label, "TESTED_REJECT", "Rejected in enforced RPC simulation; no failed transaction was committed.", label)
        add("transaction.source_and_fee_payer", "UNCOVERED", "Transaction and fee-bump envelopes still use Ed25519; custom-account authentication does not replace them.")
        add("registry.admin", "EXPOSED", "Registry tenant and registrar authority remain with the run's classical Ed25519 deployer.")
        add("registry.policy", "DECLARED", "Freeze/Mint/Clawback quorums are declarations only; policy_assessment remains Unverified.")
        if deployment["registry"].get("revision_checked_writes"):
            add("registry.revision_conflict", "TESTED_REJECT", "A stale expected revision was rejected without a policy write.", "registry_revision_conflict")
        if observed["reads"]["policy"]["value"]["policy_revision"] != asset["policy_revision"]:
            for row in paths:
                if row["asset"] == code:
                    row["status"] = "STALE"
    return paths


def make_assessment(deployment, snapshot, deployment_path, snapshot_path):
    inputs = [deployment_path, snapshot_path, *[ROOT / p for p in deployment["artifacts"]],
              ROOT / "contracts/qasset-sac-admin/src/lib.rs", ROOT / "contracts/qasset-sac-admin/src/test.rs",
              ROOT / "contracts/qasset-registry/src/lib.rs", ROOT / "scripts/qasset_poc_testnet.py",
              ROOT / "Cargo.lock", ROOT / "tools/qasset-sac-signer/Cargo.lock", *[ROOT / p for p in TOOL_SOURCES]]
    body = {"schema": "qasset-authority-assessment-v2", "generated_at_utc": now(),
            "timestamp_source": "generator clock; not independently attested",
            "tool": {"name": "qasset-authority-analyzer", "version": TOOL_VERSION,
                     "source_sha256": {p: file_hash(ROOT / p)["sha256"] for p in TOOL_SOURCES}},
            "network": "testnet", "network_passphrase": PASSPHRASE,
            "ledger_sequence_read": snapshot["ledger_end"], "ledger_range": [snapshot["ledger_start"], snapshot["ledger_end"]],
            "registry": deployment["registry"]["id"],
            "assets": {code: {"sac": a["sac"], "policy_revision": a["policy_revision"],
                       "issuer": a["issuer"], "holder": a["holder"], "administrator": a["admin"],
                       "issuer_signers": snapshot["assets"][code]["issuer"]["signers"],
                       "issuer_thresholds": snapshot["assets"][code]["issuer"]["thresholds"],
                       "issuer_flags": snapshot["assets"][code]["issuer"]["flags"],
                       "administrator_wasm_sha256": snapshot["assets"][code]["admin_instance"]["wasm_sha256"]}
                       for code, a in deployment["assets"].items()},
            "cryptography": {"algorithm": "ML-DSA-65", "implementation": "RustCrypto ml-dsa 0.1.1",
                "execution": "inside contract Wasm; unaudited; not CAP-87", "context": "qasset-sac-admin-auth-v1",
                "operator_public_key_sha256": deployment["operator_public_key_sha256"]},
            "deployment_input": str(deployment_path.resolve().relative_to(ROOT)),
            "snapshot_input": str(snapshot_path.resolve().relative_to(ROOT)),
            "inputs": {str(p.resolve().relative_to(ROOT)): file_hash(p) for p in inputs},
            "paths": assess(deployment, snapshot),
            "limitations": ["No overall security score or verified registry policy.",
                            "ML-DSA-65 runs inside Wasm with unaudited RustCrypto ml-dsa 0.1.1, not CAP-87.",
                            "Live reads span a ledger range, not an atomic snapshot.",
                            "Historical negative responses are recorded transcripts, not signed attestations; live probes require re-execution."]}
    return {**body, "assessment_sha256": hashlib.sha256(canonical(body)).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, default=ROOT / "deployments/testnet/qasset-poc.json")
    parser.add_argument("--snapshot", type=Path, default=ROOT / "evidence/qasset-authority-inputs.json")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/qasset-authority-assessment.json")
    args = parser.parse_args()
    deployment = json.loads(args.deployment.read_text())
    snapshot = collect(deployment)
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    args.snapshot.write_text(json.dumps(snapshot, indent=2) + "\n")
    result = make_assessment(deployment, snapshot, args.deployment, args.snapshot)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "paths": len(result["paths"]), "sha256": result["assessment_sha256"]}))


if __name__ == "__main__":
    main()
