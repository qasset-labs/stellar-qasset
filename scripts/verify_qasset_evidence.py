#!/usr/bin/env python3
"""Separate implementation of authority-evidence verification. No analyzer imports.

Offline mode checks recorded input consistency. Online mode additionally rechecks
ledger receipts, executable bytes, live authority and registry revisions on Testnet.
Historical RPC simulation transcripts are not signed attestations.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

from stellar_sdk import (Account, Address, Asset, FeeBumpTransactionEnvelope,
                         Keypair, TransactionBuilder, TransactionEnvelope, scval, xdr)
from stellar_sdk.auth import authorization_payload_hash
from stellar_sdk.operation import InvokeHostFunction, Payment, SetOptions, SetTrustLineFlags

BASE = Path(__file__).resolve().parents[1]
NETWORK = "Test SDF Network ; September 2015"
RPC_URL = "https://soroban-testnet.stellar.org"
HORIZON_URL = "https://horizon-testnet.stellar.org"
ALLOWED = frozenset(("DECLARED", "TESTED_PASS", "TESTED_REJECT", "EXPOSED", "UNCOVERED", "STALE", "INCONCLUSIVE"))
TOOL_VERSION = "2.0.0"
ADMIN_WASM = "f7ed9b81ca062af1b52c793fa068d43220d900c0d572e648f6e2d0f5a2a472b6"
REGISTRY_WASM = "26f684edb7e3255ac1617f1455fbfcf886a0f5b189f31974b873a5bc0f98a207"
LEGACY_REGISTRY_WASM = "fab41a07a9686c18cdffafd503ab96bdfc01ef9d9c03aa3be0e3079c5a8e5aed"
NEGATIVE_ERRORS = {"operator_mint": "Contract, #4", "corrupted_signature": "Contract, #3",
                   "wrong_network_signature": "Contract, #3", "replayed_entry": "Auth",
                   "registry_revision_conflict": "Contract, #15"}


class LiveEvidenceUnavailable(Exception):
    """A valid local assessment cannot currently be established against the network."""


class ConfigurationChanged(Exception):
    def __init__(self, reason, asset=None):
        super().__init__(reason)
        self.asset = asset


def unchanged(condition, reason, asset=None):
    if not condition:
        raise ConfigurationChanged(reason, asset)


def check_credentials(deployment):
    """Verify public credentials, invocation bindings and the specific negative mutations."""
    rows, expected = [], []
    labelled = {(o.get("asset"), o["label"]): o for o in deployment["observations"]}
    for observation in deployment["observations"]:
        label, code = observation["label"], observation.get("asset")
        if label not in ("operator_mint", "corrupted_signature", "wrong_network_signature", "replayed_entry",
                         "ml_dsa_set_authorized", "ml_dsa_after_lock"):
            continue
        _, tx = envelope(observation["envelope_xdr"])
        op = tx.operations[0]
        require(isinstance(op, InvokeHostFunction) and len(op.auth) == 1, "credential requires one invocation and authorization")
        entry = op.auth[0]
        require(entry.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS, "expected address credential")
        invocation = entry.root_invocation
        require(not invocation.sub_invocations
                and invocation.function.contract_fn == op.host_function.invoke_contract,
                "credential invocation differs from operation")
        credential = entry.credentials.address
        signature = scval.from_bytes(credential.signature)

        def append(network, signature_bytes, should_verify):
            preimage = xdr.HashIDPreimage(xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
                soroban_authorization=xdr.HashIDPreimageSorobanAuthorization(
                    xdr.Hash(hashlib.sha256(network.encode()).digest()), credential.nonce,
                    credential.signature_expiration_ledger, invocation))
            rows.append({"public_key": deployment["operator_public_key_hex"],
                         "payload": authorization_payload_hash(preimage).hex(), "signature": signature_bytes.hex()})
            expected.append(should_verify)

        append(NETWORK, signature, label not in ("corrupted_signature", "wrong_network_signature"))
        if label == "wrong_network_signature":
            append("wrong-network", signature, True)
        elif label == "corrupted_signature":
            append(NETWORK, bytes([signature[0] ^ 1]) + signature[1:], True)
        elif label == "replayed_entry":
            previous = labelled.get((code, "ml_dsa_set_authorized"))
            require(previous is not None, "replay lacks consumed successful credential")
            consumed = envelope(previous["envelope_xdr"])[1].operations[0].auth[0]
            require(entry.to_xdr() == consumed.to_xdr(), "replay differs from consumed successful credential")
            require(observation["result"]["latestLedger"] >= previous["receipt"]["ledger"],
                    "replay predates the successful credential consumption")
            require(observation["result"]["latestLedger"] <= credential.signature_expiration_ledger.uint32,
                    "replay credential was already expired")
    if not rows:
        return
    helper = BASE / "tools/qasset-evidence-crypto/target/release/qasset-evidence-crypto"
    require(helper.is_file(), "build tools/qasset-evidence-crypto before verifying credentials")
    result = subprocess.run([str(helper)], input=json.dumps(rows), text=True, capture_output=True, timeout=45)
    require(result.returncode == 0, "public credential verification helper failed")
    require(json.loads(result.stdout) == expected, "credential signature or claimed mutation is invalid")


def check_collection_metadata(body, snapshot):
    start, end = snapshot["ledger_start"], snapshot["ledger_end"]
    require(type(start) is int and type(end) is int and 0 < start <= end, "invalid observation ledger interval")
    require(body["ledger_range"] == [start, end] and body["ledger_sequence_read"] == end, "observation ledger mismatch")
    responses = [snapshot["registry_instance"]]
    for item in snapshot["assets"].values():
        responses.extend((item["admin_instance"], item["sac_instance"], item["policy_end"]))
        responses.extend(item["reads"].values())
        responses.extend(item["quorums"].values())
    for item in responses:
        for response in (item["result"], item.get("code_result")):
            if response is not None:
                ledger = response.get("latestLedger")
                require(type(ledger) is int and start <= ledger <= end, "raw response ledger outside assessment interval")
    timestamp = datetime.fromisoformat(body["generated_at_utc"])
    require(timestamp.tzinfo is not None and timestamp <= datetime.now(timezone.utc), "invalid or future assessment timestamp")
    # Timestamp is generator metadata, not a signed historical-time attestation.


def validate_tool(body, root):
    if body["schema"] == "qasset-authority-assessment-v1":
        require(digest(body) in {
            "fdb0549c31f8c75639e3b4db78cce1ad941f6b636d4bb1cc579b7e9eb4deb33b",
            "5d113555dfea699f39b2553fe12d0e5e91dd67fe2e98f76a73243a5d1f22e0ef",
            "c5e7188de27145d3e473c309b3d57a652ccf48ff631985e0b2dbb17d1c337c82"},
            "legacy schema is limited to immutable historical assessments")
        return
    require(set(body) == {"schema", "generated_at_utc", "timestamp_source", "tool", "network",
            "network_passphrase", "ledger_sequence_read", "ledger_range", "registry", "assets",
            "deployment_input", "snapshot_input", "inputs", "paths", "limitations", "cryptography"},
            "assessment schema fields mismatch")
    require(body["tool"]["version"] == TOOL_VERSION and body["tool"]["name"] == "qasset-authority-analyzer",
            "unsupported assessment tool version")
    require(body["timestamp_source"] == "generator clock; not independently attested", "unsupported timestamp provenance")
    for path in ("scripts/qasset_authority_analyzer.py", "scripts/verify_qasset_evidence.py",
                 "tools/qasset-evidence-crypto/src/main.rs", "tools/qasset-evidence-crypto/Cargo.lock",
                 "tools/qasset-evidence-crypto/Cargo.toml", "scripts/requirements-poc.lock"):
        require(path in body["inputs"], "assessment lacks tool source identity")
        require(hashlib.sha256((root / path).read_bytes()).hexdigest() == body["tool"]["source_sha256"].get(path),
                "tool source identity mismatch")
        require(body["tool"]["source_sha256"][path] == hashlib.sha256((BASE / path).read_bytes()).hexdigest(),
                "assessment was produced by different tool source; regenerate with this version")


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def input_bytes(root, name, expected):
    path = (root / name).resolve()
    require(not Path(name).is_absolute() and path.is_relative_to(root.resolve()), "input path escapes repository")
    require(re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]) is not None, "invalid input digest")
    if path.is_file():
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == expected["sha256"]:
            return data
    archived = (root / "evidence/input-archive" / expected["sha256"]).resolve()
    require(archived.is_relative_to(root.resolve()), "archived input path escapes repository")
    if archived.is_file():
        data = archived.read_bytes()
        require(hashlib.sha256(data).hexdigest() == expected["sha256"], "archived input hash mismatch")
        return data
    require(path.is_file(), f"missing input: {name}")
    return path.read_bytes()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def json_value(sc_value):
    def normalize(v):
        if isinstance(v, Address):
            return v.address
        if isinstance(v, bytes):
            return {"bytes_hex": v.hex()}
        if isinstance(v, list):
            return list(map(normalize, v))
        if isinstance(v, dict):
            return {str(k): normalize(w) for k, w in v.items()}
        return v
    return normalize(scval.to_native(sc_value))


def envelope(encoded):
    raw = xdr.TransactionEnvelope.from_xdr(encoded)
    if raw.type == xdr.EnvelopeType.ENVELOPE_TYPE_TX_FEE_BUMP:
        outer = FeeBumpTransactionEnvelope.from_xdr(encoded, NETWORK)
        return outer, outer.transaction.inner_transaction_envelope.transaction
    require(raw.type == xdr.EnvelopeType.ENVELOPE_TYPE_TX, "unsupported envelope type")
    outer = TransactionEnvelope.from_xdr(encoded, NETWORK)
    return outer, outer.transaction


def check_instance(item, address, expected_hash):
    require(item["contract"] == address, "instance identity mismatch")
    key = xdr.LedgerKey.from_xdr(item["key_xdr"])
    require(key.contract_data is not None and key.contract_data.contract == Address(address).to_xdr_sc_address()
            and key.contract_data.key.type == xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE, "wrong instance key")
    entries = item["result"].get("entries", [])
    require(len(entries) == 1 and entries[0]["key"] == item["key_xdr"], "missing instance response")
    data = xdr.LedgerEntryData.from_xdr(entries[0]["xdr"]).contract_data
    require(data.contract == key.contract_data.contract and data.key == key.contract_data.key, "instance data mismatch")
    executable = data.val.instance.executable
    if expected_hash is None:
        require(executable.type == xdr.ContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET, "SAC is not built in")
    else:
        require(executable.wasm_hash is not None and executable.wasm_hash.hash.hex() == expected_hash,
                "instance executable hash mismatch")
        code_entry = item["code_result"]["entries"][0]
        code_key = xdr.LedgerKey.from_xdr(item["code_key_xdr"])
        require(code_key.contract_code.hash.hash.hex() == expected_hash and code_entry["key"] == item["code_key_xdr"], "wrong code key")
        code = xdr.LedgerEntryData.from_xdr(code_entry["xdr"]).contract_code
        require(code.hash.hash.hex() == expected_hash and hashlib.sha256(code.code).hexdigest() == expected_hash,
                "Wasm bytes do not hash to the executable")
    require(item["wasm_sha256"] == expected_hash, "edited decoded executable hash")


def check_read(item, contract, function, values=()):
    require(item["contract"] == contract and item["function"] == function, "read identity mismatch")
    require(item["args_xdr"] == [v.to_xdr() for v in values], "read arguments mismatch")
    _, transaction = envelope(item["request_xdr"])
    op = transaction.operations[0]
    require(isinstance(op, InvokeHostFunction) and len(transaction.operations) == 1, "read is not a single invocation")
    call = op.host_function.invoke_contract
    require(call.contract_address == Address(contract).to_xdr_sc_address()
            and call.function_name.sc_symbol.decode() == function
            and [v.to_xdr() for v in call.args] == item["args_xdr"], "read request differs from claimed query")
    require(not item["result"].get("error"), "failed read used as evidence")
    value = json_value(xdr.SCVal.from_xdr(item["result"]["results"][0]["xdr"]))
    require(value == item["value"], "edited decoded read value")
    return value


def check_observations(deployment):
    ids, labelled = {}, {}
    for observation in deployment["observations"]:
        identity = observation["id"]
        require(identity not in ids, "duplicate observation ID")
        ids[identity] = observation
        key = (observation.get("asset"), observation["label"])
        require(key not in labelled, "duplicate observation label")
        labelled[key] = observation
        outer, tx = envelope(observation["envelope_xdr"])
        require(len(tx.operations) == 1, "each recorded transaction must contain one operation")
        if observation["kind"] == "transaction":
            require(re.fullmatch(r"[0-9a-f]{64}", observation["hash"]) is not None and outer.hash_hex() == observation["hash"], "transaction hash differs from envelope")
            receipt = observation["receipt"]
            require(receipt["status"] == observation["observed"] and receipt["envelopeXdr"] == observation["envelope_xdr"]
                    and receipt["txHash"] == observation["hash"], "recorded receipt mismatch")
            result = xdr.TransactionResult.from_xdr(receipt["resultXdr"])
            good_codes = (xdr.TransactionResultCode.txSUCCESS, xdr.TransactionResultCode.txFEE_BUMP_INNER_SUCCESS)
            require((result.result.code in good_codes) == (observation["observed"] == "SUCCESS"), "result XDR outcome mismatch")
        elif observation["kind"] == "simulation":
            require(observation["auth_mode"] == "enforce" and observation["expected"] == "REJECT"
                    and observation["observed"] == "REJECT" and observation["result"].get("error"), "simulation was not an enforced rejection")
            expected_error = NEGATIVE_ERRORS.get(observation["label"])
            label = observation["label"]
            cause = {"replayed_entry": "Auth, ExistingValue", "registry_revision_conflict": "Contract, #15"}.get(label, "Auth, InvalidAction")
            require(expected_error is not None and observation["expected_error"] == expected_error
                    and observation["result"]["error"].splitlines()[0] == f"HostError: Error({cause})",
                    "simulation rejected for a different reason")
            if label != "replayed_entry":
                contract = deployment["registry"]["id"] if label == "registry_revision_conflict" else deployment["assets"][observation["asset"]]["admin"]
                contract_id = Address(contract).to_xdr_sc_address().contract_id
                error_code = int(expected_error.rsplit("#", 1)[1])
                found = False
                for raw_event in observation["result"].get("events", []):
                    event = xdr.DiagnosticEvent.from_xdr(raw_event).event
                    topics = event.body.v0.topics
                    found |= (event.contract_id == contract_id and len(topics) == 2
                              and topics[0] == scval.to_symbol("error") and topics[1].type == xdr.SCValType.SCV_ERROR
                              and topics[1].error.type == xdr.SCErrorType.SCE_CONTRACT
                              and topics[1].error.contract_code.uint32 == error_code)
                require(found, "simulation lacks the expected contract error diagnostic")
        elif observation["kind"] == "submission_rejection":
            require(observation["observed"] == "REJECT" and observation["hash"] == outer.hash_hex(), "submission rejection mismatch")
            result = xdr.TransactionResult.from_xdr(observation["response"]["errorResultXdr"])
            require(result.result.code == xdr.TransactionResultCode.txBAD_AUTH, "post-lock rejection was not bad authentication")
        else:
            raise ValueError("unknown observation kind")
        code = observation.get("asset")
        if code is None:
            continue
        asset = deployment["assets"][code]
        op = tx.operations[0]
        label = observation["label"]
        invocation_labels = {"handover": "set_admin", "ml_dsa_set_authorized": "set_authorized",
                             "ml_dsa_after_lock": "set_authorized", "operator_mint": "mint",
                             "corrupted_signature": "set_authorized", "wrong_network_signature": "set_authorized",
                             "replayed_entry": "set_authorized"}
        if label in invocation_labels:
            require(isinstance(op, InvokeHostFunction), "claimed SAC operation is not an invocation")
            call = op.host_function.invoke_contract
            require(call.contract_address == Address(asset["sac"]).to_xdr_sc_address()
                    and call.function_name.sc_symbol.decode() == invocation_labels[label], "claimed SAC operation mismatch")
            if label == "handover":
                require(call.args == [Address(asset["admin"]).to_xdr_sc_val()]
                        and tx.source.account_id == asset["issuer"], "handover arguments or source mismatch")
            else:
                expected_value = scval.to_int128(10000000) if label == "operator_mint" else scval.to_bool(True)
                require(call.args == [Address(asset["holder"]).to_xdr_sc_val(), expected_value], "SAC invocation arguments mismatch")
                require(len(op.auth) == 1 and Address.from_xdr_sc_address(op.auth[0].credentials.address.address).address == asset["admin"], "wrong administrator credential")
                require(len(scval.from_bytes(op.auth[0].credentials.address.signature)) == 3309, "wrong credential length")
        elif label in ("staleness_declaration", "registry_revision_conflict"):
            require(isinstance(op, InvokeHostFunction), "revision change is not an invocation")
            call = op.host_function.invoke_contract
            signer = scval.to_struct({"address": Address(asset["admin"]).to_xdr_sc_val(),
                "algo": scval.to_enum("MlDsa65", None), "weight": scval.to_uint32(1)})
            quorum = scval.to_struct({"signers": scval.to_vec([signer]), "threshold": scval.to_uint32(1)})
            guarded = deployment["registry"].get("revision_checked_writes", False)
            args = [Address(asset["sac"]).to_xdr_sc_val(), scval.to_enum("Freeze", None), quorum]
            if guarded:
                args.append(scval.to_uint64(0 if label == "registry_revision_conflict" else asset["policy_revision"] - 1))
            require((label == "registry_revision_conflict" and guarded and observation["kind"] == "simulation"
                     or label == "staleness_declaration" and observation["kind"] == "transaction" and observation["observed"] == "SUCCESS")
                    and tx.source.account_id == deployment["registry"]["admin"]
                    and call.contract_address == Address(deployment["registry"]["id"]).to_xdr_sc_address()
                    and call.function_name.sc_symbol.decode() == ("set_role_quorum_if_revision" if guarded else "set_role_quorum")
                    and call.args == args,
                    "registry revision declaration mismatch")
            if label == "registry_revision_conflict":
                require(len(op.auth) == 1 and op.auth[0].credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT
                        and not op.auth[0].root_invocation.sub_invocations
                        and op.auth[0].root_invocation.function.contract_fn == call, "revision probe lacks tenant source authorization")
        elif label in ("classic_mint", "classic_mint_after_lock"):
            require(isinstance(op, Payment) and tx.source.account_id == asset["issuer"] and op.source is None
                    and op.destination.account_id == asset["holder"] and op.asset.code == code
                    and op.asset.issuer == asset["issuer"] and str(op.amount) == "1", "classic Payment claim mismatch")
            if label == "classic_mint_after_lock":
                require(isinstance(outer, TransactionEnvelope) and len(outer.signatures) == 1,
                        "post-lock Payment requires the issuer signature")
                try:
                    Keypair.from_public_key(asset["issuer"]).verify(outer.hash(), outer.signatures[0].signature)
                except Exception as error:
                    raise ValueError("invalid post-lock issuer signature") from error
                response = observation["response"]
                require(response["status"] == "ERROR" and response["hash"] == outer.hash_hex(),
                        "post-lock submission response mismatch")
        elif label == "classic_trustline_flags":
            require(isinstance(op, SetTrustLineFlags) and tx.source.account_id == asset["issuer"]
                    and op.trustor == asset["holder"] and op.asset.code == code and op.asset.issuer == asset["issuer"], "classic flags claim mismatch")
        elif label == "lock_issuer":
            require(isinstance(op, SetOptions) and tx.source.account_id == asset["issuer"] and op.master_weight == 0,
                    "lock claim mismatch")
    check_credentials(deployment)
    return ids, labelled


def verify(assessment, root=BASE, current_revisions=None):
    require(assessment["schema"] in ("qasset-authority-assessment-v1", "qasset-authority-assessment-v2"), "unknown assessment schema")
    body = {k: v for k, v in assessment.items() if k != "assessment_sha256"}
    require(digest(body) == assessment["assessment_sha256"], "assessment body checksum mismatch")
    require(body["network"] == "testnet" and body["network_passphrase"] == NETWORK, "not Testnet")
    inputs = {}
    for name, expected in body["inputs"].items():
        data = input_bytes(root, name, expected)
        require(hashlib.sha256(data).hexdigest() == expected["sha256"] and len(data) == expected["bytes"], f"input hash mismatch: {name}")
        inputs[name] = data
    deployment = json.loads(inputs[body["deployment_input"]])
    snapshot = json.loads(inputs[body["snapshot_input"]])
    require(deployment["schema"] == "qasset-poc-deployment-v1" and deployment["network_passphrase"] == NETWORK
            and deployment["network"] == "testnet" and snapshot["network"]["passphrase"] == NETWORK, "input network mismatch")
    require(deployment["status"] in ("completed", "pending_issuer_lock"), "unfinished deployment")
    check_collection_metadata(body, snapshot)
    require(body["registry"] == deployment["registry"]["id"], "registry identity mismatch")
    for path, expected in deployment["artifacts"].items():
        require(body["inputs"].get(path) == expected, "deployment artifact hash mismatch")
    require(hashlib.sha256(bytes.fromhex(deployment["operator_public_key_hex"])).hexdigest()
            == deployment["operator_public_key_sha256"], "operator public-key hash mismatch")
    admin_hash = next(v["sha256"] for p, v in deployment["artifacts"].items() if p.endswith("qasset_sac_admin.wasm"))
    require(admin_hash == ADMIN_WASM, "unsupported administrator executable")
    require(deployment["registry"]["wasm_sha256"] == (REGISTRY_WASM if deployment["registry"].get("revision_checked_writes")
            else LEGACY_REGISTRY_WASM), "unsupported registry executable or revision interface")
    check_instance(snapshot["registry_instance"], body["registry"], deployment["registry"]["wasm_sha256"])
    ids, observations = check_observations(deployment)
    require(set(body["assets"]) == set(deployment["assets"]) == set(snapshot["assets"]) == {"QEXP", "QCTL"}, "asset set mismatch")
    expected_rows = {}
    stale_assets = set()
    for code, asset in deployment["assets"].items():
        require(Asset(code, asset["issuer"]).contract_id(NETWORK) == asset["sac"], "issuer and asset do not derive the SAC identity")
        item = snapshot["assets"][code]
        binding = {"sac": asset["sac"], "policy_revision": asset["policy_revision"]}
        if body["schema"] == "qasset-authority-assessment-v2":
            binding.update(issuer=asset["issuer"], holder=asset["holder"], administrator=asset["admin"],
                           issuer_signers=item["issuer"]["signers"], issuer_thresholds=item["issuer"]["thresholds"],
                           issuer_flags=item["issuer"]["flags"], administrator_wasm_sha256=admin_hash)
        require(body["assets"][code] == binding, "asset revision or configuration binding mismatch")
        check_instance(item["admin_instance"], asset["admin"], admin_hash)
        check_instance(item["sac_instance"], asset["sac"], None)
        reads = item["reads"]
        require(check_read(reads["sac_admin"], asset["sac"], "admin") == asset["admin"], "live SAC admin mismatch")
        require(check_read(reads["configured_sac"], asset["admin"], "sac") == asset["sac"], "admin SAC binding mismatch")
        require(check_read(reads["protected_function"], asset["admin"], "protected_function") == "set_authorized", "protected function mismatch")
        require(check_read(reads["operator_key"], asset["admin"], "operator_key")["bytes_hex"] == deployment["operator_public_key_hex"], "operator key mismatch")
        values = [Address(asset["sac"]).to_xdr_sc_val()]
        policy = check_read(reads["policy"], body["registry"], "policy_assessment", values)
        end_policy = check_read(item["policy_end"], body["registry"], "policy_assessment", values)
        require(policy["asset"] == asset["sac"] and policy["verification"] == ["Unverified"]
                and policy["policy_revision"] == end_policy["policy_revision"], "policy is not a stable unverified declaration")
        require(check_read(reads["registry_admin"], body["registry"], "asset_admin", values) == deployment["registry"]["admin"], "registry admin mismatch")
        for role, signer, algo in (("Freeze", asset["admin"], "MlDsa65"), ("Mint", asset["issuer"], "Ed25519"), ("Clawback", asset["issuer"], "Ed25519")):
            quorum = check_read(item["quorums"][role], body["registry"], "get_role_quorum", values + [scval.to_enum(role, None)])
            require(quorum == {"signers": [{"address": signer, "algo": [algo], "weight": 1}], "threshold": 1}, "declared quorum mismatch")
        issuer = item["issuer"]
        require(issuer["account_id"] == asset["issuer"] and item["holder"]["account_id"] == asset["holder"], "Horizon identity mismatch")
        balance = next(b for b in item["holder"]["balances"] if b.get("asset_code") == code and b.get("asset_issuer") == asset["issuer"])
        require(balance["is_authorized"] and issuer["flags"]["auth_required"] and issuer["flags"]["auth_revocable"], "issuer flags or trustline authorization mismatch")
        classical = sum(s["weight"] for s in issuer["signers"] if s["type"] == "ed25519_public_key")
        has_classic = classical > 0 and classical >= max(1, issuer["thresholds"]["med_threshold"])
        post_lock = code == "QCTL" and deployment["lock_gate"]["state"] == "LOCKED"
        if post_lock:
            require(deployment["status"] == "completed" and deployment["lock_gate"]["environment_enabled"]
                    and deployment["lock_gate"]["issuer_created_this_run"] and asset["issuer_created_this_run"],
                    "lock lacks explicit gate or same-run issuer")
            require(not any(s["weight"] for s in issuer["signers"]), "locked issuer retains a positive-weight signer")
            require(all((code, label) in observations for label in ("lock_issuer", "classic_mint_after_lock", "ml_dsa_after_lock")),
                    "locked run is missing post-lock observations")
            lock = observations[code, "lock_issuer"]
            after_lock = observations[code, "ml_dsa_after_lock"]
            require(lock["kind"] == after_lock["kind"] == "transaction" and lock["observed"] == after_lock["observed"] == "SUCCESS",
                    "post-lock action or lock lacks a successful receipt")
            order = lambda o: (o["receipt"]["ledger"], o["receipt"]["applicationOrder"])
            require(order(after_lock) > order(lock), "ML-DSA action did not occur after the lock")
            rejection = observations[code, "classic_mint_after_lock"]
            lock_tx = envelope(lock["envelope_xdr"])[1]
            rejected_tx = envelope(rejection["envelope_xdr"])[1]
            require(lock["receipt"]["ledger"] <= rejection["response"]["latestLedger"] <= after_lock["receipt"]["ledger"]
                    and rejected_tx.sequence == lock_tx.sequence + 1, "classic rejection is not bound to the post-lock interval")

        def expect(path, status, label=None, additional=()):
            citations = []
            for reference in (label, *additional):
                if reference is None:
                    continue
                o = observations.get((code, reference))
                require(o is not None, f"missing evidence for {code}/{reference}")
                if status in ("TESTED_PASS", "EXPOSED"):
                    require(o["kind"] == "transaction" and o["observed"] == "SUCCESS", "positive claim lacks a successful transaction")
                else:
                    require(o["observed"] in ("REJECT", "FAILED"), "rejection claim lacks a rejection")
                citations.append({"observation_id": o["id"], "kind": o["kind"]})
                if o["kind"] == "transaction":
                    citations[-1]["hash"] = o["hash"]
            expected_rows[code, path] = (status, citations)

        expect("issuer.classic_signers", "EXPOSED" if has_classic else "UNCOVERED")
        if (code, "classic_mint") in observations:
            expect("issuer.classic_mint", "EXPOSED", "classic_mint")
        elif deployment["lock_gate"]["state"] == "LOCKED" and not has_classic and (code, "classic_mint_after_lock") in observations:
            require(deployment["lock_gate"]["environment_enabled"] and deployment["lock_gate"]["issuer_created_this_run"], "lock lacks explicit gate")
            require((code, "lock_issuer") in observations and observations[code, "lock_issuer"]["observed"] == "SUCCESS", "lock lacks successful receipt")
            expect("issuer.classic_mint", "TESTED_REJECT", "classic_mint_after_lock")
            require((code, "ml_dsa_after_lock") in observations and observations[code, "ml_dsa_after_lock"]["observed"] == "SUCCESS", "post-lock ML-DSA action missing")
        else:
            expect("issuer.classic_mint", "INCONCLUSIVE")
        expect("issuer.trustline_flags", "EXPOSED" if has_classic else "UNCOVERED", "classic_trustline_flags" if (code, "classic_trustline_flags") in observations else None)
        expect("sac.admin", "TESTED_PASS", "handover")
        expect("sac.set_authorized", "TESTED_PASS", "ml_dsa_set_authorized", ("ml_dsa_after_lock",) if post_lock else ())
        expect("sac.mint", "TESTED_REJECT", "operator_mint")
        for path in ("sac.clawback", "sac.set_admin", "admin.upgrade", "transaction.source_and_fee_payer"):
            expect(path, "UNCOVERED")
        for label in ("corrupted_signature", "wrong_network_signature", "replayed_entry"):
            expect("auth." + label, "TESTED_REJECT", label)
        expect("registry.admin", "EXPOSED")
        expect("registry.policy", "DECLARED")
        if deployment["registry"].get("revision_checked_writes"):
            expect("registry.revision_conflict", "TESTED_REJECT", "registry_revision_conflict")
        if policy["policy_revision"] != asset["policy_revision"]:
            for key in expected_rows:
                if key[0] == code:
                    expected_rows[key] = ("STALE", expected_rows[key][1])
        if current_revisions is not None and current_revisions.get(code) != asset["policy_revision"]:
            stale_assets.add(code)
    seen = set()
    for row in body["paths"]:
        key = row["asset"], row["path"]
        require(key not in seen and key in expected_rows, "duplicate or unknown authority path")
        seen.add(key)
        require(row["status"] in ALLOWED, "unknown status")
        require(not row["status"].startswith("TESTED_") or row.get("citations"), "tested path lacks citation")
        status, citations = expected_rows[key]
        require(row["status"] == status and row["citations"] == citations, f"assessment does not recompute: {key}")
        for citation in row["citations"]:
            require(citation["observation_id"] in ids, "unknown observation citation")
    require(seen == set(expected_rows), "authority paths removed")
    validate_tool(body, root)
    if body["schema"] == "qasset-authority-assessment-v2":
        require(body["cryptography"] == {"algorithm": "ML-DSA-65", "implementation": "RustCrypto ml-dsa 0.1.1",
                "execution": "inside contract Wasm; unaudited; not CAP-87", "context": "qasset-sac-admin-auth-v1",
                "operator_public_key_sha256": deployment["operator_public_key_sha256"]}, "cryptographic mechanism mismatch")
    stale = [{"asset": r["asset"], "path": r["path"], "status": "STALE"} for r in body["paths"] if r["asset"] in stale_assets or r["status"] == "STALE"]
    return {"status": "STALE" if stale else "SUCCESS", "consistent": True, "fresh": not stale, "paths_checked": len(seen), "stale_paths": stale,
            "historical_rejections": "recorded RPC transcripts; credential semantics checked; not signed attestations",
            "scope": "offline consistency only" if current_revisions is None else "live Testnet verification"}


def fetch(url, payload=None):
    request = urllib.request.Request(url, None if payload is None else json.dumps(payload).encode(),
                                     headers={"User-Agent": "stellar-cli/26.0.0", "Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                return json.load(response)
        except (TimeoutError, urllib.error.URLError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (429, 500, 502, 503, 504):
                raise
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def network_call(method, params=None):
    response = fetch(RPC_URL, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    if "error" in response:
        raise LiveEvidenceUnavailable(f"RPC {method} failed: {response['error']}")
    return response["result"]


def live_read(source, recorded):
    tx = (TransactionBuilder(Account(source, 0), NETWORK, 100)
          .append_invoke_contract_function_op(recorded["contract"], recorded["function"],
              [xdr.SCVal.from_xdr(v) for v in recorded["args_xdr"]]).set_timeout(300).build())
    response = network_call("simulateTransaction", {"transaction": tx.to_xdr(), "authMode": "enforce"})
    if response.get("error"):
        raise LiveEvidenceUnavailable(f"live read failed: {response['error']}")
    return json_value(xdr.SCVal.from_xdr(response["results"][0]["xdr"]))


def check_live(deployment, snapshot):
    require(network_call("getNetwork")["passphrase"] == NETWORK, "RPC is not Testnet")
    transactions = [o for o in deployment["observations"] if o["kind"] == "transaction"]

    def recheck(observation):
        live = network_call("getTransaction", {"hash": observation["hash"]})
        if live["status"] == "NOT_FOUND":
            raise LiveEvidenceUnavailable(f"live receipt unavailable: {observation['hash']}")
        require(live["status"] == observation["observed"], f"live receipt changed: {observation['hash']}")
        require(live["envelopeXdr"] == observation["envelope_xdr"]
                and live["resultXdr"] == observation["receipt"]["resultXdr"]
                and live["ledger"] == observation["receipt"]["ledger"]
                and live["applicationOrder"] == observation["receipt"]["applicationOrder"], "live transaction data mismatch")
        return observation["hash"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        checked_hashes = list(pool.map(recheck, transactions))

    def live_instance(recorded, asset=None):
        updated = dict(recorded)
        updated["result"] = network_call("getLedgerEntries", {"keys": [recorded["key_xdr"]]})
        if recorded.get("code_key_xdr"):
            updated["code_result"] = network_call("getLedgerEntries", {"keys": [recorded["code_key_xdr"]]})
        if not updated["result"].get("entries") or (recorded.get("code_key_xdr") and not updated["code_result"].get("entries")):
            raise LiveEvidenceUnavailable(f"live contract unavailable or archived: {recorded['contract']}")
        data = xdr.LedgerEntryData.from_xdr(updated["result"]["entries"][0]["xdr"]).contract_data
        actual = data.val.instance.executable
        actual_hash = actual.wasm_hash.hash.hex() if actual.wasm_hash else None
        unchanged(actual_hash == recorded["wasm_sha256"], "live executable changed", asset)
        check_instance(updated, recorded["contract"], recorded["wasm_sha256"])

    live_instance(snapshot["registry_instance"])
    revisions = {}
    source = deployment["accounts"]["deployer"]
    for code, asset in deployment["assets"].items():
        item = snapshot["assets"][code]
        live_instance(item["admin_instance"], code)
        live_instance(item["sac_instance"], code)
        policy = live_read(source, item["reads"]["policy"])
        revisions[code] = policy["policy_revision"]
        # Revision changes are returned as STALE for affected paths, not an integrity error.
        if revisions[code] != asset["policy_revision"]:
            continue
        for key in ("sac_admin", "configured_sac", "operator_key", "protected_function", "registry_admin"):
            unchanged(live_read(source, item["reads"][key]) == item["reads"][key]["value"], f"live {code}/{key} changed", code)
        for quorum in item["quorums"].values():
            unchanged(live_read(source, quorum) == quorum["value"], f"live {code} quorum changed without matching revision", code)
        issuer = fetch(HORIZON_URL + "/accounts/" + asset["issuer"])
        for field in ("signers", "thresholds", "flags"):
            unchanged(issuer[field] == item["issuer"][field], f"live issuer {field} changed", code)
        holder = fetch(HORIZON_URL + "/accounts/" + asset["holder"])
        balance = next((b for b in holder["balances"] if b.get("asset_code") == code and b.get("asset_issuer") == asset["issuer"]), None)
        unchanged(balance is not None and balance["is_authorized"], f"{code} holder trustline changed", code)
        # Close the read interval by checking the monotonic policy revision again.
        revisions[code] = live_read(source, item["reads"]["policy"])["policy_revision"]
    return revisions, checked_hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assessment", type=Path, default=BASE / "evidence/qasset-authority-assessment.json")
    parser.add_argument("--offline", action="store_true", help="consistency only; does not establish live receipt availability or freshness")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        assessment = json.loads(args.assessment.read_text())
        result = verify(assessment)
        if not args.offline:
            deployment = json.loads(input_bytes(BASE, assessment["deployment_input"], assessment["inputs"][assessment["deployment_input"]]))
            snapshot = json.loads(input_bytes(BASE, assessment["snapshot_input"], assessment["inputs"][assessment["snapshot_input"]]))
            revisions, hashes = check_live(deployment, snapshot)
            result = verify(assessment, current_revisions=revisions)
            result.update(transactions_rechecked=len(hashes), current_policy_revisions=revisions)
            result.update(verified_at_utc=datetime.now(timezone.utc).isoformat(),
                          latest_ledger=network_call("getLatestLedger")["sequence"])
        else:
            result["live_freshness_checked"] = False
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0 if result["fresh"] else 1
    except ConfigurationChanged as error:
        result = {"status": "STALE", "consistent": True, "fresh": False, "reason": str(error),
                  "stale_paths": [{"asset": row["asset"], "path": row["path"], "status": "STALE"}
                                  for row in assessment["paths"] if error.asset is None or row["asset"] == error.asset]}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 1
    except (LiveEvidenceUnavailable, urllib.error.URLError, TimeoutError) as error:
        result = {"status": "INCONCLUSIVE", "consistent": True, "fresh": None, "reason": str(error),
                  "inconclusive_paths": [{"asset": row["asset"], "path": row["path"], "status": "INCONCLUSIVE"}
                                         for row in assessment["paths"]]}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 2
    except (ValueError, KeyError, IndexError, TypeError, StopIteration, OSError) as error:
        result = {"status": "INVALID", "consistent": False, "fresh": None, "error": str(error)}
        if args.report:
            args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
