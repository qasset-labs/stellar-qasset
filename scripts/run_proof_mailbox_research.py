#!/usr/bin/env python3
"""PUBLIC-FIXTURE bounded proof transport, independent XDR and actual Wasm probe.

Never signs/submits/deploys. Sealing proves only uploaded byte commitment.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess

from stellar_sdk import Account, Address, DecoratedSignature, Network, SorobanDataBuilder, StrKey, TransactionBuilder, scval, xdr
from verify_recovery_research import LEAF_PUBLIC, parse_statement

ROOT = Path(__file__).resolve().parents[1]
CHUNK = 32768


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identifiers(config):
    fields = [scval.to_string("qasset-proof-upload-v1"), scval.to_bytes(bytes.fromhex(config["network_id_hex"])),
              scval.to_address(config["parent"]), scval.to_address(config["uploader"]),
              scval.to_bytes(bytes.fromhex(config["nonce_hex"])), scval.to_bytes(bytes.fromhex(config["statement_hex"])),
              scval.to_bytes(bytes.fromhex(config["verifier_hex"])), scval.to_bytes(bytes.fromhex(config["parameters_hex"])),
              scval.to_uint32(config["length"]), scval.to_uint32(config["expires"]), scval.to_uint32(CHUNK)]
    return hashlib.sha256(scval.to_vec(fields).to_xdr_bytes()).digest()


def chain(config, proof):
    session = identifiers(config)
    rolling = hashlib.sha256(b"qasset-upload-start-v1" + session).digest()
    for index, start in enumerate(range(0, len(proof), CHUNK)):
        chunk = proof[start:start + CHUNK]
        rolling = hashlib.sha256(b"qasset-upload-chunk-v1" + rolling + index.to_bytes(4, "big")
                                 + len(chunk).to_bytes(4, "big") + chunk).digest()
    return session, rolling


def key(config, value):
    return xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA,
                         contract_data=xdr.LedgerKeyContractData(Address(config["parent"]).to_xdr_sc_address(),
                                                                value, xdr.ContractDataDurability.TEMPORARY))


def envelope(config, method, args, wasm_hash, *, chunk_index=None, authorize=False, sequence=0):
    """Complete explicit data/code footprint shape, not simulated resource estimates."""
    session_key = key(config, scval.to_vec([scval.to_symbol("Session"), scval.to_bytes(bytes.fromhex(config["session_id_hex"]))]))
    code = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_CODE, contract_code=xdr.LedgerKeyContractCode(xdr.Hash(bytes.fromhex(wasm_hash))))
    instance = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA,
        contract_data=xdr.LedgerKeyContractData(Address(config["parent"]).to_xdr_sc_address(),
           xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE), xdr.ContractDataDurability.PERSISTENT))
    writable = [session_key]
    if chunk_index is not None:
        writable.append(key(config, scval.to_vec([scval.to_symbol("Chunk"),scval.to_bytes(bytes.fromhex(config["session_id_hex"])), scval.to_uint32(chunk_index)])))
    auth = []
    if authorize:
        invocation = xdr.SorobanAuthorizedInvocation(
            xdr.SorobanAuthorizedFunction(xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
                contract_fn=xdr.InvokeContractArgs(Address(config["parent"]).to_xdr_sc_address(),xdr.SCSymbol(method.encode()),args)), [])
        auth = [xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT), invocation)]
    result = (TransactionBuilder(Account(config["uploader"],sequence),Network.TESTNET_NETWORK_PASSPHRASE,100)
              .append_invoke_contract_function_op(config["parent"],method,args,auth=auth)
              .add_time_bounds(0,0)
              .set_soroban_data(SorobanDataBuilder().set_read_only([code,instance]).set_read_write(writable).build())
              .build())
    result.signatures.append(DecoratedSignature(bytes(4),bytes(64)))
    return result.to_xdr_object().to_xdr_bytes()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof",type=Path,default=ROOT/"target/binius-seed-research/proof.bin")
    parser.add_argument("--wasm",type=Path,default=ROOT/"target/wasm32v1-none/release/recovery_proof_mailbox.wasm")
    parser.add_argument("--target-dir",type=Path,default=ROOT/"target")
    parser.add_argument("--output-dir",type=Path,default=ROOT/"target/proof-mailbox-research")
    parser.add_argument("--report",type=Path,default=ROOT/"docs/proof-mailbox-research.json")
    parser.add_argument("--prepare-only",action="store_true")
    args=parser.parse_args()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    evidence={"schema":"qasset-proof-mailbox-research-v1","status":"in_progress",
              "recorded_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"network_requests":0,
              "submitted_transactions":0,"cryptographic_recovery_verified_by_mailbox":False}
    def save():
        args.report.write_text(json.dumps(evidence,indent=2)+"\n")
    save()
    try:
        sources=["scripts/run_proof_mailbox_research.py","scripts/verify_recovery_research.py","scripts/recovery_statement.py","docs/binius-seed-research.json","docs/seed-proof-network-limits.json",
                 "contracts/recovery-proof-mailbox/Cargo.toml","contracts/recovery-proof-mailbox/src/lib.rs",
                 "contracts/recovery-proof-mailbox/src/test.rs","contracts/recovery-proof-mailbox/examples/mailbox_wasm_probe.rs",
                 "Cargo.toml","Cargo.lock"]
        initial={p:sha(ROOT/p) for p in sources}
        previous=json.loads((ROOT/"docs/binius-seed-research.json").read_text())
        if sha(args.proof)!=previous["proof_sha256"]:
            raise RuntimeError("Expected the previously verified public proof fixture")
        proof=args.proof.read_bytes()
        statement=parse_statement(bytes.fromhex(previous["statement"]["canonical_xdr_hex"]))
        config={"network_id_hex":statement.network_id.hex(),"parent":StrKey.encode_contract(bytes([85])*32),
                "uploader":StrKey.encode_ed25519_public_key(LEAF_PUBLIC),
                "nonce_hex":hashlib.sha256(b"qasset-mailbox-public-fixture-v1"+bytes.fromhex(previous["proof_sha256"])).hexdigest(),
                "statement_hex":statement.digest().hex(),"verifier_hex":statement.verifier_id.hex(),
                "parameters_hex":statement.parameters_id.hex(),"length":len(proof),"expires":statement.valid_until_ledger,
                "current_ledger":1000,"proof_sha256":previous["proof_sha256"]}
        session,commitment=chain(config,proof)
        config.update({"session_id_hex":session.hex(),"expected_chain_hex":commitment.hex()})
        input_path=args.output_dir/"input.json"
        input_path.write_text(json.dumps(config,indent=2)+"\n")
        header=scval.to_struct({"uploader":scval.to_address(config["uploader"]),"nonce":scval.to_bytes(bytes.fromhex(config["nonce_hex"])),
                               "statement":scval.to_bytes(statement.digest()),"verifier":scval.to_bytes(statement.verifier_id),
                               "parameters":scval.to_bytes(statement.parameters_id),"length":scval.to_uint32(len(proof)),
                               "expires":scval.to_uint32(config["expires"])})
        wasm_hash=sha(args.wasm)
        messages=[("open",[header,scval.to_bytes(commitment)],None,True)]
        for index,start in enumerate(range(0,len(proof),CHUNK)):
            messages.append(("append",[scval.to_bytes(session),scval.to_uint32(index),scval.to_bytes(proof[start:start+CHUNK])],index,True))
        messages.append(("seal",[scval.to_bytes(session)],None,False))
        sizes=[]
        for sequence,(method,parameters,index,auth) in enumerate(messages):
            raw=envelope(config,method,parameters,wasm_hash,chunk_index=index,authorize=auth,sequence=sequence)
            (args.output_dir/f"unsigned-{sequence:02}-{method}.xdr").write_text(xdr.TransactionEnvelope.from_xdr_bytes(raw).to_xdr()+"\n")
            sizes.append({"method":method,"chunk_index":index,"envelope_bytes":len(raw)})
        settings=json.loads((ROOT/"docs/seed-proof-network-limits.json").read_text())["response"]["updated_entry"]
        caps=[x["contract_bandwidth_v0"]["tx_max_size_bytes"] for x in settings if "contract_bandwidth_v0" in x]
        if len(caps)!=1 or any(s["envelope_bytes"]>caps[0] for s in sizes):
            raise RuntimeError("A serialized upload envelope exceeds the recorded bandwidth cap")
        evidence.update({"source_sha256":initial,"proof_sha256":sha(args.proof),"wasm_sha256":wasm_hash,
                         "wasm_bytes":args.wasm.stat().st_size,"config":config,"upload_envelopes":sizes,
                         "max_envelope_bytes":max(s["envelope_bytes"] for s in sizes),"recorded_transaction_cap_bytes":caps[0],
                         "serialization_scope":"Explicit code/instance/session/chunk footprint plus source-account authorization and one zero outer signature placeholder. Resource/fee values are not simulated. No transaction signed, valid fee/sequence attested, or submitted.",
                         "chunk_bytes":CHUNK,"input_sha256":sha(input_path),"artifact_directory":str(args.output_dir.resolve())})
        save()
        if args.prepare_only:
            print(input_path)
            return
        host_output=args.output_dir/"wasm-host.json"
        result=subprocess.run(["cargo","run","--locked","--offline","-p","recovery-proof-mailbox","--example","mailbox_wasm_probe",
                               "--target-dir",str(args.target_dir.resolve()),"--",str(args.wasm.resolve()),str(args.proof.resolve()),
                               str(input_path.resolve()),str(host_output.resolve())],cwd=ROOT,text=True,capture_output=True,timeout=600)
        if result.returncode:
            raise RuntimeError("Actual Wasm host probe failed: "+result.stderr[-3000:])
        host=json.loads(host_output.read_text())
        evidence["wasm_host"]=host
        checks = host.get("measurements", [])
        if not (host.get("status") == "passed_actual_wasm_transport_only"
                and host.get("actual_wasm_contract") is True
                and host.get("security_approved") is False
                and host.get("backend_available") is False
                and host.get("require_verified_rejected") is True
                and host.get("sealed_unverified") is True
                and host.get("roundtrip_bytes_equal") is True
                and host.get("roundtrip_sha256_equal") is True
                and host.get("independent_session_id_matches") is True
                and host.get("proof_sha256") == sha(args.proof)
                and host.get("wasm_sha256") == wasm_hash
                and host.get("input_sha256") == sha(input_path)
                and host.get("session_id_hex") == session.hex()
                and host.get("expected_chain_hex") == commitment.hex()
                and host.get("proof_bytes") == len(proof)
                and host.get("chunk_bytes") == CHUNK
                and host.get("chunk_count") == (len(proof) + CHUNK - 1) // CHUNK
                and host.get("read_slice_bytes") == 8192
                and host.get("stellar_rpc_requests") == 0
                and host.get("submitted_transactions") == 0
                and host.get("per_call_cpu_limit") == 400000000
                and host.get("per_call_memory_limit") == 41943040
                and len(checks) == 87
                and all(row.get("passed") is True and row.get("error") is None
                        and 0 < row.get("cpu_instructions", 0) <= 400000000
                        and 0 < row.get("memory_bytes", 0) <= 41943040 for row in checks)
                and host.get("maximum_call_cpu_instructions") == max(row["cpu_instructions"] for row in checks)
                and host.get("maximum_call_memory_bytes") == max(row["memory_bytes"] for row in checks)):
            raise RuntimeError("Wasm host probe has incomplete or mismatched transport evidence")
        if any(sha(ROOT/p)!=h for p,h in initial.items()):
            raise RuntimeError("Research sources changed during probe")
        evidence.update({"status":"passed_staged_transport_only_not_recovery",
                         "limits":["Sealing is only a hash-chain byte commitment; no seed proof, replacement possession or recovery authority is verified.",
                                    "Transport authorization is mocked in the local Wasm host probe; sender credentials need real network signatures for a live upload.",
                                    "CPU/memory observations are local SDK-host measurements with pinned test configuration, not live RPC simulation, fees or network inclusion.",
                                    "Protocol23+ live-state reads have no disk-byte cap; footprint, CPU, host+guest memory, write and restored/classic disk limits still apply.",
                                    "The quantum proof/backend and complete on-chain authority lifecycle remain unapproved; legacy recovery remains disabled."]})
        save()
        print("PASS: actual Wasm staged transport, never recovery verification")
    except Exception as error:
        evidence.update({"status":"failed","error_type":type(error).__name__,"error":str(error)})
        save()
        raise


if __name__=="__main__":
    main()
