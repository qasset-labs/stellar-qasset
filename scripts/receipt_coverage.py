"""Fail closed when CLI logging omits a required public transaction receipt.

This is capture completeness only. verify_testnet performs full scenario binding.
"""
from collections import Counter

from stellar_sdk import TransactionEnvelope, xdr

PASSPHRASE = "Test SDF Network ; September 2015"


def require_coverage(records, contracts, expected_calls):
    hashes, creates, calls = set(), Counter(), []
    code_to_name = {contract["wasm_sha256"]: name for name, contract in contracts.items()}
    address_to_name = {contract["id"]: name for name, contract in contracts.items()}
    for record in records:
        if record["hash"] in hashes or record["status"] != "SUCCESS":
            raise ValueError("Duplicate or unsuccessful journal receipt")
        hashes.add(record["hash"])
        envelope = TransactionEnvelope.from_xdr(record["rpc_receipt"]["envelopeXdr"], PASSPHRASE)
        if envelope.hash_hex() != record["hash"] or len(envelope.transaction.operations) != 1:
            raise ValueError("Journal envelope/hash/operation mismatch")
        host = envelope.transaction.operations[0].host_function
        if host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2:
            creates[code_to_name[host.create_contract_v2.executable.wasm_hash.hash.hex()]] += 1
        elif host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT:
            from stellar_sdk import Address
            invocation = host.invoke_contract
            name = address_to_name[Address.from_xdr_sc_address(invocation.contract_address).address]
            calls.append((name, invocation.function_name.sc_symbol.decode()))
        elif host.type != xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM:
            raise ValueError("Unsupported journal operation")
    if creates != Counter({name: 1 for name in contracts}) or calls != expected_calls:
        raise ValueError("Missing, reordered, or extra deployment/mutation receipts")
    return {"unique_receipts": len(hashes), "contract_creations": dict(creates), "ordered_calls": calls}
