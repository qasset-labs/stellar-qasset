"""Draft seed-recovery statement and policy preconditions, for LOCAL research only.

This module neither verifies a ZK proof nor authorizes a contract operation. It
defines the bytes a future proof must bind and checks explicit policy inputs.
The policy inputs are a model, not observations of an actual Stellar account.
"""

from dataclasses import dataclass
import hashlib

from nacl.bindings import crypto_core_ed25519_is_valid_point
from stellar_sdk import Address, scval, xdr

DOMAIN = "qasset-seed-recovery-statement-v1"
LEAF = "rfc8032-leaf-seed-v1"
ROOT = "sep5-root-seed-v1"
OPERATION = "rotate-authority"
ALGORITHM = "ML-DSA-65"


def fixed_bytes(value: bytes, size: int, field: str) -> None:
    if type(value) is not bytes or len(value) != size:
        raise ValueError("Invalid " + field)


def unsigned(value: int, bits: int, field: str) -> None:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError("Invalid " + field)


@dataclass(frozen=True)
class RecoveryStatement:
    network_id: bytes
    parent_contract: str
    protected_public_key: bytes
    relation: str
    account_index: int | None
    policy_epoch: int
    policy_hash: bytes
    replacement_algorithm: str
    replacement_public_key: bytes
    valid_until_ledger: int
    verifier_id: bytes
    parameters_id: bytes
    operation: str = OPERATION

    def __post_init__(self):
        for name in ("network_id", "protected_public_key", "policy_hash", "verifier_id", "parameters_id"):
            fixed_bytes(getattr(self, name), 32, name)
        if not crypto_core_ed25519_is_valid_point(self.protected_public_key):
            raise ValueError("Protected key must be a canonical nonidentity prime-subgroup point")
        if type(self.parent_contract) is not str:
            raise ValueError("Parent must be a contract StrKey")
        if Address(self.parent_contract).to_xdr_sc_address().type != xdr.SCAddressType.SC_ADDRESS_TYPE_CONTRACT:
            raise ValueError("Parent must be a contract StrKey")
        if self.relation == LEAF:
            if self.account_index is not None:
                raise ValueError("A leaf relation does not assert a derivation path")
        elif self.relation == ROOT:
            unsigned(self.account_index, 31, "SEP-5 account index")
        else:
            raise ValueError("Unsupported relation")
        unsigned(self.policy_epoch, 64, "policy epoch")
        unsigned(self.valid_until_ledger, 32, "expiry")
        if self.operation != OPERATION or self.replacement_algorithm != ALGORITHM:
            raise ValueError("Unsupported operation or replacement algorithm")
        # This is a structural check, not ML-DSA key validation or possession.
        fixed_bytes(self.replacement_public_key, 1952, "ML-DSA-65 public key")

    def to_xdr_bytes(self) -> bytes:
        return scval.to_vec([
            scval.to_string(DOMAIN),
            scval.to_bytes(self.network_id),
            scval.to_address(self.parent_contract),
            scval.to_bytes(self.protected_public_key),
            scval.to_string(self.relation),
            scval.to_void() if self.account_index is None else scval.to_uint32(self.account_index),
            scval.to_uint64(self.policy_epoch),
            scval.to_bytes(self.policy_hash),
            scval.to_string(self.operation),
            scval.to_string(self.replacement_algorithm),
            scval.to_bytes(self.replacement_public_key),
            scval.to_uint32(self.valid_until_ledger),
            scval.to_bytes(self.verifier_id),
            scval.to_bytes(self.parameters_id),
        ]).to_xdr_bytes()

    def digest(self) -> bytes:
        # A research transcript domain, not the current host's 32-byte auth hash.
        # SHA512 here does not upgrade Soroban's host binding or prove PQ security.
        return hashlib.sha512(self.to_xdr_bytes()).digest()


@dataclass(frozen=True)
class CurrentPolicy:
    network_id: bytes
    parent_contract: str
    protected_public_key: bytes
    relation: str
    account_index: int | None
    epoch: int
    policy_hash: bytes
    verifier_id: bytes
    parameters_id: bytes
    eligible: bool
    classical_authority_retired: bool


def check_policy_preconditions(statement: RecoveryStatement, policy: CurrentPolicy, ledger: int) -> None:
    """Reject stale/unentitled requests. Returning does NOT mean a proof is valid.

    Production would have to load authoritative state atomically, check replacement
    key possession, verify an approved proof, rotate and increment the epoch, and
    cover external/cached authorities. None of those is implemented here.
    """
    unsigned(ledger, 32, "current ledger")
    if policy.eligible is not True or policy.classical_authority_retired is not True:
        raise ValueError("Current eligibility and classical retirement are required")
    pairs = (("policy_epoch", "epoch"), ("network_id", "network_id"),
             ("parent_contract", "parent_contract"), ("protected_public_key", "protected_public_key"),
             ("relation", "relation"), ("account_index", "account_index"),
             ("policy_hash", "policy_hash"), ("verifier_id", "verifier_id"),
             ("parameters_id", "parameters_id"))
    for statement_field, policy_field in pairs:
        if getattr(statement, statement_field) != getattr(policy, policy_field):
            raise ValueError("Statement does not match current policy: " + statement_field)
    if not ledger <= statement.valid_until_ledger <= min(ledger + 1000, (1 << 32) - 1):
        raise ValueError("Statement expiry is outside the model's 1000-ledger window")
