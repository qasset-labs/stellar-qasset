"""Strict request checks for the PUBLIC-FIXTURE off-chain recovery experiment.

This is a local model with an insecure proof backend. It does not authorize funds,
observe network state, retire a real key, or implement a production wallet.
"""

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import subprocess

from stellar_sdk import scval, xdr

from recovery_statement import (
    DOMAIN, LEAF, ROOT, CurrentPolicy, RecoveryStatement, check_policy_preconditions,
    fixed_bytes, unsigned,
)

REPO = Path(__file__).resolve().parents[1]
POP_DOMAIN = b"qasset-research-replacement-pop-v1"
ROOT_PUBLIC = bytes.fromhex("e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544")
LEAF_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


class ResearchRejection(ValueError):
    """An explicit rejection; no failed operation returns an authorizing state."""


class ResearchProofRejected(ResearchRejection):
    """A well-formed native verifier explicitly rejected this exact proof/message."""


def parse_statement(raw: bytes) -> RecoveryStatement:
    """Decode one bounded, canonical, typed statement; reject trailing data."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192:
        raise ResearchRejection("Statement size or type rejected")
    try:
        value = xdr.SCVal.from_xdr_bytes(raw)
        if value.type != xdr.SCValType.SCV_VEC or value.vec is None:
            raise ResearchRejection("Statement must be an XDR vector")
        fields = value.vec.sc_vec
        types = [xdr.SCValType.SCV_STRING, xdr.SCValType.SCV_BYTES,
                 xdr.SCValType.SCV_ADDRESS, xdr.SCValType.SCV_BYTES,
                 xdr.SCValType.SCV_STRING, None, xdr.SCValType.SCV_U64,
                 xdr.SCValType.SCV_BYTES, xdr.SCValType.SCV_STRING,
                 xdr.SCValType.SCV_STRING, xdr.SCValType.SCV_BYTES,
                 xdr.SCValType.SCV_U32, xdr.SCValType.SCV_BYTES, xdr.SCValType.SCV_BYTES]
        if len(fields) != len(types) or any(t is not None and v.type != t for v, t in zip(fields, types)):
            raise ResearchRejection("Statement field count or types rejected")
        if scval.from_string(fields[0]) != DOMAIN.encode("ascii"):
            raise ResearchRejection("Unknown statement domain")
        index = None
        if fields[5].type == xdr.SCValType.SCV_U32:
            index = scval.from_uint32(fields[5])
        elif fields[5].type != xdr.SCValType.SCV_VOID:
            raise ResearchRejection("Invalid typed derivation index")
        statement = RecoveryStatement(
            network_id=scval.from_bytes(fields[1]), parent_contract=scval.from_address(fields[2]).address,
            protected_public_key=scval.from_bytes(fields[3]), relation=scval.from_string(fields[4]).decode("ascii"),
            account_index=index, policy_epoch=scval.from_uint64(fields[6]),
            policy_hash=scval.from_bytes(fields[7]), operation=scval.from_string(fields[8]).decode("ascii"),
            replacement_algorithm=scval.from_string(fields[9]).decode("ascii"), replacement_public_key=scval.from_bytes(fields[10]),
            valid_until_ledger=scval.from_uint32(fields[11]), verifier_id=scval.from_bytes(fields[12]),
            parameters_id=scval.from_bytes(fields[13]),
        )
        if statement.to_xdr_bytes() != raw:
            raise ResearchRejection("Noncanonical XDR or trailing data")
        return statement
    except ResearchRejection:
        raise
    except Exception as error:
        raise ResearchRejection("Malformed statement") from error


def replacement_possession_digest(statement: RecoveryStatement) -> bytes:
    return hashlib.sha256(POP_DOMAIN + statement.digest()).digest()


@dataclass(frozen=True)
class ResearchBackend:
    mode: str
    rounds: int
    verifier_id: bytes
    parameters_id: bytes
    binary: Path
    binary_sha256: str

    def check_relation(self, statement: RecoveryStatement):
        """The binary has a fixed fixture relation, never an arbitrary wallet key."""
        if type(self.rounds) is not int or self.rounds != 8:
            raise ResearchRejection("This adapter supports only the recorded insecure eight-round experiment")
        if self.mode == "sep5-root":
            expected = (ROOT, 0, ROOT_PUBLIC)
        elif self.mode == "leaf":
            expected = (LEAF, None, LEAF_PUBLIC)
        else:
            raise ResearchRejection("Unsupported circuit mode")
        if (statement.relation, statement.account_index, statement.protected_public_key) != expected:
            raise ResearchRejection("Statement key/path does not match the proof circuit")
        if statement.verifier_id != self.verifier_id or statement.parameters_id != self.parameters_id:
            raise ResearchRejection("Statement verifier or parameters mismatch")

    @classmethod
    def from_record(cls, record: dict, binary: Path, repo: Path = REPO):
        if record.get("status") != "passed_functional_experiment_only_not_secure":
            raise ResearchRejection("No passed functional experiment")
        # These are operator-trusted repository records, not attacker-provided certificates.
        for relative, expected in record["source_sha256"].items():
            source = (repo / relative).resolve()
            if not source.is_relative_to(repo.resolve()) or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
                raise ResearchRejection("Recorded proof sources changed")
        fingerprint = hashlib.sha256(json.dumps(record["source_sha256"], sort_keys=True, separators=(",", ":")).encode()).digest()
        parameters = record["statement"]["parameters"]
        parameters_id = hashlib.sha256(json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode()).digest()
        expected = parse_statement(bytes.fromhex(record["statement"]["canonical_xdr_hex"]))
        if parameters.get("approved") is not False or record["statement"].get("backend_approved") is not False:
            raise ResearchRejection("A research record cannot assert production approval")
        backend = cls(parameters["research_mode"], parameters["rounds"], fingerprint, parameters_id,
                      binary.resolve(), record["binary_sha256"])
        backend.check_relation(expected)
        return backend

    def verify(self, statement: RecoveryStatement, proof: Path):
        self.check_relation(statement)
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.binary_sha256:
            raise ResearchRejection("Research verifier binary changed")
        if not 1 <= proof.stat().st_size <= 256 * 1024 * 1024:
            raise ResearchRejection("Proof size rejected")
        result = subprocess.run([str(self.binary), "verify", statement.digest().hex(), str(proof.resolve()),
                                 str(self.rounds), self.mode], text=True, capture_output=True, timeout=600)
        try:
            response = json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise ResearchRejection("Invalid proof-verifier response") from error
        if (response.get("message_digest_hex") != statement.digest().hex()
                or response.get("relation_mode") != self.mode or response.get("rounds") != self.rounds):
            raise ResearchRejection("Proof-verifier response identity mismatch")
        if result.returncode == 1 and response.get("valid") is False:
            raise ResearchProofRejected("Proof verification rejected")
        if result.returncode != 0 or response.get("valid") is not True:
            raise ResearchRejection("Research proof verifier failed")
        return response


@dataclass(frozen=True)
class RecoveryState:
    policy: CurrentPolicy
    active_public_key: bytes
    consumed: bool = False

    def __post_init__(self):
        fixed_bytes(self.active_public_key, 1952, "model active key")
        unsigned(self.policy.epoch, 64, "model epoch")
        if type(self.consumed) is not bool:
            raise ResearchRejection("Invalid consumed flag")


def consume_research_recovery(state: RecoveryState, raw_statement: bytes, proof: Path,
                              possession_signature: bytes, ledger: int,
                              backend: ResearchBackend, fixture_verifier: Path) -> tuple[RecoveryState, dict]:
    """Return a new local state ONLY after real proof and ML-DSA verification.

    The local retirement flag is an explicit model assumption, not observed
    on-chain retirement. No arbitrary callback can replace either verifier.
    """
    if state.consumed:
        raise ResearchRejection("Recovery permission already consumed")
    if state.policy.epoch == (1 << 64) - 1:
        raise ResearchRejection("Epoch cannot increment")
    statement = parse_statement(raw_statement)
    backend.check_relation(statement)
    check_policy_preconditions(statement, state.policy, ledger)
    if statement.replacement_public_key == state.active_public_key:
        raise ResearchRejection("Replacement must change the active key")
    fixed_bytes(possession_signature, 3309, "replacement possession signature")
    possession = subprocess.run([str(fixture_verifier.resolve()), "verify", statement.replacement_public_key.hex(),
                                  replacement_possession_digest(statement).hex(), possession_signature.hex(), "RECOVERY"],
                                 text=True, capture_output=True, timeout=60)
    if possession.returncode != 0 or possession.stdout.strip() != "valid":
        raise ResearchRejection("Replacement-key possession rejected")
    verification = backend.verify(statement, proof)
    updated = RecoveryState(replace(state.policy, epoch=state.policy.epoch + 1, eligible=False),
                            statement.replacement_public_key, True)
    return updated, verification
