"""PUBLIC-FIXTURE native Binius adapter; not a Soroban or approved PQ verifier."""

from dataclasses import dataclass
import hashlib
import json
import os
import resource
from pathlib import Path
import subprocess

from recovery_statement import LEAF
from verify_recovery_research import (
    LEAF_PUBLIC, ResearchProofRejected, ResearchRejection, parse_statement,
)

ROOT = Path(__file__).resolve().parents[1]
SCALAR = bytes.fromhex("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).digest()


@dataclass(frozen=True)
class BiniusResearchBackend:
    """Operator-trusted local research configuration; never an untrusted plugin."""
    verifier_id: bytes
    parameters_id: bytes
    binary: Path
    binary_sha256: str

    def check_relation(self, statement):
        if (statement.relation, statement.account_index, statement.protected_public_key) != (LEAF, None, LEAF_PUBLIC):
            raise ResearchRejection("This circuit supports only the fixed RFC8032 leaf fixture")
        if (statement.verifier_id, statement.parameters_id) != (self.verifier_id, self.parameters_id):
            raise ResearchRejection("Binius source or parameter identity differs")

    @classmethod
    def from_record(cls, record, binary: Path, repo: Path = ROOT):
        if record.get("status") != "passed_binius_leaf_functional_experiment_only":
            raise ResearchRejection("Missing successful Binius functional experiment")
        for relative, expected in record["source_sha256"].items():
            source = (repo / relative).resolve()
            if not source.is_relative_to(repo.resolve()) or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
                raise ResearchRejection("Binius experiment source changed")
        params = record["statement"]["parameters"]
        if (record.get("security_approved") is not False or record["statement"].get("backend_approved") is not False
                or params.get("approved") is not False or params.get("public_clamped_scalar_hex") != SCALAR.hex()):
            raise ResearchRejection("Unapproved fixture configuration required")
        backend = cls(fingerprint(record["source_sha256"]), fingerprint(params),
                      binary.resolve(), record["binary_sha256"])
        backend.check_relation(parse_statement(bytes.fromhex(record["statement"]["canonical_xdr_hex"])))
        return backend

    def verify(self, statement, proof: Path):
        self.check_relation(statement)
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.binary_sha256:
            raise ResearchRejection("Native Binius verifier binary changed")
        if not 1 <= proof.stat().st_size <= 256 * 1024 * 1024:
            raise ResearchRejection("Research proof size rejected")
        env = os.environ.copy()
        env["RAYON_NUM_THREADS"] = "2"
        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
        result = subprocess.run([str(self.binary), "verify", str(proof.resolve()),
                                 SCALAR.hex(), statement.digest().hex()],
                                text=True, capture_output=True, timeout=600, env=env, preexec_fn=limits)
        try:
            response = json.loads(result.stdout)
        except ValueError as error:
            raise ResearchRejection("Malformed Binius verifier response") from error
        if (type(response) is not dict or response.get("backend") != "binius64-115108-zk-96-log-inv-rate1"
                or response.get("relation") != "rfc8032-leaf-clamped-seed-v1"
                or response.get("public_scalar_hex") != SCALAR.hex()
                or response.get("action_digest_sha512_hex") != statement.digest().hex()):
            raise ResearchRejection("Binius verifier response identity mismatch")
        if result.returncode == 2 and response.get("valid") is False:
            raise ResearchProofRejected("Native Binius proof rejected")
        if result.returncode != 0 or response.get("valid") is not True:
            raise ResearchRejection("Native Binius verifier failed")
        return response
