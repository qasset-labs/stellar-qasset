#!/usr/bin/env python3
"""Check PUBLIC SEP-5 vectors; this is ordinary derivation, never a ZK proof.

Run: python3 scripts/check_recovery_relation.py
Dependency: python3 -m pip install -r scripts/requirements-crypto-demo.txt

Only the repository's explicitly public fixtures are accepted. There are no seed,
mnemonic, path, or key command-line options. Never fund these published test keys.
Witness bytes are neither printed nor written. Python cannot guarantee zeroization;
this deliberately small compatibility demonstration is not production wallet code.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unicodedata

import nacl
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from nacl.signing import SigningKey

FIXTURES = Path(__file__).resolve().parents[1] / "docs" / "recovery-relation-vectors.json"
PUBLIC_KEY_VERSION = 6 << 3
HARDENED = 1 << 31
SUBGROUP_ORDER = (1 << 252) + 27742317777372353535851937790883648493


class CheckFailure(Exception):
    """Failure whose message deliberately excludes fixture witness material."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def mnemonic_to_seed(mnemonic: str, passphrase: str) -> bytes:
    # BIP-39 normalization and PBKDF2 are checked against the published seed.
    # This does not validate a mnemonic's dictionary/checksum or generated entropy.
    normalized = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", normalized, salt, 2048, dklen=64)


def slip10_ed25519(seed: bytes, path: tuple[int, ...]) -> bytes:
    require(16 <= len(seed) <= 64, "Unsupported public-fixture root length")
    digest = hmac.digest(b"ed25519 seed", seed, "sha512")
    key, chain = digest[:32], digest[32:]
    for index in path:
        require(type(index) is int and 0 <= index < HARDENED, "Invalid hardened account index")
        message = b"\x00" + key + (index | HARDENED).to_bytes(4, "big")
        digest = hmac.digest(chain, message, "sha512")
        key, chain = digest[:32], digest[32:]
    return key


def ed25519_public_key(leaf_seed: bytes) -> bytes:
    require(len(leaf_seed) == 32, "Ed25519 seed must be 32 bytes")
    return bytes(SigningKey(leaf_seed).verify_key)


def expanded_clamped_scalar(leaf_seed: bytes) -> bytes:
    scalar = bytearray(hashlib.sha512(leaf_seed).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


def encode_strkey(version: int, payload: bytes) -> str:
    require(len(payload) == 32, "StrKey payload must be 32 bytes")
    body = bytes([version]) + payload
    checksum = binascii.crc_hqx(body, 0).to_bytes(2, "little")
    return base64.b32encode(body + checksum).decode("ascii")


def decode_public_strkey(address: str) -> bytes:
    if not isinstance(address, str) or len(address) != 56:
        raise ValueError("Invalid public StrKey length")
    try:
        raw = base64.b32decode(address, casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid public StrKey encoding") from exc
    if len(raw) != 35 or raw[0] != PUBLIC_KEY_VERSION:
        raise ValueError("Wrong public StrKey version")
    expected_crc = binascii.crc_hqx(raw[:-2], 0).to_bytes(2, "little")
    if not hmac.compare_digest(raw[-2:], expected_crc):
        raise ValueError("Invalid public StrKey checksum")
    if base64.b32encode(raw).decode("ascii") != address:
        raise ValueError("Noncanonical public StrKey")
    return raw[1:-2]


def must_reject_public_strkey(address: str) -> None:
    try:
        decode_public_strkey(address)
    except ValueError:
        return
    raise CheckFailure("Malformed public StrKey was accepted")


def run() -> tuple[int, int]:
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    require(data.get("schema_version") == 1, "Unsupported fixture schema")
    require(data.get("public_test_vectors_only") is True, "Fixture is not marked public")
    require(nacl.__version__ == data["dependency"]["version"], "Install the pinned PyNaCl version")
    checks = 0
    vectors = data["vectors"]
    require(len(vectors) == 5, "Expected all five official SEP-5 examples")
    for vector in vectors:
        seed = mnemonic_to_seed(vector["mnemonic"], vector["passphrase"])
        require(hmac.compare_digest(seed.hex(), vector["expected_bip39_seed_hex"]), "BIP-39 vector mismatch")
        parent = slip10_ed25519(seed, (44, 148))
        require(hmac.compare_digest(parent.hex(), vector["expected_parent_seed_hex"]), "SLIP-0010 parent mismatch")
        checks += 2
        for account in vector["accounts"]:
            index = account["index"]
            expected = decode_public_strkey(account["address"])
            leaf = slip10_ed25519(seed, (44, 148, index))
            public = ed25519_public_key(leaf)
            require(public == expected, "SEP-5 public-key vector mismatch")
            require(encode_strkey(PUBLIC_KEY_VERSION, public) == account["address"], "StrKey roundtrip mismatch")
            scalar = expanded_clamped_scalar(leaf)
            # This public fixture already gives us the seed. We derive its scalar
            # normally; we do NOT recover it from A or simulate a quantum attack.
            require(crypto_scalarmult_ed25519_base_noclamp(scalar) == public, "RFC8032 scalar-to-public relation mismatch")
            reduced = (int.from_bytes(scalar, "little") % SUBGROUP_ORDER).to_bytes(32, "little")
            require(crypto_scalarmult_ed25519_base_noclamp(reduced) == public, "Reduced scalar-to-public relation mismatch")
            require(ed25519_public_key(reduced) != public, "Reduced scalar unexpectedly acts as original seed")
            require(leaf != scalar, "Fixture seed unexpectedly equals expanded scalar")
            require(ed25519_public_key(scalar) != public, "Expanded scalar unexpectedly acts as original seed")
            wrong_leaf = bytes([leaf[0] ^ 1]) + leaf[1:]
            require(ed25519_public_key(wrong_leaf) != expected, "Wrong leaf seed matched protected public key")
            checks += 8
        first = vector["accounts"][0]
        expected = decode_public_strkey(first["address"])
        wrong_root = bytes([seed[0] ^ 1]) + seed[1:]
        require(ed25519_public_key(slip10_ed25519(wrong_root, (44, 148, 0))) != expected, "Wrong root matched protected public key")
        require(ed25519_public_key(slip10_ed25519(seed, (44, 148, 2))) != expected, "Changed account index matched protected public key")
        require(ed25519_public_key(slip10_ed25519(seed, (44, 501, 0))) != expected, "Wrong coin type matched protected public key")
        altered_passphrase = mnemonic_to_seed(vector["mnemonic"], vector["passphrase"] + "!")
        require(ed25519_public_key(slip10_ed25519(altered_passphrase, (44, 148, 0))) != expected, "Wrong passphrase matched protected public key")
        raw = bytearray(base64.b32decode(first["address"]))
        raw[-1] ^= 1
        must_reject_public_strkey(base64.b32encode(raw).decode("ascii"))
        must_reject_public_strkey(encode_strkey(18 << 3, expected))
        must_reject_public_strkey(first["address"].lower())
        checks += 7
        print(f"PASS {vector['id']}: root/leaf/scalar relation, published G-addresses, negative cases")

    # Invalid path indices must not silently wrap into a different SLIP-0010 path.
    for invalid in (-1, HARDENED, True):
        try:
            slip10_ed25519(bytes(32), (44, 148, invalid))
        except CheckFailure:
            checks += 1
        else:
            raise CheckFailure("Invalid account index was accepted")
    return len(vectors), checks


def main() -> int:
    try:
        count, checks = run()
    except (CheckFailure, KeyError, TypeError, ValueError, OSError) as exc:
        # Do not print exception values: JSON or dependency errors might include
        # fixture input. This checker never accepts user key material.
        print(f"FAIL: public-fixture check ({type(exc).__name__}); no witness values printed", file=sys.stderr)
        return 1
    print(f"PASS: {count} public SEP-5 fixture groups, {checks} checks; PyNaCl {nacl.__version__}")
    print("Compatibility check only: no ZK proof, implemented recovery, quantum attack, or PQ security certification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
