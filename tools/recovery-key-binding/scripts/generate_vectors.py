#!/usr/bin/env python3
"""Independently derive only published RFC8032/official SEP5 fixture keys."""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import unicodedata
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strkey(value):
    raw = base64.b32decode(value)
    require(len(raw) == 35 and raw[0] == 48, "public StrKey length/version mismatch")
    require(raw[-2:] == binascii.crc_hqx(raw[:-2], 0).to_bytes(2, "little"), "public StrKey CRC mismatch")
    return raw[1:-2]


def expanded(seed):
    scalar = bytearray(hashlib.sha512(seed).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


def derive(root, index):
    data = hmac.digest(b"ed25519 seed", root, "sha512")
    for component in [44, 148, index]:
        key, chain = data[:32], data[32:]
        data = hmac.digest(chain, b"\0" + key + (component | (1 << 31)).to_bytes(4, "big"), "sha512")
    return data[:32]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    vectors = []

    def add(name, seed, expected, source):
        scalar = expanded(seed)
        require(bytes(SigningKey(seed).verify_key) == expected, "independent seed/key mismatch")
        require(crypto_scalarmult_ed25519_base_noclamp(scalar) == expected, "independent scalar/key mismatch")
        vectors.append({"id": name, "public_test_seed_hex": seed.hex(), "scalar_hex": scalar.hex(),
                        "public_key_hex": expected.hex(), "source": source})

    for i, (seed, key) in enumerate(RFC):
        add(f"rfc8032-{i+1}", bytes.fromhex(seed), bytes.fromhex(key), "https://www.rfc-editor.org/rfc/rfc8032#section-7.1")
    official = json.loads((ROOT / "fixtures/official-sep5.json").read_text())
    require(official["public_test_vectors_only"] is True and len(official["vectors"]) == 5, "public SEP5 fixture scope mismatch")
    for case in official["vectors"]:
        mnemonic = unicodedata.normalize("NFKD", case["mnemonic"]).encode()
        salt = ("mnemonic" + unicodedata.normalize("NFKD", case["passphrase"])).encode()
        root = hashlib.pbkdf2_hmac("sha512", mnemonic, salt, 2048, 64)
        require(root.hex() == case["expected_bip39_seed_hex"], "official root derivation mismatch")
        for account in case["accounts"]:
            add(case["id"] + "-account-" + str(account["index"]), derive(root, account["index"]),
                strkey(account["address"]), official["sources"][0]["url"])
    require(len(vectors) == 18, "public vector coverage mismatch")
    record = {"scope": "Published fixture derivation, not proof knowledge or recovery authorization", "public_test_vectors_only": True,
              "independent_implementations": ["Python hashlib/HMAC", "PyNaCl/libsodium seed-to-key and scalar-to-key"], "vectors": vectors}
    source = "//! Generated published fixtures; never fund these accounts.\n#[derive(Clone, Copy)]\npub struct Fixture { pub seed:[u8;32], pub scalar:[u8;32], pub public_key:[u8;32] }\npub const VECTORS: [Fixture;18] = [\n"
    for vector in vectors:
        source += "Fixture {" + ",".join(name + ":[" + ",".join(str(b) for b in bytes.fromhex(vector[key])) + "]"
                                           for name, key in [("seed", "public_test_seed_hex"), ("scalar", "scalar_hex"), ("public_key", "public_key_hex")]) + "},\n"
    source += "];\n"
    formatted = subprocess.run(["rustfmt", "--edition", "2021", "--emit", "stdout"], input=source, text=True, capture_output=True, check=True).stdout
    outputs = {ROOT / "fixtures/binding-vectors.json": json.dumps(record, indent=2)+"\n", ROOT / "src/fixture_vectors.rs": formatted}
    for path, content in outputs.items():
        if args.check:
            require(path.read_text() == content, "Generated public fixtures changed")
        else:
            path.write_text(content)
    print("PASS 18 independently derived public RFC8032/SEP5 key/scalar vectors")


if __name__ == "__main__":
    main()
