# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
# See LICENSING.md in the workspace root.
"""Independent synthetic vectors: Python/cbor2/hashlib/OpenSSL-backed cryptography.

No Rust helper, live service, discovery or real provisioning is used.
Run with --check to reproduce every fixture in memory and compare to frozen bytes.
Fixed private seeds are PUBLIC TEST MATERIAL, never production credentials.
"""
import argparse
import hashlib
import json
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent


def encode(value):
    return cbor2.dumps(value, canonical=True)


def sha(data):
    return hashlib.sha256(data).digest()


def tree(entries):
    if len(entries) == 1:
        return sha(b"\0" + entries[0])
    split = 1 << ((len(entries) - 1).bit_length() - 1)
    return sha(b"\1" + tree(entries[:split]) + tree(entries[split:]))


def path(entries, index):
    if len(entries) == 1:
        return []
    split = 1 << ((len(entries) - 1).bit_length() - 1)
    if index < split:
        return path(entries[:split], index) + [tree(entries[split:])]
    return path(entries[split:], index - split) + [tree(entries[:split])]


def fixtures():
    result = {}
    service = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    rotated = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(65, 97)))
    result["service-key.bin"] = service.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    result["rotated-key.bin"] = rotated.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Deliberately non-shortest integer label/value bytes, kept as signed content.
    statement_p = bytes.fromhex("a21801270763726177")
    payload = b'{"fixture":"local only","site.id":"not-the-receipt-subject"}'
    statement_sig = issuer.sign(encode(["Signature1", statement_p, b"", payload]))
    issuer.public_key().verify(statement_sig, encode(["Signature1", statement_p, b"", payload]))
    statement = encode(cbor2.CBORTag(18, [statement_p, {700: "mutable"}, payload, statement_sig]))
    candidate = encode([statement_p, {}, payload, statement_sig])
    result["statement.cbor"] = statement
    result["candidate.cbor"] = candidate
    # Width-16 alg label preserves noncanonical Receipt protected contents as well.
    receipt_p = b"\xa4\x19\x00\x01\x27" + encode(4) + encode(b"shared-kid")
    receipt_p += encode(15) + encode({1: "https://ts.example.test", 2: "issuer-defined-subject"})
    receipt_p += encode(395) + encode(1)
    result["receipt-protected.bin"] = receipt_p
    roots = {}
    signatures = {}
    for count, index in [(2, 0), (5, 0), (5, 2), (5, 4), (8, 7), (9, 8)]:
        entries = [b"independent-neighbor-" + bytes([i]) for i in range(count)]
        entries[index] = candidate
        root = tree(entries)
        proof = encode([count, index, path(entries, index)])
        signed = encode(["Signature1", receipt_p, b"", root])
        signature = service.sign(signed)
        service.public_key().verify(signature, signed)
        name = f"tree{count}-leaf{index}"
        roots[name] = root.hex()
        signatures[name] = signature.hex()
        result[f"{name}-root.bin"] = root
        for attached in [False, True]:
            result[f"{name}-{'attached' if attached else 'detached'}.cbor"] = encode(
                cbor2.CBORTag(18, [receipt_p, {396: {-1: [proof]}}, root if attached else None, signature])
            )
        if (count, index) == (2, 0):
            rotated_sig = rotated.sign(signed)
            rotated.public_key().verify(rotated_sig, signed)
            result["rotated-detached.cbor"] = encode(
                cbor2.CBORTag(18, [receipt_p, {396: {-1: [proof]}}, None, rotated_sig])
            )
    manifest = {
        "origin": "LOCAL SYNTHETIC SIMULATION; no real service authentication or registration",
        "independent_of": "Rust candidate encoder, Rust root reconstruction and Rust Ed25519 verifier",
        "generator": "cbor2 canonical outer serialization, recursive hashlib RFC9162 tree, cryptography Ed25519",
        "public_test_seeds_hex": [bytes(range(1, 33)).hex(), bytes(range(33, 65)).hex(), bytes(range(65, 97)).hex()],
        "roots": roots,
        "signatures": signatures,
        "hashes": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(result.items())},
        "references": [
            "https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1",
            "https://www.rfc-editor.org/rfc/rfc9942.html#section-5.2",
            "https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4",
        ],
    }
    result["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = fixtures()
    for name, content in data.items():
        if args.check:
            assert (HERE / name).read_bytes() == content, name
        else:
            (HERE / name).write_bytes(content)
    print(f"{'Checked' if args.check else 'Generated'} {len(data)} independently reproduced synthetic fixture files.")
