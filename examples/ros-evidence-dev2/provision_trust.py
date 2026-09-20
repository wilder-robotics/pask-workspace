#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Operator action: explicitly authorize an independently checked TEST public key.

Reads no bundle, manifest, producer status or private key. Not a real PKI.
"""
import argparse
import hashlib
import json
from pathlib import Path

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--public-key", required=True)
    p.add_argument("--issuer", required=True)
    p.add_argument("--record", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    key = bytes.fromhex(args.public_key)
    if len(key) != 32:
        raise SystemExit("Ed25519 public key must be 32 bytes")
    value = {"version": "local-test-trust/1",
             "provenance": "explicit local operator TEST enrollment; no independent organization",
             "software_test_material": True,
             "accepted": [{"issuer": args.issuer, "algorithm": "Ed25519",
                           "key_id": hashlib.sha256(key).hexdigest(),
                           "public_key_hex": key.hex(), "valid_record_id": args.record}]}
    Path(args.output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
