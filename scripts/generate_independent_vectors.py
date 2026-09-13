#!/usr/bin/env python3
"""
Independent derivation of expected candidate entry, Merkle root, and inclusion path
from a signed fixture exported by Rust.

This script does NOT use any Rust function. It reads the raw statement bytes
exported by the Rust example, independently decodes the CBOR using cbor2, and
derives the candidate entry, leaf hash, root, and inclusion path using the same
RFC 9942 algorithms but implemented entirely in Python.

Usage:
    python3 scripts/generate_independent_vectors.py

Dependencies:
    cbor2 >= 5.0
    (standard library: hashlib, json, sys)

The script reads fixture_export_raw.txt (produced by the Rust export_fixture
example) and writes pask_67_independent_signed_vectors.json.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import cbor2
except ImportError:
    print("ERROR: cbor2 is required. Install with: pip3 install cbor2", file=sys.stderr)
    sys.exit(1)

WORKSPACE = Path(__file__).resolve().parent.parent


def parse_export(raw_text: str) -> dict:
    """Parse the key: value lines from the Rust export output."""
    result = {}
    for line in raw_text.strip().splitlines():
        line = line.strip()
        if line.startswith("=== ") or not line:
            continue
        if ": " in line:
            key, value = line.split(": ", 1)
            result[key.strip()] = value.strip()
    return result


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(entry: bytes) -> bytes:
    """RFC 9162 leaf hash: SHA-256(0x00 || entry)."""
    return sha256(b"\x00" + entry)


def internal_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 9162 internal node hash: SHA-256(0x01 || left || right)."""
    return sha256(b"\x01" + left + right)


def largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than n."""
    assert n > 1
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(entries: list[bytes]) -> bytes:
    """RFC 9162 Merkle tree hash algorithm (Section 2.1.3)."""
    if len(entries) == 0:
        return sha256(b"")
    if len(entries) == 1:
        return leaf_hash(entries[0])
    k = largest_power_of_two_below(len(entries))
    left = merkle_tree_hash(entries[:k])
    right = merkle_tree_hash(entries[k:])
    return internal_node_hash(left, right)


def inclusion_path(entries: list[bytes], index: int) -> list[bytes]:
    """RFC 9162 inclusion proof path (Section 2.1.3)."""
    assert index < len(entries)
    if len(entries) == 1:
        return []
    k = largest_power_of_two_below(len(entries))
    if index < k:
        path = inclusion_path(entries[:k], index)
        path.append(merkle_tree_hash(entries[k:]))
        return path
    else:
        path = inclusion_path(entries[k:], index - k)
        path.append(merkle_tree_hash(entries[:k]))
        return path


def derive_candidate_entry_independently(statement_bytes: bytes) -> bytes:
    """
    Independently derive the candidate entry from a COSE_Sign1 statement.

    The candidate entry is [Payload, ProtectedHeader, Manifest, Signature]
    where Manifest is the SHA-256 of the payload bytes extracted from the
    COSE_Sign1 structure.

    This uses cbor2 to decode, NOT the Rust pask-wire library.
    """
    value = cbor2.loads(statement_bytes)

    # COSE_Sign1 is a tagged array: Tag(18) => [Payload, ProtectedHeader, UnprotectedHeader, Signature]
    # Or untagged array for compatibility
    if isinstance(value, cbor2.CBORTag):
        assert value.tag == 18, f"Expected tag 18, got {value.tag}"
        items = value.value
    else:
        items = value

    assert isinstance(items, list), f"Expected list, got {type(items)}"
    assert len(items) == 4, f"Expected 4 items, got {len(items)}"

    payload_bytes = items[2]
    protected_header = items[0]
    # items[1] is unprotected header (empty in the candidate entry)
    signature = items[3]

    # The candidate entry is [ProtectedHeader, {}, PayloadBytes, Signature]
    # per the Rust derive_candidate_entry implementation.
    # P, M, S are preserved by content - their bytes are not parsed or reserialized.
    # Note: Rust does NOT wrap in tag 18 - it's a plain array.
    candidate_entry = cbor2.dumps([protected_header, {}, payload_bytes, signature])

    return candidate_entry


def main():
    # Read the exported fixture
    export_path = WORKSPACE / "fixture_export_raw.txt"
    if not export_path.exists():
        print(f"ERROR: {export_path} not found. Run the Rust export_fixture example first.",
              file=sys.stderr)
        sys.exit(1)

    raw_text = export_path.read_text()
    export = parse_export(raw_text)

    raw_statement_hex = export["raw_statement_hex"]
    final_statement_hex = export["final_statement_hex"]
    candidate_entry_hex_rust = export["candidate_entry_hex"]
    receipt_hex = export["receipt_hex"]
    issuer_public_key_hex = export["issuer_public_key_hex"]
    ts_public_key_hex = export["ts_public_key_hex"]
    merkle_root_hex_rust = export["merkle_root_hex"]
    inclusion_path_hex_rust = export["inclusion_path_hex"]
    tree_size = int(export["tree_size"])
    leaf_index = int(export["leaf_index"])

    raw_statement = bytes.fromhex(raw_statement_hex)
    final_statement = bytes.fromhex(final_statement_hex)
    receipt = bytes.fromhex(receipt_hex)
    issuer_public_key = bytes.fromhex(issuer_public_key_hex)
    ts_public_key = bytes.fromhex(ts_public_key_hex)

    # Step 1: Independently derive the candidate entry from the raw statement
    print("Independently deriving candidate entry from raw statement bytes...")
    candidate_entry_python = derive_candidate_entry_independently(raw_statement)
    candidate_entry_python_hex = candidate_entry_python.hex()

    # Also derive from the final statement (should be the same)
    print("Independently deriving candidate entry from final statement bytes...")
    candidate_entry_from_final = derive_candidate_entry_independently(final_statement)
    candidate_entry_from_final_hex = candidate_entry_from_final.hex()

    print(f"Rust candidate entry:    {candidate_entry_hex_rust}")
    print(f"Python candidate entry: {candidate_entry_python_hex}")
    print(f"Match (raw): {candidate_entry_python_hex == candidate_entry_hex_rust}")
    print(f"Match (final): {candidate_entry_from_final_hex == candidate_entry_hex_rust}")

    if candidate_entry_python_hex != candidate_entry_hex_rust:
        print("WARNING: Python-derived candidate entry does not match Rust output!")
        print("This may indicate a difference in CBOR encoding between cbor2 and Rust's coset.")
        print("The test will use the Python-derived value as the independent expected output.")
        # Use the Python value as the independent expected output
        candidate_entry_hex_expected = candidate_entry_python_hex
        candidate_entry_expected = candidate_entry_python
    else:
        candidate_entry_hex_expected = candidate_entry_python_hex
        candidate_entry_expected = candidate_entry_python

    # Step 2: Independently compute the Merkle tree
    print("\nBuilding Merkle tree with candidate entry at index 6...")
    log_entries = [f"entry-{i}".encode() for i in range(tree_size)]
    log_entries[leaf_index] = candidate_entry_expected

    # Compute leaf hash of candidate entry
    leaf = leaf_hash(candidate_entry_expected)
    leaf_hex = leaf.hex()

    # Compute root
    root = merkle_tree_hash(log_entries)
    root_hex = root.hex()

    # Compute inclusion path
    path = inclusion_path(log_entries, leaf_index)
    path_hex = [h.hex() for h in path]

    print(f"Leaf hash:  {leaf_hex}")
    print(f"Root:       {root_hex}")
    print(f"Path:       {', '.join(path_hex)}")
    print(f"Rust root:  {merkle_root_hex_rust}")
    print(f"Rust path:  {inclusion_path_hex_rust}")
    print(f"Root match: {root_hex == merkle_root_hex_rust}")

    # Step 3: Build the JSON output
    vectors = {
        "description": "Independent signed-fixture vectors for #67 candidate-entry derivation and inclusion verification. The candidate entry, leaf hash, Merkle root, and inclusion path are independently derived in Python using cbor2 from bytes exported by the Rust producer. The Rust test loads these fixed expected values and asserts exact agreement.",
        "independence_note": "The expected candidate entry, leaf, root, and path in this file were computed by generate_independent_vectors.py using cbor2 and hashlib, not by invoking any Rust function. The Rust producer exported the signed fixture bytes; Python independently derived the expected transformation outputs.",
        "generator": "scripts/generate_independent_vectors.py",
        "generator_dependencies": {
            "cbor2": ">= 5.0",
            "python": ">= 3.10"
        },
        "fixture": {
            "raw_statement_hex": raw_statement_hex,
            "final_statement_hex": final_statement_hex,
            "receipt_hex": receipt_hex,
            "issuer_public_key_hex": issuer_public_key_hex,
            "ts_public_key_hex": ts_public_key_hex,
            "tree_size": tree_size,
            "leaf_index": leaf_index
        },
        "expected": {
            "candidate_entry_hex": candidate_entry_hex_expected,
            "leaf_hash_hex": leaf_hex,
            "merkle_root_hex": root_hex,
            "inclusion_path_hex": path_hex
        },
        "cross_check": {
            "rust_candidate_entry_hex": candidate_entry_hex_rust,
            "rust_merkle_root_hex": merkle_root_hex_rust,
            "rust_inclusion_path_hex": inclusion_path_hex_rust,
            "candidate_entry_matches": candidate_entry_python_hex == candidate_entry_hex_rust,
            "merkle_root_matches": root_hex == merkle_root_hex_rust
        }
    }

    output_path = WORKSPACE / "pask_67_independent_signed_vectors.json"
    output_path.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"\nWrote {output_path}")

    # Verify
    print("\n=== VERIFICATION ===")
    if candidate_entry_python_hex == candidate_entry_hex_rust:
        print("PASS: Python-derived candidate entry matches Rust output")
    else:
        print("NOTE: Python-derived candidate entry differs from Rust output (CBOR encoding difference)")
        print("  The test will use the Python value as the independent expected output.")

    if root_hex == merkle_root_hex_rust:
        print("PASS: Python-derived Merkle root matches Rust output")
    else:
        print("FAIL: Python-derived Merkle root does not match Rust output")


if __name__ == "__main__":
    main()
