#!/usr/bin/env python3
"""Generate byte-exact test vectors for #67 candidate-entry derivation.

Produces hex-encoded test vectors that are hardcoded in the Rust test file.
These vectors are generated independently of the Rust implementation under test.

Dependencies:
  Python 3.8+
  cbor2 >= 6.0 (pip install cbor2)

Invocation:
  python3 scripts/gen_test_vectors_67.py

Output is printed to stdout as hex-encoded constants.
"""

import cbor2
import hashlib
import json


def build_cose_sign1(protected_map_bytes, payload_bytes, signature_bytes, unprotected=None):
    """Build a COSE_Sign1 array [P, U, M, S]."""
    if unprotected is None:
        unprotected = {}
    return cbor2.dumps([protected_map_bytes, unprotected, payload_bytes, signature_bytes])


def build_tagged(protected_map_bytes, payload_bytes, signature_bytes, unprotected=None):
    """Build a tag-18 wrapped COSE_Sign1."""
    if unprotected is None:
        unprotected = {}
    return cbor2.dumps(cbor2.CBORTag(18, [protected_map_bytes, unprotected, payload_bytes, signature_bytes]))


def candidate_entry(protected_map_bytes, payload_bytes, signature_bytes):
    """Build the expected candidate entry [P, {}, M, S]."""
    return cbor2.dumps([protected_map_bytes, {}, payload_bytes, signature_bytes])


def leaf_hash(entry_bytes):
    """SHA256(0x00 || entry_bytes)."""
    return hashlib.sha256(bytes([0x00]) + entry_bytes).digest()


# ===========================================================================
# Test Vector 1: Standard fixture (from original generation)
# ===========================================================================

protected_map = cbor2.dumps({1: -8, 3: "application/pser+json; profile=wilder.pser/0.5"})
payload_json = json.dumps({
    "spec": "wilder.pser/0.5",
    "ts": "2025-09-12T14:00:00Z",
    "notBefore": "2025-09-12T13:00:00Z",
    "notAfter": "2025-09-12T15:00:00Z",
    "subject": {"site_id": "res-001"},
    "attestation": {
        "witnessKey": "key:tee:res-001-witness-01",
        "bindingMode": "DIRECT_WITNESS",
        "evidence": "ref-001"
    },
    "provenance": {"scope": "unit-1a", "chain": {"hash": "0000000000000000000000000000000000000000000000000000000000000000"}}
}, separators=(",", ":"))
payload_bytes = payload_json.encode("utf-8")
signature = bytes([0xAA] * 64)

tv1_cose = build_cose_sign1(protected_map, payload_bytes, signature)
tv1_candidate = candidate_entry(protected_map, payload_bytes, signature)
tv1_leaf = leaf_hash(tv1_candidate)

print("# === TV1: Standard untagged COSE_Sign1 ===")
print(f"TV1_COSE = \"{tv1_cose.hex()}\"")
print(f"TV1_CANDIDATE = \"{tv1_candidate.hex()}\"")
print(f"TV1_LEAF = \"{tv1_leaf.hex()}\"")

# ===========================================================================
# Test Vector 2: Tag-18 wrapped (same content)
# ===========================================================================

tv2_cose = build_tagged(protected_map, payload_bytes, signature)
print("\n# === TV2: Tag-18 wrapped COSE_Sign1 ===")
print(f"TV2_COSE = \"{tv2_cose.hex()}\"")
print(f"# Candidate entry and leaf hash same as TV1")

# ===========================================================================
# Test Vector 3: Transparent Statement with receipt
# ===========================================================================

receipt_bytes = bytes([0xBB] * 80)
tv3_cose = build_cose_sign1(protected_map, payload_bytes, signature, unprotected={7: [receipt_bytes]})
print("\n# === TV3: Transparent Statement with one receipt ===")
print(f"TV3_COSE = \"{tv3_cose.hex()}\"")
print(f"# Candidate entry and leaf hash same as TV1 (acceptance invariant)")

# ===========================================================================
# Test Vector 4: Transparent Statement with multiple receipts
# ===========================================================================

receipt1 = bytes([0xCC] * 80)
receipt2 = bytes([0xDD] * 80)
tv4_cose = build_cose_sign1(protected_map, payload_bytes, signature, unprotected={7: [receipt1, receipt2]})
print("\n# === TV4: Transparent Statement with two receipts ===")
print(f"TV4_COSE = \"{tv4_cose.hex()}\"")
print(f"# Candidate entry and leaf hash same as TV1 (acceptance invariant)")

# ===========================================================================
# Test Vector 5: Tampered payload
# ===========================================================================

tampered_payload = payload_json.replace('"unit-1a"', '"unit-1b"').encode("utf-8")
tv5_cose = build_cose_sign1(protected_map, tampered_payload, signature)
tv5_candidate = candidate_entry(protected_map, tampered_payload, signature)
tv5_leaf = leaf_hash(tv5_candidate)
print("\n# === TV5: Tampered payload ===")
print(f"TV5_COSE = \"{tv5_cose.hex()}\"")
print(f"TV5_CANDIDATE = \"{tv5_candidate.hex()}\"")
print(f"TV5_LEAF = \"{tv5_leaf.hex()}\"")

# ===========================================================================
# Test Vector 6: Short protected header (length < 24, 1-byte bstr header)
# ===========================================================================

short_protected = cbor2.dumps({1: -8})  # Just alg, no content_type
print(f"\n# === TV6: Short protected header (len={len(short_protected)}) ===")
print(f"# Protected header length {len(short_protected)} uses 1-byte bstr header (0x4N)")
tv6_cose = build_cose_sign1(short_protected, payload_bytes, signature)
tv6_candidate = candidate_entry(short_protected, payload_bytes, signature)
tv6_leaf = leaf_hash(tv6_candidate)
print(f"TV6_COSE = \"{tv6_cose.hex()}\"")
print(f"TV6_CANDIDATE = \"{tv6_candidate.hex()}\"")
print(f"TV6_LEAF = \"{tv6_leaf.hex()}\"")

# ===========================================================================
# Test Vector 7: Protected header at length boundary 23 (1-byte vs 2-byte)
# ===========================================================================

# Build a protected header map that is exactly 23 bytes
# {1: -8, 3: "short"} => let's check the length
p23_map = cbor2.dumps({1: -8, 3: "short"})
print(f"\n# === TV7: Protected header at length {len(p23_map)} ===")
if len(p23_map) <= 23:
    print(f"# Length {len(p23_map)} uses 1-byte bstr header")
else:
    print(f"# Length {len(p23_map)} uses 2-byte bstr header")
tv7_cose = build_cose_sign1(p23_map, payload_bytes, signature)
tv7_candidate = candidate_entry(p23_map, payload_bytes, signature)
tv7_leaf = leaf_hash(tv7_candidate)
print(f"TV7_COSE = \"{tv7_cose.hex()}\"")
print(f"TV7_CANDIDATE = \"{tv7_candidate.hex()}\"")
print(f"TV7_LEAF = \"{tv7_leaf.hex()}\"")

# ===========================================================================
# Test Vector 8: Protected header at length 24 (boundary for 2-byte header)
# ===========================================================================

# Build a protected header map that is exactly 24 bytes
# {1: -8, 3: "application/pser+json; profile=wilder.pser/0.5"} is 52 bytes
# We need a shorter content type string to hit 24 bytes
# {1: -8, 3: "0123456789abcdef0123"} => let's try
p24_map = cbor2.dumps({1: -8, 3: "0123456789abcdef0123"})
print(f"\n# === TV8: Protected header at length {len(p24_map)} ===")
if len(p24_map) <= 23:
    print(f"# Length {len(p24_map)} uses 1-byte bstr header")
else:
    print(f"# Length {len(p24_map)} uses 2-byte bstr header")
tv8_cose = build_cose_sign1(p24_map, payload_bytes, signature)
tv8_candidate = candidate_entry(p24_map, payload_bytes, signature)
tv8_leaf = leaf_hash(tv8_candidate)
print(f"TV8_COSE = \"{tv8_cose.hex()}\"")
print(f"TV8_CANDIDATE = \"{tv8_candidate.hex()}\"")
print(f"TV8_LEAF = \"{tv8_leaf.hex()}\"")

# ===========================================================================
# Test Vector 9: Empty payload (length 0)
# ===========================================================================

empty_payload = b""
tv9_cose = build_cose_sign1(protected_map, empty_payload, signature)
tv9_candidate = candidate_entry(protected_map, empty_payload, signature)
tv9_leaf = leaf_hash(tv9_candidate)
print(f"\n# === TV9: Empty payload (len=0) ===")
print(f"TV9_COSE = \"{tv9_cose.hex()}\"")
print(f"TV9_CANDIDATE = \"{tv9_candidate.hex()}\"")
print(f"TV9_LEAF = \"{tv9_leaf.hex()}\"")

# ===========================================================================
# Test Vector 10: Short signature (length < 24)
# ===========================================================================

short_sig = bytes([0x42] * 8)
tv10_cose = build_cose_sign1(protected_map, payload_bytes, short_sig)
tv10_candidate = candidate_entry(protected_map, payload_bytes, short_sig)
tv10_leaf = leaf_hash(tv10_candidate)
print(f"\n# === TV10: Short signature (len={len(short_sig)}) ===")
print(f"TV10_COSE = \"{tv10_cose.hex()}\"")
print(f"TV10_CANDIDATE = \"{tv10_candidate.hex()}\"")
print(f"TV10_LEAF = \"{tv10_leaf.hex()}\"")

# ===========================================================================
# Negative vectors
# ===========================================================================

print("\n# === Negative vectors ===")

# Detached payload (null)
nv_detached = cbor2.dumps([protected_map, {}, None, signature])
print(f"NV_DETACHED = \"{nv_detached.hex()}\"")

# Unsupported tag 99
nv_bad_tag = cbor2.dumps(cbor2.CBORTag(99, [protected_map, {}, payload_bytes, signature]))
print(f"NV_BAD_TAG = \"{nv_bad_tag.hex()}\"")

# Trailing bytes
nv_trailing = tv1_cose + bytes([0x00])
print(f"NV_TRAILING = \"{nv_trailing.hex()}\"")

# Unprotected header is integer
nv_uh_int = cbor2.dumps([protected_map, 0, payload_bytes, signature])
print(f"NV_UH_INT = \"{nv_uh_int.hex()}\"")

# Unprotected header is null
nv_uh_null = cbor2.dumps([protected_map, None, payload_bytes, signature])
print(f"NV_UH_NULL = \"{nv_uh_null.hex()}\"")

# Unprotected header is array
nv_uh_array = cbor2.dumps([protected_map, [1], payload_bytes, signature])
print(f"NV_UH_ARRAY = \"{nv_uh_array.hex()}\"")

# Unprotected header is text
nv_uh_text = cbor2.dumps([protected_map, "not a map", payload_bytes, signature])
print(f"NV_UH_TEXT = \"{nv_uh_text.hex()}\"")

# Unprotected header is bytes
nv_uh_bytes = cbor2.dumps([protected_map, b"not a map", payload_bytes, signature])
print(f"NV_UH_BYTES = \"{nv_uh_bytes.hex()}\"")

# Protected header not bytes (integer)
nv_ph_int = cbor2.dumps([0, {}, payload_bytes, signature])
print(f"NV_PH_INT = \"{nv_ph_int.hex()}\"")

# Payload not bytes (integer)
nv_pl_int = cbor2.dumps([protected_map, {}, 42, signature])
print(f"NV_PL_INT = \"{nv_pl_int.hex()}\"")

# Signature not bytes (integer)
nv_sig_int = cbor2.dumps([protected_map, {}, payload_bytes, 42])
print(f"NV_SIG_INT = \"{nv_sig_int.hex()}\"")

# Three-element array
nv_3elem = cbor2.dumps([protected_map, {}, payload_bytes])
print(f"NV_3_ELEM = \"{nv_3elem.hex()}\"")

# Non-array (integer)
nv_non_array = cbor2.dumps(42)
print(f"NV_NON_ARRAY = \"{nv_non_array.hex()}\"")

# Empty input
print("NV_EMPTY = \"\"")

# Invalid CBOR
print("NV_INVALID_CBOR = \"ffffff\"")
