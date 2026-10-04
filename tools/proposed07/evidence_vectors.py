# SPDX-License-Identifier: Apache-2.0
"""Independent Python expectations for a LOCAL, unitless root-scalar comparator.

This does not run Rust and is not a content-proof, resolver or signature oracle.
Expected findings are written explicitly; oracle() checks the stated contract
with Python json/hashlib, independently of the Rust implementation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "crates/pask-wire/tests/fixtures/proposed07/evidence-scalar-v1.json"
LIMIT = 65_536
COMPARATOR = "json-root-unitless-scalar-exact/1"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def row(name: str, data: bytes, recorded: object, outcome: str, reason: str,
        *, integrity: str = "MATCHED", reference: str = "digest",
        expected_digest: str | None = None, presentation: str = "bytes",
        compare: bool = True, unit: str | None = None) -> dict:
    checked = len(data) if integrity in ("MATCHED", "MISMATCH") else 0
    return {
        "name": name, "raw_hex": data.hex(), "reference": reference,
        "expected_digest": digest(data) if expected_digest is None else expected_digest,
        "presentation": presentation, "recorded_value": recorded,
        "compare": compare, "declared_unit": unit,
        "expected": {
            "schema": "pask-local-presented-evidence-report/1",
            "integrity": integrity, "checked_bytes": checked,
            "comparison": outcome, "comparison_reason": reason,
            "comparator": COMPARATOR if compare else None,
            "digest_origin": "CALLER_SUPPLIED_UNAUTHENTICATED",
            "receipt_binding": "NOT_EVALUATED", "fact_constraints": "NOT_EVALUATED",
            "attributed_party_authenticated": False,
        },
    }


def cases() -> list[dict]:
    return [
        row("integer-match", b"7", 7, "MATCH", "exact_scalar_agreement"),
        row("matched-bytes-contradict-value", b"8", 7, "CONTRADICTION", "exact_scalar_disagreement"),
        row("raw-whitespace-committed", b"  7\n", 7, "MATCH", "exact_scalar_agreement"),
        row("changed-whitespace-fails-old-digest", b" 7", 7, "NOT_RUN", "integrity_not_established", integrity="MISMATCH", expected_digest=digest(b"7")),
        row("boolean-match", b"true", True, "MATCH", "exact_scalar_agreement"),
        row("boolean-contradiction", b"false", True, "CONTRADICTION", "exact_scalar_disagreement"),
        row("no-bool-integer-coercion", b"true", 1, "NOT_COMPARABLE", "scalar_type_mismatch"),
        row("text-match", b'"model-A"', "model-A", "MATCH", "exact_scalar_agreement"),
        row("text-contradiction", b'"model-B"', "model-A", "CONTRADICTION", "exact_scalar_disagreement"),
        row("escaped-text-meaning", b'"model-\\u0041"', "model-A", "MATCH", "exact_scalar_agreement"),
        row("no-unicode-normalization", '"e\u0301"'.encode(), "é", "CONTRADICTION", "exact_scalar_disagreement"),
        row("no-string-number-coercion", b'"7"', 7, "NOT_COMPARABLE", "scalar_type_mismatch"),
        row("large-integer-exact-match", b"9007199254740993", 9007199254740993, "MATCH", "exact_scalar_agreement"),
        row("large-integer-not-float-rounded", b"9007199254740992", 9007199254740993, "CONTRADICTION", "exact_scalar_disagreement"),
        row("unsigned-max", b"18446744073709551615", 18446744073709551615, "MATCH", "exact_scalar_agreement"),
        row("signed-min", b"-9223372036854775808", -9223372036854775808, "MATCH", "exact_scalar_agreement"),
        row("float-evidence-not-supported", b"7.0", 7, "NOT_COMPARABLE", "evidence_scalar_not_supported"),
        row("float-recorded-not-supported", b"7", 7.0, "NOT_COMPARABLE", "recorded_scalar_not_supported"),
        row("null-does-not-prove-unavailability", b"null", 7, "NOT_COMPARABLE", "evidence_scalar_not_supported"),
        row("compound-root-not-interpreted", b'{"value":7}', 7, "NOT_COMPARABLE", "compound_evidence_not_supported"),
        row("compound-syntax-not-validated", b"{", 7, "NOT_COMPARABLE", "compound_evidence_not_supported"),
        row("compound-recorded-not-supported", b"7", {"value": 7}, "NOT_COMPARABLE", "recorded_scalar_not_supported"),
        row("invalid-scalar-json", b"tru", True, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("trailing-data-not-ignored", b"7 8", 7, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("invalid-utf8", b'"\xff"', "x", "NOT_COMPARABLE", "invalid_scalar_json"),
        row("empty-present-object-is-hashed", b"", 7, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("unit-binding-not-invented", b"7", 7, "NOT_COMPARABLE", "unit_binding_not_supported", unit="N"),
        row("hash-only-does-not-compare", b"7", 7, "NOT_RUN", "comparison_not_requested", compare=False),
        row("mismatch-never-compares", b"8", 8, "NOT_RUN", "integrity_not_established", integrity="MISMATCH", expected_digest=digest(b"7")),
        row("no-reference", b"7", 7, "NOT_RUN", "integrity_not_established", reference="absent", integrity="NO_REFERENCE"),
        row("pointer-does-not-supply-binding", b"7", 7, "NOT_RUN", "integrity_not_established", reference="pointer", integrity="DIGEST_BINDING_UNAVAILABLE"),
        row("not-requested", b"7", 7, "NOT_RUN", "integrity_not_established", presentation="not-requested", integrity="NOT_REQUESTED"),
        row("unavailable-not-empty", b"", 7, "NOT_RUN", "integrity_not_established", presentation="unavailable", integrity="BYTES_UNAVAILABLE"),
        row("bad-digest-rejected", b"7", 7, "NOT_RUN", "integrity_not_established", expected_digest="sha256:bad", integrity="MALFORMED_DIGEST"),
        row("uppercase-digest-rejected", b"7", 7, "NOT_RUN", "integrity_not_established", expected_digest=digest(b"7").upper(), integrity="MALFORMED_DIGEST"),
        # Review E01-INT-01: append cases; retain every original expected row.
        row("integer-negative-zero-match", b"-0", 0, "MATCH", "exact_scalar_agreement"),
        row("negative-zero-json-whitespace", b"\t\r\n -0 \n\r\t", 0, "MATCH", "exact_scalar_agreement"),
        row("integer-negative-zero-contradiction", b"-0", 1, "CONTRADICTION", "exact_scalar_disagreement"),
        row("negative-zero-requires-own-digest", b"-0", 0, "NOT_RUN", "integrity_not_established", integrity="MISMATCH", expected_digest=digest(b"0")),
        row("zero-does-not-reuse-negative-zero-digest", b"0", 0, "NOT_RUN", "integrity_not_established", integrity="MISMATCH", expected_digest=digest(b"-0")),
        row("negative-zero-fraction-unsupported", b"-0.0", 0, "NOT_COMPARABLE", "evidence_scalar_not_supported"),
        row("negative-zero-exponent-unsupported", b"-0e0", 0, "NOT_COMPARABLE", "evidence_scalar_not_supported"),
        row("negative-zero-uppercase-exponent-unsupported", b"-0E+0", 0, "NOT_COMPARABLE", "evidence_scalar_not_supported"),
        row("negative-zero-text-not-coerced", b'"-0"', 0, "NOT_COMPARABLE", "scalar_type_mismatch"),
        row("negative-zero-recorded-float-unsupported", b"-0", -0.0, "NOT_COMPARABLE", "recorded_scalar_not_supported"),
        row("negative-zero-not-boolean-false", b"-0", False, "NOT_COMPARABLE", "scalar_type_mismatch"),
        row("negative-zero-leading-zero-invalid", b"-00", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("plus-zero-invalid", b"+0", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("negative-zero-trailing-token-invalid", b"-0 0", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("negative-zero-form-feed-invalid", b"\x0c-0", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("negative-zero-nonbreaking-space-invalid", b"\xc2\xa0-0", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("negative-zero-unit-unsupported", b"-0", 0, "NOT_COMPARABLE", "unit_binding_not_supported", unit="N"),
        row("negative-zero-hash-only", b"-0", 0, "NOT_RUN", "comparison_not_requested", compare=False),
        row("negative-zero-invalid-utf8", b"-0\xff", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("negative-zero-vertical-tab-invalid", b"\x0b-0", 0, "NOT_COMPARABLE", "invalid_scalar_json"),
        row("negative-zero-null-recorded-unsupported", b"-0", None, "NOT_COMPARABLE", "recorded_scalar_not_supported"),
    ]


def scalar_kind(value: object) -> str | None:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "text"
    if isinstance(value, int) and -(2**63) <= value <= 2**64 - 1:
        return "integer"
    return None


def reject_constant(value: str) -> None:
    raise ValueError(value)


def oracle(case: dict) -> tuple[str, int, str, str]:
    data = bytes.fromhex(case["raw_hex"])
    pending = "integrity_not_established" if case["compare"] else "comparison_not_requested"
    def no_integrity(status: str) -> tuple[str, int, str, str]:
        return status, 0, "NOT_RUN", pending
    if case["reference"] == "absent":
        return no_integrity("NO_REFERENCE")
    if case["reference"] == "pointer":
        return no_integrity("DIGEST_BINDING_UNAVAILABLE")
    wanted = case["expected_digest"]
    if len(wanted) != 71 or not wanted.startswith("sha256:") or any(c not in "0123456789abcdef" for c in wanted[7:]):
        return no_integrity("MALFORMED_DIGEST")
    if case["presentation"] == "not-requested":
        return no_integrity("NOT_REQUESTED")
    if case["presentation"] == "unavailable":
        return no_integrity("BYTES_UNAVAILABLE")
    if len(data) > LIMIT:
        return no_integrity("INPUT_LIMIT_EXCEEDED")
    if digest(data) != wanted:
        return "MISMATCH", len(data), "NOT_RUN", pending
    def compared(result: str, reason: str) -> tuple[str, int, str, str]:
        return "MATCHED", len(data), result, reason
    if not case["compare"]:
        return compared("NOT_RUN", "comparison_not_requested")
    if case["declared_unit"] is not None:
        return compared("NOT_COMPARABLE", "unit_binding_not_supported")
    recorded = case["recorded_value"]
    if isinstance(recorded, str) and len(recorded.encode()) > LIMIT:
        return compared("NOT_COMPARABLE", "recorded_scalar_limit")
    kind = scalar_kind(recorded)
    if kind is None:
        return compared("NOT_COMPARABLE", "recorded_scalar_not_supported")
    if data.lstrip(b" \n\r\t").startswith((b"{", b"[")):
        return compared("NOT_COMPARABLE", "compound_evidence_not_supported")
    try:
        evidence = json.loads(data.decode("utf-8"), parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError):
        return compared("NOT_COMPARABLE", "invalid_scalar_json")
    other_kind = scalar_kind(evidence)
    if other_kind is None:
        return compared("NOT_COMPARABLE", "evidence_scalar_not_supported")
    if kind != other_kind:
        return compared("NOT_COMPARABLE", "scalar_type_mismatch")
    if recorded == evidence:
        return compared("MATCH", "exact_scalar_agreement")
    return compared("CONTRADICTION", "exact_scalar_disagreement")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check committed vector bytes; do not rewrite")
    args = parser.parse_args()
    rows = cases()
    if len({c["name"] for c in rows}) != len(rows):
        raise SystemExit("duplicate vector name")
    for case in rows:
        expected = case["expected"]
        actual = oracle(case)
        wanted = tuple(expected[k] for k in ("integrity", "checked_bytes", "comparison", "comparison_reason"))
        if actual != wanted:
            raise SystemExit(f"oracle mismatch: {case['name']}: {actual} != {wanted}")
    result = {
        "contract": COMPARATOR,
        "scope": "Local reference/byte and root-scalar checks only; no receipt binding or provenance authentication.",
        "oracle": "Explicit expected findings cross-checked with Python json/hashlib; no Rust imported or run.",
        "cases": rows,
    }
    encoded = (json.dumps(result, ensure_ascii=True, indent=2) + "\n").encode()
    if args.check:
        if OUTPUT.read_bytes() != encoded:
            raise SystemExit("vector file differs from deterministic generated bytes")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(encoded)
    print(json.dumps({"python_expectations_passed": len(rows), "vector_sha256": hashlib.sha256(encoded).hexdigest(), "rust_executed": False}))


if __name__ == "__main__":
    main()
