#!/usr/bin/env python3
"""Judge pinned scitt-verifier results.

Exit 0 means the case matched its documented expectation.
Exit 3 from the checker is a pass only when the documented reason is present.
A missing record, a parse failure, or an exit 0 on an expected failure is a fail.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CONTENT_TYPE_05 = "application/pser+json; profile=wilder.pser/0.5"
VDS_UNSUPPORTED = "verifiable data structure 1 is not implemented"
NO_X5CHAIN = "no x5chain"
PROTECTED_NOT_CBOR = "protected bucket is not CBOR"


def load_json(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError("empty checker output")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("checker JSON is not an object")
    return value


def diagnostics(doc: dict) -> list[dict]:
    appraisal = doc.get("appraisal") or {}
    items = appraisal.get("diagnostics") or []
    if not isinstance(items, list):
        raise ValueError("appraisal.diagnostics is not a list")
    return items


def primary(doc: dict) -> tuple[str, str]:
    appraisal = doc.get("appraisal") or {}
    item = appraisal.get("primaryDiagnostic")
    if not item:
        return "", ""
    if not isinstance(item, dict):
        raise ValueError("primaryDiagnostic is not an object")
    return str(item.get("code") or ""), str(item.get("message") or "")


def messages(doc: dict) -> str:
    parts = [primary(doc)[1]]
    for item in diagnostics(doc):
        parts.append(str(item.get("message") or ""))
        parts.append(str(item.get("code") or ""))
    receipts = doc.get("receipts") or {}
    for item in receipts.get("unevaluable") or []:
        if isinstance(item, dict):
            parts.append(str(item.get("reason") or ""))
            parts.append(str(item.get("kind") or ""))
    statement = doc.get("signedStatement") or {}
    for problem in statement.get("problems") or []:
        parts.append(str(problem))
    return "\n".join(parts)


def require_exit(exit_code: int, expected: int) -> None:
    if exit_code != expected:
        raise ValueError(f"exit {exit_code}, expected {expected}")


def require_verdict(doc: dict, verdict: str, passed: bool) -> None:
    appraisal = doc.get("appraisal") or {}
    got = appraisal.get("verdict")
    if got != verdict:
        raise ValueError(f"verdict {got!r}, expected {verdict!r}")
    if appraisal.get("pass") is not passed:
        raise ValueError(f"appraisal.pass is {appraisal.get('pass')!r}, expected {passed}")
    recorded = appraisal.get("exitCode")
    if verdict == "cannot-evaluate" and recorded not in (3, None):
        raise ValueError(f"appraisal.exitCode is {recorded}, expected 3")
    if passed and recorded not in (0, None):
        raise ValueError(f"appraisal.exitCode is {recorded}, expected 0")


def receipt_headers(doc: dict) -> list[dict]:
    unprotected = doc.get("unprotected") or {}
    receipts = unprotected.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        raise ValueError("inspect JSON has no unprotected.receipts array")
    headers = []
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise ValueError(f"receipt {index} is not an object")
        protected = receipt.get("protected")
        if not isinstance(protected, dict):
            raise ValueError(f"receipt {index} has no protected object")
        headers.append(protected)
    return headers


def judge_c1(exit_code: int, doc: dict) -> str:
    require_exit(exit_code, 0)
    require_verdict(doc, "statement-transparent", True)
    code, message = primary(doc)
    if code or message:
        raise ValueError(f"unexpected primary diagnostic {code}: {message}")
    return "exit=0 verdict=statement-transparent primary=-"


def judge_c2(exit_code: int, doc: dict) -> str:
    require_exit(exit_code, 0)
    if doc.get("verified") is not False:
        raise ValueError("inspect document does not say verified=false")
    payload = doc.get("payload") or {}
    content_type = payload.get("contentType")
    if content_type != CONTENT_TYPE_05:
        raise ValueError(f"contentType {content_type!r}")
    header = receipt_headers(doc)[0]
    vds = header.get("verifiableDataStructure")
    if vds != 1:
        raise ValueError(f"receipt verifiableDataStructure {vds!r}, expected 1")
    return f"exit=0 contentType={content_type} receiptVds=1"


def judge_c3(exit_code: int, doc: dict) -> str:
    require_exit(exit_code, 3)
    require_verdict(doc, "cannot-evaluate", False)
    text = messages(doc)
    if VDS_UNSUPPORTED not in text:
        raise ValueError("diagnostics do not include unsupported VDS 1")
    if NO_X5CHAIN not in text:
        raise ValueError("diagnostics do not include the missing x5chain observation")
    code, message = primary(doc)
    if not code:
        raise ValueError("missing primary diagnostic")
    return (
        f"exit=3 verdict=cannot-evaluate primary={code}: {message}; "
        "includes verifiable data structure 1 is not implemented; includes no x5chain"
    )


def judge_c4(exit_code: int, doc: dict) -> str:
    require_exit(exit_code, 3)
    require_verdict(doc, "cannot-evaluate", False)
    code, message = primary(doc)
    if code != "StatementMalformed":
        raise ValueError(f"primary diagnostic {code!r}, expected StatementMalformed")
    if PROTECTED_NOT_CBOR not in message and PROTECTED_NOT_CBOR not in messages(doc):
        raise ValueError("diagnostic does not say the protected bucket is not CBOR")
    return f"exit=3 verdict=cannot-evaluate primary={code}: {message}"


def judge_c5(exit_code: int, doc: dict) -> str:
    require_exit(exit_code, 0)
    if doc.get("verified") is not False:
        raise ValueError("inspect document does not say verified=false")
    header = receipt_headers(doc)[0]
    vds = header.get("verifiableDataStructure")
    if vds != 2:
        raise ValueError(f"receipt verifiableDataStructure {vds!r}, expected 2")
    alg = header.get("alg")
    if not isinstance(alg, dict):
        raise ValueError(f"receipt alg {alg!r}")
    if alg.get("name") != "ES384" and alg.get("id") != -35:
        raise ValueError(f"receipt alg {alg!r}, expected ES384")
    return "exit=0 receiptVds=2 alg=ES384 receipts=label-394"


def judge_c6(exit_code: int, doc: dict) -> str:
    require_exit(exit_code, 3)
    require_verdict(doc, "cannot-evaluate", False)
    codes = [str(item.get("code") or "") for item in diagnostics(doc)]
    if "ReceiptKeyUnknown" not in codes:
        raise ValueError(f"diagnostics {codes} do not include ReceiptKeyUnknown")
    if "StatementMalformed" in codes:
        raise ValueError("StatementMalformed is present")
    if "UnsupportedFeature" in codes or "UnsupportedVds" in codes:
        raise ValueError(f"unsupported-VDS diagnostic present: {codes}")
    text = messages(doc)
    if "verifiable data structure" in text:
        raise ValueError("diagnostic mentions an unsupported verifiable data structure")
    statement = doc.get("signedStatement") or {}
    if statement.get("signatureValid") is not True:
        raise ValueError(f"signatureValid is {statement.get('signatureValid')!r}")
    entries = (doc.get("receipts") or {}).get("entries") or []
    if not entries or not isinstance(entries[0], dict):
        raise ValueError("no receipt entry was reported")
    bound = entries[0].get("boundToStatement")
    if bound is not True:
        raise ValueError(f"boundToStatement is {bound!r}")
    code, message = primary(doc)
    return (
        f"exit=3 verdict=cannot-evaluate primary={code}: {message}; "
        "signatureValid=true boundToStatement=true"
    )


JUDGES = {
    "C1": judge_c1,
    "C2": judge_c2,
    "C3": judge_c3,
    "C4": judge_c4,
    "C4d": judge_c4,
    "C5": judge_c5,
    "C6": judge_c6,
}


def judge(case: str, exit_code: int, doc: dict) -> str:
    try:
        fn = JUDGES[case]
    except KeyError as exc:
        raise ValueError(f"unknown case {case}") from exc
    return fn(exit_code, doc)


def write_case(directory: Path, name: str, exit_code: int, doc: dict) -> tuple[int, dict]:
    path = directory / f"{name}.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return exit_code, doc


def self_test() -> int:
    failures = 0

    def expect(ok: bool, label: str, case: str, exit_code: int, doc: dict) -> None:
        nonlocal failures
        try:
            judge(case, exit_code, doc)
            matched = True
        except ValueError:
            matched = False
        if matched != ok:
            print(f"SELF-TEST FAIL: {label}", file=sys.stderr)
            failures += 1

    c1 = {
        "appraisal": {
            "verdict": "statement-transparent",
            "exitCode": 0,
            "pass": True,
            "primaryDiagnostic": None,
            "diagnostics": [],
        }
    }
    expect(True, "C1 pass shape", "C1", 0, c1)
    expect(False, "C1 rejects exit 3", "C1", 3, c1)
    expect(
        False,
        "C1 rejects a pass flag on cannot-evaluate",
        "C1",
        0,
        {
            "appraisal": {
                "verdict": "cannot-evaluate",
                "exitCode": 3,
                "pass": True,
                "primaryDiagnostic": None,
            }
        },
    )

    c2 = {
        "verified": False,
        "payload": {"contentType": CONTENT_TYPE_05},
        "unprotected": {"receipts": [{"protected": {"verifiableDataStructure": 1}}]},
    }
    expect(True, "C2 inspect shape", "C2", 0, c2)
    expect(False, "C2 rejects a wrong content type", "C2", 0, {**c2, "payload": {"contentType": "application/json"}})
    expect(False, "C2 rejects exit 3", "C2", 3, c2)

    vds_message = (
        "receipt 1: could not be evaluated: verifiable data structure 1 is not "
        "implemented; this release verifies only 2 (CCF_LEDGER_SHA256)"
    )
    c3 = {
        "appraisal": {
            "verdict": "cannot-evaluate",
            "exitCode": 3,
            "pass": False,
            "primaryDiagnostic": {
                "code": "NoVerifiedReceipt",
                "message": "no receipt on this statement could be fully verified",
            },
            "diagnostics": [
                {"code": "ReceiptUnevaluable", "message": vds_message},
                {
                    "code": "StatementSignatureNotEvaluated",
                    "message": "the statement signature could not be evaluated",
                },
            ],
        },
        "signedStatement": {
            "signatureValid": None,
            "problems": ["statement carries no x5chain, so its signature could not be checked"],
        },
        "receipts": {
            "unevaluable": [
                {
                    "kind": "unsupported",
                    "reason": "verifiable data structure 1 is not implemented; this release verifies only 2 (CCF_LEDGER_SHA256)",
                }
            ],
            "entries": [],
        },
    }
    expect(True, "C3 expected failure", "C3", 3, c3)
    expect(False, "C3 rejects exit 0", "C3", 0, c3)
    expect(False, "C3 rejects a blank diagnostic", "C3", 3, {"appraisal": {"verdict": "cannot-evaluate", "exitCode": 3, "pass": False, "primaryDiagnostic": {"code": "NoVerifiedReceipt", "message": "unspecified"}, "diagnostics": []}})
    expect(
        False,
        "C3 rejects pass=true",
        "C3",
        3,
        {
            "appraisal": {
                "verdict": "cannot-evaluate",
                "exitCode": 3,
                "pass": True,
                "primaryDiagnostic": {"code": "NoVerifiedReceipt", "message": vds_message},
                "diagnostics": [{"code": "ReceiptUnevaluable", "message": vds_message}],
            },
            "signedStatement": {"problems": ["statement carries no x5chain"]},
        },
    )

    c4 = {
        "appraisal": {
            "verdict": "cannot-evaluate",
            "exitCode": 3,
            "pass": False,
            "primaryDiagnostic": {
                "code": "StatementMalformed",
                "message": "malformed COSE_Sign1: protected bucket is not CBOR: indefinite",
            },
            "diagnostics": [
                {
                    "code": "StatementMalformed",
                    "message": "malformed COSE_Sign1: protected bucket is not CBOR: indefinite",
                }
            ],
        }
    }
    expect(True, "C4 expected failure", "C4", 3, c4)
    expect(False, "C4 rejects a different malformation", "C4", 3, {"appraisal": {"verdict": "cannot-evaluate", "exitCode": 3, "pass": False, "primaryDiagnostic": {"code": "StatementMalformed", "message": "truncated"}, "diagnostics": []}})
    expect(False, "C4 rejects exit 0", "C4", 0, c4)

    c5 = {
        "verified": False,
        "unprotected": {
            "receipts": [
                {"protected": {"verifiableDataStructure": 2, "alg": {"id": -35, "name": "ES384"}}}
            ]
        },
    }
    expect(True, "C5 inspect shape", "C5", 0, c5)
    expect(False, "C5 rejects VDS 1", "C5", 0, {"verified": False, "unprotected": {"receipts": [{"protected": {"verifiableDataStructure": 1, "alg": {"name": "ES384"}}}]}})

    c6 = {
        "appraisal": {
            "verdict": "cannot-evaluate",
            "exitCode": 3,
            "pass": False,
            "primaryDiagnostic": {
                "code": "ReceiptKeyUnknown",
                "message": "receipt 1: no key in the supplied set matches kid abc",
            },
            "diagnostics": [
                {
                    "code": "ReceiptKeyUnknown",
                    "message": "receipt 1: no key in the supplied set matches kid abc",
                }
            ],
        },
        "signedStatement": {"signatureValid": True, "problems": []},
        "receipts": {"entries": [{"boundToStatement": True}], "unevaluable": []},
    }
    expect(True, "C6 expected failure", "C6", 3, c6)
    expect(False, "C6 rejects a valid signature that is false", "C6", 3, {**c6, "signedStatement": {"signatureValid": False}})
    expect(False, "C6 rejects unbound receipt", "C6", 3, {**c6, "receipts": {"entries": [{"boundToStatement": False}], "unevaluable": []}})
    bad_vds = {
        "appraisal": {
            "verdict": "cannot-evaluate",
            "exitCode": 3,
            "pass": False,
            "primaryDiagnostic": {"code": "UnsupportedFeature", "message": VDS_UNSUPPORTED},
            "diagnostics": [{"code": "UnsupportedFeature", "message": VDS_UNSUPPORTED}],
        },
        "signedStatement": {"signatureValid": True},
        "receipts": {"entries": [{"boundToStatement": True}], "unevaluable": []},
    }
    expect(False, "C6 rejects unsupported VDS", "C6", 3, bad_vds)
    malformed = {
        "appraisal": {
            "verdict": "cannot-evaluate",
            "exitCode": 3,
            "pass": False,
            "primaryDiagnostic": {"code": "StatementMalformed", "message": PROTECTED_NOT_CBOR},
            "diagnostics": [
                {"code": "StatementMalformed", "message": PROTECTED_NOT_CBOR},
                {"code": "ReceiptKeyUnknown", "message": "missing"},
            ],
        },
        "signedStatement": {"signatureValid": True},
        "receipts": {"entries": [{"boundToStatement": True}]},
    }
    expect(False, "C6 rejects StatementMalformed", "C6", 3, malformed)
    expect(False, "blank document is not a pass", "C3", 3, {})

    if failures:
        print(f"judge.py self-test: FAIL ({failures})", file=sys.stderr)
        return 1
    print("judge.py self-test: PASS")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 3:
        print("usage: judge.py --self-test | judge.py CASE EXIT_CODE JSON", file=sys.stderr)
        return 2
    case, exit_text, json_path = argv
    try:
        exit_code = int(exit_text)
        summary = judge(case, exit_code, load_json(Path(json_path)))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL {case}: {exc}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
