#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent process entry point for LOCAL BUNDLE checks, not #71/SCITT validation.

Imports no producer modules. It consumes final objects and operator-provisioned
public inputs. It does not implement Receipt parsing, candidate derivation or TS trust.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import resource
import time

VERSION = "pask-robotics-evidence-dev/1"
VERSION2 = "pask-robotics-evidence-dev/2"
SAMPLED_POLICY = "collector-monotonic-sampled-bracket/1"
# Recipient-local requirements, never imported from producer or accepted as knobs.
SAMPLED_PERIODS = {"/demo/movement": 100000000, "/demo/control_mode": 500000000,
                   "/demo/diagnostics": 500000000}
SAMPLED_LIMITS = {"queue_records": 8, "record_bytes": 4096, "pre_records": 128,
                  "pre_bytes": 262144, "event_records": 256, "event_bytes": 524288,
                  "export_bytes": 1048576, "input_records": 5000, "quality_entries": 64,
                  "duration_ns": 30000000000, "pre_ns": 2000000000, "post_ns": 3000000000}
PROFILE = "software-test-only/not-PSER"
LAYERS = ["schema", "evidence_integrity", "issuer_signature", "issuer_key_association",
          "receipt_claims_support", "ts_signature", "inclusion", "ts_identity_trust",
          "subject_policy", "application_policy", "timing_coverage",
          "hardware_appraisal", "overall_profile"]
MAX_OBJECTS, MAX_BYTES, MAX_MANIFEST = 1024, 1048576, 262144


def finding(status, reason, **details):
    return {"status": status, "reason": reason, **({"details": details} if details else {})}


def pairs_no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key")
        d[k] = v
    return d


def load_json(raw):
    def disallow(_):
        raise ValueError("floating point / constants outside local encoding subset")
    return json.loads(raw, object_pairs_hook=pairs_no_duplicates,
                      parse_float=disallow, parse_constant=disallow)


def read_limited(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("not a regular non-symlink file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file byte ceiling")
    return data


def sampled_findings(loaded, manifest, findings):
    """Independent dev/2 recomputation; no producer helper import."""
    window = load_json(loaded["event-window.json"])
    summary = load_json(loaded["engagement-summary.json"])
    schemas = load_json(loaded["schemas.json"])
    rows = load_json(loaded["observations.json"])
    if (window["coverage_policy"] != SAMPLED_POLICY or
            window["clock"] != "collector-monotonic-relative" or
            set(schemas["topics"]) != set(SAMPLED_PERIODS) or
            set(window["streams"]) != set(SAMPLED_PERIODS) or
            summary["limits"] != SAMPLED_LIMITS or
            window["engagement_id"] != manifest["record_id"] or
            summary["record_id"] != manifest["record_id"]):
        raise ValueError("dev/2 named policy/context mismatch")
    # Equality alone accepts bools as integers in Python.
    if any(type(v) is not int for v in summary["limits"].values()):
        raise ValueError("dev/2 limits must be integers")
    for topic, period in SAMPLED_PERIODS.items():
        if type(schemas["topics"][topic]["period_ns"]) is not int or schemas["topics"][topic]["period_ns"] != period:
            raise ValueError("dev/2 cadence cannot be weakened by metadata")
    trigger, requested = window["trigger"], window["requested_bounds_ns"]
    if trigger is None:
        if requested is not None or rows:
            raise ValueError("event without trigger")
    else:
        if (not isinstance(trigger, dict) or
                set(trigger) != {"topic", "receive_ns", "source_ns", "rule"} or
                trigger["topic"] != "/demo/diagnostics" or
                trigger["rule"] != "diagnostic_level_gte_2/dev1" or
                type(trigger["receive_ns"]) is not int or trigger["receive_ns"] < 0 or
                (trigger["source_ns"] is not None and type(trigger["source_ns"]) is not int) or
                not isinstance(requested, list) or len(requested) != 2 or
                any(type(x) is not int for x in requested) or
                requested != [trigger["receive_ns"] - 2000000000, trigger["receive_ns"] + 3000000000]):
            raise ValueError("dev/2 trigger/requested contract mismatch")
    if not isinstance(rows, list) or len(rows) > 256:
        raise ValueError("dev/2 observation capacity")
    indexed, previous, raw_bytes = set(), -1, 0
    for i, row in enumerate(rows):
        path, at, topic = row["path"], row["receive_ns"], row["topic"]
        if (path != f"observations/{i:06d}.bin" or path not in loaded or
                type(at) is not int or at < previous or at < 0 or topic not in SAMPLED_PERIODS or
                (row.get("source_ns") is not None and type(row["source_ns"]) is not int) or
                (row.get("source_sequence") is not None and type(row["source_sequence"]) is not int) or
                ("trigger" in row and type(row["trigger"]) is not bool)):
            raise ValueError("invalid dev/2 observation index")
        previous = at
        indexed.add(path)
        if len(loaded[path]) > 4096:
            raise ValueError("dev/2 record capacity")
        raw_bytes += len(loaded[path])
        expected_role = "before" if at < requested[0] else "after" if at > requested[1] else "in_window"
        if row["coverage_role"] != expected_role:
            raise ValueError("context role differs from timestamp")
    if raw_bytes > 524288 or indexed != {p for p in loaded if p.startswith("observations/")}:
        raise ValueError("dev/2 event capacity/unindexed bytes")
    counts = summary["counts"]
    if not isinstance(counts, dict) or set(counts) != set(SAMPLED_PERIODS):
        raise ValueError("dev/2 count topic map")
    dropped_counts, seen_total = {}, 0
    for topic, counters in counts.items():
        if (not isinstance(counters, dict) or not set(counters).issubset({"seen", "accepted", "dropped"}) or
                any(type(v) is not int or not 0 <= v <= 5000 for v in counters.values())):
            raise ValueError("dev/2 count shape/range")
        seen, accepted, dropped = (counters.get(k, 0) for k in ("seen", "accepted", "dropped"))
        if seen != accepted + dropped or accepted < sum(r["topic"] == topic for r in rows):
            raise ValueError("dev/2 count relationship inconsistent")
        seen_total += seen
        if dropped:
            dropped_counts[topic] = dropped
    if seen_total > 5000:
        raise ValueError("dev/2 total input count ceiling")
    marked = [r for r in rows if r.get("trigger") is True]
    if trigger is not None and (not marked or
            marked[0]["topic"] != trigger["topic"] or marked[0]["receive_ns"] != trigger["receive_ns"] or
            marked[0].get("source_ns") != trigger["source_ns"]):
        # Lost trigger is an adverse capture, not evidence fabricated to replace it.
        if marked:
            raise ValueError("covered trigger inconsistent")
    def bounds(records):
        return [records[0]["receive_ns"], records[-1]["receive_ns"]] if records else None
    inside_all = [r for r in rows if r["coverage_role"] == "in_window"]
    if (json.dumps(window["actual_bounds_ns"]) != json.dumps(bounds(inside_all)) or
            json.dumps(window["retained_bounds_ns"]) != json.dumps(bounds(rows))):
        raise ValueError("dev/2 event/context bounds inconsistent")
    input_bounds = summary["actual_input_bounds_ns"]
    if (not isinstance(input_bounds, list) or len(input_bounds) != 2 or
            (input_bounds != [None, None] and (
                any(type(n) is not int or n < 0 for n in input_bounds) or input_bounds[1] < input_bounds[0])) or
            (rows and (input_bounds == [None, None] or
                       not input_bounds[0] <= rows[0]["receive_ns"] <= rows[-1]["receive_ns"] <= input_bounds[1]))):
        raise ValueError("dev/2 input/retained bounds inconsistent")
    computed, source_anomalies = {}, []
    for topic, period in SAMPLED_PERIODS.items():
        stream = [r for r in rows if r["topic"] == topic]
        inside = [r for r in stream if r["coverage_role"] == "in_window"]
        before = [r for r in stream if r["coverage_role"] == "before"]
        after = [r for r in stream if r["coverage_role"] == "after"]
        if len(before) > 1 or len(after) > 1:
            raise ValueError("more than nearest single context per side")
        left, right = requested if requested is not None else (None, None)
        lower = [r for r in stream if left is not None and r["receive_ns"] <= left]
        upper = [r for r in stream if right is not None and r["receive_ns"] >= right]
        a, b = (lower[-1] if lower else None), (upper[0] if upper else None)
        if (before and any(r["receive_ns"] == left for r in inside)) or (
                after and any(r["receive_ns"] == right for r in inside)):
            raise ValueError("unnecessary context duplicates endpoint support")
        times = sorted({r["receive_ns"] for r in stream})
        spans = [y - x for x, y in zip(times, times[1:])]
        gaps = []
        if not inside:
            gaps.append("stream_unavailable")
        if a is None:
            gaps.append("insufficient_prehistory")
        if b is None:
            gaps.append("incomplete_posthistory")
        if any(x > 2 * period for x in spans):
            gaps.append("excessive_sample_span")
        if a and left - a["receive_ns"] > 2 * period:
            gaps.append("left_support_too_far")
        if b and b["receive_ns"] - right > 2 * period:
            gaps.append("right_support_too_far")
        computed[topic] = {
            "native_period_ns": period, "maximum_span_ns": 2 * period,
            "in_window_count": len(inside), "actual_bounds_ns": bounds(inside),
            "in_window_start_offset_ns": inside[0]["receive_ns"] - left if inside else None,
            "in_window_end_offset_ns": right - inside[-1]["receive_ns"] if inside else None,
            "retained_bounds_ns": [times[0], times[-1]] if times else None,
            "left_support": a["path"] if a else None, "right_support": b["path"] if b else None,
            "left_offset_ns": left - a["receive_ns"] if a else None,
            "right_offset_ns": b["receive_ns"] - right if b else None,
            "observed_max_span_ns": max(spans) if spans else None, "gaps": gaps}
        # Compare encoded types as well as values (reject True == 1 aliases).
        if json.dumps(window["streams"][topic], sort_keys=True) != json.dumps(computed[topic], sort_keys=True):
            raise ValueError("dev/2 support/gap metadata differs from recomputation")
        stamps = [r["source_ns"] for r in stream if r.get("source_ns") is not None]
        if any(y < x for x, y in zip(stamps, stamps[1:])):
            source_anomalies.append({"topic": topic, "reason": "source_clock_rollback"})
        sequences = [r["source_sequence"] for r in stream if r.get("source_sequence") is not None]
        if any(y != x + 1 for x, y in zip(sequences, sequences[1:])):
            source_anomalies.append({"topic": topic, "reason": "source_sequence_discontinuity"})
    reasons = summary["quality_reason_counts"]
    if not isinstance(reasons, dict) or any(not isinstance(k, str) or type(v) is not int or v <= 0 for k, v in reasons.items()):
        raise ValueError("invalid quality counters")
    entries = summary["quality_entries"]
    if (not isinstance(entries, list) or len(entries) > 64 or
            type(summary["quality_entries_omitted"]) is not int or
            summary["quality_entries_omitted"] != max(0, sum(reasons.values()) - len(entries))):
        raise ValueError("invalid bounded quality entries")
    entry_counts = {}
    for entry in entries:
        if (not isinstance(entry, dict) or not {"reason", "topic", "receive_ns"}.issubset(entry) or
                (entry["topic"] is not None and
                 (not isinstance(entry["topic"], str) or entry["topic"] not in SAMPLED_PERIODS)) or
                (entry["receive_ns"] is not None and
                 (type(entry["receive_ns"]) is not int or entry["receive_ns"] < 0))):
            raise ValueError("invalid quality entry shape")
        reason = entry["reason"]
        if not isinstance(reason, str) or not reason or reason not in reasons:
            raise ValueError("quality entry missing from counter")
        entry_counts[reason] = entry_counts.get(reason, 0) + 1
        if entry_counts[reason] > reasons[reason]:
            raise ValueError("quality entries exceed counter")
    source_reports = {k: v for k, v in reasons.items() if k in ("source_clock_rollback", "source_sequence_discontinuity")}
    adverse = {k: v for k, v in reasons.items() if k not in (
        "source_clock_rollback", "source_sequence_discontinuity", "timing_relationship_unestablished")}
    failed = bool(trigger is None or not marked or adverse or dropped_counts or
                  any(s["gaps"] for s in computed.values()))
    state = {"ready_at_trigger": trigger is not None and all(s["left_support"] is not None for s in computed.values()),
             "right_brackets_present": trigger is not None and all(s["right_support"] is not None for s in computed.values()),
             "capture_complete": not failed}
    if (summary["coverage_state"] != state or
            any(type(v) is not bool for v in summary["coverage_state"].values()) or
            summary["task_state"] != ("completed_simulation" if state["capture_complete"] else "incomplete_sampled_capture")):
        raise ValueError("dev/2 readiness/completion inconsistent")
    details = dict(policy=SAMPLED_POLICY, streams=computed, capture_state=state,
                   adverse_quality_reasons=adverse, all_quality_reasons=reasons,
                   reported_dropped_records=dropped_counts,
                   count_scope="seen=accepted+dropped; retained subset is not inferred loss",
                   quality_entries=entries, quality_entries_omitted=summary["quality_entries_omitted"],
                   clock="collector-monotonic-relative",
                   limitation="sampled evidence only; no continuous physical-state or DDS completeness proof")
    findings["collector_sampled_coverage"] = finding("failed" if failed else "passed",
                                                    "named per-stream bracketing contract", **details)
    findings["timing_coverage"] = finding("failed" if failed else "passed",
        "dev/2 collector sampled coverage only; source and real-world time are separate findings",
        policy=SAMPLED_POLICY)
    findings["source_clock_anomalies"] = finding(
        "failed" if source_reports or source_anomalies else "passed",
        "observed/reported source anomalies only; no clock synchronization claim",
        collector_reports=source_reports, retained_index_anomalies=source_anomalies)
    findings["real_world_time"] = finding("unestablished",
        "source-to-collector/wall-clock correspondence not established",
        preserved_warning_count=reasons.get("timing_relationship_unestablished", 0))


def verify(root, public_inputs):
    root = Path(root).resolve()
    report = {"report_version": "dev-recipient/1", "bundle_type": "local-independent-capture",
              "core_integration": "unestablished", "findings": {
                  layer: finding("not-evaluated", "dependent check not reached") for layer in LAYERS}}
    f = report["findings"]
    f["receipt_claims_support"] = finding("not-evaluated", "no Receipt input; #71 coordinator pending")
    for name in ("ts_signature", "inclusion", "ts_identity_trust"):
        f[name] = finding("unestablished", "no Transparency Service or Receipt supplied")
    f["subject_policy"] = finding("unestablished", "no PSER/SCITT subject or named subject policy")
    f["application_policy"] = finding("unestablished", "no application acceptance policy")
    f["hardware_appraisal"] = finding("unestablished", "software-only test key; no hardware evidence")
    f["overall_profile"] = finding("unsupported", "local bundle is not a PSER profile")
    try:
        raw = read_limited(root / "manifest.json", MAX_MANIFEST)
        manifest = load_json(raw)
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
        if manifest.get("schema_version") not in (VERSION, VERSION2):
            f["schema"] = finding("unsupported", "unknown evidence version; no coercion")
            return report
        if manifest["schema_version"] == VERSION2:
            report["report_version"] = "dev-recipient/2"
            report["effective_coverage_policy"] = SAMPLED_POLICY
            for layer in ("collector_sampled_coverage", "source_clock_anomalies", "real_world_time"):
                f[layer] = finding("not-evaluated", "dependent check not reached")
        if manifest.get("profile_version") != PROFILE:
            f["schema"] = finding("unsupported", "unknown profile declaration; no coercion")
            return report
        required = {"schema_version", "profile_version", "record_id", "issuer", "signing_key_id",
                    "signature_algorithm", "software_test_material", "core_integration",
                    "versions", "objects", "digest_exclusions"}
        if set(manifest) != required:
            raise ValueError("unexpected or missing manifest fields")
        if manifest["signature_algorithm"] != "Ed25519":
            f["schema"] = finding("unsupported", "unsupported signature algorithm")
            return report
        if (manifest["software_test_material"] is not True or
                manifest["core_integration"] != "unestablished" or
                not all(isinstance(manifest[k], str) for k in ("record_id", "issuer", "signing_key_id"))):
            raise ValueError("invalid manifest identity/assurance structure")
        if not re.fullmatch("[0-9a-f]{64}", manifest["signing_key_id"]):
            raise ValueError("key id must be exact public-key SHA-256")
        if not isinstance(manifest["versions"], dict):
            raise ValueError("versions must be an object")
        if manifest["digest_exclusions"] != [
                "manifest.json", "manifest.sig", "recipient-findings.json",
                "transport archive metadata", "public trust inputs"]:
            raise ValueError("digest exclusions not the declared dev/1 contract")
        objects = manifest["objects"]
        if not isinstance(objects, list) or not 1 <= len(objects) <= MAX_OBJECTS:
            raise ValueError("object count ceiling/shape")
        names = []
        total = 0
        for obj in objects:
            if not isinstance(obj, dict) or set(obj) != {"path", "size_bytes", "sha256"}:
                raise ValueError("invalid object structure")
            name = obj["path"]
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                    or PurePosixPath(name).is_absolute() or
                    any(part in (".", "..", "") for part in name.split("/"))):
                raise ValueError("unsafe object path")
            if name in ("manifest.json", "manifest.sig", "recipient-findings.json"):
                raise ValueError("self-reference or excluded file in commitments")
            if type(obj["size_bytes"]) is not int or not 0 <= obj["size_bytes"] <= MAX_BYTES:
                raise ValueError("object size ceiling")
            if not isinstance(obj["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", obj["sha256"]):
                raise ValueError("invalid object digest")
            total += obj["size_bytes"]
            names.append(name)
        if names != sorted(set(names)) or total > MAX_BYTES:
            raise ValueError("unsorted/duplicate paths or total byte ceiling")
        essentials = {"configuration.json", "schemas.json", "observations.json",
                      "event-window.json", "engagement-summary.json"}
        if not essentials.issubset(names):
            raise ValueError("missing required evidence objects")
        # Canonicality is this local JSON subset only. Never rewrite signed input.
        rendered = json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                              separators=(",", ":"), allow_nan=False).encode("ascii")
        if rendered != raw:
            raise ValueError("non-deterministic manifest encoding")
        f["schema"] = finding("passed", "local " + ("dev/2" if manifest["schema_version"] == VERSION2
                                                   else "dev/1") + " manifest structure and version; not PSER")
    except (ValueError, OSError, TypeError, KeyError, UnicodeError) as exc:
        f["schema"] = finding("failed", str(exc))
        return report
    report["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    loaded = {}
    try:
        # Hard ceiling for directory scan, including unlisted and symlink objects.
        disk_names = []
        for scanned, path in enumerate(root.rglob("*")):
            if scanned >= 2 * MAX_OBJECTS + 3:
                raise ValueError("directory entry ceiling")
            if path.is_symlink():
                raise ValueError("symlink forbidden anywhere in input")
            if path.is_file():
                disk_names.append(path.relative_to(root).as_posix())
        if set(disk_names) != set(names) | {"manifest.json", "manifest.sig"}:
            raise ValueError("unlisted/missing final object; findings/trust must remain outside bundle")
        for obj in objects:
            path = root / obj["path"]
            if not path.resolve().is_relative_to(root):
                raise ValueError("path escapes bundle")
            data = read_limited(path, obj["size_bytes"])
            if len(data) != obj["size_bytes"] or hashlib.sha256(data).hexdigest() != obj["sha256"]:
                raise ValueError("covered object mismatch: " + obj["path"])
            loaded[obj["path"]] = data
        f["evidence_integrity"] = finding("passed", "all listed original object bytes match final manifest")
    except (OSError, ValueError) as exc:
        f["evidence_integrity"] = finding("failed", str(exc))
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if Path(public_inputs).resolve().is_relative_to(root):
            raise ValueError("public trust path must be outside the bundle; caller must provision authority")
        trust = load_json(read_limited(Path(public_inputs), 65536))
        if trust.get("version") != "local-test-trust/1":
            raise ValueError("unsupported public trust input version")
        accepted = trust.get("accepted", [])
        candidates = trust.get("verification_candidates", accepted)
        if not isinstance(candidates, list) or len(candidates) > 8 or not isinstance(accepted, list) or len(accepted) > 8:
            raise ValueError("public-key candidate ceiling")
        signature = read_limited(root / "manifest.sig", 64)
        if len(signature) != 64:
            raise ValueError("wrong Ed25519 signature length")
        verified = None
        for candidate in candidates:
            public = bytes.fromhex(candidate["public_key_hex"])
            if len(public) != 32 or candidate.get("algorithm") != "Ed25519":
                continue
            try:
                Ed25519PublicKey.from_public_bytes(public).verify(signature, raw)
                verified = public
                break
            except InvalidSignature:
                continue
        if verified is None:
            f["issuer_signature"] = finding("failed" if candidates else "unestablished",
                                             "no signature verifies under supplied public candidates")
            f["issuer_key_association"] = finding("unestablished", "no actual verifying key")
        else:
            key_hash = hashlib.sha256(verified).hexdigest()
            f["issuer_signature"] = finding("passed", "detached Ed25519 signature over exact manifest bytes",
                                             verifying_public_key_sha256=key_hash)
            matched = any(
                entry.get("public_key_hex") == verified.hex() and
                entry.get("issuer") == manifest["issuer"] and
                entry.get("key_id") == key_hash == manifest["signing_key_id"] and
                entry.get("algorithm") == "Ed25519" and
                entry.get("valid_record_id") == manifest["record_id"]
                for entry in accepted)
            f["issuer_key_association"] = finding(
                "passed" if matched else "failed",
                "exact verifying key authorized by supplied local test policy" if matched
                else "verifying key not authorized for this issuer/record; labels do not grant trust",
                trust_scope="operator-supplied software test inputs, not independent hardware/organization",
                time_validity="not-evaluated/no authenticated wall-clock input")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        f["issuer_signature"] = finding("unestablished", "public input/signature processing unavailable: " + str(exc))
        f["issuer_key_association"] = finding("unestablished", "no usable public policy")
    if f["evidence_integrity"]["status"] == "passed":
        try:
            if manifest["schema_version"] == VERSION2:
                sampled_findings(loaded, manifest, f)
                return report
            window = load_json(loaded["event-window.json"])
            summary = load_json(loaded["engagement-summary.json"])
            schemas = load_json(loaded["schemas.json"])
            observations = load_json(loaded["observations.json"])
            if (not isinstance(observations, list) or len(observations) > 256 or
                    not isinstance(window["streams"], dict) or not isinstance(summary["counts"], dict) or
                    window["engagement_id"] != manifest["record_id"] or
                    summary["record_id"] != manifest["record_id"]):
                raise ValueError("invalid evidence index/context")
            if len({r["path"] for r in observations}) != len(observations):
                raise ValueError("duplicate observation index path")
            indexed = set()
            previous = -1
            for r in observations:
                if r["path"] not in loaded or not r["path"].startswith("observations/"):
                    raise ValueError("observation index points outside covered observations")
                if type(r["receive_ns"]) is not int or r["receive_ns"] < previous:
                    raise ValueError("nonmonotonic indexed receive time")
                previous = r["receive_ns"]
                indexed.add(r["path"])
            if indexed != {name for name in names if name.startswith("observations/")}:
                raise ValueError("unindexed observation")
            actual_bounds = [min(r["receive_ns"] for r in observations),
                             max(r["receive_ns"] for r in observations)] if observations else None
            if window["actual_bounds_ns"] != actual_bounds:
                raise ValueError("claimed actual window differs from covered index")
            if set(window["streams"]) != set(schemas["topics"]):
                raise ValueError("stream metadata does not match declared allowlist")
            if any(r["topic"] not in schemas["topics"] for r in observations):
                raise ValueError("observation topic outside declared allowlist")
            requested = window["requested_bounds_ns"]
            if requested is not None and (
                    not isinstance(requested, list) or len(requested) != 2 or
                    not all(type(n) is int for n in requested) or requested[1] < requested[0]):
                raise ValueError("invalid requested time bounds")
            trigger = window["trigger"]
            if trigger is not None:
                if (not isinstance(trigger, dict) or
                        set(trigger) != {"topic", "receive_ns", "source_ns", "rule"} or
                        trigger["topic"] != "/demo/diagnostics" or
                        trigger["rule"] != "diagnostic_level_gte_2/dev1" or
                        type(trigger["receive_ns"]) is not int or
                        (trigger["source_ns"] is not None and type(trigger["source_ns"]) is not int)):
                    raise ValueError("invalid trigger structure/topic/rule")
                if requested is None:
                    raise ValueError("triggered event lacks requested coverage bounds")
                at = trigger["receive_ns"]
                if not requested[0] <= at <= requested[1]:
                    raise ValueError("trigger outside requested window")
                pre, post = summary["limits"]["pre_ns"], summary["limits"]["post_ns"]
                if (type(pre) is not int or type(post) is not int or pre < 0 or post < 0 or
                        requested != [at - pre, at + post]):
                    raise ValueError("trigger/requested pre-post coverage mismatch")
            elif requested is not None or observations:
                raise ValueError("event coverage present without a trigger")
            gaps = {}
            for topic, spec in schemas["topics"].items():
                period = spec["period_ns"]
                if type(period) is not int or period <= 0:
                    raise ValueError("invalid declared native period")
                times = sorted({r["receive_ns"] for r in observations if r["topic"] == topic})
                local_gaps = []
                bounds = [times[0], times[-1]] if times else None
                if window["streams"][topic]["actual_bounds_ns"] != bounds:
                    raise ValueError("stream bounds differ from covered index")
                intervals = sorted(b - a for a, b in zip(times, times[1:]))
                median = None
                if intervals:
                    n = len(intervals)
                    median = (intervals[n // 2] if n % 2
                              else (intervals[n // 2 - 1] + intervals[n // 2]) // 2)
                observed = {"unique_receive_times": len(times),
                            "observed_median_interval_ns": median,
                            "observed_max_interval_ns": max(intervals) if intervals else None,
                            "native_period_ns": period, "requested_period_ns": period}
                for field, expected in observed.items():
                    actual = window["streams"][topic][field]
                    if actual != expected or (expected is not None and type(actual) is not int):
                        raise ValueError("reported resolution differs from covered index/declaration: " + field)
                if requested:
                    if not times:
                        local_gaps = [{"start_ns": requested[0], "end_ns": requested[1],
                                       "kind": "stream_unavailable"}]
                    else:
                        if times[0] < requested[0] or times[-1] > requested[1]:
                            raise ValueError("observation outside requested window")
                        if times[0] > requested[0]:
                            local_gaps.append({"start_ns": requested[0], "end_ns": times[0], "kind": "prefix"})
                        local_gaps.extend({"start_ns": a, "end_ns": b,
                                           "kind": "interval_exceeds_2_native_periods"}
                                          for a, b in zip(times, times[1:]) if b - a > 2 * period)
                        if times[-1] < requested[1]:
                            local_gaps.append({"start_ns": times[-1], "end_ns": requested[1], "kind": "suffix"})
                if window["streams"][topic]["gaps"] != local_gaps:
                    raise ValueError("claimed gaps differ from recipient-recomputed gaps")
                if local_gaps:
                    gaps[topic] = local_gaps
            reasons = summary["quality_reason_counts"]
            bad = bool(gaps or reasons or window["trigger"] is None)
            f["timing_coverage"] = finding(
                "failed" if bad else "passed",
                "requested local capture coverage has visible gaps/errors" if bad
                else "declared local receive-time window present; no physical timing claim",
                gaps=gaps, quality_reason_counts=reasons,
                verification_scope="trigger/requested-window consistency; bounds/gaps/resolution independently recomputed from covered index; source-clock issues are signed collector reports",
                cross_clock_relationship="unestablished/source-to-wall-time",
                applicability="simulation-only; not safety adequacy")
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            f["schema"] = finding("failed", "evidence object structure: " + str(exc))
            f["timing_coverage"] = finding("not-evaluated", "malformed evidence metadata")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bundle")
    p.add_argument("--public-trust", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    started = time.perf_counter_ns()
    before = resource.getrusage(resource.RUSAGE_SELF)
    report = verify(args.bundle, args.public_trust)
    after = resource.getrusage(resource.RUSAGE_SELF)
    elapsed = time.perf_counter_ns() - started
    report["process_measurement"] = {
        "verification_wall_ns": elapsed,
        "verification_user_cpu_seconds": after.ru_utime - before.ru_utime,
        "verification_system_cpu_seconds": after.ru_stime - before.ru_stime,
        "process_peak_rss_kib": after.ru_maxrss,
        "note": "recipient SELF measurements inside isolation; peak includes interpreter startup"}
    Path(args.output).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: v["status"] for k, v in report["findings"].items()}, sort_keys=True))
    # 0 = performed local checks pass; this is NEVER overall PSER acceptance.
    local = ("schema", "evidence_integrity", "issuer_signature", "issuer_key_association")
    raise SystemExit(0 if all(report["findings"][k]["status"] == "passed" for k in local) else 2)


if __name__ == "__main__":
    main()
