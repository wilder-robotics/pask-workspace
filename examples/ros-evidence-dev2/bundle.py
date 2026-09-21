#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local developmental capture/export, NOT ROS middleware or a PSER producer."""
import argparse
import base64
from collections import Counter, deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import statistics
import time

VERSION = "pask-robotics-evidence-dev/1"
VERSION2 = "pask-robotics-evidence-dev/2"
POLICY_ID = "collector-monotonic-sampled-bracket/1"
PROFILE = "software-test-only/not-PSER"
NS = 1_000_000_000
TOPICS = {
    "/demo/movement": {"type": "geometry_msgs/msg/PoseStamped", "period_ns": NS // 10,
                       "units": {"position": "m", "orientation": "unit quaternion"},
                       "frame": "map", "source_clock": "simulated/source"},
    "/demo/control_mode": {"type": "std_msgs/msg/String", "period_ns": NS // 2,
                           "units": None, "frame": None, "source_clock": None},
    "/demo/diagnostics": {"type": "diagnostic_msgs/msg/DiagnosticArray", "period_ns": NS // 2,
                          "units": None, "frame": None, "source_clock": "simulated/source"},
}
LIMITS = {"queue_records": 8, "record_bytes": 4096, "pre_records": 128,
          "pre_bytes": 262144, "event_records": 256, "event_bytes": 524288,
          "export_bytes": 1048576, "input_records": 5000, "quality_entries": 64,
          "duration_ns": 30 * NS, "pre_ns": 2 * NS, "post_ns": 3 * NS}


def encoded(value):
    """Local deterministic ASCII JSON subset, NOT a general JCS implementation."""
    def check(v):
        if v is None or isinstance(v, (bool, str)):
            return
        if type(v) is int and abs(v) <= 2**53 - 1:
            return
        if isinstance(v, list):
            for item in v:
                check(item)
            return
        if isinstance(v, dict) and all(isinstance(k, str) for k in v):
            for item in v.values():
                check(item)
            return
        raise ValueError("manifest subset excludes floats, large integers and non-JSON values")
    check(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def public_bytes(key):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class Capture:
    """Bounded ingress queue and event buffer. Monotonic receive time selects windows."""
    def __init__(self, limits=None, policy=None):
        if policy not in (None, POLICY_ID):
            raise ValueError("unknown prospective coverage policy")
        self.policy = policy
        self.limits = {**LIMITS, **(limits or {})}
        if policy == POLICY_ID and (self.limits != LIMITS or
                                    any(type(v) is not int for v in self.limits.values())):
            raise ValueError("named dev/2 policy does not permit limit overrides")
        self.queue, self.pre, self.event = deque(), deque(), []
        self.pre_bytes = self.event_bytes = 0
        self.quality, self.reasons = [], Counter()
        self.counts = {t: Counter() for t in TOPICS}
        self.last_source, self.last_seq, self.last_receive = {}, {}, None
        self.trigger = None
        self.start = self.end = None
        self.attempts = 0
        self.high_water = {"queue_records": 0, "pre_bytes": 0, "event_bytes": 0}

    def issue(self, reason, topic=None, at=None, **detail):
        self.reasons[reason] += 1
        if len(self.quality) < self.limits["quality_entries"]:
            self.quality.append({"reason": reason, "topic": topic, "receive_ns": at, **detail})

    def submit(self, r):
        self.attempts += 1
        if self.attempts > self.limits["input_records"]:
            raise ValueError("input record ceiling")
        topic, at = r["topic"], r["receive_ns"]
        if topic not in TOPICS:
            self.issue("topic_not_allowlisted", topic, at)
            return False
        if type(at) is not int or at < 0:
            raise ValueError("invalid receive time")
        if self.last_receive is not None and at < self.last_receive:
            self.issue("receive_clock_rollback", topic, at)
            return False
        self.last_receive = at
        self.start = at if self.start is None else self.start
        self.end = at
        if at - self.start > self.limits["duration_ns"]:
            raise ValueError("capture duration ceiling")
        if not isinstance(r["raw"], bytes) or len(r["raw"]) > self.limits["record_bytes"]:
            self.issue("oversize_record", topic, at)
            return False
        self.counts[topic]["seen"] += 1
        source = r.get("source_ns")
        if source is not None:
            if topic in self.last_source and source < self.last_source[topic]:
                self.issue("source_clock_rollback", topic, at, previous_ns=self.last_source[topic],
                           current_ns=source)
            self.last_source[topic] = source
        seq = r.get("source_sequence")
        if seq is not None:
            previous = self.last_seq.get(topic)
            if previous is not None and seq != previous + 1:
                self.issue("source_sequence_discontinuity", topic, at, previous=previous, current=seq)
            self.last_seq[topic] = seq
        if len(self.queue) >= self.limits["queue_records"]:
            self.counts[topic]["dropped"] += 1
            self.issue("queue_overflow_drop_newest", topic, at)
            return False
        self.queue.append(r)
        self.high_water["queue_records"] = max(self.high_water["queue_records"], len(self.queue))
        return True

    def save_event(self, r):
        if len(self.event) >= self.limits["event_records"] or (
                self.event_bytes + len(r["raw"]) > self.limits["event_bytes"]):
            self.issue("event_truncated", r["topic"], r["receive_ns"])
            return
        self.event.append(r)
        self.event_bytes += len(r["raw"])
        self.high_water["event_bytes"] = max(self.high_water["event_bytes"], self.event_bytes)

    def drain(self):
        if self.policy == POLICY_ID:
            return self.drain_sampled()
        while self.queue:
            r = self.queue.popleft()
            at = r["receive_ns"]
            self.counts[r["topic"]]["accepted"] += 1
            # Time eviction is normal retention; size eviction is separately visible.
            while self.pre and self.pre[0]["receive_ns"] < at - self.limits["pre_ns"]:
                self.pre_bytes -= len(self.pre.popleft()["raw"])
            if self.trigger is None and r.get("trigger") is True:
                self.trigger = {"topic": r["topic"], "receive_ns": at,
                                "rule": "diagnostic_level_gte_2/dev1",
                                "source_ns": r.get("source_ns")}
                for item in self.pre:
                    self.save_event(item)
            if self.trigger is not None and at <= self.trigger["receive_ns"] + self.limits["post_ns"]:
                self.save_event(r)
            if self.trigger is None:
                while self.pre and (len(self.pre) >= self.limits["pre_records"] or
                                    self.pre_bytes + len(r["raw"]) > self.limits["pre_bytes"]):
                    old = self.pre.popleft()
                    self.pre_bytes -= len(old["raw"])
                    self.issue("prebuffer_size_eviction", old["topic"], at)
                if len(r["raw"]) <= self.limits["pre_bytes"]:
                    self.pre.append(r)
                    self.pre_bytes += len(r["raw"])
                else:
                    self.issue("prebuffer_record_too_large", r["topic"], at)
                self.high_water["pre_bytes"] = max(self.high_water["pre_bytes"], self.pre_bytes)

    def drain_sampled(self):
        """Bounded real context; no fabricated endpoint or shifted trigger."""
        while self.queue:
            r = self.queue.popleft()
            at = r["receive_ns"]
            self.counts[r["topic"]]["accepted"] += 1
            horizon = self.limits["pre_ns"] + max(2 * s["period_ns"] for s in TOPICS.values())
            while self.pre and self.pre[0]["receive_ns"] < at - horizon:
                self.pre_bytes -= len(self.pre.popleft()["raw"])
            if self.trigger is None and r.get("trigger") is True:
                self.trigger = {"topic": r["topic"], "receive_ns": at,
                                "rule": "diagnostic_level_gte_2/dev1",
                                "source_ns": r.get("source_ns")}
                left = at - self.limits["pre_ns"]
                nearest = {}
                for old in self.pre:
                    if old["receive_ns"] < left:
                        nearest[old["topic"]] = old
                exact_left = {old["topic"] for old in self.pre if old["receive_ns"] == left}
                selected = [old for old in self.pre if old["receive_ns"] >= left or
                            (old["topic"] not in exact_left and nearest.get(old["topic"]) is old and
                             left - old["receive_ns"] <= 2 * TOPICS[old["topic"]]["period_ns"])]
                for old in selected:
                    self.save_event(dict(old, coverage_role=(
                        "before" if old["receive_ns"] < left else "in_window")))
            if self.trigger is not None:
                right = self.trigger["receive_ns"] + self.limits["post_ns"]
                if at <= right:
                    self.save_event(dict(r, coverage_role="in_window"))
                elif (at <= right + 2 * TOPICS[r["topic"]]["period_ns"] and
                      not any(old["topic"] == r["topic"] and old["receive_ns"] >= right
                              for old in self.event)):
                    self.save_event(dict(r, coverage_role="after"))
            else:
                while self.pre and (len(self.pre) >= self.limits["pre_records"] or
                                    self.pre_bytes + len(r["raw"]) > self.limits["pre_bytes"]):
                    old = self.pre.popleft()
                    self.pre_bytes -= len(old["raw"])
                    self.issue("prebuffer_size_eviction", old["topic"], at)
                if len(r["raw"]) <= self.limits["pre_bytes"]:
                    self.pre.append(r)
                    self.pre_bytes += len(r["raw"])
                else:
                    self.issue("prebuffer_record_too_large", r["topic"], at)
                self.high_water["pre_bytes"] = max(self.high_water["pre_bytes"], self.pre_bytes)

    def sampled_window(self, requested):
        streams = {}
        for topic, spec in TOPICS.items():
            rows = [(f"observations/{i:06d}.bin", r) for i, r in enumerate(self.event)
                    if r["topic"] == topic]
            inside = [(p, r) for p, r in rows if r["coverage_role"] == "in_window"]
            left, right = requested if requested is not None else (None, None)
            before = [(p, r) for p, r in rows if left is not None and r["receive_ns"] <= left]
            after = [(p, r) for p, r in rows if right is not None and r["receive_ns"] >= right]
            a, b = (before[-1] if before else None), (after[0] if after else None)
            times = sorted(set(r["receive_ns"] for _, r in rows))
            spans = [y - x for x, y in zip(times, times[1:])]
            gaps = []
            if not inside:
                gaps.append("stream_unavailable")
            if a is None:
                gaps.append("insufficient_prehistory")
            if b is None:
                gaps.append("incomplete_posthistory")
            maximum = 2 * spec["period_ns"]
            if any(span > maximum for span in spans):
                gaps.append("excessive_sample_span")
            if a and left - a[1]["receive_ns"] > maximum:
                gaps.append("left_support_too_far")
            if b and b[1]["receive_ns"] - right > maximum:
                gaps.append("right_support_too_far")
            streams[topic] = {
                "native_period_ns": spec["period_ns"], "maximum_span_ns": maximum,
                "in_window_count": len(inside),
                "actual_bounds_ns": [inside[0][1]["receive_ns"], inside[-1][1]["receive_ns"]] if inside else None,
                "in_window_start_offset_ns": inside[0][1]["receive_ns"] - left if inside else None,
                "in_window_end_offset_ns": right - inside[-1][1]["receive_ns"] if inside else None,
                "retained_bounds_ns": [times[0], times[-1]] if times else None,
                "left_support": a[0] if a else None, "right_support": b[0] if b else None,
                "left_offset_ns": left - a[1]["receive_ns"] if a else None,
                "right_offset_ns": b[1]["receive_ns"] - right if b else None,
                "observed_max_span_ns": max(spans) if spans else None, "gaps": gaps}
        return streams

    def summaries(self):
        self.drain()
        requested = None if self.trigger is None else [
            self.trigger["receive_ns"] - self.limits["pre_ns"],
            self.trigger["receive_ns"] + self.limits["post_ns"]]
        streams = {}
        for topic, spec in TOPICS.items():
            times = sorted(set(r["receive_ns"] for r in self.event if r["topic"] == topic))
            intervals = [b - a for a, b in zip(times, times[1:])]
            gaps = []
            if requested:
                if not times:
                    gaps.append({"start_ns": requested[0], "end_ns": requested[1],
                                 "kind": "stream_unavailable"})
                else:
                    if times[0] > requested[0]:
                        gaps.append({"start_ns": requested[0], "end_ns": times[0], "kind": "prefix"})
                    gaps += [{"start_ns": a, "end_ns": b, "kind": "interval_exceeds_2_native_periods"}
                             for a, b in zip(times, times[1:]) if b - a > 2 * spec["period_ns"]]
                    if times[-1] < requested[1]:
                        gaps.append({"start_ns": times[-1], "end_ns": requested[1], "kind": "suffix"})
            streams[topic] = {"actual_bounds_ns": [times[0], times[-1]] if times else None,
                             "native_period_ns": spec["period_ns"],
                             "requested_period_ns": spec["period_ns"],
                             "observed_median_interval_ns": int(statistics.median(intervals)) if intervals else None,
                             "observed_max_interval_ns": max(intervals) if intervals else None,
                             "unique_receive_times": len(times), "gaps": gaps}
        window = {"record_id": "demo-engagement-001/event-001", "engagement_id": "demo-engagement-001",
                  "trigger": self.trigger, "requested_bounds_ns": requested,
                  "actual_bounds_ns": [min(r["receive_ns"] for r in self.event),
                                       max(r["receive_ns"] for r in self.event)] if self.event else None,
                  "clock": "collector-monotonic-relative", "streams": streams}
        summary = {"record_id": "demo-engagement-001", "task_state": "completed_simulation",
                   "site": "simulated-inspection-bay-A", "actor": "simulated-mobile-inspector",
                   "task": "inspection/service", "intended_window_ns": [0, 12 * NS],
                   "actual_input_bounds_ns": [self.start, self.end],
                   "event_record_id": window["record_id"], "interpretation": "simulated",
                   "counts": self.counts, "quality_reason_counts": dict(self.reasons),
                   "quality_entries": self.quality,
                   "quality_entries_omitted": max(0, sum(self.reasons.values()) - len(self.quality)),
                   "qos_compatibility": "not-evaluated/test-input",
                   "physical_truth": "unestablished", "limits": self.limits,
                   "high_water": self.high_water}
        if self.policy == POLICY_ID:
            window["coverage_policy"] = POLICY_ID
            window["streams"] = self.sampled_window(requested)
            inside = [r["receive_ns"] for r in self.event if r["coverage_role"] == "in_window"]
            window["retained_bounds_ns"] = window["actual_bounds_ns"]
            window["actual_bounds_ns"] = [min(inside), max(inside)] if inside else None
            summary["coverage_state"] = {
                "ready_at_trigger": self.trigger is not None and all(
                    s["left_support"] is not None for s in window["streams"].values()),
                "right_brackets_present": self.trigger is not None and all(
                    s["right_support"] is not None for s in window["streams"].values())}
            adverse = set(self.reasons) - {"timing_relationship_unestablished",
                                          "source_clock_rollback", "source_sequence_discontinuity"}
            summary["coverage_state"]["capture_complete"] = (
                self.trigger is not None and any(r.get("trigger") is True for r in self.event) and
                not adverse and not any(s["gaps"] for s in window["streams"].values()))
            summary["task_state"] = "completed_simulation" if summary["coverage_state"][
                "capture_complete"] else "incomplete_sampled_capture"
        return window, summary


def manifest_for(objects, signer, versions=None):
    return {"schema_version": VERSION, "profile_version": PROFILE,
            "record_id": "demo-engagement-001", "issuer": "urn:pask:local:test-issuer",
            "signing_key_id": signer, "signature_algorithm": "Ed25519",
            "software_test_material": True, "core_integration": "unestablished",
            "versions": versions or {"input": "test-json/1", "ros_runtime": "not-executed"},
            "objects": [{"path": path, "size_bytes": len(data), "sha256": digest(data)}
                        for path, data in sorted(objects.items())],
            "digest_exclusions": ["manifest.json", "manifest.sig", "recipient-findings.json",
                                  "transport archive metadata", "public trust inputs"]}


def export_capture(capture, output, private_key, versions=None, extra_objects=None):
    window, summary = capture.summaries()
    ros_input = bool(versions and versions.get("input") == "ROS2-CDR")
    if ros_input:
        summary["qos_compatibility"] = "ROS callback issues reported; end-to-end completeness unestablished"
        summary["intended_window_ns"] = [0, 17 * NS]
    objects = {
        "event-window.json": encoded(window),
        "engagement-summary.json": encoded(summary),
        "configuration.json": encoded({"id": "demo-config/1", "source": "local fixture configuration",
                                      "collection_receive_ns": 0, "active_configuration_proven": False,
                                      "claimed": {"movement_period_ns": NS // 10,
                                                  "inspection_only": True, "robot_actuation_authorized": False}}),
        "schemas.json": encoded({"version": "test-input-schema/1",
                                 "topics": TOPICS,
                                 "test_encoding": None if ros_input else "ASCII JSON; NOT ROS CDR",
                                 "test_fields": None if ros_input else ["position_mm", "mode", "level", "text"],
                                 "test_units_override": None if ros_input else {"position_mm": "mm"},
                                 "ROS_type_references_are_not_test_wire_schema": not ros_input,
                                 "actual_ROS_schema_objects": "ros-schema/" if ros_input else None,
                                 "transformation": "raw CDR retained; index adds metadata" if ros_input else
                                     "test raw JSON bytes retained exactly; observations index adds metadata",
                                 "uncertainty": None}),
    }
    observations = []
    for i, r in enumerate(capture.event):
        path = f"observations/{i:06d}.bin"
        objects[path] = r["raw"]
        observations.append({k: v for k, v in r.items() if k != "raw"} | {"path": path})
    objects["observations.json"] = encoded(observations)
    if extra_objects:
        if objects.keys() & extra_objects.keys():
            raise ValueError("object collision")
        objects.update(extra_objects)
    for name in objects:
        if PurePosixPath(name).is_absolute() or any(p in ("", ".", "..") for p in name.split("/")):
            raise ValueError("unsafe export object path")
    public = public_bytes(private_key)
    declaration = manifest_for(objects, digest(public), versions)
    if capture.policy == POLICY_ID:
        declaration["schema_version"] = VERSION2
    manifest = encoded(declaration)
    signature = private_key.sign(manifest)
    objects["manifest.json"] = manifest
    objects["manifest.sig"] = signature
    if sum(map(len, objects.values())) > capture.limits["export_bytes"]:
        raise ValueError("export byte ceiling; no output committed")
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    try:
        for name, data in sorted(objects.items()):
            path = root / name
            if path.is_absolute() and not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("export path outside root")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
    except OSError:
        # Preserve partial artifacts for diagnosis, never report them as complete.
        raise
    return {"manifest_sha256": digest(manifest), "export_bytes": sum(map(len, objects.values())),
            "objects": len(objects), "event_observations": len(observations)}


def load_fixture(path):
    with Path(path).open("rb") as stream:
        while line := stream.readline(16385):
            if len(line) > 16384:
                raise ValueError("fixture line limit")
            r = json.loads(line)
            r["raw"] = base64.b64decode(r.pop("raw_b64"), validate=True)
            yield r


def capture_fixture(path, limits=None):
    capture = Capture(limits)
    prior = None
    for r in load_fixture(path):
        if prior is not None and r["receive_ns"] != prior:
            capture.drain()
        capture.submit(r)
        prior = r["receive_ns"]
    capture.drain()
    return capture


def main():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("fixture")
    p.add_argument("output")
    p.add_argument("--public-key-output", required=True)
    args = p.parse_args()
    started = time.perf_counter_ns()
    # Random ephemeral key in memory only: no private-key artifact.
    key = Ed25519PrivateKey.generate()
    public = public_bytes(key)
    # Enrollment data alone confers no authority. Operator policy is a separate step.
    Path(args.public_key_output).write_text(public.hex() + "\n")
    result = export_capture(capture_fixture(args.fixture), args.output, key)
    result["elapsed_ns"] = time.perf_counter_ns() - started
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
