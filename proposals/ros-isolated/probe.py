#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small isolated test harness; recipient source remains unchanged.

Executed ONLY inside the proposed network-none container, not in local checks.
Clean means no deliberately injected gap/rollback, NOT a coverage-pass claim.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import time
import traceback


def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def process_metrics():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return {"peak_rss_kib": r.ru_maxrss, "user_cpu_seconds": r.ru_utime,
            "system_cpu_seconds": r.ru_stime}


def graph(node):
    from pask_ros2_local_demo import node as frozen
    return frozen.checked_graph(node, "/out/graph-qos-snapshots.json", "collect/probe")


def publisher_class(frozen, case):
    """The actual clean/missing-stream publisher; also used by offline smoke."""
    class ContinuousPublisher(frozen.Publisher):
        def emit(self):
            t = self.tick
            stamp = t * frozen.NS // 10
            msg = frozen.PoseStamped()
            msg.header.stamp.sec, msg.header.stamp.nanosec = divmod(stamp, frozen.NS)
            msg.header.frame_id = "map"
            msg.pose.position.x, msg.pose.orientation.w = t * 0.01, 1.0
            frozen.publish_observation(self, "/demo/movement", msg)
            if t % 5 == 0:
                if case != "missing-stream":
                    mode = frozen.String()
                    mode.data = "assisted" if t >= 60 else "autonomous"
                    frozen.publish_observation(self, "/demo/control_mode", mode)
                diag = frozen.DiagnosticArray()
                diag.header.stamp.sec, diag.header.stamp.nanosec = divmod(stamp, frozen.NS)
                status = frozen.DiagnosticStatus()
                status.level = b"\x02" if t == 60 else b"\x00"
                status.name, status.message = "simulated-inspection", "test stimulus"
                status.hardware_id = "SIMULATED-NOT-TEE"
                diag.status = [status]
                frozen.publish_observation(self, "/demo/diagnostics", diag)
            self.tick += 1
            frozen.marker("published_tick", tick=t, case=case, source_stamp_ns=stamp)
            if self.tick > 120:
                self.done = True
                self.timer.cancel()
    return ContinuousPublisher


def role(args):
    import rclpy
    from pask_ros2_local_demo import node as frozen
    versions = frozen.environment()  # selected exact versions, no substitution

    class ObservedCollector(frozen.Collector):
        def receive(self, topic, cls, data):
            # These hashes are of the original callback bytes, before parsing.
            count = getattr(self, "_raw_logs", 0)
            if count < 256:
                print(json.dumps({"raw_callback": topic, "bytes": len(data),
                                  "sha256": sha(bytes(data)), "monotonic_ns": time.monotonic_ns(),
                                  "clock": "CLOCK_MONOTONIC"}), flush=True)
            elif count == 256:
                frozen.marker("raw_callback_logging_capped", limit=256,
                              note="capture unchanged; later callback log entries suppressed")
            self._raw_logs = count + 1
            super().receive(topic, cls, data)

    rclpy.init()
    node = None
    snapshots = []
    began = time.monotonic()
    deadline = began + (17 if args.role == "collect" else 15)
    next_graph = began + 2
    try:
        node = (ObservedCollector() if args.role == "collect" else
                frozen.Publisher() if args.case == "scenario" else publisher_class(frozen, args.case)())
        while time.monotonic() < deadline and not getattr(node, "done", False):
            rclpy.spin_once(node, timeout_sec=0.05)
            if args.role == "collect" and time.monotonic() >= next_graph:
                snapshot = graph(node)
                snapshots.append(snapshot)
                next_graph += 1
        if args.role == "collect":
            write("/out/raw-callback-counts.json", node.local_sequences)
            write("/out/queue-observation.json",
                  {"high_water": node.capture.high_water,
                   "limits": node.capture.limits,
                   "quality_reason_counts": dict(node.capture.reasons),
                   "note": "measured application queue, NOT DDS internal queue occupancy"})
            expected_topics = set(frozen.TYPES)
            if not any(all(snapshot["endpoints"].get(t, {}).get("publishers")
                           and snapshot["endpoints"].get(t, {}).get("subscriptions")
                           for t in expected_topics) for snapshot in snapshots):
                raise RuntimeError("no graph snapshot establishes publisher/subscriber endpoints")
            node.export("/out/final-bundle", versions)
        else:
            print(json.dumps({"publisher_finished": node.done, "ticks": node.tick,
                              "case": args.case,
                              "withheld_topic": "/demo/control_mode"
                              if args.case == "missing-stream" else None}), flush=True)
            if not node.done:
                raise RuntimeError("publisher deadline before all fixture ticks")
    except BaseException as exc:
        def partial_state():
            if args.role != "collect" or node is None:
                return
            path = Path("/out/partial-debug")
            path.mkdir(exist_ok=True)
            write(path / "collector-state.json",
                  {"status": "partial failed capture; NOT a final export",
                   "monotonic_ns": time.monotonic_ns(), "clock": "CLOCK_MONOTONIC",
                   "callback_counts": node.local_sequences,
                   "callback_log_entries_suppressed": max(0, getattr(node, "_raw_logs", 0) - 256),
                   "queue_high_water": node.capture.high_water, "queue_limits": node.capture.limits,
                   "quality_reason_counts": {str(k)[:128]: v for k, v in
                                             list(node.capture.reasons.items())[:32]},
                   "quality_counts_truncated": len(node.capture.reasons) > 32,
                   "primary_error": repr(exc)[:256],
                   "raw_CDR_exported": False})
        frozen.cleanup_preserving_error(exc, [
            ("failure_marker", lambda: frozen.marker("process_exception", role=args.role,
                                                     error=repr(exc))),
            ("partial_collector_state", partial_state)])
        raise
    finally:
        frozen.cleanup_preserving_error(sys.exc_info()[1], [
            ("resources", lambda: write("/out/" + args.role + "-resources.json",
                                        process_metrics() | {"elapsed_seconds": time.monotonic() - began})),
            ("destroy_node", lambda: node.destroy_node() if node is not None else None),
            ("shutdown", rclpy.shutdown)])


def capture(args):
    from pask_ros2_local_demo import node as frozen
    commands = {}
    children = []
    try:
        for name in ("collect", "publish"):
            command = [sys.executable, "-u", __file__, name, "--case", args.case]
            commands[name] = {"argv": command}
            log = open("/out/" + name + ".log", "w")
            try:
                p = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            except BaseException as exc:
                commands[name]["start_error"] = repr(exc)[:256]
                frozen.cleanup_preserving_error(exc, [(name + "_log_close", log.close)])
                raise
            children.append((name, p, log))
            frozen.marker("child_started", role=name, child_pid=p.pid)
            if name == "collect":
                time.sleep(1)
        for name, p, _ in children:
            commands[name]["exit_code"] = p.wait(timeout=23)
            commands[name]["exit_observed_monotonic_ns"] = time.monotonic_ns()
            commands[name]["time_note"] = "parent wait observation, not exact fault time"
            frozen.marker("child_exit_observed", role=name, exit_code=p.returncode)
        if any(v["exit_code"] != 0 for v in commands.values()):
            raise RuntimeError("publisher/collector integration failure; see original logs")
    finally:
        primary = sys.exc_info()[1]
        actions = []
        for name, p, log in children:
            def stop(name=name, p=p):
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=3)
                commands[name]["exit_code"] = p.returncode
                commands[name].setdefault("exit_observed_monotonic_ns", time.monotonic_ns())
                commands[name]["time_note"] = "parent observation, not exact fault time"
            actions.extend([(name + "_stop", stop), (name + "_log_close", log.close)])
        actions.append(("process_results", lambda: write("/out/process-commands.json", commands)))
        frozen.cleanup_preserving_error(primary, actions)


def smoke(args):
    """PENDING matching ROS runtime: real generated CDR, actual emit/receive code.

    A sink replaces transport only for focused trigger checks; the later capture
    must still prove publisher/subscriber callbacks, bags and recipient results.
    """
    import importlib
    import inspect
    from types import SimpleNamespace
    import xml.etree.ElementTree as ET
    import rclpy
    from rclpy.serialization import serialize_message, deserialize_message
    from ament_index_python.packages import get_package_share_directory
    from pask_ros2_local_demo import node as frozen
    versions = frozen.environment()
    out = Path("/out")
    installed = out / "installed-contract"
    installed.mkdir()
    inventory = []
    total = 0

    def preserve(label, source):
        nonlocal total
        source = Path(source)
        size = source.stat().st_size
        if size > 160000 or total + size > 512000:
            raise RuntimeError("installed source evidence budget exceeded")
        raw = source.read_bytes()
        (installed / label).write_bytes(raw)
        total += size
        inventory.append({"file": label, "installed_path": str(source),
                          "bytes": size, "sha256": sha(raw)})
        write(out / "installed-contract-inventory.json", inventory)

    for module, label in (
            ("rclpy.node", "rclpy-node.py"),
            ("rclpy.parameter", "rclpy-parameter.py"),
            ("rclpy.action.graph", "rclpy-action-graph.py"),
            ("rclpy.type_description_service", "rclpy-type-description-service.py"),
            ("diagnostic_msgs.msg._diagnostic_status", "diagnostic-status.py"),
            ("diagnostic_msgs.msg._diagnostic_array", "diagnostic-array.py")):
        preserve(label, inspect.getsourcefile(importlib.import_module(module)))
    for package, expected in (("diagnostic_msgs", "5.3.8"), ("rosidl_generator_py", "0.22.2"),
                              ("rclpy", "7.1.12")):
        share = Path(get_package_share_directory(package))
        xml = share / "package.xml"
        preserve(package + "-package.xml", xml)
        if ET.parse(xml).findtext("version") != expected:
            raise RuntimeError("installed message/generator/rclpy contract version mismatch")
    share = Path(get_package_share_directory("diagnostic_msgs"))
    for name in ("DiagnosticStatus.msg", "DiagnosticStatus.idl", "DiagnosticArray.msg",
                 "DiagnosticArray.idl"):
        preserve(name, share / "msg" / name)
    preserve("msg-support.c.em", Path(get_package_share_directory("rosidl_generator_py")) /
             "resource" / "_msg_support.c.em")
    support = importlib.import_module("diagnostic_msgs.diagnostic_msgs_s__rosidl_typesupport_c")
    digest = hashlib.sha256()
    with open(support.__file__, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)
    write(out / "generated-type-support.json",
          {"installed_binary": support.__file__, "sha256": digest.hexdigest(),
           "DiagnosticStatus_fields": frozen.DiagnosticStatus.get_fields_and_field_types(),
           "default_level_type": type(frozen.DiagnosticStatus().level).__name__,
           "default_level_repr": repr(frozen.DiagnosticStatus().level),
           "note": "installed Python source, schema, generator template and extension hash; not generated C source"})
    checks = []

    class Sink:
        limits = {"record_bytes": 65536}

        def __init__(self):
            self.records, self.errors = [], []

        def submit(self, record):
            self.records.append(record)

        def issue(self, *args, **kwargs):
            self.errors.append((args, kwargs))

    sink = Sink()
    collector = SimpleNamespace(capture=sink, started=time.monotonic_ns(),
                                local_sequences={t: 0 for t in frozen.TYPES})

    def roundtrip(topic, message, trigger):
        frozen.marker("smoke_serializing", topic=topic)
        raw = serialize_message(message)
        decoded = deserialize_message(raw, type(message))
        assert serialize_message(decoded) == raw
        count = len(sink.records)
        frozen.Collector.receive(collector, topic, type(message), raw)
        assert not sink.errors and len(sink.records) == count + 1
        assert sink.records[-1]["raw"] == raw and sink.records[-1]["trigger"] is trigger
        checks.append({"topic": topic, "bytes": len(raw), "sha256": sha(raw),
                       "actual_receive_trigger": trigger})
        write(out / "smoke-progress.json", checks)

    roundtrip("/demo/movement", frozen.PoseStamped(), False)
    mode = frozen.String()
    mode.data = "smoke"
    roundtrip("/demo/control_mode", mode, False)
    for levels in ([], [0], [1], [2], [3], [0, 1], [0, 2], [2, 0]):
        message = frozen.DiagnosticArray()
        for level in levels:
            status = frozen.DiagnosticStatus()
            status.level = bytes((level,))
            message.status.append(status)
        roundtrip("/demo/diagnostics", message, any(v >= 2 for v in levels))
    for invalid in (0, True, bytearray(b"\x02"), "", b"", b"\x00\x02", None):
        try:
            frozen.diagnostic_level_number(invalid)
        except TypeError:
            pass
        else:
            raise AssertionError("malformed diagnostic accepted")
    # Invoke BOTH real emit implementations at normal and trigger ticks. Sinks
    # run real serialize/deserialize/Collector.receive without a DDS assertion.
    for case in ("scenario", "clean", "missing-stream"):
        cls = frozen.Publisher if case == "scenario" else publisher_class(frozen, case)
        for tick in (0, 60):
            published = []

            class Output:
                def __init__(self, topic):
                    self.topic = topic

                def publish(self, message):
                    published.append(self.topic)
                    roundtrip(self.topic, message,
                              self.topic == "/demo/diagnostics" and tick == 60)

            instance = SimpleNamespace(tick=tick, done=False,
                                       outputs={t: Output(t) for t in frozen.TYPES})
            cls.emit(instance)
            assert set(published) == set(frozen.TYPES) - (
                {"/demo/control_mode"} if case == "missing-stream" else set())
    # Exercise supported overrides in the actual controlled constructors.
    # No spin/publish and no services/actions invoked; graph policy remains strict.
    nodes = []
    rclpy.init()
    try:
        nodes.append(frozen.Publisher())
        nodes.append(frozen.Collector())
        time.sleep(1)
        for node in nodes:
            assert node.get_parameter("start_type_description_service").value is False
            frozen.checked_graph(node, out / "smoke-graph.json", "smoke/" + node.get_name())
    finally:
        frozen.cleanup_preserving_error(sys.exc_info()[1],
                                         [("destroy", n.destroy_node) for n in nodes] +
                                         [("shutdown", rclpy.shutdown)])
    write(out / "smoke-result.json",
          {"status": "passed", "versions": versions, "checks": checks,
           "scope": "real installed CDR roundtrips, actual emit/receive with test sinks; "
                    "controlled constructors and strict graph; full DDS capture still required"})


def reopen(args):
    # Separate process/container; no import of producer or its claimed result.
    import rosbag2_py
    from rclpy.serialization import deserialize_message
    from rosidl_runtime_py.utilities import get_message
    from ament_index_python.packages import get_package_share_directory
    root = Path("/bundle")
    observations = json.loads((root / "observations.json").read_text())
    expected = Counter()
    source_clock_checks = []
    for row in observations:
        raw = (root / row["path"]).read_bytes()
        if row["wire_encoding"] != "ROS2-CDR":
            raise RuntimeError("not CDR")
        msg = deserialize_message(raw, get_message(row["type"]))
        stamp = getattr(getattr(msg, "header", None), "stamp", None)
        source = None if stamp is None else stamp.sec * 1_000_000_000 + stamp.nanosec
        if source != row["source_ns"]:
            raise RuntimeError("CDR source timestamp differs from exported index")
        source_clock_checks.append({"path": row["path"], "source_ns": source,
                                    "collector_receive_ns": row["receive_ns"]})
        expected[(row["topic"], row["receive_ns"], sha(raw))] += 1
    reader = rosbag2_py.SequentialReader()
    reader.open(rosbag2_py.StorageOptions(uri=str(root / "rosbag2"), storage_id="sqlite3"),
                rosbag2_py.ConverterOptions("", ""))
    types = {t.name: (t.type, t.serialization_format)
             for t in reader.get_all_topics_and_types()}
    actual = Counter()
    while reader.has_next():
        topic, raw, timestamp = reader.read_next()
        actual[(topic, timestamp, sha(bytes(raw)))] += 1
    if not expected or expected != actual:
        raise RuntimeError("bag reopen differs from exact retained CDR/topic/receive-time multiset")
    if any(types.get(r["topic"]) != (r["type"], "cdr") for r in observations):
        raise RuntimeError("bag topic schema/encoding mismatch")
    schemas = []
    for p in sorted((root / "ros-schema").rglob("*")):
        if not p.is_file():
            continue
        relative = p.relative_to(root / "ros-schema")
        package, name = relative.parts
        installed = Path(get_package_share_directory(package))
        installed /= name if name == "package.xml" else "msg/" + name
        if installed.read_bytes() != p.read_bytes():
            raise RuntimeError("retained schema differs from installed definition")
        schemas.append({"path": str(p.relative_to(root)), "sha256": sha(p.read_bytes())})
    if not schemas or not any(s["path"].endswith(".msg") for s in schemas):
        raise RuntimeError("no actual message definitions retained")
    write("/out/bag-reopen.json",
          {"status": "passed", "observations": sum(expected.values()),
           "comparison": "exact CDR SHA256/topic/collector timestamp multiset",
           "types": types, "actual_schema_inventory": schemas,
           "source_timestamp_checks": source_clock_checks,
           "source_to_collector_clock_relationship": "unestablished",
           "process_resources": process_metrics()})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["capture", "collect", "publish", "reopen", "smoke"])
    parser.add_argument("--case", choices=["clean", "scenario", "missing-stream"], default="clean")
    args = parser.parse_args()
    try:
        ({"capture": capture, "reopen": reopen, "smoke": smoke}.get(args.role, role))(args)
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
