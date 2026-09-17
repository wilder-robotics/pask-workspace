#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small test harness; frozen producer/recipient sources are never rewritten.

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
    from rclpy.action.graph import get_action_names_and_types
    topics = node.get_topic_names_and_types()
    endpoints = {}
    for name, _ in topics:
        endpoints[name] = {}
        for kind, getter in (("publishers", node.get_publishers_info_by_topic),
                             ("subscriptions", node.get_subscriptions_info_by_topic)):
            endpoints[name][kind] = [
                {"node_name": x.node_name, "node_namespace": x.node_namespace,
                 "topic_type": x.topic_type,
                 "endpoint_gid": list(x.endpoint_gid),
                 "qos": {"reliability": str(x.qos_profile.reliability),
                         "durability": str(x.qos_profile.durability),
                         "history": str(x.qos_profile.history),
                         "depth": x.qos_profile.depth}}
                for x in getter(name)]
    result = {"topics": topics, "services": node.get_service_names_and_types(),
              "actions": get_action_names_and_types(node), "endpoints": endpoints,
              "monotonic_ns": time.monotonic_ns()}
    allowed = {"/demo/movement", "/demo/control_mode", "/demo/diagnostics",
               "/parameter_events"}
    if set(n for n, _ in topics) - allowed or result["services"] or result["actions"]:
        raise RuntimeError("unexpected graph endpoints; no runtime continuation")
    return result


def role(args):
    import rclpy
    from pask_ros2_local_demo import node as frozen
    versions = frozen.environment()  # selected exact versions, no substitution

    class ObservedCollector(frozen.Collector):
        def receive(self, topic, cls, data):
            # These hashes are of the original callback bytes, before parsing.
            print(json.dumps({"raw_callback": topic, "bytes": len(data),
                              "sha256": sha(bytes(data))}), flush=True)
            super().receive(topic, cls, data)

    class ContinuousPublisher(frozen.Publisher):
        def emit(self):
            # Test stimulus only: unlike frozen scenario, no rollback or gap.
            t = self.tick
            stamp = t * frozen.NS // 10
            msg = frozen.PoseStamped()
            msg.header.stamp.sec, msg.header.stamp.nanosec = divmod(stamp, frozen.NS)
            msg.header.frame_id = "map"
            msg.pose.position.x, msg.pose.orientation.w = t * 0.01, 1.0
            self.outputs["/demo/movement"].publish(msg)
            if t % 5 == 0:
                if args.case != "missing-stream":
                    mode = frozen.String()
                    mode.data = "assisted" if t >= 60 else "autonomous"
                    self.outputs["/demo/control_mode"].publish(mode)
                diag = frozen.DiagnosticArray()
                diag.header.stamp.sec, diag.header.stamp.nanosec = divmod(stamp, frozen.NS)
                status = frozen.DiagnosticStatus()
                status.level = 2 if t == 60 else 0
                status.name, status.message = "simulated-inspection", "test stimulus"
                status.hardware_id = "SIMULATED-NOT-TEE"
                diag.status = [status]
                self.outputs["/demo/diagnostics"].publish(diag)
            self.tick += 1
            print(json.dumps({"published_tick": t, "case": args.case,
                              "source_stamp_ns": stamp}), flush=True)
            if self.tick > 120:
                self.done = True
                self.timer.cancel()

    rclpy.init()
    node = (ObservedCollector() if args.role == "collect" else
            frozen.Publisher() if args.case == "scenario" else ContinuousPublisher())
    snapshots = []
    began = time.monotonic()
    deadline = began + (17 if args.role == "collect" else 15)
    next_graph = began + 2
    try:
        while time.monotonic() < deadline and not getattr(node, "done", False):
            rclpy.spin_once(node, timeout_sec=0.05)
            if args.role == "collect" and time.monotonic() >= next_graph:
                snapshot = graph(node)
                snapshots.append(snapshot)
                write("/out/graph-qos-snapshots.json", snapshots)
                next_graph += 1
        if args.role == "collect":
            write("/out/raw-callback-counts.json", node.local_sequences)
            write("/out/queue-observation.json",
                  {"high_water": node.capture.high_water,
                   "limits": node.capture.limits,
                   "quality_reason_counts": dict(node.capture.reasons),
                   "note": "measured application queue, NOT DDS internal queue occupancy"})
            node.export("/out/final-bundle", versions)
            expected_topics = set(frozen.TYPES)
            if not any(all(snapshot["endpoints"].get(t, {}).get("publishers")
                           and snapshot["endpoints"].get(t, {}).get("subscriptions")
                           for t in expected_topics) for snapshot in snapshots):
                raise RuntimeError("no graph snapshot establishes publisher/subscriber endpoints")
        else:
            print(json.dumps({"publisher_finished": node.done, "ticks": node.tick,
                              "case": args.case,
                              "withheld_topic": "/demo/control_mode"
                              if args.case == "missing-stream" else None}), flush=True)
            if not node.done:
                raise RuntimeError("publisher deadline before all fixture ticks")
    finally:
        write("/out/" + args.role + "-resources.json",
              process_metrics() | {"elapsed_seconds": time.monotonic() - began})
        node.destroy_node()
        rclpy.shutdown()


def capture(args):
    commands = {}
    children = []
    try:
        for name in ("collect", "publish"):
            command = [sys.executable, "-u", __file__, name, "--case", args.case]
            commands[name] = {"argv": command}
            log = open("/out/" + name + ".log", "w")
            p = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            children.append((name, p, log))
            if name == "collect":
                time.sleep(1)
        for name, p, _ in children:
            commands[name]["exit_code"] = p.wait(timeout=23)
        if any(v["exit_code"] != 0 for v in commands.values()):
            raise RuntimeError("publisher/collector integration failure; see original logs")
    finally:
        for name, p, log in children:
            if p.poll() is None:
                p.kill()
                p.wait()
            commands[name]["exit_code"] = p.returncode
            log.close()
        write("/out/process-commands.json", commands)


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
    parser.add_argument("role", choices=["capture", "collect", "publish", "reopen"])
    parser.add_argument("--case", choices=["clean", "scenario", "missing-stream"], default="clean")
    args = parser.parse_args()
    try:
        (capture if args.role == "capture" else reopen if args.role == "reopen" else role)(args)
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
