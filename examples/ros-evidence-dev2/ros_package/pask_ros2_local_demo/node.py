#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual rclpy raw-subscription/rosbag2 recipe. NOT executed in the sandbox.

Run only using the isolated container recipe. All publishers are simulated
observation publishers, never robot commands. No services/actions are invoked.
"""
import argparse
from functools import partial
from itertools import islice
import json
import os
from pathlib import Path
import sys
import time
import xml.etree.ElementTree as ET

import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import QoSProfile, ReliabilityPolicy, HistoryPolicy, DurabilityPolicy
from rclpy.event_handler import SubscriptionEventCallbacks
from rclpy.serialization import deserialize_message, serialize_message
from ament_index_python.packages import get_package_share_directory
from geometry_msgs.msg import PoseStamped
from std_msgs.msg import String
from diagnostic_msgs.msg import DiagnosticArray, DiagnosticStatus
import rosbag2_py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bundle import Capture, NS, TOPICS, POLICY_ID, encoded, export_capture, public_bytes

TYPES = {"/demo/movement": PoseStamped, "/demo/control_mode": String,
         "/demo/diagnostics": DiagnosticArray}
QOS = QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=8,
                 reliability=ReliabilityPolicy.BEST_EFFORT,
                 durability=DurabilityPolicy.VOLATILE)
EXPECTED = {"rclpy": "7.1.12", "rmw_fastrtps_cpp": "8.4.4", "rosbag2_py": "0.26.11"}
_marker_count = 0


def marker(event, **details):
    """Bounded flushed diagnostics; CLOCK_MONOTONIC is shared within this container."""
    global _marker_count
    if _marker_count >= 768:
        return
    _marker_count += 1
    print(json.dumps({"marker": event, "pid": os.getpid(),
                      "monotonic_ns": time.monotonic_ns(),
                      "clock": "CLOCK_MONOTONIC, same-host/container processes",
                      **{k: str(v)[:256] for k, v in details.items()}}), flush=True)


def cleanup_preserving_error(primary, actions):
    """Attempt every teardown; a secondary failure must not replace primary."""
    errors = []
    for name, action in actions:
        try:
            action()
        except BaseException as exc:
            errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:256]}")
    if errors:
        try:
            marker("cleanup_errors", errors=errors, primary=repr(primary))
        except BaseException:
            pass
        if primary is None:
            raise RuntimeError("cleanup failed: " + "; ".join(errors))


def diagnostic_level_number(value):
    # ROS byte/IDL octet is exactly one Python byte, not uint8/int.
    if type(value) is not bytes or len(value) != 1:
        raise TypeError("DiagnosticStatus.level requires bytes of length one")
    return value[0]


def diagnostic_trigger(statuses):
    # Validate ALL nested values; do not short-circuit past a malformed status.
    levels = [diagnostic_level_number(status.level) for status in statuses]
    return any(level >= 2 for level in levels)


def publish_observation(node, topic, msg):
    marker("message_prepared", role="publish", topic=topic)
    raw = serialize_message(msg)
    marker("message_serialized", role="publish", topic=topic, bytes=len(raw))
    node.outputs[topic].publish(msg)
    marker("message_published", role="publish", topic=topic)


def graph_observation(node, role):
    """Bound each dimension; retain partial queries, never call them complete."""
    errors, truncated = [], []
    result = {"monotonic_ns": time.monotonic_ns(), "clock": "CLOCK_MONOTONIC",
              "node_role": role, "topics": [], "services": [], "actions": [],
              "nodes": [], "endpoints": {}, "query_errors": errors,
              "truncated": truncated}

    def text(value):
        value = str(value)
        if len(value) > 256:
            truncated.append("string exceeds 256 characters")
        return value[:256]

    def bounded(label, values, limit):
        items = list(islice(iter(values), limit + 1))
        if len(items) > limit:
            truncated.append(label)
        return items[:limit]

    def query(label, call, limit, transform=lambda x: x):
        values = []
        try:
            for v in bounded(label, call(), limit):
                values.append(transform(v))
        except Exception as exc:
            errors.append({"query": label, "error": text(f"{type(exc).__name__}: {exc}"),
                           "availability": "unavailable or partial; not a complete query"})
        return values

    def names(value):
        return [text(value[0]), [text(v) for v in bounded("types", value[1], 8)]]

    def actions(name=None, namespace=None, direction=None):
        from rclpy.action import graph as action_graph
        return (action_graph.get_action_names_and_types(node) if name is None else
                getattr(action_graph, "get_action_" + direction + "_names_and_types_by_node")(
                    node, name, namespace))

    result["topics"] = query("topics", lambda: node.get_topic_names_and_types(), 32, names)
    result["services"] = query("services", lambda: node.get_service_names_and_types(), 32, names)
    result["actions"] = query("actions", actions, 16, names)
    for name, _ in result["topics"]:
        directions = result["endpoints"][name] = {}
        for direction, getter in (("publishers", "get_publishers_info_by_topic"),
                                   ("subscriptions", "get_subscriptions_info_by_topic")):
            def endpoint(x):
                qos = x.qos_profile
                return {"node_name": text(x.node_name), "node_namespace": text(x.node_namespace),
                        "topic_type": text(x.topic_type), "direction": direction,
                        "endpoint_gid": bounded("endpoint_gid", x.endpoint_gid, 32),
                        "qos": {key: text(getattr(qos, key)) for key in
                                ("reliability", "durability", "history", "depth")}}
            directions[direction] = query(f"{name}/{direction}", lambda: getattr(node, getter)(name),
                                          8, endpoint)
    nodes = query("nodes", lambda: node.get_node_names_and_namespaces(), 16,
                  lambda v: [text(v[0]), text(v[1])])
    for name, namespace in nodes:
        result["nodes"].append({
            "name": name, "namespace": namespace,
            "services": query(f"node-services/{namespace}/{name}",
                              lambda: node.get_service_names_and_types_by_node(name, namespace),
                              32, names),
            "action_clients": query(f"node-action-clients/{namespace}/{name}",
                                    lambda: actions(name, namespace, "client"), 16, names),
            "action_servers": query(f"node-action-servers/{namespace}/{name}",
                                    lambda: actions(name, namespace, "server"), 16, names)})
    allowed = sorted(set(TYPES) | {"/parameter_events"})
    result["policy"] = {"allowed_topics": allowed, "allow_services": False,
                        "allow_actions": False,
                        "unexpected_topics": [v for v in result["topics"] if v[0] not in allowed],
                        "unexpected_services": result["services"],
                        "unexpected_actions": result["actions"]}
    # Fail if a node-attributed service/action exists even if discovery snapshots
    # disagree between calls. No guessed endpoint is added to the allowlist.
    result["policy"]["node_services_or_actions"] = [
        v for v in result["nodes"] if v["services"] or v["action_clients"] or v["action_servers"]]
    result["complete"] = not errors and not truncated
    result["policy"]["passed"] = result["complete"] and not any(
        result["policy"][key] for key in
        ("unexpected_topics", "unexpected_services", "unexpected_actions", "node_services_or_actions"))
    serialized = json.dumps(result)
    if len(serialized.encode()) > 131072:
        # An explicitly incomplete prefix, NOT a complete/accepted graph.
        result = {"monotonic_ns": result["monotonic_ns"], "clock": result["clock"],
                  "node_role": role, "complete": False,
                  "policy": {"allowed_topics": allowed, "allow_services": False,
                             "allow_actions": False, "passed": False},
                  "query_errors": errors[:8], "truncated": ["128KiB snapshot budget"],
                  "partial_observation_json_prefix": serialized[:32768]}
    return result


def checked_graph(node, path, role):
    marker("graph_sampling", role=role)
    result = graph_observation(node, role)
    path = Path(path)
    snapshots = json.loads(path.read_text()) if path.exists() else []
    if len(snapshots) >= 20:
        result["complete"] = result["policy"]["passed"] = False
        result["truncated"].append("20 snapshot count budget exceeded")
        path.with_name(path.stem + "-budget-rejection.json").write_text(
            json.dumps(result, sort_keys=True) + "\n")
        raise RuntimeError("graph snapshot count budget exceeded; rejection saved")
    snapshots.append(result)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Persist first, including the decision; never raise away the decisive graph.
    path.write_text(json.dumps(snapshots, sort_keys=True, separators=(",", ":")) + "\n")
    marker("graph_saved", role=role, complete=result["complete"],
           passed=result["policy"]["passed"], path=path)
    if not result["policy"]["passed"]:
        raise RuntimeError("unexpected or incomplete graph; saved policy rejection")
    return result


def environment():
    actual = {name: ET.parse(Path(get_package_share_directory(name)) / "package.xml").findtext("version")
              for name in EXPECTED}
    if actual != EXPECTED:
        raise RuntimeError(f"version mismatch; no silent fallback: {actual} != {EXPECTED}")
    if os.environ.get("RMW_IMPLEMENTATION") != "rmw_fastrtps_cpp":
        raise RuntimeError("explicit rmw_fastrtps_cpp required")
    if os.environ.get("PASK_ISOLATED_DEMO") != "container-network-none":
        raise RuntimeError("use the documented network-none container; domain id is not isolation")
    # Environment flag is an accidental-misuse guard, NOT proof of isolation.
    return actual | {"ROS_DISTRO": os.environ.get("ROS_DISTRO"),
                     "input": "ROS2-CDR", "ros_runtime": "executed-by-this-process",
                     "isolation_assertion": "operator container-network-none"}


class Publisher(Node):
    def __init__(self):
        marker("node_starting", role="publish")
        super().__init__("pask_fixture_publisher", enable_rosout=False, start_parameter_services=False,
                         parameter_overrides=[Parameter("start_type_description_service", value=False)])
        marker("node_started", role="publish")
        self.outputs = {topic: self.create_publisher(cls, topic, QOS) for topic, cls in TYPES.items()}
        self.tick = 0
        self.done = False
        self.timer = self.create_timer(0.1, self.emit)

    def emit(self):
        tick = self.tick
        stamp = tick * NS // 10 - (2 * NS if tick >= 80 else 0)
        msg = PoseStamped()
        msg.header.stamp.sec, msg.header.stamp.nanosec = divmod(stamp, NS)
        msg.header.frame_id = "map"
        msg.pose.position.x = tick * 0.01
        msg.pose.orientation.w = 1.0
        publish_observation(self, "/demo/movement", msg)
        if tick % 5 == 0:
            if not 70 <= tick <= 85:
                mode = String()
                mode.data = "assisted" if tick >= 60 else "autonomous"
                publish_observation(self, "/demo/control_mode", mode)
            diag = DiagnosticArray()
            diag.header.stamp.sec, diag.header.stamp.nanosec = divmod(tick * NS // 10, NS)
            status = DiagnosticStatus()
            status.level = b"\x02" if tick == 60 else b"\x00"
            status.name = "simulated-inspection"
            status.message = "test trigger" if tick == 60 else "nominal"
            status.hardware_id = "SIMULATED-NOT-TEE"
            diag.status = [status]
            publish_observation(self, "/demo/diagnostics", diag)
        self.tick += 1
        if self.tick > 120:
            self.done = True
            self.timer.cancel()


class Collector(Node):
    def __init__(self):
        marker("node_starting", role="collect")
        super().__init__("pask_fixture_collector", enable_rosout=False, start_parameter_services=False,
                         parameter_overrides=[Parameter("start_type_description_service", value=False)])
        marker("node_started", role="collect")
        self.capture = Capture(policy=POLICY_ID)
        self.started = time.monotonic_ns()
        self.local_sequences = {t: 0 for t in TYPES}
        self.subscriptions_ = [
            self.create_subscription(
                cls, topic, partial(self.receive, topic, cls), QOS, raw=True,
                event_callbacks=SubscriptionEventCallbacks(
                    incompatible_qos=partial(self.qos_error, topic)))
            for topic, cls in TYPES.items()]
        self.create_timer(0.02, self.capture.drain)

    def qos_error(self, topic, event):
        self.capture.issue("qos_incompatible", topic, time.monotonic_ns() - self.started,
                           total_count=event.total_count)

    def receive(self, topic, cls, data):
        now = time.monotonic_ns() - self.started
        if len(data) > self.capture.limits["record_bytes"]:
            self.capture.issue("oversize_record", topic, now)
            return
        try:
            msg = deserialize_message(data, cls)
            stamp = getattr(getattr(msg, "header", None), "stamp", None)
            source = None if stamp is None else stamp.sec * NS + stamp.nanosec
            self.local_sequences[topic] += 1
            r = {"topic": topic, "raw": bytes(data), "type": TOPICS[topic]["type"],
                 "wire_encoding": "ROS2-CDR", "source_ns": source,
                 "source_sequence": None, "sequence_origin": "not-supplied-by-selected-ROS-types",
                 "collector_sequence": self.local_sequences[topic],
                 "source_clock": None if stamp is None else "fixture-stamped-simulated/source",
                 "receive_ns": now, "receive_clock": "collector-monotonic-relative",
                 "frame": getattr(getattr(msg, "header", None), "frame_id", None),
                 "units": "m" if topic == "/demo/movement" else None,
                 "interpretation": "simulated",
                 "trigger": topic == "/demo/diagnostics" and diagnostic_trigger(msg.status)}
            self.capture.submit(r)
        except (ValueError, TypeError, RuntimeError) as exc:
            self.capture.issue("decode_or_ingress_error", topic, now, detail=str(exc)[:256])

    def export(self, output, versions):
        marker("export_starting", role="collect")
        graph = checked_graph(self, Path(output).parent / "export-graph-snapshots.json",
                              "collect/export")
        self.capture.drain()
        # Writer is reused for storage, not a newly implemented bag format.
        bag = Path("/tmp/event-bag")
        writer = rosbag2_py.SequentialWriter()
        writer.open(rosbag2_py.StorageOptions(uri=str(bag), storage_id="sqlite3",
                                             max_cache_size=0),
                    rosbag2_py.ConverterOptions("", ""))
        for topic in TYPES:
            writer.create_topic(rosbag2_py.TopicMetadata(
                id=0, name=topic, type=TOPICS[topic]["type"], serialization_format="cdr"))
        for r in self.capture.event:
            writer.write(r["topic"], r["raw"], r["receive_ns"])
        del writer  # close and finalize metadata before hashing files
        extras = {}
        for path in bag.iterdir():
            if path.is_file():
                extras["rosbag2/" + path.name] = path.read_bytes()
        # Preserve actual installed schema definitions, including nested dependencies.
        for package in ("geometry_msgs", "std_msgs", "diagnostic_msgs", "builtin_interfaces"):
            share = Path(get_package_share_directory(package))
            extras[f"ros-schema/{package}/package.xml"] = (share / "package.xml").read_bytes()
            for path in sorted((share / "msg").iterdir()):
                if path.suffix in (".msg", ".idl"):
                    extras[f"ros-schema/{package}/{path.name}"] = path.read_bytes()
        extras["ros-graph.json"] = encoded(graph)
        extras["ros-capture-metadata.json"] = encoded({
            "actual_schema_objects": "ros-schema/",
            "native_period_ns": {t: spec["period_ns"] for t, spec in TOPICS.items()},
            "qos": "best-effort/volatile/keep-last-8",
            "qos_status": "incompatible callbacks reported; delivery completeness not proven",
            "original_bytes": "raw rclpy CDR callback; rosbag2 stores same payload",
            "bag_timestamp": "collector monotonic relative nanoseconds, not ROS wall time",
            "replay": "only network-none graph; play publishes messages"})
        key = Ed25519PrivateKey.generate()
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        (Path(output).parent / "enrollment-public-key.hex").write_text(
            public_bytes(key).hex() + "\n")
        self.capture.issue("timing_relationship_unestablished", detail="source stamps not wall time")
        result = export_capture(self.capture, output, key, versions, extras)
        print(json.dumps(result, sort_keys=True), flush=True)
        marker("export_finished", role="collect")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["publish", "collect"])
    parser.add_argument("--output", default="/out/final-bundle")
    args = parser.parse_args()
    versions = environment()
    rclpy.init()
    node = None
    deadline = time.monotonic() + (15 if args.role == "publish" else 17)
    try:
        node = Publisher() if args.role == "publish" else Collector()
        while time.monotonic() < deadline and not getattr(node, "done", False):
            rclpy.spin_once(node, timeout_sec=0.05)
        if args.role == "collect":
            node.export(args.output, versions)
    finally:
        cleanup_preserving_error(sys.exc_info()[1],
                                 [("destroy_node", lambda: node.destroy_node() if node is not None else None),
                                  ("shutdown", rclpy.shutdown)])


if __name__ == "__main__":
    main()
