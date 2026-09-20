#!/usr/bin/env python3
"""Actual candidate functions with EXPLICIT ROS/Docker mocks; not ROS execution."""
import ast
from contextlib import redirect_stdout
from functools import partial
import io
from itertools import islice
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace as S
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
NODE = ROOT / "ros_package/pask_ros2_local_demo/node.py"
PROBE = ROOT / "probe.py"
RUNNER = ROOT / "runtime.py"


def load_selected(path, names, namespace):
    tree = ast.parse(path.read_text())
    selected = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                and n.name in names]
    assert {n.name for n in selected} == set(names)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


class Pose:
    def __init__(self):
        self.header = S(stamp=S(sec=0, nanosec=0), frame_id="")
        self.pose = S(position=S(x=0.0), orientation=S(w=0.0))


class String:
    data = ""


class Status:
    level = b"\x00"


class Array:
    def __init__(self):
        self.header = S(stamp=S(sec=0, nanosec=0), frame_id="")
        self.status = []


class Sink:
    limits = {"record_bytes": 65536}

    def __init__(self):
        self.records, self.errors = [], []

    def submit(self, record):
        self.records.append(record)

    def issue(self, *args, **kwargs):
        self.errors.append((args, kwargs))


class Graph:
    def __init__(self, **kwargs):
        self.topics = [("/demo/movement", ["geometry_msgs/msg/PoseStamped"])]
        self.services, self.actions, self.node_services = [], [], []
        self.query_failure = False

    def get_topic_names_and_types(self):
        return self.topics

    def get_service_names_and_types(self):
        if self.query_failure:
            raise RuntimeError("injected query failure")
        return self.services

    def get_node_names_and_namespaces(self):
        return [("controlled", "/")]

    def get_service_names_and_types_by_node(self, *args):
        return self.node_services

    def get_publishers_info_by_topic(self, topic):
        return [S(node_name="controlled", node_namespace="/", topic_type="mock",
                  endpoint_gid=[1, 2], qos_profile=S(reliability="best-effort",
                  durability="volatile", history="keep-last", depth=8))]

    get_subscriptions_info_by_topic = get_publishers_info_by_topic


class FakeNode(Graph):
    def __init__(self, name, **kwargs):
        super().__init__()
        self.name, self.kwargs = name, kwargs

    def create_publisher(self, *args, **kwargs):
        return S(publish=lambda msg: None)

    def create_timer(self, *args):
        return S(cancel=lambda: None)

    def create_subscription(self, *args, **kwargs):
        return (args, kwargs)


class CaptureSink(Sink):
    def __init__(self, policy=None):
        super().__init__()
        self.policy = policy

    def drain(self):
        pass


def namespace():
    types = {"/demo/movement": Pose, "/demo/control_mode": String, "/demo/diagnostics": Array}
    ns = dict(json=json, os=os, Path=Path, sys=sys, time=time, islice=islice, partial=partial,
              _marker_count=0, NS=10**9, TYPES=types,
              TOPICS={t: {"type": t} for t in types}, QOS=0, PoseStamped=Pose, String=String,
              DiagnosticArray=Array, DiagnosticStatus=Status, Capture=CaptureSink,
              POLICY_ID="collector-monotonic-sampled-bracket/1",
              Node=FakeNode, Parameter=lambda name, **kw: S(name=name, **kw),
              SubscriptionEventCallbacks=lambda **kw: kw)
    names = ["marker", "cleanup_preserving_error", "diagnostic_level_number",
             "diagnostic_trigger", "publish_observation", "graph_observation", "checked_graph",
             "Publisher", "Collector"]
    return load_selected(NODE, names, ns)


action_graph = ModuleType("rclpy.action.graph")
action_graph.get_action_names_and_types = lambda node: node.actions
action_graph.get_action_client_names_and_types_by_node = lambda node, *args: []
action_graph.get_action_server_names_and_types_by_node = lambda node, *args: []
action_module = ModuleType("rclpy.action")
action_module.graph = action_graph
FAKES = {"rclpy": ModuleType("rclpy"), "rclpy.action": action_module,
         "rclpy.action.graph": action_graph}


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.ns = namespace()
        self.temp = Path(tempfile.mkdtemp(prefix="local-check-", dir=ROOT / "test-evidence"))
        self.module_patch = patch.dict(sys.modules, FAKES)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.output = io.StringIO()
        self.output_patch = redirect_stdout(self.output)
        self.output_patch.__enter__()
        self.addCleanup(lambda: (self.output_patch.__exit__(None, None, None),
                                (self.temp / "markers.log").write_text(self.output.getvalue())))

    def test_checked_byte_contract_all_levels(self):
        for level in (0, 1, 2, 3, 255):
            self.assertEqual(self.ns["diagnostic_level_number"](bytes((level,))), level)
            self.assertEqual(self.ns["diagnostic_trigger"]([S(level=bytes((level,)))]), level >= 2)

    def test_malformed_levels_never_coerced(self):
        for value in (None, 0, 2, True, "", "2", b"", b"\x00\x02", bytearray(b"\x02"),
                      memoryview(b"\x02")):
            with self.subTest(value=repr(value)):
                with self.assertRaises(TypeError):
                    self.ns["diagnostic_level_number"](value)

    def test_nested_trigger_validates_after_true(self):
        for levels, expected in (([], False), ([0, 1], False), ([0, 2], True), ([3, 0], True)):
            self.assertEqual(self.ns["diagnostic_trigger"]([S(level=bytes((v,))) for v in levels]),
                             expected)
        with self.assertRaises(TypeError):
            self.ns["diagnostic_trigger"]([S(level=b"\x02"), S(level=2)])

    def receive(self, msg, raw=b"UNCHANGED-MOCK-CDR"):
        sink = Sink()
        obj = S(started=time.monotonic_ns(), capture=sink,
                local_sequences={t: 0 for t in self.ns["TYPES"]})
        self.ns["deserialize_message"] = lambda data, cls: msg
        self.ns["Collector"].receive(obj, "/demo/diagnostics", Array, raw)
        return sink

    def test_actual_collector_threshold_and_original_bytes(self):
        for level in (0, 1, 2, 3):
            msg = Array()
            msg.status = [S(level=bytes((level,)))]
            sink = self.receive(msg)
            self.assertEqual(sink.errors, [])
            self.assertEqual(sink.records[0]["trigger"], level >= 2)
            self.assertEqual(sink.records[0]["raw"], b"UNCHANGED-MOCK-CDR")

    def test_actual_collector_malformed_nested_records_ingress_error(self):
        for bad in (None, 2, b"", b"\x02\x03", bytearray(b"\x02")):
            msg = Array()
            msg.status = [S(level=b"\x02"), S(level=bad)]
            sink = self.receive(msg)
            self.assertEqual(sink.records, [])
            self.assertEqual(sink.errors[0][0][0], "decode_or_ingress_error")

    def test_both_actual_publishers_normal_trigger_and_missing_stream(self):
        probe = load_selected(PROBE, ["publisher_class"], {})
        frozen = S(**self.ns)
        for case in ("scenario", "clean", "missing-stream"):
            cls = self.ns["Publisher"] if case == "scenario" else probe["publisher_class"](frozen, case)
            for tick in (0, 60):
                outputs = {}
                def serialize(message):
                    if isinstance(message, Array):
                        self.assertEqual(message.status[0].level, b"\x02" if tick == 60 else b"\x00")
                        self.ns["diagnostic_trigger"](message.status)
                    return b"MOCK-SERIALIZED"
                self.ns["serialize_message"] = serialize
                obj = S(tick=tick, done=False, outputs={t: S(publish=lambda m, t=t: outputs.update({t: m}))
                                                      for t in self.ns["TYPES"]})
                cls.emit(obj)
                self.assertEqual(set(outputs), set(self.ns["TYPES"]) -
                                 ({"/demo/control_mode"} if case == "missing-stream" else set()))
                self.assertEqual(obj.tick, tick + 1)

    def test_both_actual_constructors_supported_parameter_override(self):
        for cls in (self.ns["Publisher"], self.ns["Collector"]):
            obj = cls()
            self.assertFalse(obj.kwargs["enable_rosout"])
            self.assertFalse(obj.kwargs["start_parameter_services"])
            params = obj.kwargs["parameter_overrides"]
            self.assertEqual(len(params), 1)
            self.assertEqual(params[0].name, "start_type_description_service")
            self.assertIs(params[0].value, False)
            if hasattr(obj, "capture"):
                self.assertEqual(obj.capture.policy, "collector-monotonic-sampled-bracket/1")

    def test_actual_callback_logging_cap_does_not_drop_capture_records(self):
        role = next(n for n in ast.parse(PROBE.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == "role")
        cls = next(n for n in role.body if isinstance(n, ast.ClassDef) and n.name == "ObservedCollector")
        self.ns["deserialize_message"] = lambda raw, cls: String()
        ns = dict(frozen=S(**self.ns), json=json, time=time, sha=lambda raw: "mock-digest")
        exec(compile(ast.Module(body=[cls], type_ignores=[]), str(PROBE), "exec"), ns)
        obj = ns["ObservedCollector"]()
        for _ in range(300):
            obj.receive("/demo/control_mode", String, b"original-bytes")
        self.assertEqual(len(obj.capture.records), 300)
        self.assertTrue(all(r["raw"] == b"original-bytes" for r in obj.capture.records))
        lines = [json.loads(l) for l in self.output.getvalue().splitlines()]
        self.assertEqual(sum("raw_callback" in row for row in lines), 256)
        self.assertEqual(sum(row.get("marker") == "raw_callback_logging_capped" for row in lines), 1)

    def test_actual_partial_failure_metadata_is_separate_from_export(self):
        role = next(n for n in ast.parse(PROBE.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == "role")
        function = next(n for n in ast.walk(role) if isinstance(n, ast.FunctionDef)
                        and n.name == "partial_state")
        obj = S(local_sequences={"mock": 300}, _raw_logs=300,
                capture=S(high_water=3, limits={"records": 5}, reasons={"mock-error": 1}))
        ns = dict(args=S(role="collect"), node=obj, exc=RuntimeError("original"),
                  Path=lambda path: self.temp / "partial-debug", time=time,
                  write=lambda path, data: path.write_text(json.dumps(data)))
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(PROBE), "exec"), ns)
        ns["partial_state"]()
        saved = json.loads((self.temp / "partial-debug/collector-state.json").read_text())
        self.assertFalse(saved["raw_CDR_exported"])
        self.assertEqual(saved["callback_log_entries_suppressed"], 44)
        self.assertIn("NOT a final export", saved["status"])
        self.assertFalse((self.temp / "final-bundle").exists())

    def checked(self, graph):
        path = self.temp / "graph.json"
        result = self.ns["checked_graph"](graph, path, "explicit-mock")
        self.assertEqual(result, json.loads(path.read_text())[-1])
        return result

    def rejected(self, graph):
        path = self.temp / "graph.json"
        with self.assertRaises(RuntimeError):
            self.ns["checked_graph"](graph, path, "explicit-mock")
        result = json.loads(path.read_text())[-1]
        self.assertFalse(result["policy"]["passed"])
        self.assertLessEqual(len(json.dumps(result).encode()), 131072)
        return result

    def test_allowed_graph_saved_and_passed(self):
        result = self.checked(Graph())
        self.assertTrue(result["complete"])
        self.assertEqual(result["endpoints"]["/demo/movement"]["publishers"][0]["qos"]["depth"], "8")

    def test_unexpected_topic_saved_before_rejection(self):
        graph = Graph()
        graph.topics.append(("/forbidden", ["Other"]))
        self.assertEqual(self.rejected(graph)["policy"]["unexpected_topics"][0][0], "/forbidden")

    def test_unexpected_service_saved_before_rejection(self):
        graph = Graph()
        graph.services = [("/unknown", ["Some/srv/Type"])]
        self.assertEqual(self.rejected(graph)["policy"]["unexpected_services"][0][0], "/unknown")

    def test_unexpected_action_saved_before_rejection(self):
        graph = Graph()
        graph.actions = [("/unknown", ["Some/action/Type"])]
        self.assertEqual(self.rejected(graph)["policy"]["unexpected_actions"][0][0], "/unknown")

    def test_node_attributed_service_cannot_pass_discovery_race(self):
        graph = Graph()
        graph.node_services = [("/unknown", ["Service"])]
        self.assertTrue(self.rejected(graph)["policy"]["node_services_or_actions"])

    def test_real_named_node_action_client_and_server_queries_reject(self):
        for direction in ("client", "server"):
            name = "get_action_" + direction + "_names_and_types_by_node"
            with patch.object(action_graph, name, lambda node, *args: [("/bad", ["Action"])]):
                result = self.rejected(Graph())
                self.assertTrue(result["policy"]["node_services_or_actions"])
                self.assertEqual(result["nodes"][0]["action_" + direction + "s"][0][0], "/bad")

    def test_query_error_retains_partial_graph_and_rejects(self):
        graph = Graph()
        graph.query_failure = True
        result = self.rejected(graph)
        self.assertEqual(result["topics"][0][0], "/demo/movement")
        self.assertFalse(result["complete"])
        self.assertEqual(result["query_errors"][0]["query"], "services")

    def test_missing_endpoint_attribute_is_unavailable_not_success(self):
        graph = Graph()
        good = graph.get_publishers_info_by_topic("")[0]
        graph.get_publishers_info_by_topic = lambda t: [good, S(node_name="partial")]
        result = self.rejected(graph)
        self.assertEqual(len(result["endpoints"]["/demo/movement"]["publishers"]), 1)
        self.assertTrue(result["query_errors"])

    def test_truncation_cannot_pass(self):
        graph = Graph()
        graph.topics = graph.topics * 33
        result = self.rejected(graph)
        self.assertIn("topics", result["truncated"])
        self.assertFalse(result["complete"])

    def test_huge_graph_remains_bounded_and_rejected(self):
        graph = Graph()
        graph.topics = [("/demo/" + str(i) + "x" * 250, ["y" * 256] * 8) for i in range(32)]
        graph.services = [("s" * 256, ["t" * 256] * 8)] * 32
        result = self.rejected(graph)
        self.assertFalse(result["complete"])

    def test_snapshot_count_budget_retains_decisive_failure(self):
        graph = Graph()
        for _ in range(20):
            self.checked(graph)
        with self.assertRaises(RuntimeError):
            self.checked(graph)
        saved = json.loads((self.temp / "graph-budget-rejection.json").read_text())
        self.assertFalse(saved["policy"]["passed"])

    def test_frozen_export_rejects_before_bag_or_final_output(self):
        obj = self.ns["Collector"]()
        obj.services = [("/bad", ["Service"])]
        final = self.temp / "final-bundle"
        with self.assertRaisesRegex(RuntimeError, "saved policy rejection"):
            obj.export(final, {})
        self.assertFalse(final.exists())
        self.assertTrue((self.temp / "export-graph-snapshots.json").exists())

    def test_actual_probe_graph_delegates_persist_then_enforce(self):
        frozen = ModuleType("pask_ros2_local_demo.node")
        frozen.checked_graph = lambda node, path, role: self.ns["checked_graph"](
            node, self.temp / "graph.json", role)
        package = ModuleType("pask_ros2_local_demo")
        package.node = frozen
        probe = load_selected(PROBE, ["graph"], {})
        graph = Graph()
        graph.services = [("/bad", ["Service"])]
        with patch.dict(sys.modules, {"pask_ros2_local_demo": package}):
            with self.assertRaises(RuntimeError):
                probe["graph"](graph)
        self.assertTrue((self.temp / "graph.json").exists())

    def test_cleanup_keeps_primary_and_attempts_all_actions(self):
        seen = []
        def bad():
            raise RuntimeError("secondary teardown")
        original = ValueError("original failure")
        self.ns["cleanup_preserving_error"](original, [("bad", bad), ("good", lambda: seen.append(1))])
        self.assertEqual(seen, [1])
        with self.assertRaisesRegex(RuntimeError, "secondary teardown"):
            self.ns["cleanup_preserving_error"](None, [("bad", bad)])

    def test_markers_flush_bound_and_clock(self):
        self.ns["_marker_count"] = 0
        for _ in range(800):
            self.ns["marker"]("bounded", detail="x" * 10000)
        rows = [json.loads(l) for l in self.output.getvalue().splitlines()]
        self.assertEqual(len(rows), 768)
        self.assertEqual(len(rows[0]["detail"]), 256)
        self.assertIn("CLOCK_MONOTONIC", rows[0]["clock"])

    def runtime_namespace(self, command, clock=time):
        return load_selected(RUNNER, ["runtime"], {
            "json": json, "Path": Path, "time": clock, "sys": sys, "os": os,
            "CONTAINERS": [], "command": command,
            "write": lambda p, d: Path(p).write_text(json.dumps(d))})

    def test_runtime_primary_state_error_survives_logs_and_inspection(self):
        def command(name, *args, **kwargs):
            if name.endswith("-state"):
                raise RuntimeError("original-state-error")
            if name.endswith(("-console", "-inspect-after")):
                raise RuntimeError("secondary-evidence-error")
            return ""
        ns = self.runtime_namespace(command)
        with self.assertRaisesRegex(RuntimeError, "original-state-error"):
            ns["runtime"]("case", "mock-image", self.temp / "runtime", ["mock"])
        errors = json.loads((self.temp / "runtime/evidence-errors.json").read_text())
        self.assertIn("original-state-error", errors["primary_error"])
        self.assertEqual(len(errors["secondary_errors"]), 2)

    def test_runtime_timeout_survives_kill_and_log_errors(self):
        calls = iter((0.0, 10.0))
        clock = S(monotonic=lambda: next(calls, 10.0))
        def command(name, *args, **kwargs):
            if name.endswith(("-timeout-kill", "-console", "-inspect-after")):
                raise RuntimeError("secondary kill/log")
            return ""
        ns = self.runtime_namespace(command, clock)
        with self.assertRaisesRegex(RuntimeError, "runtime deadline") as err:
            ns["runtime"]("case", "mock-image", self.temp / "runtime", ["mock"], seconds=1)
        self.assertIn("timeout kill also failed", err.exception.__notes__[0])

    def test_actual_smoke_and_capture_order_static_only(self):
        probe = ast.parse(PROBE.read_text())
        smoke = next(n for n in probe.body if isinstance(n, ast.FunctionDef) and n.name == "smoke")
        text = ast.unparse(smoke)
        for required in ("serialize_message", "deserialize_message", "Collector.receive",
                         "cls.emit", "smoke-result.json", "installed-contract",
                         "rosidl_generator_py", "start_type_description_service"):
            self.assertIn(required, text)
        role = ast.unparse(next(n for n in probe.body if isinstance(n, ast.FunctionDef) and n.name == "role"))
        self.assertLess(role.index("no graph snapshot establishes"), role.index("node.export"))
        runner = ast.parse(RUNNER.read_text())
        test = ast.unparse(next(n for n in runner.body if isinstance(n, ast.FunctionDef) and n.name == "test"))
        self.assertLess(test.index("serialization-smoke"), test.index("for case"))


if __name__ == "__main__":
    (ROOT / "test-evidence").mkdir(exist_ok=True)
    unittest.main(verbosity=2)
