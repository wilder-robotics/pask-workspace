"""Actual candidate helpers with EXPLICIT generated-message/codec mocks, no ROS."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probe.py"
spec = importlib.util.spec_from_file_location("candidate_probe", PROBE)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def registry():
    """Generated-message-shaped mocks, not installed ROS bindings."""
    result = {}
    for name, fields in P.SMOKE_SCHEMAS.items():
        def init(self, fields=fields):
            for key, kind in fields.items():
                if kind in P.SMOKE_SCHEMAS:
                    value = result[kind]()
                elif kind.startswith("sequence<"):
                    value = []
                else:
                    value = {"string": "", "double": 0.0, "int32": 0,
                             "uint32": 0, "octet": b"\0"}[kind]
                setattr(self, key, value)
        result[name] = type(name.split("/")[-1], (), {
            "__init__": init,
            "get_fields_and_field_types": classmethod(lambda cls, f=fields: dict(f)),
        })
    return result


class Codec:
    """Alternate byte tags map to the same typed object. NOT CDR or ROS."""
    def __init__(self, mutation=None, second_mutation=None):
        self.objects = {}
        self.encodes = self.decodes = 0
        self.mutation, self.second_mutation = mutation, second_mutation

    def serialize(self, obj):
        self.encodes += 1
        raw = b"EXPLICIT-MOCK-" + bytes((self.encodes % 256,))
        self.objects[raw] = copy.deepcopy(obj)
        return raw

    def deserialize(self, raw, cls):
        self.decodes += 1
        obj = copy.deepcopy(self.objects[raw])
        mutation = self.mutation if self.decodes == 1 else self.second_mutation
        if mutation:
            mutation(obj)
        return obj


class SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "test-runs").mkdir(exist_ok=True)
        cls.run_root = Path(tempfile.mkdtemp(prefix="smoke-mocks-", dir=ROOT / "test-runs"))

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=self.run_root))
        self.types = registry()
        self.fixtures = P.smoke_fixtures(self.types)
        self.evidence = P.SmokeEvidence(self.root / "cases", self.types)
        self.codec = Codec()
        self.accepted = []

    def fixture(self, name="diagnostic-layout-1"):
        return next(x for x in self.fixtures if x[0] == name)

    def run_case(self, fixture=None, codec=None, receive=None, case_id="case"):
        _, topic, message, trigger = fixture or self.fixture()
        codec = codec or self.codec
        def accept(raw):
            self.accepted.append(raw)
            return {"raw": raw, "trigger": trigger}
        return self.evidence.run(case_id, topic, message, trigger,
                                 codec.serialize, codec.deserialize, receive or accept)

    def failure(self):
        return json.loads((self.root / "cases/case/failure.json").read_text())

    def test_alternate_encoding_passes_semantics_keeps_original_bytes(self):
        result = self.run_case()
        self.assertEqual(result["typed_message_fidelity"], "passed")
        self.assertFalse(result["serialization_byte_stability"]["equal"])
        self.assertIn("unclassified", result["serialization_byte_stability"]["classification"])
        root = self.root / "cases/case"
        self.assertEqual(self.accepted, [(root / "original.bin").read_bytes()])
        self.assertNotEqual(self.accepted[0], (root / "reserialized.bin").read_bytes())
        self.assertEqual(json.loads((root / "intended.json").read_text()),
                         json.loads((root / "redecoded.json").read_text()))

    def test_all_selected_fields_have_typed_snapshots(self):
        fields = P.typed_snapshot(self.fixture()[2], "diagnostic_msgs/DiagnosticArray", self.types)
        self.assertEqual(set(fields["fields"]), {"header", "status"})
        statuses = fields["fields"]["status"]
        self.assertEqual(statuses["length"], 2)
        self.assertEqual(set(statuses["items"][0]["fields"]),
                         {"level", "name", "message", "hardware_id", "values"})
        values = statuses["items"][0]["fields"]["values"]
        self.assertEqual(values["length"], 2)
        self.assertEqual(set(values["items"][0]["fields"]), {"key", "value"})

    def test_every_movement_scalar_mutation_fails(self):
        paths = ["header.stamp.sec", "header.stamp.nanosec", "header.frame_id",
                 "pose.position.x", "pose.position.y", "pose.position.z",
                 "pose.orientation.x", "pose.orientation.y", "pose.orientation.z", "pose.orientation.w"]
        for i, path in enumerate(paths):
            with self.subTest(path=path):
                def mutate(obj, path=path):
                    parts = path.split(".")
                    for name in parts[:-1]:
                        obj = getattr(obj, name)
                    old = getattr(obj, parts[-1])
                    setattr(obj, parts[-1], old + "changed" if isinstance(old, str) else old + 1)
                with self.assertRaisesRegex(AssertionError, "typed message fidelity"):
                    self.run_case(self.fixture("movement-rich-1"), Codec(mutate), case_id=f"field-{i}")

    def test_each_diagnostic_content_mutation_fails(self):
        mutations = [
            lambda x: setattr(x.header.stamp, "sec", 22),
            lambda x: setattr(x.header.stamp, "nanosec", 123),
            lambda x: setattr(x.header, "frame_id", "altered"),
            lambda x: setattr(x.status[0], "level", b"\x01"),
            lambda x: setattr(x.status[0], "name", "altered"),
            lambda x: setattr(x.status[0], "message", "altered"),
            lambda x: setattr(x.status[0], "hardware_id", "altered"),
            lambda x: setattr(x.status[0].values[0], "key", "altered"),
            lambda x: setattr(x.status[0].values[0], "value", "altered"),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i), self.assertRaisesRegex(AssertionError, "typed message fidelity"):
                self.run_case(codec=Codec(mutate), case_id=f"field-{i}")

    def test_control_content_mutation_fails(self):
        with self.assertRaisesRegex(AssertionError, "typed message fidelity"):
            self.run_case(self.fixture("control-smoke"), Codec(lambda x: setattr(x, "data", "different")))

    def test_second_decode_field_mutation_fails(self):
        with self.assertRaisesRegex(AssertionError, "typed message fidelity"):
            self.run_case(codec=Codec(second_mutation=lambda x: setattr(x.header, "frame_id", "other")))

    def test_status_sequence_order_and_length_mutations_fail(self):
        for i, mutate in enumerate((lambda x: x.status.reverse(), lambda x: x.status.pop(),
                                   lambda x: x.status.append(copy.deepcopy(x.status[0])))):
            with self.subTest(mutation=i), self.assertRaisesRegex(AssertionError, "typed message fidelity"):
                self.run_case(codec=Codec(mutate), case_id=f"sequence-{i}")

    def test_keyvalue_order_and_length_mutations_fail(self):
        for i, mutate in enumerate((lambda x: x.status[0].values.reverse(),
                                   lambda x: x.status[0].values.pop(),
                                   lambda x: x.status[0].values.append(copy.deepcopy(x.status[0].values[0])))):
            with self.subTest(mutation=i), self.assertRaisesRegex(AssertionError, "typed message fidelity"):
                self.run_case(codec=Codec(mutate), case_id=f"sequence-{i}")

    def test_type_mutations_fail_closed(self):
        mutations = [
            lambda x: setattr(x.header.stamp, "sec", True),
            lambda x: setattr(x.header.stamp, "nanosec", 1.0),
            lambda x: setattr(x.header, "frame_id", b"map"),
            lambda x: setattr(x, "status", tuple(x.status)),
            lambda x: setattr(x.status[0], "level", 0),
            lambda x: setattr(x.status[0], "name", 3),
            lambda x: setattr(x.status[0], "values", tuple(x.status[0].values)),
            lambda x: setattr(x.status[0].values[0], "value", b"value"),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i), self.assertRaises(TypeError):
                self.run_case(codec=Codec(mutate), case_id=f"type-{i}")

    def test_unknown_schema_fields_rejected(self):
        cls = self.types["diagnostic_msgs/KeyValue"]
        cls.get_fields_and_field_types = classmethod(lambda c: {"key": "string", "value": "string", "extra": "string"})
        with self.assertRaisesRegex(TypeError, "unsupported schema"):
            self.run_case()
        self.assertEqual(self.codec.encodes, 0)

    def test_unknown_message_class_rejected(self):
        fixture = list(self.fixture())
        fixture[2] = SimpleNamespace(header=fixture[2].header, status=fixture[2].status)
        with self.assertRaisesRegex(TypeError, "unexpected ROS message type"):
            self.run_case(fixture)

    def test_malformed_level_after_trigger_still_rejected(self):
        fixture = self.fixture()
        fixture[2].status[0].level = b"\x02"
        fixture[2].status[1].level = b""
        with self.assertRaisesRegex(TypeError, "exactly one byte"):
            self.run_case(fixture)
        self.assertEqual(self.codec.encodes, 0)

    def test_float_signed_zero_change_rejected(self):
        codec = Codec(lambda x: setattr(x.pose.position, "z", 0.0))
        with self.assertRaisesRegex(AssertionError, "typed message fidelity"):
            self.run_case(self.fixture("movement-rich-0"), codec)

    def test_nonfinite_and_integer_float_inputs_rejected(self):
        for i, value in enumerate((float("nan"), float("inf"), float("-inf"), 1, True)):
            fixture = self.fixture("movement-rich-0")
            fixture[2].pose.position.x = value
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, "finite float64"):
                self.run_case(fixture, case_id=f"float-{i}")

    def test_nonfinite_decoded_value_rejected(self):
        with self.assertRaisesRegex(TypeError, "finite float64"):
            self.run_case(self.fixture("movement-rich-0"),
                          Codec(lambda x: setattr(x.pose.position, "x", float("nan"))))

    def test_serializer_mutation_preserves_original_before_failure(self):
        serialize = self.codec.serialize
        def mutate(obj):
            raw = serialize(obj)
            obj.header.frame_id = "mutated"
            return raw
        self.codec.serialize = mutate
        with self.assertRaisesRegex(AssertionError, "mutated intended"):
            self.run_case()
        self.assertTrue((self.root / "cases/case/original.bin").is_file())
        self.assertEqual(self.codec.decodes, 0)

    def test_reencoder_mutation_fails_after_both_bytes_saved(self):
        serialize = self.codec.serialize
        def mutate(obj):
            raw = serialize(obj)
            if self.codec.encodes == 2:
                obj.header.frame_id = "mutated-by-reencoder"
            return raw
        self.codec.serialize = mutate
        with self.assertRaisesRegex(AssertionError, "typed message fidelity"):
            self.run_case()
        self.assertTrue((self.root / "cases/case/original.bin").is_file())
        self.assertTrue((self.root / "cases/case/reserialized.bin").is_file())

    def test_identical_encoding_is_reported_separately(self):
        def stable(obj):
            self.codec.objects[b"EXPLICIT-MOCK-STABLE"] = copy.deepcopy(obj)
            return b"EXPLICIT-MOCK-STABLE"
        self.codec.serialize = stable
        result = self.run_case()
        self.assertTrue(result["serialization_byte_stability"]["equal"])
        self.assertEqual(result["typed_message_fidelity"], "passed")

    def test_missing_nested_field_is_error_before_encode(self):
        fixture = self.fixture()
        del fixture[2].status[0].hardware_id
        with self.assertRaises(AttributeError):
            self.run_case(fixture)
        self.assertEqual(self.codec.encodes, 0)

    def test_invalid_stamp_ranges_rejected(self):
        for i, (sec, nanosec) in enumerate(((2**31, 0), (0, -1), (0, 1000000000))):
            fixture = self.fixture()
            fixture[2].header.stamp.sec, fixture[2].header.stamp.nanosec = sec, nanosec
            with self.subTest(case=i), self.assertRaises(TypeError):
                self.run_case(fixture, case_id=f"stamp-{i}")

    def test_all_octet_levels_preserve_existing_numeric_rule(self):
        fixture = list(self.fixture("diagnostic-levels-1"))
        fixture[2].status[0].level = b"\xff"
        fixture[3] = True
        result = self.run_case(fixture)
        self.assertTrue(result["actual_receive_trigger"])

    def test_intended_saved_before_serialization_exception(self):
        def fail(obj):
            self.assertTrue((self.root / "cases/case/intended.json").is_file())
            raise RuntimeError("primary encode")
        self.codec.serialize = fail
        with self.assertRaisesRegex(RuntimeError, "primary encode"):
            self.run_case()
        self.assertNotIn("original.bin", self.failure()["available_artifacts"])

    def test_original_saved_before_decode_exception(self):
        def fail(raw, cls):
            self.assertEqual((self.root / "cases/case/original.bin").read_bytes(), raw)
            raise RuntimeError("primary decode")
        self.codec.deserialize = fail
        with self.assertRaisesRegex(RuntimeError, "primary decode"):
            self.run_case()
        self.assertIn("original.bin", self.failure()["available_artifacts"])

    def test_original_and_decoded_saved_before_reencode_exception(self):
        serialize = self.codec.serialize
        def fail(obj):
            if self.codec.encodes == 1:
                self.assertTrue((self.root / "cases/case/decoded.json").is_file())
                raise RuntimeError("primary reencode")
            return serialize(obj)
        self.codec.serialize = fail
        with self.assertRaisesRegex(RuntimeError, "primary reencode"):
            self.run_case()
        self.assertIn("original.bin", self.failure()["available_artifacts"])

    def test_both_byte_strings_saved_before_redecode_exception(self):
        deserialize = self.codec.deserialize
        def fail(raw, cls):
            if self.codec.decodes == 1:
                self.assertEqual((self.root / "cases/case/reserialized.bin").read_bytes(), raw)
                self.assertTrue((self.root / "cases/case/byte-comparison.json").is_file())
                raise RuntimeError("primary redecode")
            return deserialize(raw, cls)
        self.codec.deserialize = fail
        with self.assertRaisesRegex(RuntimeError, "primary redecode"):
            self.run_case()

    def test_both_raw_and_typed_artifacts_before_semantic_failure(self):
        with self.assertRaises(AssertionError):
            self.run_case(codec=Codec(lambda x: setattr(x.header, "frame_id", "different")))
        for name in ("intended.json", "original.bin", "decoded.json", "reserialized.bin",
                     "byte-comparison.json", "redecoded.json"):
            self.assertTrue((self.root / "cases/case" / name).is_file())
        self.assertFalse(self.accepted)

    def test_receive_error_preserves_preceding_evidence(self):
        def fail(raw):
            self.assertTrue((self.root / "cases/case/redecoded.json").is_file())
            raise RuntimeError("primary receive")
        with self.assertRaisesRegex(RuntimeError, "primary receive"):
            self.run_case(receive=fail)
        self.assertEqual(self.failure()["typed_message_fidelity"], "passed")

    def test_primary_exception_not_masked_by_failure_write_error(self):
        save = self.evidence.save
        def fail_save(path, data, raw=False):
            if path.name == "failure.json":
                raise OSError("secondary disk")
            return save(path, data, raw)
        self.evidence.save = fail_save
        self.codec.deserialize = lambda raw, cls: (_ for _ in ()).throw(RuntimeError("primary decode"))
        with self.assertRaisesRegex(RuntimeError, "primary decode") as error:
            self.run_case()
        self.assertIn("secondary disk", error.exception.__notes__[0])
        self.assertTrue((self.root / "cases/case/original.bin").is_file())

    def test_failed_original_write_prevents_decode(self):
        save = self.evidence.save
        def fail_save(path, data, raw=False):
            if path.name == "original.bin":
                raise OSError("primary raw save")
            return save(path, data, raw)
        self.evidence.save = fail_save
        with self.assertRaisesRegex(OSError, "primary raw save"):
            self.run_case()
        self.assertEqual(self.codec.decodes, 0)

    def test_collector_reencoded_substitution_rejected(self):
        with self.assertRaisesRegex(AssertionError, "retain original"):
            self.run_case(receive=lambda raw: {"raw": b"different", "trigger": True})

    def test_collector_trigger_type_and_value_rejected(self):
        for i, trigger in enumerate((False, 1, None)):
            with self.subTest(trigger=trigger), self.assertRaisesRegex(AssertionError, "trigger mismatch"):
                self.run_case(receive=lambda raw, t=trigger: {"raw": raw, "trigger": t}, case_id=f"trigger-{i}")

    def test_expected_trigger_must_match_all_levels(self):
        fixture = list(self.fixture())
        fixture[3] = False
        with self.assertRaisesRegex(AssertionError, "validated levels"):
            self.run_case(fixture)
        self.assertEqual(self.codec.encodes, 0)

    def test_complete_pairs_diff_lengths_offsets_ranges(self):
        diff = P.byte_comparison(b"abc123xy", b"abc12qxyz")
        self.assertEqual(diff["offsets"], [5, 8])
        self.assertEqual(diff["ranges_half_open"], [[5, 6], [8, 9]])
        self.assertFalse(diff["offsets_truncated"])

    def test_diff_metadata_truncation_explicit_full_raw_unchanged(self):
        original, altered = bytes(4096), bytes([1]) * 4096
        diff = P.byte_comparison(original, altered)
        self.assertEqual(diff["differing_offset_count"], 4096)
        self.assertTrue(diff["offsets_truncated"])
        self.assertEqual(diff["ranges_half_open"], [[0, 4096]])

    def test_oversize_raw_records_hash_and_explicit_absence(self):
        self.codec.serialize = lambda obj: b"x" * 4097
        with self.assertRaisesRegex(RuntimeError, "raw bound"):
            self.run_case()
        root = self.root / "cases/case"
        meta = json.loads((root / "original.json").read_text())
        self.assertFalse(meta["full_bytes_preserved"])
        self.assertFalse((root / "original.bin").exists())
        self.assertTrue(self.failure()["truncated"])
        self.assertEqual(self.codec.decodes, 0)

    def test_serializer_output_type_rejected(self):
        self.codec.serialize = lambda obj: bytearray(b"fake")
        with self.assertRaisesRegex(TypeError, "must return bytes"):
            self.run_case()
        self.assertEqual(self.codec.decodes, 0)

    def test_capacity_and_case_id_bounds_fail_closed(self):
        self.evidence.count = P.SMOKE_LIMITS["cases"]
        with self.assertRaisesRegex(RuntimeError, "case bound"):
            self.run_case()
        self.evidence.count = 0
        with self.assertRaisesRegex(ValueError, "identifier"):
            self.run_case(case_id="../escape")
        self.evidence.total = P.SMOKE_LIMITS["evidence_bytes"]
        with self.assertRaisesRegex(RuntimeError, "evidence bound"):
            self.run_case()

    def test_fixture_string_and_sequence_bounds(self):
        fixture = self.fixture()
        fixture[2].status[0].name = "x" * 257
        with self.assertRaisesRegex(TypeError, "string exceeds"):
            self.run_case(fixture)
        fixture[2].status[0].name = ""
        fixture[2].status *= 5
        with self.assertRaisesRegex(TypeError, "sequence exceeds"):
            self.run_case(fixture, case_id="sequence")

    def test_fixed_48_check_plan_with_actual_publisher_emit_methods_mock_transport(self):
        # Actual unchanged emitter methods, generated fields and wire codec MOCKED.
        node = ROOT / "ros_package/pask_ros2_local_demo/node.py"
        tree = ast.parse(node.read_text())
        publisher = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Publisher")
        ns = {"Node": object, "NS": 1000000000, "marker": lambda *a, **k: None,
              "publish_observation": lambda self, topic, msg: self.outputs[topic].publish(msg)}
        for name in ("PoseStamped", "String", "DiagnosticArray", "DiagnosticStatus"):
            ns[name] = next(v for k, v in self.types.items() if k.endswith("/" + name))
        exec(compile(ast.Module(body=[publisher], type_ignores=[]), str(node), "exec"), ns)
        frozen = SimpleNamespace(**ns)
        self.assertEqual(len(self.fixtures), 16)
        results = []
        for fixture in self.fixtures:
            for repeat in range(2):
                results.append(self.run_case(fixture, case_id=fixture[0] + f"-r{repeat}"))
        for case in ("scenario", "clean", "missing-stream"):
            cls = frozen.Publisher if case == "scenario" else P.publisher_class(frozen, case)
            for tick in (0, 60):
                outputs = {}
                for topic in P.SMOKE_TOPICS:
                    def publish(msg, topic=topic):
                        fixture = ("emit", topic, msg, topic == "/demo/diagnostics" and tick == 60)
                        results.append(self.run_case(fixture, case_id=
                            "emit-" + case + f"-tick{tick}-" + topic.rsplit("/", 1)[-1]))
                    outputs[topic] = SimpleNamespace(publish=publish)
                cls.emit(SimpleNamespace(tick=tick, done=False, outputs=outputs))
        self.assertEqual(len(results), 48)
        self.assertLess(self.evidence.total, P.SMOKE_LIMITS["evidence_bytes"])
        (self.root / "fixed-plan-mock-results.json").write_text(json.dumps({
            "scope": "actual fixture/emit/helper code with mocked messages/codec/transport; NOT ROS",
            "checks": len(results), "evidence_bytes_written": self.evidence.total,
            "results": results}, indent=2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
