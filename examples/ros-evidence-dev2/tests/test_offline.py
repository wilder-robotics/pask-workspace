#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual-data regressions and local adapter tests. Never run ROS or Docker."""
from collections import Counter
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import fixtures
import local_run
import recipient


class ActualData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get("PASK_ROS_TEST_OUT", ROOT / "test-runs"))
        base.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix="actual-data-", dir=base))
        cls.input = cls.work / "frozen"
        cls.index = fixtures.materialize(cls.input)
        print("Preserved test work:", cls.work)

    def verify(self, case, root=None, trust=None):
        return recipient.verify(root or self.input / case / "export",
                                trust or self.input / case / "public-trust.json")["findings"]

    def copy(self, case, label):
        dst = self.work / label
        shutil.copytree(self.input / case / "export", dst)
        return dst

    def test_actual_three_full_recipient_findings_equal_hosted(self):
        for case in ("clean", "scenario", "missing-stream"):
            with self.subTest(case=case):
                expected = json.loads((self.input / case / "hosted-findings.json").read_text())["findings"]
                self.assertEqual(self.verify(case), expected)

    def test_actual_recipient_entrypoint_three_subprocesses(self):
        for case in ("clean", "scenario", "missing-stream"):
            out = self.work / (case + "-findings.json")
            p = subprocess.run([sys.executable, str(ROOT / "recipient.py"),
                str(self.input / case / "export"), "--public-trust",
                str(self.input / case / "public-trust.json"), "--output", str(out)],
                capture_output=True, text=True, timeout=20)
            (self.work / (case + "-cli.log")).write_text(p.stdout + p.stderr)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(out.read_text())["findings"], self.verify(case))

    def test_all_actual_bag_bytes_topics_timestamps_multiplicity(self):
        for case in ("clean", "scenario", "missing-stream"):
            root = self.input / case / "export"
            rows = json.loads((root / "observations.json").read_text())
            expected = Counter((x["topic"], x["receive_ns"], (root / x["path"]).read_bytes()) for x in rows)
            actual = Counter()
            for db in (root / "rosbag2").glob("*.db3"):
                with contextlib.closing(sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
                    actual.update((t, ns, bytes(raw)) for t, ns, raw in conn.execute(
                        "SELECT t.name,m.timestamp,m.data FROM messages m JOIN topics t ON t.id=m.topic_id"))
            self.assertTrue(actual)
            self.assertEqual(actual, expected)

    def test_actual_boundary_roles_and_raw_offsets_remain(self):
        for case, roles in (("clean", (3,70,3)), ("scenario", (3,67,3)), ("missing-stream", (2,61,2))):
            root = self.input / case / "export"
            rows = json.loads((root / "observations.json").read_text())
            counts = Counter(x["coverage_role"] for x in rows)
            self.assertEqual(tuple(counts[x] for x in ("before", "in_window", "after")), roles)
            streams = json.loads((root / "event-window.json").read_text())["streams"]
            for stream in streams.values():
                self.assertIn("in_window_start_offset_ns", stream)
                self.assertIn("in_window_end_offset_ns", stream)
                self.assertIn("left_offset_ns", stream)
                self.assertIn("right_offset_ns", stream)
        self.assertGreater(streams["/demo/movement"]["in_window_start_offset_ns"], 0)

    def test_adverse_coverage_and_unknown_time_remain_distinct(self):
        for case in ("clean", "scenario", "missing-stream"):
            f = self.verify(case)
            self.assertEqual(f["collector_sampled_coverage"]["status"], "passed" if case=="clean" else "failed")
            self.assertEqual(f["source_clock_anomalies"]["status"], "failed" if case=="scenario" else "passed")
            self.assertEqual(f["real_world_time"]["status"], "unestablished")
            self.assertEqual(f["application_policy"]["status"], "unestablished")

    def test_tampered_actual_support_integrity_fails_signature_still_passes(self):
        root = self.copy("clean", "tampered-support")
        row = next(x for x in json.loads((root/"observations.json").read_text()) if x["coverage_role"]=="before")
        p = root / row["path"]
        raw = p.read_bytes()
        p.write_bytes(bytes([raw[0]^1])+raw[1:])
        f = self.verify("clean", root)
        self.assertEqual(f["evidence_integrity"]["status"], "failed")
        self.assertEqual(f["issuer_signature"]["status"], "passed")

    def test_missing_actual_object_rejected(self):
        root = self.copy("clean", "missing-object")
        obj = next((root/"observations").glob("*.bin"))
        obj.rename(self.work / "preserved-missing-object.bin")
        self.assertEqual(self.verify("clean",root)["evidence_integrity"]["status"],"failed")

    def test_noncanonical_manifest_rejected_before_signature(self):
        root = self.copy("clean", "changed-manifest")
        p=root/"manifest.json"
        p.write_bytes(p.read_bytes()+b"\n")
        f = self.verify("clean", root)
        self.assertEqual(f["schema"]["status"], "failed")
        self.assertEqual(f["issuer_signature"]["status"], "not-evaluated")

    def test_changed_signature_rejected(self):
        root = self.copy("clean", "changed-signature")
        p = root / "manifest.sig"
        raw = p.read_bytes()
        p.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        self.assertEqual(self.verify("clean", root)["issuer_signature"]["status"], "failed")

    def test_no_test_key_authorization_does_not_pass(self):
        p=self.work/"empty-trust.json"
        p.write_text(json.dumps({"version":"local-test-trust/1","accepted":[]}))
        f=self.verify("clean",trust=p)
        self.assertNotEqual(f["issuer_key_association"]["status"],"passed")

    def test_eight_original_encoding_pairs_remain_unclassified(self):
        cases=list((self.input/"encoding-differences").iterdir())
        self.assertEqual(len(cases),8)
        for p in cases:
            a=(p/"original.bin").read_bytes();b=(p/"reserialized.bin").read_bytes()
            self.assertEqual([i for i in range(len(a)) if a[i]!=b[i]],[49,50,51])
            intended=json.loads((p/"intended.json").read_text())
            for name in ("decoded","redecoded","after-original-encode","decoded-after-reencode"):
                self.assertEqual(intended,json.loads((p/(name+".json")).read_text()))
            self.assertEqual(json.loads((p/"byte-comparison.json").read_text())["classification"],
                             "encoding difference; cause unclassified")

    def test_fixture_no_overwrite(self):
        with self.assertRaises(ValueError):
            fixtures.materialize(self.input)

    def test_fixture_archive_tamper_rejected_before_output(self):
        with patch.object(fixtures.hashlib,"sha256") as h:
            h.return_value.hexdigest.return_value="bad"
            with self.assertRaises(ValueError):
                fixtures.materialize(self.work/"not-created")
        self.assertFalse((self.work/"not-created").exists())

    def test_visible_source_identity_mapping(self):
        self.assertEqual(local_run.verify_source()["experiment_head"],"6a2b0d828a3a63bb76b058d982bcd333773af24c")

    def test_plan_never_calls_runtime(self):
        with patch.object(local_run.runtime,"command",side_effect=AssertionError("execution")),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(local_run.main(["plan"]),0)

    def test_execution_requires_explicit_flag_and_output(self):
        with patch.object(local_run,"host_preflight",side_effect=AssertionError("preflight")):
            with self.assertRaises(ValueError):
                local_run.main(["all"])
            with self.assertRaises(ValueError):
                local_run.main(["all","--execute","--output",str(ROOT)])

    def test_frozen_inputs_unchanged_after_tests(self):
        for name,v in self.index["selected_files"].items():
            p=self.input/name
            self.assertEqual(p.stat().st_size,v["bytes"])
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),v["sha256"])

    def adapter_output(self):
        base = Path(os.environ.get("PASK_ROS_ADAPTER_TEST_OUT", "/tmp/pask-ros-local-adapter-tests"))
        base.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="mock-", dir=base)) / "output"

    def test_mock_adapter_dispatches_build_then_test_only(self):
        out = self.adapter_output()
        calls = []
        with patch.object(local_run, "host_preflight", side_effect=lambda p: calls.append("preflight")), \
             patch.object(local_run.runtime, "build", side_effect=lambda p: calls.append("build")), \
             patch.object(local_run.runtime, "test", side_effect=lambda p: calls.append("test")), \
             patch.object(local_run.runtime, "command", side_effect=AssertionError("unexpected runtime")):
            self.assertEqual(local_run.main(["all", "--execute", "--output", str(out)]), 0)
        self.assertEqual(calls, ["preflight", "build", "test"])
        self.assertEqual(json.loads((out/"local-attempt-summary.json").read_text())["status"],
                         "expected-outcomes-met")

    def test_mock_preflight_failure_preserved_no_build(self):
        out = self.adapter_output()
        with patch.object(local_run, "host_preflight", side_effect=RuntimeError("primary preflight")), \
             patch.object(local_run.runtime, "build", side_effect=AssertionError("must not build")):
            self.assertEqual(local_run.main(["all", "--execute", "--output", str(out)]), 1)
        self.assertIn("primary preflight", (out/"failure-traceback.txt").read_text())
        self.assertIn("primary preflight", json.loads((out/"local-attempt-summary.json").read_text())["error"])

    def test_mock_cleanup_failure_cannot_erase_primary(self):
        out = self.adapter_output()
        def fail(p):
            local_run.runtime.CONTAINERS.append("pask-ros-mock-owned")
            raise RuntimeError("primary build")
        with patch.object(local_run, "host_preflight"), \
             patch.object(local_run.runtime, "build", side_effect=fail), \
             patch.object(local_run.runtime, "command", side_effect=RuntimeError("secondary cleanup")):
            self.assertEqual(local_run.main(["all", "--execute", "--output", str(out)]), 1)
        result = json.loads((out/"local-attempt-summary.json").read_text())
        self.assertIn("primary build", result["error"])
        self.assertIn("secondary cleanup", result["cleanup_errors"][0])

    def test_mock_summary_write_failure_reports_primary_on_stderr(self):
        out = self.adapter_output()
        err = io.StringIO()
        with patch.object(local_run, "host_preflight", side_effect=RuntimeError("primary host")), \
             patch.object(local_run.runtime, "write", side_effect=OSError("secondary summary")), \
             contextlib.redirect_stderr(err):
            self.assertEqual(local_run.main(["all", "--execute", "--output", str(out)]), 1)
        self.assertIn("primary host", err.getvalue())
        self.assertIn("secondary summary", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
