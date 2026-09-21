#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""RINT-01: import the real module; mock subprocess boundaries, never its globals."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
MODULE = Path(os.environ.get("PASK_RUNTIME_MODULE", ROOT / "runtime.py"))


class DockerBoundary:
    """Deterministic subprocess double, not Docker or installed ROS execution."""
    def __init__(self):
        self.calls = []
        self.state_error = None
        self.console_error = None
        self.final_inspect_error = None
        self.kill_error = None
        self.exit_code = 0
        self.oom = False
        self.inspect_count = 0

    def run(self, argv, *, stdout, stderr, timeout, check):
        self.calls.append(list(argv))
        if argv[0] != "docker":
            raise AssertionError("unexpected external program")
        verb = argv[1]
        state = {"Running": False, "ExitCode": self.exit_code, "OOMKilled": self.oom}
        if verb == "inspect" and "--format" in argv:
            if self.state_error:
                raise self.state_error
            text = json.dumps(state)
        elif verb == "inspect":
            self.inspect_count += 1
            if self.inspect_count == 2 and self.final_inspect_error:
                raise self.final_inspect_error
            text = json.dumps([{"State": state, "HostConfig": {"NetworkMode": "none"},
                                "Mounts": [], "NetworkSettings": {}}])
        elif verb == "logs":
            if self.console_error:
                raise self.console_error
            text = "mock original container console\n"
        elif verb == "kill":
            if self.kill_error:
                raise self.kill_error
            text = "mock killed"
        elif verb in ("create", "start"):
            text = "mock container"
        else:
            raise AssertionError("unexpected Docker operation: " + verb)
        stdout.write(text)
        stdout.flush()
        return subprocess.CompletedProcess(argv, 0)


class RuntimeModuleTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("rint01_actual_runtime", MODULE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        base = Path(os.environ.get("PASK_RINT_TEST_OUT", ROOT / "test-runs"))
        base.mkdir(parents=True, exist_ok=True)
        self.out = Path(tempfile.mkdtemp(prefix="rint01-", dir=base))
        self.module.OUT = self.out
        self.boundary = DockerBoundary()
        self.mock = patch.object(self.module.subprocess, "run", side_effect=self.boundary.run)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        print("Preserved module-test evidence:", self.out)

    def run_container(self, **kwargs):
        return self.module.runtime("unit", "mock:image", self.out / "container",
                                   ["/bin/mock"], **kwargs)

    def record(self, name):
        return json.loads((self.out / "container" / name).read_text())

    def test_success_finalization_returns_and_saves_evidence(self):
        self.assertEqual(self.run_container(), 0)
        self.assertEqual(self.record("resource-samples.json"), [])
        self.assertEqual(self.record("container-result.json")["state"]["ExitCode"], 0)
        self.assertEqual((self.out / "unit-console.log").read_text(),
                         "mock original container console\n")
        create = self.boundary.calls[0]
        for flag, value in (("--network", "none"), ("--memory", "256m"),
                            ("--cpus", "1"), ("--pids-limit", "96")):
            self.assertEqual(create[create.index(flag) + 1], value)
        self.assertIn("--read-only", create)
        self.assertEqual(self.module.CONTAINERS, ["pask-ros-unit"])

    def test_primary_failure_kept_with_successful_evidence_collection(self):
        primary = RuntimeError("primary state failure")
        self.boundary.state_error = primary
        with self.assertRaises(RuntimeError) as caught:
            self.run_container()
        self.assertIs(caught.exception, primary)
        self.assertTrue((self.out / "unit-console.log").is_file())
        self.assertEqual(self.record("container-result.json")["state"]["ExitCode"], 0)

    def test_runtime_timeout_kills_and_preserves_deadline(self):
        with self.assertRaisesRegex(RuntimeError, "runtime deadline; no retry"):
            self.run_container(seconds=0)
        self.assertTrue(any(x[1] == "kill" for x in self.boundary.calls))
        self.assertTrue((self.out / "container/container-result.json").is_file())

    def test_timeout_kill_failure_is_secondary_note(self):
        self.boundary.kill_error = RuntimeError("secondary kill failure")
        with self.assertRaisesRegex(RuntimeError, "runtime deadline; no retry") as caught:
            self.run_container(seconds=0)
        self.assertTrue(any("secondary kill failure" in x
                            for x in caught.exception.__notes__))
        self.assertTrue((self.out / "container/resource-samples.json").is_file())

    def test_primary_preserved_when_console_and_inspection_fail(self):
        primary = RuntimeError("primary state failure")
        self.boundary.state_error = primary
        self.boundary.console_error = OSError("secondary console failure")
        self.boundary.final_inspect_error = OSError("secondary inspection failure")
        with self.assertRaises(RuntimeError) as caught:
            self.run_container()
        self.assertIs(caught.exception, primary)
        record = self.record("evidence-errors.json")
        self.assertEqual(record["primary_error"], repr(primary))
        self.assertEqual(len(record["secondary_errors"]), 2)

    def test_success_with_missing_console_evidence_fails_closed(self):
        self.boundary.console_error = OSError("secondary console failure")
        with self.assertRaisesRegex(RuntimeError, "incomplete runtime evidence"):
            self.run_container()
        self.assertEqual(self.record("evidence-errors.json")["primary_error"], "None")
        self.assertTrue((self.out / "container/container-result.json").is_file())

    def test_failed_evidence_writes_cannot_mask_primary(self):
        primary = RuntimeError("primary state failure")
        self.boundary.state_error = primary
        output = io.StringIO()
        # Filesystem failure boundary only; the module's namespace is not repaired.
        with patch.object(Path, "write_text", side_effect=OSError("secondary disk failure")), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(RuntimeError) as caught:
                self.run_container()
        self.assertIs(caught.exception, primary)
        fallback = json.loads(output.getvalue())
        self.assertEqual(fallback["primary_error"], repr(primary))
        self.assertIn("secondary disk failure", fallback["error_record_write_failed"])
        self.assertTrue((self.out / "unit-console.log").is_file())

    def test_subprocess_timeout_recorded_and_not_masked(self):
        self.boundary.state_error = subprocess.TimeoutExpired(["docker", "inspect"], 60)
        with self.assertRaisesRegex(RuntimeError, "unit-state: exit 124"):
            self.run_container()
        records = [json.loads(x) for x in (self.out / "commands.jsonl").read_text().splitlines()]
        self.assertEqual(next(x for x in records if x["name"] == "unit-state")["exit_code"], 124)
        self.assertTrue((self.out / "container/container-result.json").is_file())

    def test_nonzero_container_exit_rejected_with_inspection(self):
        self.boundary.exit_code = 9
        with self.assertRaisesRegex(RuntimeError, "container integration failure"):
            self.run_container()
        self.assertEqual(self.record("container-result.json")["state"]["ExitCode"], 9)

    def test_oom_container_rejected_with_inspection(self):
        self.boundary.oom = True
        with self.assertRaisesRegex(RuntimeError, "container integration failure"):
            self.run_container()
        self.assertTrue(self.record("container-result.json")["state"]["OOMKilled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
