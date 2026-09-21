# SPDX-License-Identifier: Apache-2.0
"""Only ordinary local unit/static tests. Every process boundary is mocked."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import evidence
import runner


class TransportTests(unittest.TestCase):
    def sample(self):
        return evidence.encode(evidence.pack({"capture/raw.bin": b"\x00actual\xff",
                                             "failed.txt": b"expected failure"}))

    def test_twice_decoded_exact_bytes(self):
        text = self.sample()
        first = evidence.decode(text)
        self.assertEqual(first, evidence.decode(text))
        self.assertEqual(first[1]["capture/raw.bin"], b"\x00actual\xff")

    def test_timestamped_logs(self):
        lines = ["2026-09-20T00:00:00Z " + line for line in self.sample().splitlines()]
        self.assertEqual(evidence.decode("\n".join(lines))[1]["failed.txt"], b"expected failure")

    def test_missing_chunk(self):
        lines = self.sample().splitlines()
        with self.assertRaises(ValueError):
            evidence.decode("\n".join([lines[0], lines[-1]]))

    def test_duplicate_chunk(self):
        lines = self.sample().splitlines()
        with self.assertRaises(ValueError):
            evidence.decode("\n".join([*lines[:2], *lines[1:]]))

    def test_wrong_index(self):
        with self.assertRaises(ValueError):
            evidence.decode(self.sample().replace("CHUNK 000001/", "CHUNK 000002/"))

    def test_wrong_digest(self):
        lines = self.sample().splitlines()
        header = json.loads(lines[0].split("BEGIN ", 1)[1])
        header["sha256"] = "0" * 64
        lines[0] = evidence.PREFIX + "BEGIN " + json.dumps(header)
        with self.assertRaises(ValueError):
            evidence.decode("\n".join(lines))

    def test_wrong_footer(self):
        text = self.sample()
        with self.assertRaises(ValueError):
            evidence.decode(text[:-2] + "X\n")

    def test_bad_base64(self):
        with self.assertRaises(ValueError):
            evidence.decode(self.sample().replace("CHUNK 000001/000001 ", "CHUNK 000001/000001 !"))

    def test_path_traversal(self):
        with self.assertRaises(ValueError):
            evidence.pack({"../outside": b"x"})

    def test_absolute_path(self):
        with self.assertRaises(ValueError):
            evidence.pack({"/outside": b"x"})

    def test_reserved_index(self):
        with self.assertRaises(ValueError):
            evidence.pack({"TRANSPORT_INDEX.json": b"x"})

    def test_raw_cap(self):
        with patch.object(evidence, "RAW_LIMIT", 8), self.assertRaises(ValueError):
            evidence.pack({"x": b"123456789"})

    def test_gzip_cap(self):
        with patch.object(evidence, "GZIP_LIMIT", 8), self.assertRaises(ValueError):
            evidence.pack({"x": b"123"})

    def test_decompression_cap(self):
        raw = evidence.pack({"x": b"payload"})
        with patch.object(evidence, "TAR_LIMIT", 8), self.assertRaises(ValueError):
            evidence.verify_archive(raw)

    def test_archive_checksum_tamper(self):
        import gzip
        raw = evidence.pack({"x": b"original-unique-string"})
        changed = gzip.decompress(raw).replace(b"original-unique-string", b"modified-unique-string")
        with self.assertRaises(ValueError):
            evidence.verify_archive(gzip.compress(changed))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.event = {"action": "opened", "pull_request": {"number": 99, "draft": True,
            "head": {"sha": "a"*40, "ref": "test/ros-integration-once",
                     "repo": {"full_name": runner.REPO}},
            "base": {"sha": "b"*40, "ref": "main", "repo": {"full_name": runner.REPO}}}}
        self.event_path = self.root / "event.json"
        self.env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_REPOSITORY": runner.REPO, "GITHUB_EVENT_PATH": str(self.event_path),
                    "GITHUB_RUN_ID": "123", "PATH": "/usr/bin", "RUNNER_TEMP": str(self.root)}

    def tearDown(self):
        self.tmp.cleanup()

    def gate(self):
        self.event_path.write_text(json.dumps(self.event))
        return runner.event_gate(self.env)

    def test_exact_opened_event(self):
        self.assertEqual(self.gate()["head"], "a"*40)

    def test_rerun_blocked(self):
        self.env["GITHUB_RUN_ATTEMPT"] = "2"
        with self.assertRaises(ValueError):
            self.gate()

    def test_synchronize_blocked(self):
        self.event["action"] = "synchronize"
        with self.assertRaises(ValueError):
            self.gate()

    def test_reopened_blocked(self):
        self.event["action"] = "reopened"
        with self.assertRaises(ValueError):
            self.gate()

    def test_fork_blocked(self):
        self.event["pull_request"]["head"]["repo"]["full_name"] = "other/repo"
        with self.assertRaises(ValueError):
            self.gate()

    def test_nondraft_blocked(self):
        self.event["pull_request"]["draft"] = False
        with self.assertRaises(ValueError):
            self.gate()

    def test_wrong_branch_blocked(self):
        self.event["pull_request"]["head"]["ref"] += "-other"
        with self.assertRaises(ValueError):
            self.gate()

    def test_dispatch_blocked(self):
        self.env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        with self.assertRaises(ValueError):
            self.gate()

    def test_wrong_base_blocked(self):
        self.event["pull_request"]["base"]["ref"] = "other"
        with self.assertRaises(ValueError):
            self.gate()

    def test_nonimmutable_head_blocked(self):
        self.event["pull_request"]["head"]["sha"] = "main"
        with self.assertRaises(ValueError):
            self.gate()

    def test_process_deadline(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(runner.time, "monotonic", return_value=20), self.assertRaises(TimeoutError):
            runner.monitor(process, self.root, 10)

    def test_process_evidence_cap(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(runner.time, "monotonic", return_value=0), \
             patch.object(runner, "raw_inventory", return_value={"x": evidence.RAW_LIMIT + 1}), \
             self.assertRaises(ValueError):
            runner.monitor(process, self.root, 10)

    def test_process_nonzero_preserved(self):
        process = Mock()
        process.poll.return_value = 2
        process.returncode = 2
        self.assertEqual(runner.monitor(process, self.root, 10), 2)

    def test_group_termination_escalates(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("mock", 5), -9]
        with patch.object(runner.os, "killpg") as kill:
            runner.stop_group(process)
        self.assertEqual(kill.call_count, 2)

    def test_deadline_does_not_launch_command(self):
        with patch.object(runner.time, "monotonic", return_value=20), \
             patch.object(runner.subprocess, "run") as call, self.assertRaises(TimeoutError):
            runner.command(["not-executed"], 10)
        call.assert_not_called()

    def test_command_remaining_budget(self):
        with patch.object(runner.time, "monotonic", return_value=8), \
             patch.object(runner.subprocess, "run", return_value=Mock(returncode=0, stdout="ok")) as call:
            self.assertEqual(runner.command(["not-executed"], 10), "ok")
        self.assertEqual(call.call_args.kwargs["timeout"], 2)

    def test_no_secret_environment_forwarded(self):
        with patch.dict(os.environ, {"PATH": "/usr/bin", "GITHUB_TOKEN": "fake-sentinel",
                                    "AWS_SECRET_ACCESS_KEY": "fake-sentinel"}):
            env = runner.clean_env(self.root)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)

    def test_raw_inventory_excludes_only_build_and_home(self):
        for name in ("adapter/build/file", "host-home/file", "adapter/raw.bin", "log.txt"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x")
        self.assertEqual(set(runner.raw_inventory(self.root)), {"adapter/raw.bin", "log.txt"})

    def test_unsafe_symlink_yields_failure_transport(self):
        (self.root / "bad").symlink_to("/not-read")
        stream = io.StringIO()
        with patch("sys.stdout", stream):
            self.assertFalse(runner.transport(self.root))
        _, files = evidence.decode(stream.getvalue())
        self.assertFalse(json.loads(files["RECOVERY_TRANSPORT.json"])["complete"])

    def test_raw_overflow_is_not_silent_truncation(self):
        (self.root / "raw").write_bytes(b"x"*20)
        stream = io.StringIO()
        # Inventory reports a large file, but the actual payload is never read.
        with patch.object(runner, "raw_inventory", return_value={"raw": evidence.RAW_LIMIT+1}), \
             patch("sys.stdout", stream):
            self.assertFalse(runner.transport(self.root))
        _, files = evidence.decode(stream.getvalue())
        report = json.loads(files["RECOVERY_TRANSPORT.json"])
        self.assertFalse(report["complete"])
        self.assertIn("raw", report["omittedInventory"])
        self.assertNotIn("raw", files)

    def test_no_ownership_no_docker(self):
        with patch.object(runner, "command") as call:
            result = runner.recover_owned(self.root, {}, 100)
        call.assert_not_called()
        self.assertIn("notReached", result)

    def test_ownership_mismatch_no_docker(self):
        runner.save(self.root / "ownership.json", {"incorrect": True})
        with patch.object(runner, "command") as call, self.assertRaises(ValueError):
            runner.recover_owned(self.root, {}, 100)
        call.assert_not_called()

    def owned(self):
        runner.save(self.root / "ownership.json", {
            "event": {}, "output": str(self.root / "adapter"),
            "noPreexistingExperimentContainers": True})

    def test_foreign_mount_never_removed(self):
        self.owned()
        with patch.object(runner, "CONTAINERS", ("inventory",)), \
             patch.object(runner.time, "monotonic", return_value=0), \
             patch.object(runner, "command", return_value='[{"Mounts":[{"Destination":"/out","Source":"/foreign"}]}]') as call:
            result = runner.recover_owned(self.root, {}, 100)
        self.assertEqual(call.call_count, 1)
        self.assertTrue(result["errors"])

    def test_logs_failure_still_removes_owned_container(self):
        self.owned()
        item = {"Mounts": [{"Destination": "/out", "Source": str(self.root / "adapter/inventory")}]}
        with patch.object(runner, "CONTAINERS", ("inventory",)), \
             patch.object(runner.time, "monotonic", return_value=0), \
             patch.object(runner, "command", side_effect=[json.dumps([item]), RuntimeError("logs failure"), ""]) as call:
            result = runner.recover_owned(self.root, {}, 100)
        self.assertEqual(call.call_args_list[-1].args[0], ["docker", "rm", "-f", "pask-ros-inventory"])
        self.assertTrue(result["errors"])

    def test_exhausted_cleanup_is_reported(self):
        self.owned()
        with patch.object(runner.time, "monotonic", return_value=90), patch.object(runner, "command") as call:
            result = runner.recover_owned(self.root, {}, 100)
        call.assert_not_called()
        self.assertTrue(result["errors"])

    def test_run_preflight_failure_never_starts_adapter(self):
        state = self.root / "state"
        with patch.object(runner, "event_gate", return_value={}), \
             patch.object(runner, "verify_source", side_effect=ValueError("wrong hash")), \
             patch.object(runner.subprocess, "Popen") as popen:
            self.assertEqual(runner.run(self.root / "source", state), 1)
        popen.assert_not_called()
        self.assertIn("wrong hash", json.loads((state / "outer-attempt-summary.json").read_text())["error"])

    def test_existing_state_no_retry(self):
        with patch.object(runner, "event_gate", return_value={}), self.assertRaises(ValueError):
            runner.run(self.root / "source", self.root)

    def test_mock_adapter_success_unchanged_entrypoint(self):
        state = self.root / "state"
        def monitor(process, path, deadline):
            (path / "adapter").mkdir()
            runner.save(path / "adapter/local-attempt-summary.json", {"status": "expected-outcomes-met"})
            return 0
        process = Mock()
        process.poll.return_value = 0
        with patch.object(runner, "event_gate", return_value={}), \
             patch.object(runner, "verify_source", return_value={}), \
             patch.object(runner, "resource_preflight", return_value={}), \
             patch.object(runner, "monitor", side_effect=monitor), \
             patch.object(runner.subprocess, "Popen", return_value=process) as popen:
            self.assertEqual(runner.run(self.root / "source", state), 0)
        argv = popen.call_args.args[0]
        self.assertIn("all", argv)
        self.assertIn("--execute", argv)
        self.assertTrue(argv[2].endswith("examples/ros-evidence-dev2/local_run.py"))
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def source_fixture(self):
        here = self.root / "harness/tools/ros-ci"
        here.mkdir(parents=True)
        source = self.root / "source"
        source.mkdir()
        (source / "runtime.py").write_bytes(b"import sys\n")
        pin = {"status": "PINNED", "repository": runner.REPO, "commit": "c"*40,
               "tree": "d"*40, "files": {"runtime.py": {
                   "sizeBytes": 11, "sha256": evidence.sha(b"import sys\n")}}}
        runner.save(here / "source-pin.json", pin)
        event = {"head": "a"*40}
        def git(root, args, deadline):
            if args == ["rev-parse", "HEAD"]:
                return "a"*40 if root == here.parents[1] else "c"*40
            if args == ["rev-parse", "HEAD^{tree}"]:
                return "d"*40
            return ""
        return here, source, pin, event, git

    def check_source(self, modification=None, git_override=None):
        here, source, pin, event, git = self.source_fixture()
        if modification:
            modification(here, source, pin)
        with patch.object(runner, "HERE", here), patch.object(runner, "git", side_effect=git_override or git), \
             patch.dict(os.environ, {"ROS_SOURCE_COMMIT": "c"*40}):
            return runner.verify_source(source, event, 100)

    def test_exact_source_and_event_head(self):
        self.assertEqual(self.check_source()["sourceTree"], "d"*40)

    def test_source_hash_tamper(self):
        with self.assertRaises(ValueError):
            self.check_source(lambda h, s, p: (s / "runtime.py").write_bytes(b"import os \n"))

    def test_source_pending_fails_closed(self):
        def pending(h, s, p):
            p["status"] = "BLOCKED"
            runner.save(h / "source-pin.json", p)
        with self.assertRaises(ValueError):
            self.check_source(pending)

    def test_source_missing_file(self):
        def missing(h, s, p):
            (s / "runtime.py").rename(s / "renamed.py")
        with self.assertRaises(ValueError):
            self.check_source(missing)

    def test_wrong_harness_commit(self):
        with self.assertRaises(ValueError):
            self.check_source(git_override=lambda *args: "e"*40)

    def test_wrong_source_tree(self):
        def git(root, args, deadline):
            if args == ["rev-parse", "HEAD"]:
                return "a"*40 if root.name == "harness" else "c"*40
            if args == ["rev-parse", "HEAD^{tree}"]:
                return "f"*40
            return ""
        with self.assertRaises(ValueError):
            self.check_source(git_override=git)

    def test_untracked_source_rejected(self):
        def git(root, args, deadline):
            if args == ["rev-parse", "HEAD"]:
                return "a"*40 if root.name == "harness" else "c"*40
            if args == ["rev-parse", "HEAD^{tree}"]:
                return "d"*40
            return "unexpected.py" if args[0] == "ls-files" else ""
        with self.assertRaises(ValueError):
            self.check_source(git_override=git)

    def preflight(self, available=5*runner.GIB, disk=13*runner.GIB, docker=13*runner.GIB, names=""):
        def text(p):
            return ('ID=ubuntu\nVERSION_ID="24.04"\n' if str(p) == "/etc/os-release"
                    else "MemAvailable: " + str(available // 1024) + " kB\n")
        with patch.object(Path, "read_text", text), \
             patch.object(runner.platform, "machine", return_value="x86_64"), \
             patch.object(runner.shutil, "which", return_value="/usr/bin/docker"), \
             patch.object(runner.shutil, "disk_usage", return_value=Mock(free=disk)), \
             patch.object(runner, "command", side_effect=[
                 '{"DockerRootDir":"/var/lib/docker"}', "Avail\n"+str(docker)+"\n", names]):
            return runner.resource_preflight(self.root, 100, {})

    def test_resource_preflight_positive_mock(self):
        self.assertTrue(self.preflight()["noPreexistingExperimentContainers"])

    def test_low_memory_refuses(self):
        with self.assertRaises(ValueError):
            self.preflight(available=3*runner.GIB)

    def test_low_workspace_refuses(self):
        with self.assertRaises(ValueError):
            self.preflight(disk=11*runner.GIB)

    def test_low_docker_storage_refuses(self):
        with self.assertRaises(ValueError):
            self.preflight(docker=11*runner.GIB)

    def test_existing_container_refuses(self):
        with self.assertRaises(ValueError):
            self.preflight(names="pask-ros-inventory\n")


class StaticWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.root = HERE.parents[1]
        self.offline = (self.root / ".github/workflows/ros-offline.yml").read_text()
        self.integration = (self.root / ".github/workflows/ros-integration-once.yml").read_text()

    def test_no_privileged_or_dispatch_or_upload(self):
        for forbidden in ("pull_request_target", "workflow_dispatch", "repository_dispatch",
                          "secrets.", "upload-artifact", "self-hosted", "contents: write"):
            self.assertNotIn(forbidden, self.offline + self.integration)

    def test_only_opened_integration_and_immutable_checkout(self):
        self.assertIn("types: [opened]", self.integration)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", self.integration)
        self.assertIn("ref: ${{ env.ROS_SOURCE_COMMIT }}", self.integration)
        self.assertNotIn("ref: main", self.integration)
        self.assertIn("persist-credentials: false", self.integration)

    def test_timeouts_and_always_recovery(self):
        for text in ("timeout-minutes: 30", "timeout-minutes: 26", "timeout-minutes: 2",
                     "if: ${{ always() }}", "runs-on: ubuntu-24.04"):
            self.assertIn(text, self.integration)
        self.assertLess(runner.MAIN_SECONDS + 10, 26 * 60)
        self.assertLess(runner.RECOVERY_SECONDS, 2 * 60)

    def test_offline_expected_suites_and_no_docker(self):
        for name in ("test_offline.py", "test_smoke.py", "test_local_runtime.py", "test_runtime_module.py"):
            self.assertIn(name, self.offline)
        self.assertNotIn("local_run.py all", self.offline)
        self.assertNotIn("docker run", self.offline)

    def test_action_pins(self):
        import re
        pins = re.findall(r"uses: ([^\s]+)", self.offline + self.integration)
        self.assertTrue(pins)
        for pin in pins:
            self.assertRegex(pin, r"^[\w/-]+@[0-9a-f]{40}$")

    def test_reviewed_safety_constants(self):
        text = (HERE / "runner.py").read_text()
        for fragment in ("4*GIB", "12*GIB", "noPreexistingExperimentContainers",
                         "start_new_session=True", "SIGKILL"):
            self.assertIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
