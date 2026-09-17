#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One approved hosted attempt; no local runtime execution or pin fallback.

Networked pulls/apt builds finish before any simulated ROS runtime begins.
No registry push, cache service, robot/device mount, or production secrets.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import traceback

HERE = Path(__file__).resolve().parent
PAYLOAD_SHA256 = "0287d56f6fab31372aba9d435788f29184276f9af6d16b65536453bf0ed50c51"
DOCKERFILE_SHA256 = "484196d9293712b1031264dca0e39d2be83cfa891bb27457fb0255baf5bb8dbe"
CAPTURE_IMAGE = "pask-ros-proposal:capture"
RECIPIENT_IMAGE = "pask-ros-proposal:recipient"
OUT = Path(os.environ.get("PASK_ROS_OUT", "/tmp/pask-ros-evidence"))
WORK = OUT.parent / "pask-ros-build"
CONTAINERS = []
STAGE = "not-started"


def write(path, data):
    Path(path).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def command(name, argv, timeout=60, accept=(0,)):
    start = time.monotonic()
    with (OUT / (name + ".log")).open("w") as log:
        try:
            result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    record = {"name": name, "argv": list(map(str, argv)), "exit_code": code,
              "elapsed_seconds": time.monotonic() - start}
    with (OUT / "commands.jsonl").open("a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    if code not in accept:
        raise RuntimeError(f"{name}: exit {code}; no automatic retry or version fallback")
    return (OUT / (name + ".log")).read_text()


def preflight():
    # Approval is an administrative prerequisite, not just a runtime assertion.
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event["pull_request"]
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
    assert event["action"] == "opened" and pr["draft"]
    assert not event["repository"]["private"]
    assert pr["head"]["repo"]["full_name"] == event["repository"]["full_name"]
    assert os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
    assert pr["head"]["ref"] == "test/isolated-ros-once"
    head = pr["head"]["sha"]
    assert re.fullmatch(r"[0-9a-f]{40}", head)
    assert command("checked-out-head", ["git", "rev-parse", "HEAD"]).strip() == head
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                   if "=" in line)
    assert release["ID"].strip('"') == "ubuntu" and release["VERSION_ID"].strip('"') == "24.04"
    assert os.uname().machine == "x86_64"
    memory = dict((k, int(v.split()[0]) * 1024)
                  for k, v in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()))
    engine = shutil.which("docker")
    record = {"ubuntu": release, "architecture": os.uname().machine,
              "available_ram_bytes": memory["MemAvailable"],
              "free_workspace_bytes": shutil.disk_usage(HERE).free,
              "required_ram_bytes": 4 * 1024**3, "required_free_bytes": 12 * 1024**3,
              "docker_executable": engine, "event_head": head}
    write(OUT / "preflight.json", record)
    assert engine, "Docker unavailable; do not provision alternative infrastructure"
    assert record["available_ram_bytes"] >= 4 * 1024**3, "insufficient available RAM"
    assert record["free_workspace_bytes"] >= 12 * 1024**3, "insufficient free workspace disk"
    command("docker-version", ["docker", "version"])
    info = json.loads(command("docker-info", ["docker", "info", "--format", "{{json .}}"]))
    # Docker's data directory can be root-only on the standard hosted image.
    # Read-only disk inspection with hosted passwordless sudo; not provisioning.
    docker_free = int(command("docker-disk-space",
        ["sudo", "-n", "df", "-B1", "--output=avail", info["DockerRootDir"]]).splitlines()[-1])
    write(OUT / "docker-disk-preflight.json", {"free_bytes": docker_free,
                                              "root": info["DockerRootDir"]})
    assert docker_free >= 12 * 1024**3, "insufficient Docker backing disk"


def unpack():
    payload = HERE / "frozen-demo.tar.gz"
    assert hashlib.sha256(payload.read_bytes()).hexdigest() == PAYLOAD_SHA256
    source = WORK / "source"
    source.mkdir(parents=True, exist_ok=False)
    with tarfile.open(payload) as tf:
        members = tf.getmembers()
        assert len(members) == 12
        for item in members:
            assert item.isfile() and not Path(item.name).is_absolute()
            assert ".." not in Path(item.name).parts and item.size <= 100000
        tf.extractall(source, filter="data")
    assert hashlib.sha256((source / "ros_package/Dockerfile").read_bytes()).hexdigest() == DOCKERFILE_SHA256
    write(OUT / "source-inventory.json",
          {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
           for p in source.rglob("*") if p.is_file()})
    return source


def runtime(name, image, output, argv, mounts=(), seconds=60, accept=(0,)):
    """Only explicit mounts; no host socket, workspace, /dev, home or token mount."""
    output.mkdir(parents=True, exist_ok=False)
    container = "pask-ros-" + name
    CONTAINERS.append(container)
    cmd = ["docker", "create", "--name", container, "--network", "none",
           "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
           "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "96",
           "--user", f"{os.getuid()}:{os.getgid()}",
           "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777",
           "--mount", f"type=bind,src={output},dst=/out",
           "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
           "--entrypoint", argv[0]]
    for src, dst in mounts:
        cmd += ["--mount", f"type=bind,src={src},dst={dst},readonly"]
    cmd += [image, *argv[1:]]
    command(name + "-create", cmd)
    command(name + "-inspect-before", ["docker", "inspect", container])
    command(name + "-start", ["docker", "start", container])
    start = time.monotonic()
    samples = []
    state = None
    try:
        while time.monotonic() - start < seconds:
            state = json.loads(command(name + "-state",
                                       ["docker", "inspect", "--format", "{{json .State}}", container]))
            if not state["Running"]:
                break
            samples.append({"elapsed_seconds": time.monotonic() - start,
                            "docker_stats": command(name + "-stats",
                                ["docker", "stats", "--no-stream", "--format", "{{json .}}", container],
                                timeout=12).strip()})
            time.sleep(1)
        else:
            deadline_error = RuntimeError(name + ": runtime deadline; no retry")
            try:
                command(name + "-timeout-kill", ["docker", "kill", container])
            except Exception as exc:
                deadline_error.add_note("timeout kill also failed: " + str(exc)[:256])
            raise deadline_error
    finally:
        primary = sys.exc_info()[1]
        evidence_errors = []
        final = None
        for label, action in (
                ("resources", lambda: write(output / "resource-samples.json", samples)),
                ("console", lambda: command(name + "-console", ["docker", "logs", container]))):
            try:
                action()
            except Exception as exc:
                evidence_errors.append(f"{label}: {type(exc).__name__}: {str(exc)[:256]}")
        try:
            final = json.loads(command(name + "-inspect-after", ["docker", "inspect", container]))[0]
            write(output / "container-result.json",
                  {"state": final["State"], "host_config": final["HostConfig"],
                   "mounts": final["Mounts"], "network": final["NetworkSettings"],
                   "elapsed_seconds": time.monotonic() - start})
        except Exception as exc:
            evidence_errors.append(f"inspection: {type(exc).__name__}: {str(exc)[:256]}")
        if evidence_errors:
            try:
                write(output / "evidence-errors.json",
                      {"primary_error": repr(primary), "secondary_errors": evidence_errors,
                       "container_state": final["State"] if final is not None else None})
            except Exception as exc:
                try:
                    print(json.dumps({"evidence_errors": evidence_errors,
                                      "error_record_write_failed": str(exc)[:256],
                                      "primary_error": repr(primary)}), flush=True)
                except Exception:
                    pass  # A broken diagnostic stream cannot replace primary.
            if primary is None:
                raise RuntimeError(name + ": incomplete runtime evidence; " + "; ".join(evidence_errors))
    if final["State"]["OOMKilled"] or final["State"]["ExitCode"] not in accept:
        raise RuntimeError(f"{name}: container integration failure {final['State']}")
    return final["State"]["ExitCode"]


def ros_argv(*args):
    # ROS environment setup scripts can refer to unset variables: no `set -u`.
    return ["/bin/bash", "-c",
            "set -eo pipefail; source /opt/ros/jazzy/setup.bash; "
            "source /opt/demo_ws/install/setup.bash; exec python3 /probe.py " + " ".join(args)]


def build(source):
    command("pull-base", ["docker", "pull", "ros:jazzy-ros-base"], timeout=180)
    base = json.loads(command("base-image-inventory",
                             ["docker", "image", "inspect", "ros:jazzy-ros-base"]))[0]
    digests = base.get("RepoDigests", [])
    assert digests and "@sha256:" in digests[0], "resolved registry base digest absent"
    # The unchanged recipe uses its local tag after the single explicit pull.
    # No --build-arg is allowed: frozen selected ROS versions remain unchanged.
    command("build-frozen-recipe",
            ["docker", "build", "--pull=false", "--no-cache", "--network", "default",
             "--progress", "plain", "-f", str(source / "ros_package/Dockerfile"),
             "-t", CAPTURE_IMAGE, str(source)], timeout=900)
    command("capture-image-inventory", ["docker", "image", "inspect", CAPTURE_IMAGE])
    # Preparation container is also network-none. Recipient must NOT inherit
    # the producer layer: independent image from the resolved public ROS base.
    runtime("inventory", CAPTURE_IMAGE, OUT / "inventory",
            ["/bin/bash", "-c", "set -e; cp /opt/installed-dependencies.lock /out/installed-dependencies.lock; "
             "dpkg-query -W -f='${Version}' python3-cryptography > /out/cryptography-version.txt"])
    crypto_version = (OUT / "inventory/cryptography-version.txt").read_text().strip()
    assert re.fullmatch(r"[A-Za-z0-9.+:~_-]+", crypto_version)
    recipient = WORK / "recipient-build"
    recipient.mkdir()
    shutil.copyfile(source / "recipient.py", recipient / "recipient.py")
    (recipient / "Dockerfile").write_text(
        "FROM " + digests[0] + "\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        "python3-cryptography=" + crypto_version + " && "
        "dpkg-query -W > /opt/recipient-dependencies.lock\n"
        "COPY recipient.py /app/recipient.py\n"
        'ENTRYPOINT ["python3", "-I", "/app/recipient.py"]\n')
    shutil.copyfile(recipient / "Dockerfile", OUT / "recipient-Dockerfile")
    command("build-recipient",
            ["docker", "build", "--pull=false", "--no-cache", "--network", "default",
             "--progress", "plain", "-t", RECIPIENT_IMAGE, str(recipient)], timeout=180)
    command("recipient-image-inventory", ["docker", "image", "inspect", RECIPIENT_IMAGE])
    runtime("recipient-inventory", RECIPIENT_IMAGE, OUT / "recipient-inventory",
            ["/bin/bash", "-c", "test ! -e /opt/demo && test ! -e /opt/demo_ws && "
             "cp /opt/recipient-dependencies.lock /out/installed-dependencies.lock"])


def test(source):
    global STAGE
    STAGE = "offline-serialization-smoke"
    runtime("serialization-smoke", CAPTURE_IMAGE, OUT / "serialization-smoke",
            ros_argv("smoke"), [(HERE / "probe.py", "/probe.py")])
    STAGE = "isolated-runtime"
    results = {}
    for case in ("clean", "scenario", "missing-stream"):
        capture_out = OUT / ("capture-" + case)
        runtime("capture-" + case, CAPTURE_IMAGE, capture_out,
                ros_argv("capture", "--case", case), [(HERE / "probe.py", "/probe.py")])
        bundle = capture_out / "final-bundle"
        runtime("reopen-" + case, CAPTURE_IMAGE, OUT / ("reopen-" + case),
                ros_argv("reopen"), [(HERE / "probe.py", "/probe.py"), (bundle, "/bundle")])
        key = bytes.fromhex((capture_out / "enrollment-public-key.hex").read_text().strip())
        assert len(key) == 32
        # Explicit fixture-only enrollment, NOT independently authenticated key origin.
        trust = OUT / (case + "-public-trust.json")
        write(trust, {"version": "local-test-trust/1", "software_test_material": True,
                      "provenance": "automatic TEST fixture enrollment; real key origin unestablished",
                      "accepted": [{"issuer": "urn:pask:local:test-issuer", "algorithm": "Ed25519",
                                    "key_id": hashlib.sha256(key).hexdigest(),
                                    "public_key_hex": key.hex(), "valid_record_id": "demo-engagement-001"}]})
        cases = [(case, bundle, 0)]
        if case == "clean":
            tampered = OUT / "tampered-export"
            shutil.copytree(bundle, tampered)
            obj = sorted((tampered / "observations").glob("*.bin"))[0]
            raw = obj.read_bytes()
            obj.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
            cases.append(("tampered", tampered, 2))
        for name, final, expected in cases:
            recipient_out = OUT / ("recipient-" + name)
            code = runtime("recipient-" + name, RECIPIENT_IMAGE, recipient_out,
                           ["python3", "-I", "/app/recipient.py", "/bundle",
                            "--public-trust", "/trust.json", "--output", "/out/findings.json"],
                           [(final, "/bundle"), (trust, "/trust.json")], accept=(expected,))
            findings = json.loads((recipient_out / "findings.json").read_text())["findings"]
            for field in ("schema", "issuer_signature", "issuer_key_association"):
                assert findings[field]["status"] == "passed", (name, field, findings[field])
            assert findings["evidence_integrity"]["status"] == ("failed" if expected else "passed")
            results[name] = {"exit_code": code, "local_integrity_expected": not bool(expected),
                             "findings": findings}
        window = json.loads((bundle / "event-window.json").read_text())
        counts = json.loads((capture_out / "raw-callback-counts.json").read_text())
        for topic, count in counts.items():
            assert count > 0 or (case == "missing-stream" and topic == "/demo/control_mode")
        assert window["requested_bounds_ns"] is not None and window["actual_bounds_ns"] is not None
        if case == "missing-stream":
            missing = window["streams"]["/demo/control_mode"]
            assert counts["/demo/control_mode"] == 0 and missing["actual_bounds_ns"] is None
            assert missing["observed_median_interval_ns"] is None
            assert any(g["kind"] == "stream_unavailable" for g in missing["gaps"])
            assert results[case]["findings"]["timing_coverage"]["status"] == "failed"
    write(OUT / "test-expectations.json",
          {"cases": results, "status": "expected outcomes met",
           "clean_means": "no deliberately injected gap/rollback; not full timing coverage",
           "timing_coverage_pass_required": False,
           "recipient": "separate image/process, delivered local verifier; not independent implementation",
           "core_binding": "unestablished; separate workstream",
           "PSER_and_hardware": "not established; software test only"})


def main():
    global STAGE
    OUT.mkdir(parents=True, exist_ok=False)
    outcome = {"status": "integration-failed", "ROS_runtime": "not-reached"}
    try:
        STAGE = "preflight"
        preflight()
        STAGE = "source-integrity"
        source = unpack()
        STAGE = "networked-dependency-build"
        build(source)
        STAGE = "isolated-runtime"
        outcome["ROS_runtime"] = "smoke/capture attempt; callbacks not implied; consult per-container/process statuses"
        test(source)
        outcome["status"] = "expected-test-outcomes-met"
    except Exception as exc:
        outcome["error"] = str(exc)
        try:
            (OUT / "failure-traceback.txt").write_text(traceback.format_exc())
        except Exception as log_exc:
            outcome["failure_record_error"] = str(log_exc)[:256]
    finally:
        outcome["last_stage"] = STAGE
        for name in CONTAINERS:
            try:
                command("cleanup-" + name, ["docker", "rm", "-f", name], accept=(0, 1))
            except Exception:
                outcome.setdefault("cleanup_errors", []).append(name)
        # Bound raw evidence. The workflow emits <=4MiB compressed to logs only;
        # no artifact/cache/registry storage is purchased or enabled.
        outcome["evidence_bytes_before_summary"] = sum(
            p.stat().st_size for p in OUT.rglob("*") if p.is_file())
        if outcome["evidence_bytes_before_summary"] > 20 * 1024**2:
            outcome["status"] = "evidence-size-budget-exceeded"
        try:
            write(OUT / "attempt-summary.json", outcome)
        except Exception as log_exc:
            outcome["status"] = "evidence-preservation-failed"
            outcome["summary_write_error"] = str(log_exc)[:256]
        print(json.dumps(outcome, sort_keys=True), flush=True)
    return 0 if outcome["status"] == "expected-test-outcomes-met" else 1


if __name__ == "__main__":
    raise SystemExit(main())
