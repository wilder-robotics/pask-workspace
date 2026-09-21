#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-attempt hosted wrapper; no execution on import or without an eligible event."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

import evidence

HERE = Path(__file__).resolve().parent
REPO = "wilder-robotics/pask-workspace"
MAIN_SECONDS = 1500  # 25 minutes; step ceiling is 26, job ceiling is 30.
RECOVERY_SECONDS = 100  # step ceiling is 120 seconds.
GIB = 1024**3
CONTAINERS = (
    "inventory", "recipient-inventory", "serialization-smoke",
    "capture-clean", "capture-scenario", "capture-missing-stream",
    "reopen-clean", "reopen-scenario", "reopen-missing-stream",
    "recipient-clean", "recipient-scenario", "recipient-missing-stream", "recipient-tampered",
)


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def clean_env(state):
    home = state / "host-home"
    home.mkdir(exist_ok=True)
    return {"PATH": os.environ["PATH"], "HOME": str(home),
            "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1", "DOCKER_CONFIG": str(home / ".docker")}


def command(argv, deadline, env=None, accept=(0,)):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("aggregate deadline reached")
    result = subprocess.run(argv, timeout=min(12, left), capture_output=True,
                            text=True, env=env, check=False)
    if result.returncode not in accept:
        raise RuntimeError(f"command exit {result.returncode}: {argv[0:3]}: {result.stderr[:512]}")
    return result.stdout


def event_gate(env=os.environ):
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
    pr = event.get("pull_request", {})
    head, base = pr.get("head", {}), pr.get("base", {})
    if not (env.get("GITHUB_EVENT_NAME") == "pull_request"
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("GITHUB_REPOSITORY") == REPO
            and event.get("action") == "opened" and pr.get("draft") is True
            and head.get("repo", {}).get("full_name") == REPO
            and base.get("repo", {}).get("full_name") == REPO
            and head.get("ref") == "test/ros-integration-once"
            and base.get("ref") == "main"):
        raise ValueError("not the authorized event/branch/repository/draft/first attempt")
    for value in (head.get("sha"), base.get("sha")):
        if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("immutable event SHA absent")
    return {"head": head["sha"], "base": base["sha"], "pr": pr["number"],
            "run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"]}


def git(repo, args, deadline):
    return command(["git", "-C", str(repo), *args], deadline).strip()


def verify_source(source, event, deadline):
    pin = json.loads((HERE / "source-pin.json").read_bytes())
    if pin.get("status") != "PINNED" or pin.get("repository") != REPO or not pin["files"]:
        raise ValueError("corrected published source pin is not finalized")
    if os.environ.get("ROS_SOURCE_COMMIT") != pin["commit"]:
        raise ValueError("workflow/source configuration mismatch")
    harness = HERE.parents[1]
    if git(harness, ["rev-parse", "HEAD"], deadline) != event["head"]:
        raise ValueError("harness is not immutable event head")
    if git(source, ["rev-parse", "HEAD"], deadline) != pin["commit"]:
        raise ValueError("wrong corrected source commit")
    if git(source, ["rev-parse", "HEAD^{tree}"], deadline) != pin["tree"]:
        raise ValueError("wrong corrected source tree")
    for root in (harness, source):
        git(root, ["diff", "--exit-code", "HEAD", "--"], deadline)
        if git(root, ["ls-files", "--others", "--exclude-standard"], deadline):
            raise ValueError("untracked source files present")
    for name, row in pin["files"].items():
        if not evidence.safe_name(name):
            raise ValueError("unsafe source pin path")
        p = source / name
        if p.is_symlink() or not p.is_file():
            raise ValueError("source pin missing or symlink")
        if p.stat().st_size != row["sizeBytes"] or evidence.sha(p.read_bytes()) != row["sha256"]:
            raise ValueError("corrected source file mismatch: " + name)
    return {"sourceCommit": pin["commit"], "sourceTree": pin["tree"],
            "sourceFilesChecked": len(pin["files"]), "event": event,
            "harnessFiles": {p.relative_to(HERE).as_posix(): evidence.sha(p.read_bytes())
                             for p in sorted(HERE.rglob("*")) if p.is_file()}}


def resource_preflight(state, deadline, env):
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release["ID"].strip('"') != "ubuntu" or release["VERSION_ID"].strip('"') != "24.04":
        raise ValueError("requires unchanged Ubuntu 24.04 runner")
    if platform.machine() != "x86_64" or not shutil.which("docker"):
        raise ValueError("requires existing Docker and x86_64; no fallback")
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                         if line.startswith("MemAvailable:"))) * 1024
    workspace_free = shutil.disk_usage(state).free
    if available < 4*GIB or workspace_free < 12*GIB:
        raise ValueError("host RAM/workspace preflight budget unavailable")
    info = json.loads(command(["docker", "info", "--format", "{{json .}}"], deadline, env))
    docker_free = int(command(["sudo", "-n", "df", "-B1", "--output=avail", info["DockerRootDir"]],
                              deadline, env).splitlines()[-1])
    if docker_free < 12*GIB:
        raise ValueError("Docker backing storage below 12 GiB")
    names = command(["docker", "ps", "-a", "--format", "{{.Names}}"], deadline, env).splitlines()
    if any(name.startswith("pask-ros-") for name in names):
        raise ValueError("preexisting experiment container; do not remove")
    return {"availableRamBytes": available, "workspaceFreeBytes": workspace_free,
            "dockerFreeBytes": docker_free, "noPreexistingExperimentContainers": True}


def raw_inventory(state):
    files = {}
    for path in sorted(state.rglob("*")):
        relative = path.relative_to(state)
        # Build context and host-home are not runtime evidence and are never emitted.
        if relative.parts[0] == "host-home" or relative.parts[:2] == ("adapter", "build"):
            continue
        if path.is_symlink():
            raise ValueError("evidence symlink")
        if path.is_file():
            files[relative.as_posix()] = path.stat().st_size
        elif not path.is_dir():
            raise ValueError("nonregular evidence entry")
        if len(files) > evidence.FILE_LIMIT:
            raise ValueError("evidence file-count budget exceeded")
    return files


def monitor(process, state, deadline):
    while process.poll() is None:
        if time.monotonic() >= deadline:
            raise TimeoutError("main aggregate execution deadline; no retry")
        if sum(raw_inventory(state).values()) > evidence.RAW_LIMIT:
            raise ValueError("raw evidence budget exceeded during execution")
        if shutil.disk_usage(state).free < GIB:
            raise ValueError("workspace emergency free-space floor reached")
        time.sleep(1)
    return process.returncode


def stop_group(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def run(source, state):
    event = event_gate()
    if state.exists():
        raise ValueError("attempt state exists; no rerun or overwrite")
    state.mkdir(parents=True)
    deadline = time.monotonic() + MAIN_SECONDS
    status = {"status": "failed", "event": event, "executionBudgetSeconds": MAIN_SECONDS,
              "externalTrust": "unestablished; software test only"}
    process = None
    try:
        identity = verify_source(source, event, deadline)
        save(state / "source-identities.json", identity)
        env = clean_env(state)
        resources = resource_preflight(state, deadline, env)
        save(state / "outer-preflight.json", resources)
        save(state / "ownership.json", {"event": event, "output": str(state / "adapter"),
                                      "noPreexistingExperimentContainers": True})
        argv = [sys.executable, "-B", str(source / "examples/ros-evidence-dev2/local_run.py"),
                "all", "--execute", "--output", str(state / "adapter")]
        status["argv"] = argv
        with (state / "adapter-console.log").open("w") as log:
            process = subprocess.Popen(argv, cwd=source, stdout=log, stderr=subprocess.STDOUT,
                                       env=env, start_new_session=True)
            code = monitor(process, state, deadline)
        status["adapterExitCode"] = code
        if code:
            raise RuntimeError("adapter failed; no retry or source/dependency repair")
        summary = json.loads((state / "adapter/local-attempt-summary.json").read_bytes())
        if summary["status"] != "expected-outcomes-met":
            raise ValueError("adapter outcomes were not met")
        verify_source(source, event, deadline)
        status["status"] = "expected-outcomes-met"
    except Exception as exc:
        status["error"] = repr(exc)[:2048]
    finally:
        try:
            stop_group(process)
        except Exception as exc:
            status["terminationError"] = repr(exc)[:512]
            status["status"] = "failed"
        save(state / "outer-attempt-summary.json", status)
    return 0 if status["status"] == "expected-outcomes-met" else 1


def recover_owned(state, event, deadline):
    result = {"attempted": [], "errors": [], "scope": "owned named containers only"}
    marker = state / "ownership.json"
    if not marker.exists():
        result["notReached"] = "no verified ownership marker; no Docker cleanup attempted"
        return result
    owner = json.loads(marker.read_bytes())
    if owner != {"event": event, "output": str(state / "adapter"),
                 "noPreexistingExperimentContainers": True}:
        raise ValueError("ownership marker mismatch")
    env = clean_env(state)
    for short in CONTAINERS:
        if time.monotonic() >= deadline - 25:
            result["errors"].append("cleanup budget exhausted; runner disposal remains required")
            break
        name = "pask-ros-" + short
        try:
            raw = command(["docker", "inspect", name], deadline, env, accept=(0, 1))
            if not raw.strip():
                continue
            rows = json.loads(raw)
            if not rows:
                continue
            item = rows[0]
            mounts = item.get("Mounts", [])
            if not any(m.get("Destination") == "/out"
                       and Path(m.get("Source", "")).resolve() == (state / "adapter" / short).resolve()
                       for m in mounts):
                raise ValueError("container mount ownership mismatch; not removed")
            result["attempted"].append(name)
            # Full inspect/log results use fixed host files and remain bounded by pack().
            try:
                save(state / ("recovery-" + short + "-inspect.json"), item)
                console = command(["docker", "logs", "--tail", "200", name], deadline, env, accept=(0, 1))
                (state / ("recovery-" + short + "-console.log")).write_text(console)
            finally:
                command(["docker", "rm", "-f", name], deadline, env, accept=(0,))
        except Exception as exc:
            result["errors"].append({"container": name, "error": repr(exc)[:512]})
    return result


def transport(state):
    try:
        inventory = raw_inventory(state)
    except Exception as exc:
        # A malformed/oversized directory must still yield an honest failure record.
        archive = evidence.pack({"RECOVERY_TRANSPORT.json": json.dumps({
            "complete": False, "error": repr(exc)[:2048],
            "omitted": "full evidence inventory unavailable; no completeness claim"}).encode()})
        text = evidence.encode(archive)
        for _ in range(2):
            if evidence.decode(text)[0] != archive:
                raise ValueError("diagnostic transport differs")
        print(text, end="", flush=True)
        return False
    overflow = sum(inventory.values()) > evidence.RAW_LIMIT
    meta = {"rawBytes": sum(inventory.values()), "rawFiles": len(inventory),
            "excluded": ["adapter/build/**", "host-home/**"],
            "rawLimit": evidence.RAW_LIMIT, "gzipLimit": evidence.GZIP_LIMIT,
            "complete": not overflow}
    try:
        if overflow:
            raise ValueError("raw evidence budget exceeded")
        files = {name: (state / name).read_bytes() for name in inventory}
        files["RECOVERY_TRANSPORT.json"] = json.dumps(meta, indent=2).encode()
        archive = evidence.pack(files)
    except ValueError as exc:
        # Never silently truncate or make a partial archive look complete.
        meta.update(complete=False, error=str(exc), omittedInventory=inventory)
        files = {"RECOVERY_TRANSPORT.json": json.dumps(meta, indent=2).encode()}
        for name in ("outer-attempt-summary.json", "recovery.json"):
            if name in inventory and inventory[name] <= 32768:
                files[name] = (state / name).read_bytes()
        archive = evidence.pack(files)
    text = evidence.encode(archive)
    # Twice verified before emission; recipient decoder repeats on recovered logs.
    for _ in range(2):
        decoded, _ = evidence.decode(text)
        if decoded != archive:
            raise ValueError("transport round trip differs")
    print(text, end="", flush=True)
    return meta["complete"]


def recover(source, state):
    deadline = time.monotonic() + RECOVERY_SECONDS
    state.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "budgetSeconds": RECOVERY_SECONDS}
    try:
        event = event_gate()
        # Recovery is useful even when source checkout or preflight never completed.
        report["cleanup"] = recover_owned(state, event, deadline)
        report["status"] = "complete" if not report["cleanup"]["errors"] else "incomplete"
    except Exception as exc:
        report["error"] = repr(exc)[:2048]
    if not (state / "outer-attempt-summary.json").exists():
        report["mainResult"] = "not recorded; timeout/cancellation/checkout failure, not success"
    save(state / "recovery.json", report)
    complete = transport(state)
    return 0 if complete and report["status"] == "complete" else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("run", "recover"))
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--state", type=Path, required=True)
    args = p.parse_args()
    source, state = args.source.resolve(), args.state.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if not state.is_relative_to(runner_temp) or state == runner_temp:
        raise ValueError("state must be a dedicated directory under RUNNER_TEMP")
    if state.is_relative_to(source) or source.is_relative_to(state):
        raise ValueError("source and output must be disjoint")
    return run(source, state) if args.action == "run" else recover(source, state)


if __name__ == "__main__":
    raise SystemExit(main())
