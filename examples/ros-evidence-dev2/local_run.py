#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit local command adapter. No hosted trigger or implicit execution."""
import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import traceback

import runtime

HERE = Path(__file__).resolve().parent


def verify_source():
    mapping = json.loads((HERE / "SOURCE_MAP.json").read_text())
    for item in mapping["files"]:
        path = HERE / item["path"]
        if item["relationship"] == "byte-identical":
            if hashlib.sha256(path.read_bytes()).hexdigest() != item["source_sha256"]:
                raise ValueError("reviewed source changed: " + item["path"])
        elif "functions" in item:
            text = path.read_text()
            funcs = {n.name: ast.get_source_segment(text, n) for n in ast.parse(text).body
                     if isinstance(n, ast.FunctionDef)}
            if set(funcs) != set(item["functions"]):
                raise ValueError("runtime helper set changed")
            for name, digest in item["functions"].items():
                if hashlib.sha256(funcs[name].encode()).hexdigest() != digest:
                    raise ValueError("reviewed runtime helper changed: " + name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != item["candidate_sha256"]:
            raise ValueError("adapted test source changed: " + item["path"])
    return mapping


def host_preflight(out):
    """Same host/resource prerequisites; no emulation of a GitHub opened event."""
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                   if "=" in line)
    if release["ID"].strip('"') != "ubuntu" or release["VERSION_ID"].strip('"') != "24.04":
        raise RuntimeError("requires Ubuntu 24.04; no substitute")
    if platform.machine() != "x86_64" or not shutil.which("docker"):
        raise RuntimeError("requires x86_64 and existing Docker; do not install a fallback")
    memory = dict((k, int(v.split()[0]) * 1024)
                  for k, v in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()))
    if memory["MemAvailable"] < 4 * 1024**3 or shutil.disk_usage(out).free < 12 * 1024**3:
        raise RuntimeError("requires 4 GiB available RAM and 12 GiB free workspace")
    info = json.loads(runtime.command("docker-info", ["docker", "info", "--format", "{{json .}}"]))
    free = int(runtime.command("docker-disk-space",
               ["sudo", "-n", "df", "-B1", "--output=avail", info["DockerRootDir"]]).splitlines()[-1])
    if free < 12 * 1024**3:
        raise RuntimeError("requires 12 GiB free Docker backing storage")
    names = runtime.command("container-collision-check", ["docker", "ps", "-a", "--format", "{{.Names}}"])
    if any(x.startswith("pask-ros-") for x in names.splitlines()):
        raise RuntimeError("existing experiment container names; stop, do not remove them")
    runtime.write(out / "local-preflight.json", {
        "mode": "explicit local, not GitHub event", "architecture": platform.machine(),
        "available_ram_bytes": memory["MemAvailable"], "docker_free_bytes": free,
        "source_map_sha256": hashlib.sha256((HERE / "SOURCE_MAP.json").read_bytes()).hexdigest()})


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan", "all", "reopen"))
    p.add_argument("--output", type=Path)
    p.add_argument("--bundle", type=Path)
    p.add_argument("--execute", action="store_true", help="explicit operator execution, never implied by a plan")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    verify_source()
    if args.action == "plan":
        print(json.dumps({"execution": False, "stages": [
            "host prerequisites and source identities", "networked dependency/image build and inventories",
            "offline typed-smoke/2 48 fixed cases", "clean/scenario/missing-stream capture and final export",
            "separate bag reopen", "separate-image recipient and altered-export negative"],
            "source": "visible files; no compressed runtime source payload",
            "limits": {"cpu": 1, "memory_MiB": 256, "pids": 96,
                       "runtime_seconds_each": 60, "raw_evidence_bytes": 20 * 1024**2},
            "reopen": "existing local capture image, explicit read-only bundle mount; no replay publication",
            "new_tree_ROS_status": "not executed"}, indent=2))
        return 0
    if not args.execute or args.output is None:
        raise ValueError("execution requires --execute and a new --output path")
    out = args.output.resolve()
    if out.exists() or HERE == out or HERE in out.parents:
        raise ValueError("output must be a new directory outside source")
    if args.action == "reopen" and (args.bundle is None or not args.bundle.is_dir()):
        raise ValueError("reopen requires an existing --bundle directory")
    out.mkdir(parents=True, exist_ok=False)
    runtime.OUT, runtime.WORK = out, out / "build"
    runtime.CONTAINERS = []
    runtime.STAGE = "local-host-preflight"
    # Cooperating local entry points cannot race over the reviewed container names.
    with open("/tmp/pask-ros-maintenance.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = {"status": "failed", "execution": "local; not hosted", "action": args.action}
        try:
            host_preflight(out)
            if args.action == "all":
                runtime.WORK.mkdir()
                runtime.STAGE = "networked-dependency-build"
                runtime.build(HERE)
                runtime.test(HERE)
            else:
                runtime.STAGE = "read-only-bag-reopen"
                runtime.command("existing-capture-image", ["docker", "image", "inspect", runtime.CAPTURE_IMAGE])
                runtime.runtime("reopen-local", runtime.CAPTURE_IMAGE, out / "reopen",
                    runtime.ros_argv("reopen"), [(HERE / "probe.py", "/probe.py"),
                                               (args.bundle.resolve(), "/bundle")])
            status["status"] = "expected-outcomes-met"
        except Exception as exc:
            status["error"] = repr(exc)
            try:
                (out / "failure-traceback.txt").write_text(traceback.format_exc())
            except Exception as secondary:
                status["failure_record_error"] = repr(secondary)
        finally:
            for name in runtime.CONTAINERS:
                try:
                    runtime.command("cleanup-" + name, ["docker", "rm", "-f", name], accept=(0, 1))
                except Exception as exc:
                    status.setdefault("cleanup_errors", []).append(repr(exc))
                    status["status"] = "failed"
            status["last_stage"] = runtime.STAGE
            # Build source is not runtime evidence; preserve it, but do not count it as an observation.
            try:
                status["evidence_bytes"] = sum(p.stat().st_size for p in out.rglob("*")
                                               if p.is_file() and runtime.WORK not in p.parents)
                if status["evidence_bytes"] > 20 * 1024**2:
                    status["status"] = "evidence-size-budget-exceeded"
            except Exception as secondary:
                status["evidence_inventory_error"] = repr(secondary)
                status["status"] = "evidence-preservation-failed"
            try:
                runtime.write(out / "local-attempt-summary.json", status)
            except Exception as secondary:
                status["summary_error"] = repr(secondary)
                status["status"] = "evidence-preservation-failed"
                print(json.dumps(status), file=sys.stderr)
        return 0 if status["status"] == "expected-outcomes-met" else 1


if __name__ == "__main__":
    raise SystemExit(main())
