#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Materialize the small actual-data regression selection without execution."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent


def materialize(output):
    output = Path(output)
    index = json.loads((ROOT / "fixtures/INDEX.json").read_text())
    archive = ROOT / "fixtures/actual-five.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != index["archive_sha256"]:
        raise ValueError("fixture archive checksum mismatch")
    if output.exists():
        raise ValueError("fixture output must not already exist")
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if (len(names) > 1024 or len(set(names)) != len(names)
                or sum(m.size for m in members) > 10 * 1024**2
                or set(names) != set(index["selected_files"])):
            raise ValueError("fixture inventory mismatch or cap exceeded")
        for item in members:
            path = Path(item.name)
            if not item.isfile() or path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe fixture member")
            raw = tar.extractfile(item).read()
            expected = index["selected_files"][item.name]
            if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise ValueError("fixture member checksum mismatch: " + item.name)
        output.mkdir(parents=True, exist_ok=False)
        tar.extractall(output, filter="data")
    return index


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = materialize(args.output)
    print(json.dumps({"files": len(result["selected_files"]), "verified": True,
                      "output": str(args.output), "execution": "no ROS/Docker/runtime"}))
