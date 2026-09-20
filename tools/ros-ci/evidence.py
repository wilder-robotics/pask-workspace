# SPDX-License-Identifier: Apache-2.0
"""Bounded, indexed log transport. Digests establish equality, not provenance."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

RAW_LIMIT = 20 * 1024**2
GZIP_LIMIT = 4 * 1024**2
TAR_LIMIT = 32 * 1024**2
FILE_LIMIT = 4096
PREFIX = "PASK_EVIDENCE_V1 "


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_name(name):
    p = PurePosixPath(name)
    return (bool(p.parts) and str(p) == name and not p.is_absolute()
            and ".." not in p.parts and "\\" not in name)


def pack(files):
    if len(files) > FILE_LIMIT or sum(len(v) for v in files.values()) > RAW_LIMIT:
        raise ValueError("raw evidence budget exceeded")
    manifest = {}
    for name, raw in files.items():
        if not safe_name(name) or name == "TRANSPORT_INDEX.json":
            raise ValueError("unsafe or reserved evidence path")
        manifest[name] = {"sha256": sha(raw), "sizeBytes": len(raw)}
    index = json.dumps({"version": 1, "files": manifest}, sort_keys=True).encode()
    raw_out = io.BytesIO()
    with tarfile.open(fileobj=raw_out, mode="w") as tar:
        for name, raw in sorted({**files, "TRANSPORT_INDEX.json": index}.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o644, 0
            tar.addfile(info, io.BytesIO(raw))
    if raw_out.tell() > TAR_LIMIT:
        raise ValueError("tar budget exceeded")
    compressed = gzip.compress(raw_out.getvalue(), mtime=0)
    if len(compressed) > GZIP_LIMIT:
        raise ValueError("compressed evidence budget exceeded")
    return compressed


def verify_archive(compressed):
    if len(compressed) > GZIP_LIMIT:
        raise ValueError("gzip budget exceeded")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(TAR_LIMIT + 1)
    if len(raw) > TAR_LIMIT:
        raise ValueError("expanded archive budget exceeded")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar:
            if not member.isfile() or not safe_name(member.name) or member.name in files:
                raise ValueError("unsafe, duplicate or nonregular member")
            if len(files) >= FILE_LIMIT + 1 or member.size > RAW_LIMIT:
                raise ValueError("member budget exceeded")
            files[member.name] = tar.extractfile(member).read()
    index = json.loads(files.pop("TRANSPORT_INDEX.json"))
    if index["version"] != 1 or set(index["files"]) != set(files):
        raise ValueError("archive inventory mismatch")
    if sum(map(len, files.values())) > RAW_LIMIT:
        raise ValueError("raw payload budget exceeded")
    for name, raw in files.items():
        if index["files"][name] != {"sha256": sha(raw), "sizeBytes": len(raw)}:
            raise ValueError("file checksum mismatch")
    return files


def encode(compressed):
    verify_archive(compressed)
    text = base64.b64encode(compressed).decode("ascii")
    chunks = [text[i:i+3072] for i in range(0, len(text), 3072)]
    header = {"sha256": sha(compressed), "gzipBytes": len(compressed), "chunks": len(chunks)}
    lines = [PREFIX + "BEGIN " + json.dumps(header, sort_keys=True)]
    lines.extend(PREFIX + f"CHUNK {i+1:06d}/{len(chunks):06d} " + text
                 for i, text in enumerate(chunks))
    lines.append(PREFIX + "END " + header["sha256"])
    return "\n".join(lines) + "\n"


def decode(text):
    # GitHub's downloaded logs may add a timestamp before the marker.
    lines = [line[line.index(PREFIX):].strip() for line in text.splitlines() if PREFIX in line]
    if not lines or not lines[0].startswith(PREFIX + "BEGIN "):
        raise ValueError("missing transport header")
    header = json.loads(lines[0][len(PREFIX + "BEGIN "):])
    count = header["chunks"]
    if not isinstance(count, int) or not 1 <= count <= 2048 or len(lines) != count + 2:
        raise ValueError("missing, repeated or excessive chunks")
    chunks = []
    for i, line in enumerate(lines[1:-1], 1):
        prefix = PREFIX + f"CHUNK {i:06d}/{count:06d} "
        if not line.startswith(prefix):
            raise ValueError("chunk index mismatch")
        chunk = line[len(prefix):]
        if not re.fullmatch(r"[A-Za-z0-9+/=]{1,3072}", chunk):
            raise ValueError("malformed chunk")
        chunks.append(chunk)
    compressed = base64.b64decode("".join(chunks), validate=True)
    if len(compressed) != header["gzipBytes"] or sha(compressed) != header["sha256"]:
        raise ValueError("transport checksum mismatch")
    if lines[-1] != PREFIX + "END " + sha(compressed):
        raise ValueError("missing transport footer")
    return compressed, verify_archive(compressed)


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("log", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.log.stat().st_size > 16 * 1024**2 or args.output.exists():
        raise ValueError("log too large or output already exists")
    first, files = decode(args.log.read_text())
    second, repeated = decode(args.log.read_text())
    if first != second or files != repeated:
        raise ValueError("two independent reads disagreed")
    args.output.mkdir(parents=True)
    (args.output / "evidence.tar.gz").write_bytes(first)
    root = args.output / "files"
    for name, raw in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (args.output / "DECODE_VERIFIED.json").write_text(json.dumps({
        "sha256": sha(first), "gzipBytes": len(first), "files": len(files),
        "checksumVerifiedDecodes": 2,
        "origin": "unsigned job-log equality only; not authenticated issuer provenance"}, indent=2) + "\n")


if __name__ == "__main__":
    main()
