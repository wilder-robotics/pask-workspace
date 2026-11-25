#!/usr/bin/env bash
# Run the pinned external scitt-verifier CLI against named inputs.
#
# The binary comes from https://github.com/microsoft/scitt-verifier at
# 7bb6054a6feb0c286924042504fe9cbf5cf6bfe5. It is an external process.
# It is not a Cargo dependency of pask-wire, pask-attest, or pask-wire-cli.
#
# This run is offline. The script refuses --online. Exit 3 is not a pass
# unless the case's documented diagnostic is present.
#
# Usage:
#   bash scripts/scitt_verifier_cases.sh --self-test
#   SCITT_VERIFIER_SRC=/path/to/checkout bash scripts/scitt_verifier_cases.sh
#   SCITT_VERIFIER_BIN=/path/to/scitt-verifier \
#     SCITT_VERIFIER_SRC=/path/to/checkout \
#     bash scripts/scitt_verifier_cases.sh
#
# SCITT_VERIFIER_TOOLCHAIN defaults to 1.89.0 when the script builds the CLI.

set -euo pipefail

PINNED_REV="7bb6054a6feb0c286924042504fe9cbf5cf6bfe5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JUDGE="$ROOT/tests/scitt-verifier/judge.py"
POLICY="$ROOT/tests/scitt-verifier/offline-policy.json"
TOOLCHAIN="${SCITT_VERIFIER_TOOLCHAIN:-1.89.0}"

if [ "${1:-}" = "--self-test" ]; then
  python3 "$JUDGE" --self-test
  exit 0
fi

if [ "$#" -ne 0 ]; then
  echo "usage: bash scripts/scitt_verifier_cases.sh [--self-test]" >&2
  exit 2
fi

cd "$ROOT"

fail() {
  echo "scitt-verifier cases: $*" >&2
  exit 1
}

rustc_at_least_189() {
  local version="$1"
  local major minor
  version="${version#rustc }"
  version="${version%% *}"
  major="${version%%.*}"
  minor="${version#*.}"
  minor="${minor%%.*}"
  [ "$major" -gt 1 ] && return 0
  [ "$major" -eq 1 ] && [ "$minor" -ge 89 ]
}

require_pinned_src() {
  local src="$1"
  [ -d "$src/.git" ] || fail "checker checkout is missing at $src. A missing checkout is a fetch failure, not a Pask result."
  local actual
  actual="$(git -C "$src" rev-parse HEAD)"
  if [ "$actual" != "$PINNED_REV" ]; then
    fail "checker checkout $src is $actual, not pinned $PINNED_REV. Refusing to treat another revision as this pin."
  fi
}

invoke_checker() {
  local arg
  for arg in "$@"; do
    if [ "$arg" = "--online" ]; then
      fail "refusing --online; this run is offline"
    fi
  done
  "$@"
}

sha256_file() {
  python3 - "$1" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

require_sha256() {
  local path="$1" expected="$2" got
  got="$(sha256_file "$path")"
  if [ "$got" != "$expected" ]; then
    fail "$path sha256 $got does not match committed $expected. The input was not rewritten, and the checker was not run on it."
  fi
}

write_dummy_keyset() {
  local path="$1"
  python3 - "$path" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])

def uint(n, major):
    if n < 24:
        return bytes([major | n])
    if n < 256:
        return bytes([major | 24, n])
    raise SystemExit(f"value does not fit in one length byte: {n}")

def cbor_int(value):
    if value >= 0:
        return uint(value, 0x00)
    return uint(-1 - value, 0x20)

def bstr(data):
    return uint(len(data), 0x40) + data

def tstr(text):
    raw = text.encode("ascii")
    return uint(len(raw), 0x60) + raw

kid = "0000000000000000000000000000000000000000000000000000000000000001"
if len(kid) != 64:
    raise SystemExit("dummy kid must be 64 hex characters")
pairs = [
    (1, cbor_int(2)),
    (2, tstr(kid)),
    (-1, cbor_int(1)),
    (-2, bstr(bytes([0x01]) * 32)),
    (-3, bstr(bytes([0x02]) * 32)),
]
body = b"".join(cbor_int(key) + value for key, value in pairs)
encoded = bytes([0x81, 0xA5]) + body
path.write_bytes(encoded)
print(f"dummy COSE_KeySet bytes={len(encoded)} sha256=", end="")
import hashlib
print(hashlib.sha256(encoded).hexdigest())
PY
}

assert_definite_cbor() {
  python3 - "$1" <<'PY'
import pathlib, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
i = 0

def take(n):
    global i
    if i + n > len(data):
        raise SystemExit("truncated CBOR")
    chunk = data[i:i + n]
    i += n
    return chunk

def value():
    global i
    first = take(1)[0]
    major, info = first >> 5, first & 0x1F
    if info == 31:
        raise SystemExit(f"indefinite-length CBOR at offset {i - 1}")
    if info < 24:
        argument = info
    elif info == 24:
        argument = take(1)[0]
    elif info == 25:
        argument = int.from_bytes(take(2), "big")
    elif info == 26:
        argument = int.from_bytes(take(4), "big")
    elif info == 27:
        argument = int.from_bytes(take(8), "big")
    else:
        raise SystemExit(f"unsupported CBOR additional info {info}")
    if major in (0, 1, 7):
        return
    if major in (2, 3):
        take(argument)
        return
    if major == 4:
        for _ in range(argument):
            value()
        return
    if major == 5:
        for _ in range(argument):
            value()
            value()
        return
    if major == 6:
        value()
        return
    raise SystemExit(f"unsupported CBOR major type {major}")

value()
if i != len(data):
    raise SystemExit(f"trailing bytes after one CBOR value: {len(data) - i}")
print(f"definite-length CBOR bytes={len(data)}")
PY
}

expected_from_manifest() {
  python3 - "$ROOT/crates/pask-wire/tests/fixtures/phase3/manifest.json" "$1" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
print(manifest["files"][sys.argv[2]])
PY
}

expected_from_sums() {
  python3 - "$ROOT/evidence/issue-100/2026-09-28/SHA256SUMS" "$1" <<'PY'
import sys
name = sys.argv[2]
for line in open(sys.argv[1], encoding="utf-8"):
    digest, filename = line.split()
    if filename == name:
        print(digest)
        break
else:
    raise SystemExit(f"{name} is not listed in SHA256SUMS")
PY
}

portable_command() {
  python3 - "$ROOT" "${SCITT_VERIFIER_SRC}" "$@" <<'PY'
import sys
root, src, *args = sys.argv[1:]
out = []
for index, arg in enumerate(args):
    name = arg.rsplit("/", 1)[-1]
    if index == 0:
        out.append("scitt-verifier")
    elif arg.startswith(src + "/"):
        out.append("<scitt-verifier>" + arg[len(src):])
    elif arg.startswith(root + "/"):
        out.append(arg[len(root) + 1:])
    elif name == "native-pser05.cose":
        out.append("<generated-pser-0.5.cose>")
    elif name == "dummy-cose-keyset.cbor":
        out.append("<dummy-cose-keyset.cbor>")
    else:
        out.append(arg)
print(" ".join(out))
PY
}

RUN="$(mktemp -d)"
trap 'rm -rf "$RUN"' EXIT

echo "judge self-test"
python3 "$JUDGE" --self-test

SRC="${SCITT_VERIFIER_SRC:-}"
[ -n "$SRC" ] || fail "SCITT_VERIFIER_SRC is unset. Point it at a checkout of microsoft/scitt-verifier. Do not vendor that tree into this repository."
require_pinned_src "$SRC"

if [ -n "${SCITT_VERIFIER_BIN:-}" ]; then
  BIN="$SCITT_VERIFIER_BIN"
  [ -x "$BIN" ] || fail "SCITT_VERIFIER_BIN is not executable: $BIN"
  rustc_version="$(RUSTUP_TOOLCHAIN="$TOOLCHAIN" rustc --version)"
  rustc_at_least_189 "$rustc_version" || fail "toolchain $TOOLCHAIN is $rustc_version; the pinned checker needs rustc 1.89 or newer"
else
  echo "building scitt-verifier at $PINNED_REV with toolchain $TOOLCHAIN"
  rustc_version="$(RUSTUP_TOOLCHAIN="$TOOLCHAIN" rustc --version)"
  rustc_at_least_189 "$rustc_version" || fail "toolchain $TOOLCHAIN is $rustc_version; the pinned checker needs rustc 1.89 or newer"
  (
    cd "$SRC"
    RUSTUP_TOOLCHAIN="$TOOLCHAIN" cargo build --locked -p scitt-verifier
  )
  BIN="$SRC/target/debug/scitt-verifier"
  [ -x "$BIN" ] || fail "build did not produce $BIN. This is a checker build failure, not a Pask result."
fi

echo "checker: $BIN"
echo "checker rustc: $rustc_version"
"$BIN" --version

PHASE3_ATTACHED="$ROOT/crates/pask-wire/tests/fixtures/phase3/attached-transparent.cbor"
PHASE3_DETACHED="$ROOT/crates/pask-wire/tests/fixtures/phase3/detached-transparent.cbor"
EVIDENCE="$ROOT/evidence/issue-100/2026-09-28/transparent-statement.cose"
require_sha256 "$PHASE3_ATTACHED" "$(expected_from_manifest attached-transparent.cbor)"
require_sha256 "$PHASE3_DETACHED" "$(expected_from_manifest detached-transparent.cbor)"
require_sha256 "$EVIDENCE" "$(expected_from_sums transparent-statement.cose)"

KEYS="$RUN/dummy-cose-keyset.cbor"
write_dummy_keyset "$KEYS"

echo "generating PSER 0.5 statement with pask-wire example export_fixture"
cargo run -q --locked -p pask-wire --features alloc --example export_fixture >"$RUN/export_fixture.txt"
python3 - "$RUN/export_fixture.txt" "$RUN/native-pser05.cose" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
prefix = "final_statement_hex: "
for line in text.splitlines():
    if line.startswith(prefix):
        pathlib.Path(sys.argv[2]).write_bytes(bytes.fromhex(line[len(prefix):].strip()))
        break
else:
    raise SystemExit("export_fixture did not print final_statement_hex")
PY
assert_definite_cbor "$RUN/native-pser05.cose"
echo "generated statement sha256=$(sha256_file "$RUN/native-pser05.cose")"

failures=0
run_case() {
  local id="$1"
  shift
  local stdout="$RUN/${id}.json"
  local stderr="$RUN/${id}.err"
  local code=0
  set +e
  invoke_checker "$@" >"$stdout" 2>"$stderr"
  code=$?
  set -e
  local shown
  shown="$(portable_command "$@")"
  echo "$shown" >"$RUN/${id}.cmd"
  echo "$code" >"$RUN/${id}.exit"
  echo "CASE $id"
  echo "  command: $shown"
  echo "  exit: $code"
  if python3 "$JUDGE" "$id" "$code" "$stdout"; then
    echo "  expectation: met"
  else
    echo "  expectation: NOT MET"
    if [ -s "$stderr" ]; then
      echo "  stderr:"
      sed 's/^/    /' "$stderr"
    fi
    failures=$((failures + 1))
  fi
}

run_case C1 "$BIN" verify \
  --statement "$SRC/corpus/fixtures/transparent-statement.cose" \
  --scitt-keys "$SRC/corpus/fixtures/mst-test-scitt-keys.cbor" \
  --policy "$SRC/corpus/policies/fixture-mst.json" \
  --format json

run_case C2 "$BIN" inspect \
  --statement "$RUN/native-pser05.cose" \
  --format json

run_case C3 "$BIN" verify \
  --statement "$RUN/native-pser05.cose" \
  --scitt-keys "$KEYS" \
  --policy "$POLICY" \
  --format json

run_case C4 "$BIN" verify \
  --statement "$PHASE3_ATTACHED" \
  --scitt-keys "$KEYS" \
  --policy "$POLICY" \
  --format json

run_case C4d "$BIN" verify \
  --statement "$PHASE3_DETACHED" \
  --scitt-keys "$KEYS" \
  --policy "$POLICY" \
  --format json

run_case C5 "$BIN" inspect \
  --statement "$EVIDENCE" \
  --format json

run_case C6 "$BIN" verify \
  --statement "$EVIDENCE" \
  --scitt-keys "$KEYS" \
  --policy "$POLICY" \
  --format json

echo
if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) did not match the documented expectation."
  echo "Exit 3 is not a pass without that expectation."
  exit 1
fi
echo "All checker cases matched their documented expectations."
echo "Checker commit: $PINNED_REV"
echo "Checker rustc: $rustc_version"
