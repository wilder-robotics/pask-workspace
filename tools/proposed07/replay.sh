#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(mktemp -d)}"
python3 tools/proposed07/generate.py
python3 tools/proposed07/test_migration.py
cargo +stable test --locked -p pask-wire --all-features
cargo +stable check --locked -p pask-wire --no-default-features
cargo +stable clippy --locked -p pask-wire --all-features -- -D warnings
