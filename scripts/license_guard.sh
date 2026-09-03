#!/usr/bin/env bash
# license_guard.sh — enforce the mixed-license split recorded in LICENSING.md.
#
# The repository is deliberately not licensed uniformly. `pask-wire` and
# `pask-attest` are Apache-2.0 because they are the specification made
# executable and exist to be copied by anyone implementing the profile. The
# operational crates are AGPL-3.0-only. That split is only sound in one
# direction, and the ways to silently break it are easy to reach by accident:
#
#   1. Add a dependency from a permissive crate onto an AGPL crate. The
#      permissive crate's stated license then becomes a false statement.
#   2. Add a copyleft third-party dependency to a permissive crate. Same
#      outcome, arriving from outside the workspace.
#   3. Copy a source file between crates and carry its SPDX header along, so a
#      file's header contradicts its crate's manifest.
#   4. Add a new .rs file with no SPDX header at all.
#   5. Add a new workspace member and forget to decide which side it is on.
#
# This script fails on all five. It is not a substitute for legal review; it is
# a guard against the mechanical mistakes.
#
# Usage:  bash scripts/license_guard.sh
# Exit:   0 all checks pass, 1 a violation was found, 2 the script itself is
#         misconfigured (e.g. run from the wrong directory).

set -uo pipefail

VERSION="1.1.0"
echo "license_guard.sh v${VERSION}"
echo

# ---------------------------------------------------------------------------
# The split. Edit here and in LICENSING.md together, never one alone.
# ---------------------------------------------------------------------------
PERMISSIVE_CRATES=(pask-wire pask-attest pask-wire-cli)
COPYLEFT_CRATES=(pask-site pask-adapter)

PERMISSIVE_SPDX="Apache-2.0"
COPYLEFT_SPDX="AGPL-3.0-only"

# Third-party crates permitted as direct dependencies of a permissive crate.
# Every entry was license-checked against crates.io. Adding a name here without
# checking its license defeats the purpose of the check.
#   coset            Apache-2.0
#   ryu-js           Apache-2.0 OR BSL-1.0
#   ed25519-dalek    BSD-3-Clause
#   p256             Apache-2.0 OR MIT
#   serde            MIT OR Apache-2.0
#   serde_json       MIT OR Apache-2.0
#   sha2             MIT OR Apache-2.0
#   time             MIT OR Apache-2.0
#   thiserror        MIT OR Apache-2.0
#   proptest         MIT OR Apache-2.0
#   rand_core        MIT OR Apache-2.0
#   anyhow           MIT OR Apache-2.0
#   clap             MIT OR Apache-2.0
PERMISSIVE_DEP_ALLOWLIST=(
  coset ryu-js ed25519-dalek p256 serde serde_json sha2 time thiserror
  proptest rand_core anyhow clap
)

if [[ ! -f Cargo.toml || ! -d crates ]]; then
  echo "FAIL(config): run this from the repository root." >&2
  exit 2
fi
if [[ ! -f LICENSING.md ]]; then
  echo "FAIL(config): LICENSING.md is missing. It is the authoritative map this script enforces." >&2
  exit 2
fi

failures=0
fail() { echo "  VIOLATION: $*"; failures=$((failures + 1)); }

in_list() { local n=$1; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }

crate_license_field() {
  # Prints the literal license value from a crate manifest, or "workspace".
  local f="crates/$1/Cargo.toml"
  if grep -qE '^[[:space:]]*license\.workspace[[:space:]]*=[[:space:]]*true' "$f"; then
    echo workspace
  else
    grep -E '^[[:space:]]*license[[:space:]]*=' "$f" | head -1 | sed -E 's/.*=[[:space:]]*"([^"]*)".*/\1/'
  fi
}

workspace_license() {
  grep -E '^[[:space:]]*license[[:space:]]*=' Cargo.toml | head -1 | sed -E 's/.*=[[:space:]]*"([^"]*)".*/\1/'
}

# Direct internal + external dependency names of a crate, across all three
# dependency tables.
crate_deps() {
  awk '
    /^\[(dependencies|dev-dependencies|build-dependencies)\]/ { in_deps=1; next }
    /^\[/ { in_deps=0 }
    in_deps && /^[A-Za-z0-9_-]+[[:space:]]*=/ { sub(/[[:space:]]*=.*/, ""); print }
  ' "crates/$1/Cargo.toml"
}

# ---------------------------------------------------------------------------
echo "1. Every workspace member is assigned a side"
# ---------------------------------------------------------------------------
members=$(awk '/^members[[:space:]]*=/,/\]/' Cargo.toml | grep -oE '"crates/[^"]+"' | tr -d '"' | sed 's|crates/||')
for m in $members; do
  if in_list "$m" "${PERMISSIVE_CRATES[@]}" || in_list "$m" "${COPYLEFT_CRATES[@]}"; then
    :
  else
    fail "workspace member '$m' is in neither the permissive nor the copyleft list. Decide which side it is on, record it in LICENSING.md, and add it to this script."
  fi
done
for c in "${PERMISSIVE_CRATES[@]}" "${COPYLEFT_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || fail "crate '$c' is listed in this script but crates/$c does not exist."
done
echo "   checked $(echo "$members" | wc -w | tr -d ' ') members"
echo

# ---------------------------------------------------------------------------
echo "2. Manifest license field matches the assigned side"
# ---------------------------------------------------------------------------
ws=$(workspace_license)
for c in "${PERMISSIVE_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  got=$(crate_license_field "$c")
  [[ "$got" == "$PERMISSIVE_SPDX" ]] || fail "crates/$c/Cargo.toml declares license '$got', expected '$PERMISSIVE_SPDX'. A permissive crate must not inherit the workspace default."
done
for c in "${COPYLEFT_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  got=$(crate_license_field "$c")
  if [[ "$got" == "workspace" ]]; then
    [[ "$ws" == "$COPYLEFT_SPDX" ]] || fail "crates/$c inherits the workspace license, but the workspace declares '$ws', expected '$COPYLEFT_SPDX'."
  else
    [[ "$got" == "$COPYLEFT_SPDX" ]] || fail "crates/$c/Cargo.toml declares license '$got', expected '$COPYLEFT_SPDX'."
  fi
done
echo "   workspace default is '$ws'"
echo

# ---------------------------------------------------------------------------
echo "3. No permissive crate depends on a copyleft crate"
# ---------------------------------------------------------------------------
for c in "${PERMISSIVE_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  while read -r d; do
    [[ -z "$d" ]] && continue
    if in_list "$d" "${COPYLEFT_CRATES[@]}"; then
      fail "crates/$c depends on '$d', which is $COPYLEFT_SPDX. This makes $c's stated $PERMISSIVE_SPDX license false. If $c needs something from $d, that code is in the wrong crate."
    fi
  done < <(crate_deps "$c")
done
echo "   dependency direction checked for ${#PERMISSIVE_CRATES[@]} permissive crates"
echo

# ---------------------------------------------------------------------------
echo "4. No unreviewed third-party dependency in a permissive crate"
# ---------------------------------------------------------------------------
for c in "${PERMISSIVE_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  while read -r d; do
    [[ -z "$d" ]] && continue
    in_list "$d" "${PERMISSIVE_CRATES[@]}" && continue   # internal, handled above
    in_list "$d" "${COPYLEFT_CRATES[@]}" && continue     # internal, handled above
    if ! in_list "$d" "${PERMISSIVE_DEP_ALLOWLIST[@]}"; then
      fail "crates/$c depends on third-party crate '$d', which is not on the license-checked allowlist in scripts/license_guard.sh. Check its license on crates.io; if it is permissive, add it to the allowlist with its license in the comment. If it is copyleft, it cannot go in a permissive crate."
    fi
  done < <(crate_deps "$c")
done
echo "   allowlist holds ${#PERMISSIVE_DEP_ALLOWLIST[@]} reviewed crates"
echo

# ---------------------------------------------------------------------------
echo "5. Every .rs file carries an SPDX header matching its crate"
# ---------------------------------------------------------------------------
total=0
for c in "${PERMISSIVE_CRATES[@]}" "${COPYLEFT_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  if in_list "$c" "${PERMISSIVE_CRATES[@]}"; then want="$PERMISSIVE_SPDX"; else want="$COPYLEFT_SPDX"; fi
  while IFS= read -r f; do
    total=$((total + 1))
    line=$(grep -m1 "SPDX-License-Identifier:" "$f" || true)
    if [[ -z "$line" ]]; then
      fail "$f has no SPDX-License-Identifier header. Expected '// SPDX-License-Identifier: $want'."
      continue
    fi
    got=$(printf '%s' "$line" | sed -E 's/.*SPDX-License-Identifier:[[:space:]]*//' | tr -d '[:space:]')
    [[ "$got" == "$want" ]] || fail "$f declares SPDX '$got' but its crate is $want. A file copied between crates must have its header updated."
  done < <(find "crates/$c" -name '*.rs' -type f)
done
echo "   checked $total source files"
echo

# ---------------------------------------------------------------------------
echo "6. License texts and the authoritative map are present"
# ---------------------------------------------------------------------------
[[ -f LICENSE ]] || fail "LICENSE (the $COPYLEFT_SPDX text) is missing."
[[ -f LICENSE-APACHE-2.0 ]] || fail "LICENSE-APACHE-2.0 (the $PERMISSIVE_SPDX text) is missing."
grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" LICENSE 2>/dev/null || fail "LICENSE does not contain the AGPL text."
grep -q "Apache License" LICENSE-APACHE-2.0 2>/dev/null || fail "LICENSE-APACHE-2.0 does not contain the Apache text."
for c in "${PERMISSIVE_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  [[ -f "crates/$c/LICENSE" ]] || fail "crates/$c/LICENSE is missing. A vendored crate directory must be unambiguous on its own."
done
echo "   license texts present"
echo

# ---------------------------------------------------------------------------
echo "7. No file contradicts its own SPDX line in prose"
# ---------------------------------------------------------------------------
# Check 5 reads only the SPDX line. The relicensing on 2026-09-02 flipped that
# line on 41 files and left the human-readable sentence three lines below it
# still naming the old license, so 17 files in the permissive crates asserted
# Apache-2.0 and AGPL-3.0-only at once and check 5 passed them. Two contradictory
# license statements in a public repository is a defect whether or not a tool
# objects, so the tool now objects.
#
# A file may legitimately name the other side's license when referring to a
# different crate by name — the CLI signposts the AGPL pask-adapt binary. The
# test is therefore whether the sentence is about *this* crate.
prose_checked=0
for c in "${PERMISSIVE_CRATES[@]}" "${COPYLEFT_CRATES[@]}"; do
  [[ -d "crates/$c" ]] || continue
  if printf '%s\n' "${PERMISSIVE_CRATES[@]}" | grep -qx "$c"; then
    own="$PERMISSIVE_SPDX"; other="$COPYLEFT_SPDX"
  else
    own="$COPYLEFT_SPDX"; other="$PERMISSIVE_SPDX"
  fi
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    prose_checked=$((prose_checked + 1))
    if grep -qE "(^|[^-])\b$c is licensed $other\b" "$f"; then
      fail "$f declares SPDX $own but its prose says '$c is licensed $other'. Two contradictory license statements in one file."
    fi
  done < <(find "crates/$c" -name '*.rs' -not -path '*/target/*' 2>/dev/null)
done
echo "   prose checked in $prose_checked source files"
echo

# ---------------------------------------------------------------------------
if (( failures > 0 )); then
  echo "FAIL — $failures violation(s). See LICENSING.md for the split this enforces."
  exit 1
fi
echo "PASS — the license split in LICENSING.md holds."
exit 0
