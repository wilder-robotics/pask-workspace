#!/usr/bin/env bash
# ===================================================================
# revision_guard.sh - keep KNOWN-LIMITATIONS.md honest about which
# revision and which profile identifier it is describing.
#
# Why this exists
#
#   On 2026-09-04 the -03 revision merged with KNOWN-LIMITATIONS.md
#   claiming `wilder.pser/0.4` while the code had already moved to
#   `wilder.pser/0.5`. Nobody noticed, because nothing checked. The
#   file also carried eleven present-tense references to `-01` under a
#   header saying it applied to `-03`.
#
#   Neither error is subtle. Both survived because the only control
#   was a person remembering, and this desk has logged three separate
#   stale-item failures whose single common feature was exactly that.
#   So this is mechanical and runs on every pull request.
#
# What it checks
#
#   [1] The "Applies to" header names the one revision file under docs/.
#   [2] The "Profile identifier in the implementation" header equals
#       SPEC_VERSION in crates/pask-wire/src/payload.rs.
#   [3] Ratchet: the number of references to a revision OTHER than the
#       current one may not exceed the count recorded in
#       .revision-guard-baseline. Historical references are legitimate
#       ("`-01` made registration mandatory" is true and stays true).
#       New drift is not. The baseline may only go down.
#
# Check [3] is a ratchet rather than a ban on purpose. Banning stale
# references outright would force a rewrite of legitimate history and
# would be argued around within a month. A number that may only fall
# cannot be argued around.
#
# Exit codes
#   0  PASS
#   1  FAIL
#   2  Usage or environment error
#
# Usage
#   bash scripts/revision_guard.sh
#   bash scripts/revision_guard.sh --update-baseline   # after a cleanup pass
# ===================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

LIMITS="KNOWN-LIMITATIONS.md"
PAYLOAD="crates/pask-wire/src/payload.rs"
BASELINE=".revision-guard-baseline"

for f in "$LIMITS" "$PAYLOAD"; do
  [ -f "$f" ] || { echo "revision_guard: missing $f" >&2; exit 2; }
done

fail=0
note() { printf '  %s\n' "$1"; }

# --- current revision, from the single file under docs/ ---------------
mapfile -t drafts < <(find docs -maxdepth 1 -name 'draft-*-[0-9][0-9].md' | sort)
if [ "${#drafts[@]}" -ne 1 ]; then
  echo "revision_guard: expected exactly one revision under docs/, found ${#drafts[@]}" >&2
  exit 2
fi
DRAFT_BASE="$(basename "${drafts[0]}" .md)"
CUR="${DRAFT_BASE##*-}"          # e.g. 03

echo "revision_guard: current revision -$CUR ($DRAFT_BASE)"

# --- [1] Applies-to header -------------------------------------------
echo "--- [1] Applies to header names the in-tree revision ---"
if grep -qF "$DRAFT_BASE" <(grep -m1 '^| Applies to' "$LIMITS" || true); then
  note "PASS"
else
  note "FAIL: 'Applies to' does not name $DRAFT_BASE"
  note "      $(grep -m1 '^| Applies to' "$LIMITS" || echo '(header row absent)')"
  fail=1
fi

# --- [2] Profile identifier matches the code -------------------------
echo "--- [2] Profile identifier matches SPEC_VERSION ---"
CODE_VER="$(sed -n 's/.*SPEC_VERSION[^"]*"\([^"]*\)".*/\1/p' "$PAYLOAD" | head -1)"
DOC_VER="$(sed -n 's/^| Profile identifier in the implementation *| *`\([^`]*\)`.*/\1/p' "$LIMITS" | head -1)"
if [ -z "$CODE_VER" ]; then
  note "FAIL: could not read SPEC_VERSION from $PAYLOAD"; fail=1
elif [ -z "$DOC_VER" ]; then
  note "FAIL: could not read the profile identifier row from $LIMITS"; fail=1
elif [ "$CODE_VER" = "$DOC_VER" ]; then
  note "PASS: both say $CODE_VER"
else
  note "FAIL: $LIMITS says $DOC_VER, $PAYLOAD says $CODE_VER"
  fail=1
fi

# --- [3] Stale-reference ratchet --------------------------------------
echo "--- [3] Non-current revision references may not increase ---"
STALE="$(grep -o '`-0[0-9]`' "$LIMITS" | grep -cv "^\`-$CUR\`$" || true)"
if [ -f "$BASELINE" ]; then
  ALLOWED="$(tr -cd '0-9' < "$BASELINE")"
else
  ALLOWED=""
fi

if [ "${1:-}" = "--update-baseline" ]; then
  printf '%s\n' "$STALE" > "$BASELINE"
  note "baseline updated to $STALE"
  ALLOWED="$STALE"
fi

if [ -z "$ALLOWED" ]; then
  note "FAIL: no $BASELINE. Run: bash scripts/revision_guard.sh --update-baseline"
  fail=1
elif [ "$STALE" -le "$ALLOWED" ]; then
  note "PASS: $STALE references to other revisions, baseline $ALLOWED"
  if [ "$STALE" -lt "$ALLOWED" ]; then
    note "      baseline can be lowered to $STALE (--update-baseline)"
  fi
else
  note "FAIL: $STALE references to other revisions, baseline is $ALLOWED"
  note "      A new stale reference was added. Point it at -$CUR, or if it is"
  note "      genuinely historical, raise the baseline deliberately and say why."
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
