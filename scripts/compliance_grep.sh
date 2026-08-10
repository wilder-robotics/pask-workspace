#!/usr/bin/env bash
# ===================================================================
# compliance_grep.sh — v1.0.0 (2026-08-09)
#
# Compliance grep for the CODE-REPOSITORY surface: the profile
# document, the README, and every other public-facing text file in
# actionrob/pask-workspace.
#
# Why this exists
# ---------------
# crates/pask-attest/tests/tee_class_rejects_sku.rs has claimed to be
# "EXEMPT from deny-list enforcement" since it was written. No deny-list
# enforcement ran over this repository. A file exempt from a script that
# does not exist asserts an enforcement that is not happening, which is
# worse than no claim at all. Willa raised it on 2026-08-09 and gave it a
# 2026-08-10 deadline: ship the script or withdraw the comment.
#
# Scope boundary — read this before adding a check
# ------------------------------------------------
#   THIS script governs the code repository: docs/, README, and public
#   markdown in actionrob/pask-workspace.
#
#   social_denylist_grep.sh (actionrob/pask-marketing, compliance/)
#   governs X and LinkedIn commentary.
#
#   compliance_grep.sh v1.4+ (actionrob/willa-compliance,
#   willa-strategy/pask-deck/) governs decks and one-pagers.
#
#   Three surfaces, three rule sets. A one-pager may name the product; a
#   social post may not; this repository may and does. Do not copy a
#   check between them without deciding whether the rule actually binds
#   on the destination surface. Sharing a filename with the
#   willa-compliance script is deliberate — it is the name the exemption
#   comment already referred to — but the two are not the same script.
#
# Authority
# ---------
#   PASK-COMPLIANCE-002 / PASK-COMPLIANCE-003, as amended by Willa on
#   2026-08-09 in
#   willa-desk/witness-log/ietf-pask/2026-08-09-panel-ruling-q1-q2b-q3-01-blockers.md
#
#   The amendment, in Willa's words rather than paraphrased: the accepted
#   TEE classes are named in the profile's IANA *TEE Class* registry
#   request and in the filed -00 at lines 381 and 528, so they are public
#   by construction and no deny-list can retract them. What remains
#   prohibited on a public surface is a SKU — a specific part, board,
#   model, or ordering identifier.
#
#   This script enforces that rule. It does not interpret it, extend it,
#   or narrow it. Per Willa's standing rule of the same date, a
#   PASK-COMPLIANCE-NNN doctrine may not be amended in a code commit,
#   which includes this file. If a term below is wrong, that is a consult
#   item, not a patch.
#
# Known-unresolved, and deliberately not encoded here
# ---------------------------------------------------
#   The six accepted values sit at three levels of abstraction, so the
#   class/SKU line this script enforces is not as crisp as its name
#   suggests. Tracked at wilder-robotics/pask-workspace#29 for -02. The
#   script enforces today's ruled boundary, not the better one.
#
# Usage
# -----
#   bash scripts/compliance_grep.sh            # scan the repository
#   bash scripts/compliance_grep.sh --self-test
#
# Exit codes
# ----------
#   0  PASS
#   1  FAIL — a denied term on a governed surface, or a stale exemption
#   2  Usage error
# ===================================================================
set -uo pipefail

VERSION="1.0.0"
cd "$(dirname "$0")/.."

# -------------------------------------------------------------------
# Denied terms: SKU, board, model and ordering identifiers.
#
# Deliberately NOT denied: intel.tdx, amd.sev-snp, arm.cca,
# nvidia.h100-cc, nvidia.jetson-thor-cc, aws.nitro-enclave. Those six are
# the filed registry values. Denying them here would put this script in
# conflict with the document it is meant to protect.
# -------------------------------------------------------------------
DENIED_TERMS=(
  'h200'
  'gh200'
  'gb200'
  'sxm5'
  'sxm6'
  'agx orin'
  'jetson orin'
  'orin nx'
  'a100'
  'l40s'
  'epyc [0-9]'
  'xeon platinum'
  'part number'
  'ordering code'
)

# -------------------------------------------------------------------
# Exempt files. Each entry MUST contain at least one denied term —
# otherwise the exemption is stale and this script fails.
#
# A stale exemption is the same defect as the one that produced this
# script: a claim about enforcement that enforcement does not back.
# -------------------------------------------------------------------
EXEMPT_FILES=(
  'crates/pask-attest/tests/tee_class_rejects_sku.rs'
  'scripts/compliance_grep.sh'
)

is_exempt() {
  local candidate="$1"
  local exempt
  for exempt in "${EXEMPT_FILES[@]}"; do
    [ "${candidate}" = "${exempt}" ] && return 0
  done
  return 1
}

governed_files() {
  # Public-facing text. Rust sources are governed too: a SKU in a doc
  # comment is as public as one in the draft, and rustdoc publishes it.
  git ls-files \
    'docs/**' '*.md' '*.rs' '*.toml' '*.sh' '*.yml' '*.yaml' \
    2>/dev/null
}

# -------------------------------------------------------------------
# Self-test. Runs the matcher against fixtures with known verdicts, so a
# regex that silently stops matching is caught here rather than by a
# violation reaching a public surface.
# -------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  failures=0

  printf 'the accepted classes are intel.tdx and nvidia.h100-cc\n' > "${tmp}/clean.md"
  printf 'we selected an H200 board for the witness device\n' > "${tmp}/dirty.md"

  for term in "${DENIED_TERMS[@]}"; do
    if ! printf 'x %s x\n' "${term//\[0-9\]/4}" | grep -qiE "${term}"; then
      echo "SELF-TEST FAIL: term '${term}' does not match its own example"
      failures=$((failures + 1))
    fi
  done

  if ! grep -qiE "$(IFS='|'; echo "${DENIED_TERMS[*]}")" "${tmp}/dirty.md"; then
    echo "SELF-TEST FAIL: a known-dirty fixture did not match"
    failures=$((failures + 1))
  fi
  if grep -qiE "$(IFS='|'; echo "${DENIED_TERMS[*]}")" "${tmp}/clean.md"; then
    echo "SELF-TEST FAIL: a known-clean fixture matched; the six registry"
    echo "  values must not be denied by this script"
    failures=$((failures + 1))
  fi

  if [ "${failures}" -eq 0 ]; then
    echo "compliance_grep.sh v${VERSION} self-test: PASS"
    exit 0
  fi
  echo "compliance_grep.sh v${VERSION} self-test: FAIL (${failures})"
  exit 1
fi

if [ "$#" -gt 0 ]; then
  echo "usage: bash scripts/compliance_grep.sh [--self-test]" >&2
  exit 2
fi

PATTERN="$(IFS='|'; echo "${DENIED_TERMS[*]}")"
violations=0
scanned=0

echo "compliance_grep.sh v${VERSION} — code-repository surface"
echo "Authority: PASK-COMPLIANCE-002/003 as amended by Willa 2026-08-09"
echo

while IFS= read -r file; do
  [ -f "${file}" ] || continue
  scanned=$((scanned + 1))
  is_exempt "${file}" && continue
  if hits="$(grep -inE "${PATTERN}" "${file}")"; then
    while IFS= read -r hit; do
      echo "DENIED  ${file}:${hit}"
      violations=$((violations + 1))
    done <<< "${hits}"
  fi
done < <(governed_files | sort -u)

# Stale-exemption check.
stale=0
for exempt in "${EXEMPT_FILES[@]}"; do
  if [ ! -f "${exempt}" ]; then
    echo "STALE   exemption lists ${exempt}, which does not exist"
    stale=$((stale + 1))
    continue
  fi
  if ! grep -qiE "${PATTERN}" "${exempt}"; then
    echo "STALE   ${exempt} is exempt but contains no denied term."
    echo "        The exemption no longer protects anything. Remove it."
    stale=$((stale + 1))
  fi
done

echo
echo "Scanned ${scanned} governed files; ${#EXEMPT_FILES[@]} exempt."

if [ "${violations}" -eq 0 ] && [ "${stale}" -eq 0 ]; then
  echo "PASS"
  exit 0
fi

echo "FAIL — ${violations} denied term(s), ${stale} stale exemption(s)."
exit 1
