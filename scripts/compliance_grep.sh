#!/usr/bin/env bash
# ===================================================================
# compliance_grep.sh — v1.1.0 (2026-08-29)
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
#
# v1.1.0 — second rule set: WILLA vocabulary
# -----------------------------------------
#   Wilder Robotics and Wilder Management now share one set of machines,
#   one vault, one signer and one event log. The separation between them
#   is a catalog entry and a naming rule, not separate infrastructure.
#   That is a deliberate cost decision, and it puts a new obligation on
#   this repository: Pask's argument is that it is neutral infrastructure
#   any operator can adopt, so the operating vocabulary of one particular
#   operator must never appear on Pask's public surface. A reviewer who
#   finds an internal station name in the reference implementation reads
#   it as one company's house system wearing a standards costume.
#
#   This is gate 3 of Amendment 3, filed by Willa on 2026-08-29 in
#   willa-desk/boardroom-decisions/2026-08-21-wilder-robotics-stations-shared-substrate.md
#
#   Two things this rule deliberately does NOT do:
#
#     * It does not deny the bare word "Willa". Commit authorship and the
#       authority trail in this file both need it, and pretending the
#       operator does not exist is not the goal. What is denied is the
#       operating vocabulary: station names, board names, and internal
#       repository paths.
#
#     * It does not touch .mailmap or scripts/name_guard.sh. Those two
#       govern commit identity and must keep the names they carry. Willa
#       ruled on that specifically in Amendment 2 of the same memo.
#
#   Integration vendor names such as Buildium are not operating
#   vocabulary. Pask writes receipts into other people's systems by
#   design and naming an adapter target is the opposite of a leak.
# ===================================================================
set -uo pipefail

VERSION="1.1.0"
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

# -------------------------------------------------------------------
# WILLA vocabulary. See the v1.1.0 note in the header for why this list
# exists and why it stops where it does.
#
# Multi-word and distinctive single-word forms only. A rule that fires
# on ordinary English is a rule people learn to bypass, and this one has
# to survive contact with a Rust codebase that legitimately talks about
# collectors, witnesses and keys.
# -------------------------------------------------------------------
VOCAB_TERMS=(
  'willa[ -]os'
  'willa[ -](brigade|keeper|analyst|tribunal|herald|counsel|collector|scout|sentry|watchtower)'
  'brigade station'
  'quartermaster'
  'paskmaster'
  'garde manger'
  'boardroom'
  'willa-desk/'
  'willa-assets/'
  'willa-compliance/'
  'willa-lib/'
  'willa-board/'
)

# Files exempt from the vocabulary rule only. Commit-identity files keep
# the names they carry; this script names the terms it denies.
VOCAB_EXEMPT_FILES=(
  'scripts/compliance_grep.sh'
  'scripts/name_guard.sh'
  'crates/pask-attest/tests/tee_class_rejects_sku.rs'
)

in_list() {
  local candidate="$1"
  shift
  local entry
  for entry in "$@"; do
    [ "${candidate}" = "${entry}" ] && return 0
  done
  return 1
}

is_exempt() {
  in_list "$1" "${EXEMPT_FILES[@]}"
}

is_vocab_exempt() {
  in_list "$1" "${VOCAB_EXEMPT_FILES[@]}"
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

  # Vocabulary fixtures. The clean one carries every word a reviewer
  # SHOULD be able to read here: the operator's own name, the vendor a
  # receipt is written into, and Pask's own terms of art.
  printf 'Willa ruled on this. The Buildium adapter writes a note. The witness records the receipt.\n' \
    > "${tmp}/vocab_clean.md"
  printf 'the WILLA OS brigade station QUARTERMASTER files this under willa-desk/boardroom-decisions\n' \
    > "${tmp}/vocab_dirty.md"

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

  vocab_pattern="$(IFS='|'; echo "${VOCAB_TERMS[*]}")"

  for term in "${VOCAB_TERMS[@]}"; do
    example="${term//\[ -\]/ }"
    example="${example//(brigade|keeper|analyst|tribunal|herald|counsel|collector|scout|sentry|watchtower)/keeper}"
    if ! printf 'x %s x\n' "${example}" | grep -qiE "${term}"; then
      echo "SELF-TEST FAIL: vocabulary term '${term}' does not match its own example"
      failures=$((failures + 1))
    fi
  done

  if ! grep -qiE "${vocab_pattern}" "${tmp}/vocab_dirty.md"; then
    echo "SELF-TEST FAIL: a known-dirty vocabulary fixture did not match"
    failures=$((failures + 1))
  fi
  if grep -qiE "${vocab_pattern}" "${tmp}/vocab_clean.md"; then
    echo "SELF-TEST FAIL: a known-clean vocabulary fixture matched. The"
    echo "  operator's name, an adapter vendor and Pask's own terms of art"
    echo "  must all remain legal on this surface"
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
VOCAB_PATTERN="$(IFS='|'; echo "${VOCAB_TERMS[*]}")"
violations=0
vocab_violations=0
scanned=0

echo "compliance_grep.sh v${VERSION} — code-repository surface"
echo "Authority: PASK-COMPLIANCE-002/003 as amended by Willa 2026-08-09;"
echo "           vocabulary rule per Willa's Amendment 3, 2026-08-29"
echo

while IFS= read -r file; do
  [ -f "${file}" ] || continue
  scanned=$((scanned + 1))
  if ! is_exempt "${file}"; then
    if hits="$(grep -inE "${PATTERN}" "${file}")"; then
      while IFS= read -r hit; do
        echo "DENIED  ${file}:${hit}"
        violations=$((violations + 1))
      done <<< "${hits}"
    fi
  fi
  if ! is_vocab_exempt "${file}"; then
    if hits="$(grep -inE "${VOCAB_PATTERN}" "${file}")"; then
      while IFS= read -r hit; do
        echo "VOCAB   ${file}:${hit}"
        vocab_violations=$((vocab_violations + 1))
      done <<< "${hits}"
    fi
  fi
done < <(governed_files | sort -u)

# Stale-exemption check. Both lists, same discipline: an exemption that
# protects nothing is a claim about enforcement that enforcement does not
# back, which is the defect this whole script exists to answer.
stale=0
check_stale() {
  local pattern="$1"
  local label="$2"
  shift 2
  local exempt
  for exempt in "$@"; do
    if [ ! -f "${exempt}" ]; then
      echo "STALE   ${label} exemption lists ${exempt}, which does not exist"
      stale=$((stale + 1))
      continue
    fi
    if ! grep -qiE "${pattern}" "${exempt}"; then
      echo "STALE   ${exempt} is exempt from the ${label} rule but contains"
      echo "        no ${label} term. The exemption no longer protects"
      echo "        anything. Remove it."
      stale=$((stale + 1))
    fi
  done
}

check_stale "${PATTERN}" "SKU" "${EXEMPT_FILES[@]}"
check_stale "${VOCAB_PATTERN}" "vocabulary" "${VOCAB_EXEMPT_FILES[@]}"

echo
echo "Scanned ${scanned} governed files."
echo "SKU rule: ${#EXEMPT_FILES[@]} exempt. Vocabulary rule: ${#VOCAB_EXEMPT_FILES[@]} exempt."

if [ "${violations}" -eq 0 ] && [ "${vocab_violations}" -eq 0 ] && [ "${stale}" -eq 0 ]; then
  echo "PASS"
  exit 0
fi

echo "FAIL — ${violations} denied term(s), ${vocab_violations} vocabulary term(s), ${stale} stale exemption(s)."
exit 1
