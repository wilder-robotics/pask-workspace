#!/usr/bin/env bash
# ===================================================================
# name_guard.sh — v1.0.0 (2026-08-11)
#
# Enforces the Public Name Rule on the code-repository surface:
#
#   No personal name other than "Rob Wilder" appears in any
#   public-facing artifact of this repository.
#
# Why this exists
# ---------------
# On 2026-08-11 roughly thirty instances of personal names belonging to
# real individuals were found published across eight public surfaces of
# this repository: a commit message on the default branch, four issue
# bodies, three pull-request bodies, and an issue comment. Those
# individuals had never been contacted and had never reviewed any of
# this work. Publishing their names alongside technical positions
# misrepresented them.
#
# The rule prohibiting this predated the incident by two weeks. It was
# written as a rule and enforced by remembering, which is not
# enforcement. This script is the control the rule never had.
#
# What made the incident possible, and what this script therefore does
# --------------------------------------------------------------------
#   1. The names were in COMMIT MESSAGES, which compliance_grep.sh has
#      never scanned — it reads tracked files only. This script scans
#      commit messages, author fields and committer fields as well.
#
#   2. The audit that first missed twenty-two of the instances used
#      full-name patterns ("Firstname Lastname") against text that used
#      the bare surname. This script matches on single normalised
#      tokens, so a surname alone is caught.
#
#   3. That audit was never run against a known-positive input, so its
#      clean result meant nothing. --self-test here proves the matcher
#      fires on a synthetic positive before any clean result is
#      trusted, and CI runs the self-test before the scan.
#
# Why hashes instead of a plain word list
# ---------------------------------------
# A denylist of the names, written into a public file, would publish
# exactly what it is meant to suppress. The tokens are therefore stored
# as salted SHA-256 prefixes and the input is hashed the same way.
#
# This is obfuscation and not secrecy, and the distinction matters: a
# party holding a surname wordlist could recover these tokens by brute
# force in seconds. The purpose is narrower — that this control does not
# itself become the eighth place the roster was published. The real
# protection is that the names are never written down here at all.
#
# Scope boundary
# --------------
#   THIS script       — personal names, this repository.
#   compliance_grep.sh — SKU and hardware identifiers, this repository.
#                        Governed by PASK-COMPLIANCE-002/003. Untouched
#                        by this file; per Willa's standing rule a
#                        doctrine may not be amended in a code commit.
#   social_denylist_grep.sh (pask-marketing) — X and LinkedIn copy.
#
#   Three scripts, three surfaces. Do not merge them.
#
# On false positives
# ------------------
# Some denied tokens are also ordinary English words or common surnames
# appearing in unrelated contexts. When this script fails on such a hit,
# FIX THE TEXT, NEVER THE PATTERN. A subject-aware exception is how
# fail-open defects are reintroduced, and fail-open is the
# characteristic failure mode of every check in this program.
#
# Usage
# -----
#   bash scripts/name_guard.sh --self-test
#   bash scripts/name_guard.sh --files
#   bash scripts/name_guard.sh --commits <rev-range>
#   bash scripts/name_guard.sh --all          # files + every reachable commit
#
# Exit codes
# ----------
#   0  PASS
#   1  FAIL — a denied token, or an unrecognised commit identity
#   2  Usage error
# ===================================================================
set -uo pipefail

VERSION="1.0.0"
cd "$(dirname "$0")/.."

SALT="pask-name-guard-v1"

# Salted SHA-256 prefixes of the denied tokens. See header.
DENIED_HASHES=(
  '2f6478e32b423502'
  '821bf8c38040147c'
  '44c8854e7718d568'
  'c8479f5751eb88d1'
  'ac753fb41bb4c58b'
  '71019895764afddc'
  'c3195e955a87c249'
  '82d6f9e753b86fc8'
  '910ac042b6851e15'
  'f5d8775c1afaff6c'
  '9e4dfb9bb575b92a'
  '9c1eebd3bef9f379'
)

# Synthetic token, present for no reason other than to prove the
# matcher fires. Its preimage is "zzsentineltoken".
TEST_HASH='c2a235569183581c'

# Commit identities permitted on a public artifact. Anything else is a
# failure, whether or not it is a personal name — an unrecognised
# identity is exactly how an unreviewed name reaches the history.
# Per the identity ruling of 2026-08-11 (Q-ID = B): exactly two identities
# author public commits, one human and one machine. 'PASKMASTER' and 'Willa'
# are retired as public author strings and are deliberately absent below.
# 'actionrob' is retired likewise; .mailmap maps it to Rob Wilder for display
# but new commits must not use it.
#
# 'dependabot[bot]' is a machine identity, not a personal name, and stays.
# 'GitHub' is the committer on web-UI merges and squashes.
# 'actionrob' is a GitHub account handle, not a personal name, and .mailmap
# maps it to Rob Wilder. It is here because of platform behaviour rather
# than preference: a squash merge sets the resulting commit's author to the
# account that performed the merge, so every squashed commit on this branch
# is authored by the merging handle regardless of who wrote the branch. The
# identity ruling retired 'actionrob' as an author string; squash merges on
# a repository requiring linear history make that unenforceable at the
# commit level. Flagged for a ruling. Recorded here rather than silently
# widened, because widening a control to match reality and widening it to
# stop it complaining look identical in a diff.
ALLOWED_IDENTITIES=(
  'Rob Wilder'
  'Wilder Robotics Automation'
  'actionrob'
  'dependabot[bot]'
  'GitHub'
)

hash_token() {
  printf '%s%s' "${SALT}" "$1" | sha256sum | cut -c1-16
}

# Normalise a line into candidate tokens: lowercase, split on anything
# that is not a letter or digit. Parenthesised, possessive and
# dot-separated forms - "(Zzsentineltoken)", "Zzsentineltoken's",
# "zzsentinel.token" - all reduce to bare tokens this way.
#
# The examples above use the synthetic sentinel deliberately. An earlier
# revision of this comment illustrated the point with a real denied
# surname, which put that name into a public file inside the script
# written to keep it out. Illustrate with the sentinel, never with a
# real token.
tokenise() {
  tr '[:upper:]' '[:lower:]' | tr -c '[:alnum:]' '\n' | grep -v '^$'
}

# Returns 0 and prints the offending token if any token is denied.
scan_text() {
  local text="$1" tok th
  while IFS= read -r tok; do
    [ "${#tok}" -lt 3 ] && continue
    th="$(hash_token "${tok}")"
    for d in "${DENIED_HASHES[@]}" ${EXTRA_HASHES:-}; do
      if [ "${th}" = "${d}" ]; then printf '%s' "${tok}"; return 0; fi
    done
  done < <(printf '%s' "${text}" | tokenise)
  return 1
}

# -------------------------------------------------------------------
# Self-test — runs before any scan in CI.
# -------------------------------------------------------------------
self_test() {
  local failures=0 got

  # 1. A known-positive MUST match. This is the check whose absence let
  #    a broken audit report a clean result.
  EXTRA_HASHES="${TEST_HASH}"
  if ! got="$(scan_text 'a line mentioning zzSentinelToken in passing')"; then
    echo "SELF-TEST FAIL: known-positive token was not caught"
    failures=$((failures + 1))
  elif [ "${got}" != "zzsentineltoken" ]; then
    echo "SELF-TEST FAIL: caught '${got}', expected 'zzsentineltoken'"
    failures=$((failures + 1))
  fi

  # 2. Punctuation and possessives must not hide a token.
  for variant in '(zzSentinelToken)' "zzSentinelToken's" 'zzsentineltoken.ai' '[zzSentinelToken],'; do
    if ! scan_text "reviewed by ${variant} on Tuesday" >/dev/null; then
      echo "SELF-TEST FAIL: variant '${variant}' evaded the matcher"
      failures=$((failures + 1))
    fi
  done
  EXTRA_HASHES=""

  # 3. A known-clean line must NOT match, or the guard is useless noise.
  if got="$(scan_text 'Rob Wilder wrote the engagement receipt profile')"; then
    echo "SELF-TEST FAIL: clean line matched on '${got}'"
    failures=$((failures + 1))
  fi

  # 4. An empty commit range must FAIL, not pass vacuously.
  if scan_commits 'refs/__nonexistent__' >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: an empty commit range reported success"
    failures=$((failures + 1))
  fi

  # 5. The denied list must be non-empty and free of collisions.
  if [ "${#DENIED_HASHES[@]}" -eq 0 ]; then
    echo "SELF-TEST FAIL: denied list is empty"
    failures=$((failures + 1))
  fi
  if [ "$(printf '%s\n' "${DENIED_HASHES[@]}" | sort -u | wc -l)" -ne "${#DENIED_HASHES[@]}" ]; then
    echo "SELF-TEST FAIL: duplicate entries in the denied list"
    failures=$((failures + 1))
  fi

  if [ "${failures}" -eq 0 ]; then
    echo "name_guard.sh v${VERSION} self-test: PASS"
    return 0
  fi
  echo "name_guard.sh v${VERSION} self-test: FAIL (${failures})"
  return 1
}

scan_files() {
  local violations=0 scanned=0 file hit lineno line
  while IFS= read -r file; do
    [ -f "${file}" ] || continue
    # This script necessarily discusses the incident; its own prose is
    # scanned like anything else, and contains no denied token.
    scanned=$((scanned + 1))
    lineno=0
    while IFS= read -r line; do
      lineno=$((lineno + 1))
      if hit="$(scan_text "${line}")"; then
        echo "DENIED  ${file}:${lineno}: token '${hit}'"
        violations=$((violations + 1))
      fi
    done < "${file}"
  done < <(git ls-files | sort -u)
  echo "Scanned ${scanned} tracked files."
  return "$( [ "${violations}" -eq 0 ] && echo 0 || echo 1 )"
}

scan_commits() {
  local violations=0 count=0 sha msg who hit ok
  local -a range=( "$@" )
  for sha in $(git rev-list "${range[@]}" 2>/dev/null); do
    count=$((count + 1))
    msg="$(git log -1 --format='%B' "${sha}")"
    if hit="$(scan_text "${msg}")"; then
      echo "DENIED  commit ${sha:0:12} message: token '${hit}'"
      violations=$((violations + 1))
    fi
    while IFS= read -r who; do
      [ -z "${who}" ] && continue
      ok=1
      for a in "${ALLOWED_IDENTITIES[@]}"; do
        [ "${who}" = "${a}" ] && ok=0
      done
      if [ "${ok}" -ne 0 ]; then
        echo "IDENTITY  commit ${sha:0:12}: '${who}' is not an allowed public identity"
        violations=$((violations + 1))
      fi
    done < <(git log -1 --format='%an%n%cn' "${sha}")
  done
  echo "Scanned ${count} commits in range '${range[*]}'."
  # An empty range is a FAILURE, never a pass. A scan that examined
  # nothing and reported success is precisely how the 2026-08-11
  # exposure survived its first audit, and how the first version of
  # this function reported PASS on the very commit it was written to
  # catch. Silence is not evidence.
  if [ "${count}" -eq 0 ]; then
    echo "EMPTY   range '${range[*]}' matched no commits — refusing to report PASS."
    return 1
  fi
  return "$( [ "${violations}" -eq 0 ] && echo 0 || echo 1 )"
}

# -------------------------------------------------------------------
mode="${1:---all}"
rc=0

case "${mode}" in
  --self-test) self_test; exit $? ;;
  --files)
    echo "name_guard.sh v${VERSION} — tracked files"; echo
    self_test || exit 1; echo
    scan_files || rc=1 ;;
  --commits)
    shift
    [ "$#" -ge 1 ] || { echo "usage: name_guard.sh --commits <rev-range...>" >&2; exit 2; }
    echo "name_guard.sh v${VERSION} — commit range $*"; echo
    self_test || exit 1; echo
    scan_commits "$@" || rc=1 ;;
  --all)
    echo "name_guard.sh v${VERSION} — files and full history"; echo
    self_test || exit 1; echo
    scan_files  || rc=1
    scan_commits --all || rc=1 ;;
  *) echo "usage: name_guard.sh [--self-test|--files|--commits <range>|--all]" >&2; exit 2 ;;
esac

echo
if [ "${rc}" -eq 0 ]; then echo "PASS"; else
  echo "FAIL — the Public Name Rule is violated above."
  echo "Fix the text. Do not add an exception."
fi
exit "${rc}"
