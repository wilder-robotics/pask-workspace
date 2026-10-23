# T01. Governance charter

- State: approved for dispatch on 2026-10-23. Specification by ChatGPT. Dispatch approved by Rob Wilder.
- One issue: the governance task identified as T01 in that dispatch. No pre-existing issue number was named in the dispatch, so this file is the specification of record.
- One specification revision: the commit that adds this file. The implementation pull request records the full SHA.
- One implementation owner: Cursor.
- One active implementation branch: `cursor/t01-governance-charter-2f3d`.

## Task id

T01.

## Specification path and specification commit

- Path: `docs/tasks/T01-governance.md`
- Specification commit: recorded in the implementation pull request. That commit is the revision Cursor implements. Grok Bot does not restate it.

## Base commit and permitted modules

- Base commit: `fa78e8be7243df772eb37cf0fbead61a5d2bb047`
- Permitted modules: `GOVERNANCE.md`, `CODEOWNERS`, `.github/pull_request_template.md`, `docs/decisions/`, `docs/tasks/`, `docs/governance/`, `docs/research/README.md`, `.cursor/rules/governance.mdc`. Dated status sections on issues #66 and #76, appended without erasing history.
- Branch: `cursor/t01-governance-charter-2f3d`

## Invariants and explicit non-goals

Invariants:

- Completed records stay in place. This includes the succession plan, the license map, the IETF draft-governance section, and `docs/scoping/ccf-vds-verify.md`.
- Future instructions that would write task implementation directly to `main` are superseded. History already on `main` is not rewritten.
- `AdapterWriteIn::push` is not weakened. No Rust file is edited.
- Grant text is not edited. `pask-ts-client` joining the commercial-licensing scope waits on owner review by Rob Wilder, assisted by his Wilder Legal & IP agent. Pask does not use outside counsel. A DCO sign-off is not a copyright assignment. Grant-changing text needs Rob Wilder's explicit approval before merge.

Non-goals:

- Changing protocol behavior, wire semantics, fixtures, or licensing text.
- Changing CI behavior.
- Changing GitHub rulesets, branch protection, or team permissions. Those are reported for Rob Wilder.
- Merging this pull request, or approving it from the implementation identity.
- Allocating a package version, reopening the filed -05 draft, or merging unfinished CCF verification.
- Publishing private hardware samples, identifiers, commercial information, or unreleased tournament material.

## Acceptance cases and required evidence

| Case | Required evidence | Result |
| --- | --- | --- |
| The charter names one owner and one specification revision for a task. | `GOVERNANCE.md` §10 and this file. | Filled by the implementation pull request. |
| Security-sensitive paths require architect disposition and independent evidence review. | `GOVERNANCE.md` §11 and §12, and the security-sensitive entries in `CODEOWNERS`. | Filled by the implementation pull request. |
| The settings report names required checks, review count, stale-approval behavior, and every bypass actor the reader could see. | `docs/governance/github-settings-report-2026-10-23.md`. | Filled by the implementation pull request. |
| Rob Wilder has the settings facts and a set of options a source pull request cannot apply. The options keep the bypass used for delegated merges. | Options section of `docs/governance/github-settings-report-2026-10-23.md`, repeated in the pull request. | Filled by the implementation pull request. |
| Cursor does not merge or approve its own pull requests. A merge Grok Bot performs after Rob Wilder's explicit approval counts as Rob Wilder's merge. Settings options keep the bypass that path uses. | `GOVERNANCE.md` §2, §4.1, and §13, `.cursor/rules/governance.mdc`, and the options in `docs/governance/github-settings-report-2026-10-23.md`. | Filled by the implementation pull request. |
| Four accepted selections are recorded as selections, with implementation not done. | `docs/decisions/0001` through `0004`. | Filled by the implementation pull request. |
| T02 through T10 are named as pending specifications, without added design. | `docs/tasks/README.md`. | Filled by the implementation pull request. |

## Dependencies and assigned owner

- Dependencies: none. T01 is first.
- Assigned owner: Cursor.

## Escalation conditions

Stop and report, rather than choosing, when any of the following is true:

- A GitHub identity fact is being used to block a merge Rob Wilder has explicitly approved. Report the identity. Do not treat Grok Bot's merge of that pull request as a violation. Cursor still does not merge or approve its own pull requests.
- A settings change would remove the bypass Rob Wilder's delegated merges use. Report the facts. Offer options that keep the path. Do not apply the change.
- Freeze status is unresolved beyond the CCF checkpoint hold in `docs/decisions/0001-ccf-verification-hold.md`. This task does not decide any other freeze.
- A request would expose private evidence.
- The GitHub handle for Rob Wilder cannot be determined. On this task the handle `actionrob` was determined from `CODEOWNERS`, the collaborator list, and `.mailmap`. No placeholder was used.
