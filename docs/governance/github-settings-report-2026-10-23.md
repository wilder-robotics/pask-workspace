# GitHub settings report, 2026-10-23

Reader: the integration token available to task T01. This file records what that token could read. It does not change any GitHub setting. Rob Wilder applies the remediation below and verifies it on the live repository.

Base commit at the time of the read: `fa78e8be7243df772eb37cf0fbead61a5d2bb047`.

Ruleset HTML: <https://github.com/wilder-robotics/pask-workspace/rules/19786840>

Ruleset settings URL, for the account that can edit it: <https://github.com/wilder-robotics/pask-workspace/settings/rules/19786840>

## What was read

`GET /repos/wilder-robotics/pask-workspace/rulesets/19786840` returned HTTP 200.

| Field | Value |
| --- | --- |
| Name | `main-protection` |
| Id | 19786840 |
| Source | Repository `wilder-robotics/pask-workspace` |
| Enforcement | `active` |
| Target | Branch `refs/heads/main` (include only; exclude list empty) |
| Created | 2026-07-27T02:34:39.864Z |
| Updated | 2026-09-13T21:55:30.716Z |
| `current_user_can_bypass` | `never` (this integration) |

Rules on that ruleset:

| Rule | Parameters observed |
| --- | --- |
| `deletion` | Branch deletion blocked. No extra parameters. |
| `non_fast_forward` | Force-push blocked. No extra parameters. |
| `required_linear_history` | Linear history required. No extra parameters. |
| `pull_request` | See the next table. |
| `required_status_checks` | See the check list below. |

Pull-request rule parameters:

| Parameter | Observed |
| --- | --- |
| `required_approving_review_count` | 0 |
| `dismiss_stale_reviews_on_push` | true |
| `required_reviewers` | empty |
| `require_code_owner_review` | false |
| `require_last_push_approval` | false |
| `required_review_thread_resolution` | false |
| `require_extra_approval_for_unattributed_changes` | false |
| `dismissal_restriction.enabled` | false |
| `dismissal_restriction.allowed_actors` | empty |
| `allowed_merge_methods` | `squash` only |

Required status checks (`strict_required_status_checks_policy` true, `do_not_enforce_on_create` false):

1. `Cargo (ubuntu-latest)`
2. `DCO sign-off`
3. `Draft (xml2rfc + idnits)`
4. `Public Name Rule`
5. `Compliance grep`

There is no `required_signatures` rule in this ruleset. Signed commits are not enforced by the ruleset this token could read.

Repository merge settings from `GET /repos/wilder-robotics/pask-workspace` (not a ruleset, included because they decide which merge button exists):

| Setting | Observed |
| --- | --- |
| Default branch | `main` |
| Squash merge | allowed |
| Merge commit | not allowed |
| Rebase merge | not allowed |
| Auto-merge | not allowed |
| Delete branch on merge | true |
| Visibility | public |

This task does not ask Rob Wilder to change the merge-method settings.

`GET /repos/wilder-robotics/pask-workspace/rules/branches/main` returned the same five rules, all sourced from ruleset 19786840. No second ruleset appeared on that branch response.

## Bypass actors

The ruleset JSON this token received has no `bypass_actors` key. `GET /repos/wilder-robotics/pask-workspace/rulesets` serialized `bypass_actors` as null for ruleset 19786840. Selecting the missing field also yields null. This token therefore cannot list bypass actors, and it cannot confirm or contradict an earlier reading that organization-admin bypass is permitted.

What this token can say:

- `current_user_can_bypass` for this integration is `never`. This integration is not a bypass actor for its own calls.
- No bypass actor name was returned. The absence of the key is not proof that the bypass list is empty. Rob Wilder has to open the ruleset and read the bypass list in the UI.

## Code owner

[CODEOWNERS](../../CODEOWNERS) routes every path, and an explicit security-sensitive subset, to `@actionrob`.

Why this handle, and not a placeholder: it was already the sole owner in `CODEOWNERS` on the base commit; `GET /repos/wilder-robotics/pask-workspace/collaborators` returned only `actionrob` (`id` 270052909, `role_name` `admin`, `permissions.admin` true); `.mailmap` maps `actionrob <rob@wilder-robotics.com>` to Rob Wilder; `scripts/name_guard.sh` allows `actionrob` as a GitHub handle. `GET /users/actionrob` returned `type` `User` and a null public `name`. The mailmap and the existing `CODEOWNERS` entry are the basis for treating the handle as Rob Wilder's. No second owner was added.

Code-owner review is not required by the live ruleset (`require_code_owner_review` false), so the file does not yet force a review.

## Checks that exist in workflows and are not required

These job names were read from `.github/workflows/` on the base commit. They are not in the ruleset's required-check list. This task does not add them. Adding a required check is an administration change for Rob Wilder.

| Workflow | Job name | When it runs | Required today |
| --- | --- | --- | --- |
| CI | `Cargo (macos-latest)` | pull request and push to `main` | no |
| CI | `Cargo (windows-latest)` | pull request and push to `main` | no |
| CI | `TS Integration` | after the Cargo matrix; `continue-on-error: true` | no |
| CI | `License split` | pull request and push to `main` | no |
| CI | `Revision consistency` | pull request and push to `main` | no |
| ROS dev2 offline checks | `offline` | pull request, and only when ROS paths change | no |
| Scorecard analysis workflow | `Scorecard analysis` | push to `main`, weekly schedule, manual | no |
| CCF interop evidence (issue 100) | `Capture CCF receipt evidence` | manual dispatch only | no |

`CONTRIBUTING.md` states that signed commits are enforced by branch protection. The ruleset above has no signature rule. `GET /repos/wilder-robotics/pask-workspace/branches/main/protection` returned HTTP 403, so a classic branch-protection rule was not readable and might still exist. This task does not edit `CONTRIBUTING.md`.

## What this token could not read

| Request | Result |
| --- | --- |
| `GET /repos/wilder-robotics/pask-workspace/branches/main/protection` | HTTP 403, resource not accessible by integration |
| `GET /orgs/wilder-robotics/rulesets` | HTTP 403, resource not accessible by integration |
| `GET /repos/wilder-robotics/pask-workspace/teams` | HTTP 403, resource not accessible by integration |
| `GET /repos/wilder-robotics/pask-workspace/actions/permissions` | HTTP 403, resource not accessible by integration |
| `GET /repos/wilder-robotics/pask-workspace/installation` | HTTP 401, a JSON web token could not be decoded |
| `GET /user` | HTTP 403, so the integration's own GitHub login was not returned |
| Ruleset `bypass_actors` | key absent; no actor list |
| `GET /orgs/wilder-robotics/members` | HTTP 200 and `[]` (public members). Owners and private members were not enumerated |

Rob Wilder checks each of those in the UI before treating this report as a complete bypass inventory.

## Options for Rob Wilder

These are options, not requirements. A source pull request cannot apply them. Rob Wilder chooses. Owner override of 2026-10-23: he may delegate merging to his agents. Grok Bot merges a pull request when Rob Wilder has explicitly approved that pull request, and that merge counts as Rob Wilder's merge. Cursor does not merge and does not approve its own pull requests.

The delegated-merge path needs a bypass this token could not name. The ruleset requires zero approving reviews. `bypass_actors` was absent from the payload. An earlier reading said organization-admin bypass is permitted, and this token did not re-observe that actor. Do not remove the bypass that path uses, including an organization-admin or repository-admin bypass if that is how Grok Bot merges after Rob Wilder's explicit approval.

Options that keep that path:

1. Open the bypass list and write down every actor. This report could not see them. Keep the bypass Grok Bot uses for a pull request Rob Wilder has explicitly approved. Do not delete that actor in order to force a separate human click.
2. Optionally require the status checks that are already required to keep passing, still in strict mode: `Cargo (ubuntu-latest)`, `DCO sign-off`, `Draft (xml2rfc + idnits)`, `Public Name Rule`, `Compliance grep`. Requiring checks does not remove the bypass.
3. Optionally require conversation resolution before merging. Requiring it does not remove the bypass.
4. Stale-review dismissal is already on. Leaving it on is compatible with the delegated-merge path.
5. Optionally add `License split` and `Revision consistency` to the required checks. They are not required today.
6. Signed commits are not a rule in this ruleset. `CONTRIBUTING.md` says branch protection enforces them. One option is to add "Require signed commits". Another is to correct `CONTRIBUTING.md` in a later task. Either option can keep the delegated-merge bypass.
7. Classic branch protection returned HTTP 403, and organization rulesets returned HTTP 403. If either exists, one option is to align required checks and conversation resolution with this repository ruleset, while keeping the delegated-merge bypass on every ruleset that targets this repository. Record every bypass actor those screens show.
8. This token saw one collaborator, `actionrob`, with admin. It could not list teams, installed apps, or its own login. One option is to confirm which identity Grok Bot uses when it merges, and to keep that identity able to merge after Rob Wilder's explicit approval.
9. If code-owner review is turned on later, a pull request authored by `actionrob` has no second code owner (`GOVERNANCE.md` §4.3). That observation is not a request to remove `actionrob`'s bypass. Cursor's own pull requests are still not approved or merged by Cursor.

## Earlier reading, not re-observed

The architect's dispatch said a prior read found: pull request required, zero approving reviews, no code-owner requirement, organization-admin bypass permitted. This token re-observed the first three. It did not observe the bypass actor, for the reason in the bypass section above.
