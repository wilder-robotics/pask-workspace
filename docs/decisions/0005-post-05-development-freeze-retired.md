# 0005. Post -05 development freeze retired

- Status: Adopted by Rob Wilder on 2026-10-23 (America/Chicago). Owner decision. ChatGPT recommended it; the recommendation is advisory.
- Effective: on adoption, 2026-10-23 (America/Chicago). Not backdated.
- Implementation: policy record only. This record changes no source behavior and no repository setting.

## Owner instruction

Recorded verbatim:

> I, Rob Wilder, retire the general public-main/pask-wire development
> freeze associated with the -05 cycle, effective with this instruction.
>
> This supersedes my October 15 decision to hold that general freeze
> through November 2, 2026. It does not rewrite the historical decision
> or retroactively approve unspecified actions.
>
> Authorized -06 work may proceed on task branches and through pull
> requests under the merged GOVERNANCE.md. All implementation work
> reaches main through a PR. I approve merges. Grok Bot may perform
> a merge only after my explicit approval of that PR. Cursor does not
> self-approve or merge.
>
> Preserve the filed -05, published 0.2.0 artifacts, historical evidence
> and fixtures, and closed tournament records.
>
> The CCF, crypto-dependency, and named workflow/PR holds remain
> separately controlled. Required specifications, tests, independent
> review where applicable, and truthful limitation statements remain
> in force.
>
> Pask Engineering may prepare one narrow governance PR recording this
> transition. Do not change source behavior or repository settings in
> that PR. Record the actual adoption date and preserve the distinction
> between the historical freeze and the new policy.
>
> Task dispatch still requires an approved specification and assigned
> owner. This instruction does not authorize a release, filing,
> private-evidence publication, cloud operation, hardware capture,
> purchase, or deployment.

## Historical freeze (preserved as history, not rewritten)

- 2026-09-22 to 2026-11-02: a `pask-wire` behavioral freeze associated with closing the -05 revision. Engineering treated public `main` as frozen until Rob Wilder changed that posture. Bounded exceptions existed; the CCF scoping work was one (see `docs/scoping/ccf-vds-verify.md`).
- 2026-10-15: after -05 was filed, Rob Wilder decided to hold the public-main freeze on `pask-workspace` through 2026-11-02.
- That decision was made and recorded outside this repository. Its absence from the public governance documents before this record was a continuity gap. It does not mean the freeze did not exist.
- Owner-approved merges made while the freeze stood are not reconsidered by this record and are not, by themselves, evidence that the freeze or any other hold had been lifted.
- 2026-10-23 (America/Chicago): retired by the owner instruction above. The 2026-11-02 date no longer applies as a wait.

Historical text that mentions the freeze stays unchanged, including `KNOWN-LIMITATIONS.md`, `docs/scoping/ccf-vds-verify.md`, and `docs/tasks/T01-governance.md`.

## Policy from 2026-10-23

- Authorized -06 work proceeds on task branches and through pull requests under `GOVERNANCE.md`. All implementation work reaches `main` through a pull request.
- Rob Wilder approves merges. Grok Bot may merge only after Rob Wilder's explicit approval of that pull request. Cursor does not approve or merge.
- Task dispatch still requires an approved specification and an assigned owner.
- Branch protection is not the freeze. This record does not change rulesets, required checks, or bypass settings.

## What stays protected or held

| Item | Status after this record |
| --- | --- |
| Filed -05 draft and its source and evidence baseline | Preserved. Historical public source `2adf75ec66630ba8525d8dfdfc3e71afe87bceec`. |
| Published 0.2.0 crates | Preserved. Built from `eddbb7f7c54d4e9aea59e8a0166d1c5165baf4d0`. Not replaced, relabelled, or retargeted. |
| Historical evidence and fixtures | Preserved. Not rewritten. |
| Closed tournament records | Preserved unchanged. |
| CCF verification, issue #100, decision 0001 | Separately controlled. The hold in decision 0001 stands. |
| Crypto dependencies, issue #93 and PR #18 | Separately controlled. Still held. |
| PRs #77, #91, #92 and draft #78 | Separately controlled. Still held under their named review conditions. |
| Specifications, tests, independent review where applicable, truthful limitation statements | Remain in force. |
| Release, filing, private-evidence publication, cloud operation, hardware capture, purchase, deployment | Not authorized by this record. Each needs its own authorization. |
