# TNN. Title

- State: draft until ChatGPT has accepted the text and Rob Wilder has approved dispatch.
- One issue, one specification revision, one implementation owner, one active implementation branch.

## Task id

TNN. Issue:

## Specification path and specification commit

- Path: `docs/tasks/TNN-title.md`
- Specification commit: the commit that contains the approved text. Record the full SHA. A later amendment is a new SHA, dispatched again.

## Base commit and permitted modules

- Base commit:
- Permitted modules:
- Branch: one active implementation branch for this task.

## Invariants and explicit non-goals

Invariants:

- 

Non-goals:

- 

## Acceptance cases and required evidence

| Case | Required evidence | Result |
| --- | --- | --- |
|  |  | NOT_RUN until the implementation pull request fills it |

Include failures, ignored tests, and `NOT_RUN` items in the implementation pull request. A blank result is not a pass.

## Dependencies and assigned owner

- Dependencies:
- Assigned owner: exactly one of Cursor, or another implementation owner named in the dispatch.

## Escalation conditions

Stop and report, rather than choosing, when:

- Meaning or scope would change.
- A security-sensitive surface is touched and ChatGPT has not disposed of it: signed bytes, trust anchors, accepted algorithms, profile versions, enum meanings, time policy, key custody, fixture expectations, licensing, or public assurance claims.
- The condition named in the dispatch for this task is met.

Ordinary edit, compile, test, and repair cycles inside this task do not escalate.

## Handoff note

Perplexity Computer adds research to the same issue. ChatGPT turns a consequential finding into an amendment of this file. Grok Bot dispatches the amended commit. Cursor does not treat a research note as a change to this specification.
