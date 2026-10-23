# Task specifications

A task is work with one owner and one approved specification revision. The specification lives in this directory. Dispatch, review, and merge authority are in [`GOVERNANCE.md`](../../GOVERNANCE.md). Grok Bot dispatches the approved revision. ChatGPT amends it when a finding changes meaning or scope. Cursor implements the revision that was dispatched. Rob Wilder merges.

## Template

Copy [`TEMPLATE.md`](TEMPLATE.md). A specification is not approved until it names every field below. Missing a field is not a default.

| Field | What it fixes |
| --- | --- |
| Task id | One id, one issue, one active implementation branch. |
| Specification path and specification commit | The exact revision. A paraphrase is not this revision. |
| Base commit and permitted modules | Where the work starts, and which paths the owner may change. |
| Invariants and explicit non-goals | What must stay true, and what the task must not decide. |
| Acceptance cases and required evidence | How a reviewer tells that the revision is met, including failures and `NOT_RUN`. |
| Dependencies and assigned owner | What must land first, and the one implementation owner. |
| Escalation conditions | When the owner stops and reports instead of choosing. |

The pull request that implements the specification uses the four-part evidence block in [`.github/pull_request_template.md`](../../.github/pull_request_template.md).

## Filed specifications

| Id | Specification | State |
| --- | --- | --- |
| T01 | [Governance charter](T01-governance.md) | Approved for dispatch. Implementation is the pull request that adds this directory. |

## Queued tasks

These ids are reserved. Each is a pending specification. This list does not define scope, owner, acceptance, or design.

- T02. Conformance carry-forward. Pending specification.
- T03. CCF verification. Pending specification.
- T04. Durable state. Pending specification.
- T05. 0.7 reference-first producer. Pending specification.
- T06. Verified registration. Pending specification.
- T07. SNP capture contract. Pending specification.
- T08. Native SNP appraisal. Pending specification.
- T09. Licensing and issue reconciliation. Pending specification.
- T10. Composed acceptance suite. Pending specification.
