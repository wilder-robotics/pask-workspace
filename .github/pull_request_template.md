<!--
Thanks for opening a pull request against pask-workspace.

Fill in every section. GOVERNANCE.md section 11 is the requirement.
A pull request that changes normative draft text belongs on the SCITT
WG mailing list (scitt@ietf.org) before merge. The mailing list is the
decision venue for that text. This queue is not.

Security-sensitive changes need ChatGPT's disposition and independent
evidence review. Cursor does not approve or merge its own pull request.
-->

## 1. Decision and scope

- Task id:
- Specification path:
- Specification commit:
- Base commit:
- Head commit:
- Changed behavior:
- Unchanged boundaries:
- Dependency or license changes:

## 2. Acceptance matrix

<!--
Map every acceptance criterion to a test or an evidence artifact.
Include failures, ignored tests, and NOT_RUN items. A blank cell is
not a pass.
-->

| Criterion | Evidence | Result |
| --- | --- | --- |
|  |  |  |

## 3. Reproduction evidence

<!--
Exact commands, toolchain, feature flags, operating system, exit codes,
test counts, logs, and fixture identities. Write NOT_RUN for anything
this pull request did not execute, and say why.
-->

- Operating system:
- Toolchain:
- Feature flags:
- Commands and exit codes:
- Test counts:
- Logs:
- Fixture identities:

## 4. Risk and review

- Migrations:
- Rollback:
- Unresolved limitations:
- Reviewer findings:

## Change class

<!-- Check exactly one. -->

- [ ] Editorial fix to the in-tree draft (typo, cross-reference, reference update)
- [ ] Normative change to the draft (schema, wire format, MUST/SHOULD language). SCITT WG thread:
- [ ] Bug fix in the Rust reference implementation
- [ ] New feature or capability in the Rust reference implementation
- [ ] New conformance vector or update to existing vectors
- [ ] Documentation, governance, or repository housekeeping
- [ ] CI, tooling, or release automation
- [ ] Other (describe in section 1)

## Boundaries this pull request must not cross

- [ ] Does not introduce language that treats the repository owner as an Issuer, Attester, Verifier, or Relying Party in the RATS sense.
- [ ] Does not introduce commercial-positioning language, named-counterparty targets, or a claim that Pask solves a named deployment.
- [ ] Does not weaken a negative test to make CI green.
- [ ] Security-sensitive changes (signed bytes, trust anchors, accepted algorithms, profile versions, enum meanings, time policy, key custody, fixture expectations, licensing, or public assurance claims) are escalated, with ChatGPT's disposition linked here:

## Sign-off

Every commit in this pull request carries a `Signed-off-by:` line per the [Developer Certificate of Origin](https://developercertificate.org/). The commit identity is on the allowlist in `scripts/name_guard.sh`.

- [ ] All commits are DCO-signed (`git commit -s`)
