# T02. Conformance carry-forward

- Status: approved, filing-critical.

## Task id

T02.

## Specification path and specification commit

- Path: `docs/tasks/T02-conformance-carry-forward.md`
- Specification source file: `P06_T02_CONFORMANCE_SPRINT_SPEC_01.md`
- SHA-256: `d09dbb57c88a5d87dda395d0c6aca8b2b195f996f480f44a1ad79e2c4d10ef15`

## Base commit and permitted modules

- Base commit: `bd2bfb3f8aeaeb9c72419f424419d6429af70411`
- Permitted modules: approved specification text, section "Base, scope and files".
- Branch: not named in the approved specification text. Ordering is in section "Order and escalation".

## Invariants and explicit non-goals

Approved specification text, sections "Goal", "Base, scope and files", "Acceptance", and "Boundaries".

## Acceptance cases and required evidence

Approved specification text, section "Acceptance".

## Dependencies and assigned owner

- Dependencies: approved specification text, section "Order and escalation".
- Assigned owner: One Cursor cloud agent, assigned by Grok Bot at dispatch and recorded in the pull request.

## Escalation conditions

Approved specification text, section "Order and escalation".

The master plan and the original author package referenced by the spec are private coordination records held by the owner and are not published here.

## Approved specification text (verbatim)
# P06_T02_CONFORMANCE_SPRINT_SPEC_01

Recipient: One named Cursor worker assigned by Pask Engineering.
Actual attachments: master plan, this file, `P06_CONFORMANCE_01_AUTHOR_01.zip`, `P06_CONFORMANCE_01_REVIEW_DISPOSITION_01.md`.
Expected return: `P06_T02_SPRINT_RETURN_01.md` plus one PR and its exact native evidence.
Status: Architect specification for Rob's adoption. Size M. Filing-critical.

## Goal

Carry the existing reviewed conformance work to a current successor without claiming its three rules were absent from -05 or its author tests already ran. Finish source preservation, correctly signed positive/negative behavior and explicit identity/assurance limitations.

## Base, scope and files

Observed current base `pask-workspace@bd2bfb3f8aeaeb9c72419f424419d6429af70411`. Original author base remains historical `2adf75ec66630ba8525d8dfdfc3e71afe87bceec`.

Allowed changes: add `docs/conformance-07.md`, add `crates/pask-wire/tests/p06_conformance_01.rs`, append the selected clarification to current `KNOWN-LIMITATIONS.md`, and the minimal Cargo test-target declaration only if required by the existing explicit test configuration. Any extra production or dependency edit is out of scope. Register the spec separately as governance requires.

Read START_HERE, SOURCE_RECONCILIATION, TEST_PLAN, CONFORMANCE_CASES and C14_REFERENCE in the original ZIP plus RC01-RC05 in the supplied disposition. Check the original carrier SHA-256 `6e07d6b87e737b656a42045fa2ea0c153b5dd9bf3da83c8ece2c2bb0c842b5a9`. Do not publish its private provenance.

Adapt the old three-path candidate without overwriting later authorized limitations text. Preserve the entire existing current limitations content as a prefix where compatible with its syntax. Formatting and source repairs needed for a current PR are allowed within this new successor, with explicit diff and new identities; never overwrite or relabel the original author candidate.

## Acceptance

Execute the actual nonzero test target with alloc enabled, e.g. the current equivalent of:
`cargo test --locked -p pask-wire --features alloc --test p06_conformance_01 -- --nocapture --test-threads=1`
Run `proposed07_envelope`, `issue_30_66`, and the applicable workspace/default/es256/MSRV checks in current CI. Record feature/platform failures; do not waive them through an old test count.

C01-C13 behavior follows CONFORMANCE_CASES.json. Positive controls must establish a correctly signed serialized input before a profile rejection can count. Negatives must reach the intended error. Preserve 0.5/0.6 compatibility and exact original signed fixtures.

C14 has two distinct parts: new synthetic tag-twin characterization and the exact closed-audit baseline/test-key pair. Use the exact C14_REFERENCE identities only in an authorized private review context. Missing private fixture permission leaves that portion NOT_RUN; do not copy it into a public fixture or substitute a new pair. Escalate its filing impact rather than claim all C01-C15 complete.

C15 records source/lock/fixture preservation and execution evidence. Retain the supplementary UNKNOWN-conformance and header-mismatch tests under their actual identities, not as replacements for C15. A static count of 19 functions or 47 observation objects is not a native pass count.

The documentation must preserve SC01/SC02: the three rules already appear in -05; pask-attest has an injected-clock quote check, while statement validation has its own timestamp consistency and no automatic native report appraisal.

## Boundaries

No new normative profile field/version, trust resolver, algorithm, semantic hash domain, hardware result, archived implementation, or release. The phrase statement_sha256 remains exact presented-byte provenance, not semantic equivalence. No dependency migration; current toolchain/lock constraints remain unless ChatGPT disposes a concrete blocker.

## Order and escalation

Mandatory first code lane after owner adoption/spec registration. Check for already-completed private evaluation before duplication. Perplexity independently reproduces the actual successor where needed. Return compile/source mismatches with exact files; normal in-scope repair iterations are allowed. Changing verifier semantics, expected fixtures or case acceptance requires ChatGPT's decision. Rob approves the final PR.
