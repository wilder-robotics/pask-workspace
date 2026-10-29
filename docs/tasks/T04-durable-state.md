# T04. Durable state

- Status: approved, conditional, not a filing prerequisite.

## Task id

T04.

## Specification path and specification commit

- Path: `docs/tasks/T04-durable-state.md`
- Specification source file: `P06_T04_STATE_SPRINT_SPEC_01.md`
- SHA-256: `c53a7231b2f3b6ac698b9bc0fea89077637c9da9fcc60053c67bb0afa611b1aa`

## Base commit and permitted modules

- Base commit: `bd2bfb3f8aeaeb9c72419f424419d6429af70411`
- Permitted modules: approved specification text, section "Scope / modules".
- Branch: not named in the approved specification text. Ordering is in section "Dependencies / boundaries".

## Invariants and explicit non-goals

Approved specification text, sections "Goal / base", "Data and transaction contract", and "Dependencies / boundaries".

## Acceptance cases and required evidence

Approved specification text, section "Acceptance".

## Dependencies and assigned owner

- Dependencies: approved specification text, section "Dependencies / boundaries".
- Assigned owner: One Cursor cloud agent, assigned by Grok Bot at dispatch and recorded in the pull request.

## Escalation conditions

Approved specification text, section "Dependencies / boundaries".

The master plan and the original author package referenced by the spec are private coordination records held by the owner and are not published here.

## Approved specification text (verbatim)
# P06_T04_STATE_SPRINT_SPEC_01

Recipient: One separate Cursor state-store worker via Pask Engineering.
Attachments: master plan and this file.
Return: `P06_T04_SPRINT_RETURN_01.md`, exact PR/head, crash/concurrency evidence and remaining integration boundaries.
Status: Architect conditional contract for Rob's adoption. Size L. A completed store is not completed T05/T06.

## Goal / base

At observed public base `bd2bfb3f8aeaeb9c72419f424419d6429af70411`, add durable local operation/chain state so the future orchestrator, not its external caller, controls sequence and predecessor. Initial configuration is one local database, single active writer per issuer/subject chain, no distributed lease service or network filesystem.

## Scope / modules

Add `pask-site` store and state modules, a versioned schema/migration initializer, tests and necessary config/error types. Keep the existing default 0.5 producer/guard unchanged in this PR. Do not silently wire the new store into ReferenceSite or claim 0.7 registration. T05/T06 remain separate owners/orders. An approved SQLite dependency and feature selection must be explicit and compatible with the current Rust minimum; no generic dependency update.

## Data and transaction contract

Database path is explicit configuration, not a hidden global directory. Use SQLite WAL and full synchronous policy, verifying the requested settings. Initial deployment on one local supported filesystem. Store private signing keys and credentials outside this ordinary receipt database.

Use a local chain namespace for the exact `(issuer identity, subject/site identity)` pair. No case folding, identifier trimming or alias consolidation. Chain head stores last committed sequence and `chain.hash`; the first uses seq=0/prev=null. Key rotation and cross-chain migration need an explicit future design.

Operation ID is a separate caller-supplied idempotency key, scoped to the chain, with an exact request fingerprint. Same ID plus same request returns the existing operation state/artifact; same ID plus different request is a conflict. A caller cannot set seq/prevHash through the new managed API.

Record an append-only event history and current operational projections. At minimum distinguish reserved/pending-reference, reference-write observed or outcome-unknown, ready-to-seal, sealed, registration-pending, receipt-received, registration-verified, and delivery outcome. These are local application states, not new wire enums; independent dimensions must not be hidden in one overall success bit.

An operation may reserve its stable reference before sealing. Final statement bytes, their exact transport hash, actual payload chain.hash and new chain head commit in one transaction. No external publication of signed statement bytes before that commit. Do not use the COSE transport hash as prevHash. Rollback of an uncommitted transaction cannot publish a gap or reuse a published sequence.

A persistent outbox records exact submitted bytes, remote transaction ID if observed, every attempt/status, response identity, retry state and ambiguity. It does not promise exactly-once external effects across a lost HTTP response. A retry cannot manufacture a new signed engagement solely because the prior transport outcome is unknown.

On open, check schema compatibility and local invariants. Existing inconsistent state stops; do not silently initialize genesis, repair a corrupted tail, or reset the operation ID. New schema initialization is explicit. Old/unknown schema refusal and migration policy are tested; no in-place production migration in this sprint.

## Acceptance

ST01 explicit path and persisted settings; no key/credential persistence.
ST02 two concurrent tasks cannot commit the same sequence to the same chain; distinct chains remain separate.
ST03 signed bytes and head are atomic under injected failures before/after each transaction boundary.
ST04 restart returns exact existing statement for an identical operation; changed request conflicts.
ST05 prevHash uses payload chain.hash, with genesis and sequence continuity checked.
ST06 crash between reference publication and sealing preserves pending/unknown status, not a fabricated acknowledgment.
ST07 crash/timeout during registration retains exact bytes and observed remote ID; no automatic re-sign.
ST08 disk-full/I/O/permission/schema/corruption failures stop publication and preserve available diagnostics.
ST09 outbox retries are bounded/configured and preserve attempt history; transport ambiguity is explicit.
ST10 unknown or rollback evidence is not a claim of tamper-proof/latest history. Document that malicious database rollback beyond available external evidence is not generally detected.
ST11 current producer behavior, immutable fixtures, dependencies not selected by this PR and baseline tests remain unchanged.

## Dependencies / boundaries

May run beside CCF, but coordinate Cargo changes. T05 may consume the accepted store interface only after a separate reviewed orchestration contract; no competitive implementation. Deliver by optional Oct 30 noon gate or keep the PR outside the selected filing snapshot. Escalate multisite/multiwriter needs, public API breakage, unresolved acknowledgment semantics, key lifecycle, or database recovery that would rewrite an issued record.
