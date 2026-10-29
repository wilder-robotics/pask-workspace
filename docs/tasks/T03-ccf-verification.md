# T03. CCF verification

- Status: approved, conditional, not a filing prerequisite.

## Task id

T03.

## Specification path and specification commit

- Path: `docs/tasks/T03-ccf-verification.md`
- Specification source file: `P06_T03_CCF_SPRINT_SPEC_01.md`
- SHA-256: `be50c664034227691329a1ff6f5ca1240f426bb0130374a5ca505d8790a6d1b7`

## Base commit and permitted modules

- Base commit: `bd2bfb3f8aeaeb9c72419f424419d6429af70411`
- Permitted modules: approved specification text, section "Scope and files".
- Branch: not named in the approved specification text. Ordering is in section "Order and cut".

## Invariants and explicit non-goals

Approved specification text, sections "Goal and baseline", "Scope and files", "Protocol contract", and "Trust contract".

## Acceptance cases and required evidence

Approved specification text, section "Acceptance cases".

## Dependencies and assigned owner

- Dependencies: approved specification text, sections "Required primary-source check before algorithm edits" and "Order and cut".
- Assigned owner: One Cursor cloud agent, assigned by Grok Bot at dispatch and recorded in the pull request.

## Escalation conditions

Approved specification text, section "Order and cut".

The master plan and the original author package referenced by the spec are private coordination records held by the owner and are not published here.

## Approved specification text (verbatim)
# P06_T03_CCF_SPRINT_SPEC_01

Recipient: One separate Cursor CCF worker via Pask Engineering.
Attachments: master plan and this file. Repository source/evidence are read at the recorded current pin; no private sample carrier is included.
Return: `P06_T03_SPRINT_RETURN_01.md`, exact PR/head, case matrix and raw evidence.
Status: Architect conditional development contract for Rob's adoption. Size L. Not a new CCF merge or release approval.

## Goal and baseline

Implement bounded experimental CCF verification without routing CCF proofs through RFC9162 or allowing a Receipt to authorize its own key. Observed base `pask-workspace@bd2bfb3f8aeaeb9c72419f424419d6429af70411`. Preserve decision 0001's hold until its conditions and Rob's approval are satisfied. The historical scoping note supplies procedure, not current version/release authority.

## Required primary-source check before algorithm edits

Read `docs/scoping/ccf-vds-verify.md`, decision 0001, issue #100, current receipt modules and authentic `evidence/issue-100/2026-09-28/` bytes. Perplexity records the exact CCF profile revision and current official registry. The historical chosen profile is draft-ietf-scitt-receipts-ccf-profile-05; it requests value 2. If a newer normative procedure or assignment differs, return it to ChatGPT rather than silently adopting it. No invented IANA assignment. Default production path remains unsupported unless explicit experimental policy enables the selected draft convention.

## Scope and files

`pask-wire` receipt parsing/inspection/verification/transparent-statement modules, a dedicated CCF backend and tests, lib exports, reviewed feature/dependency declarations, and the minimal authentic-receipt test integration in `pask-ts-client`. Existing evidence files remain immutable. Preserve no_std/alloc/default feature behavior and Apache-only dependency direction. No #93 major crypto migration, endpoint deployment, service enrollment, full-history implementation, signed payload change or package publication.

## Protocol contract

Dispatch by explicit VDS before interpreting proof shape. Under the selected historical profile, decode each bounded byte-string-wrapped proof as a map with the exact leaf and path fields. Leaf: internal transaction hash (32 bytes), internal evidence (profile-bounded UTF-8 text), data hash (32 bytes). Path elements are boolean direction and 32-byte hash. Compute the root exactly as the pinned profile states, including SHA256 of original UTF-8 internal-evidence bytes. Never introduce RFC9162's domain/size/index rules into this backend.

Reconstruct root per proof and require all supplied proofs to agree. Verify ES384 COSE signature with the reconstructed root as detached payload and the chosen profile's exact external AAD policy. Bound nesting, items, proof depth/count, byte sizes and crypto attempts before work. Validate signature algorithm/key type agreement and COSE signature encoding; no DER/raw guessing. Preserve original protected bytes.

Compare leaf data-hash with the hash of the repository's defined `derive_candidate_entry` result for the exact supplied statement; do not hash the entire HTTP body or silently normalize payload/protected/signature contents. Any mismatch is an explicit failed dimension.

## Trust contract

Extend the existing explicit TsTrustContext model with an authorized P-384 key representation. Service identity, algorithm, actual public key, validity interval, evaluation time, provisioning evidence and distrust are relying-party inputs. kid is only a hint. Receipt-carried certificates/URLs do not enroll an anchor. No network key discovery.

Selection must be bounded and permutation-invariant. A matching row cannot override an explicit distrust row for the same actual key. Conflicting incompatible policy rows do not resolve by order. Reject malformed/unsupported key data rather than reinterpreting it. LocalSimulation cannot pass real registration acceptance. Initial automatic certificate rollover and trust enrollment are excluded.

## Acceptance cases

CCF01 authentic fixture supports the specifically tested mathematical/signature dimension.
CCF02 authentic full-conformance positive requires all required claims and authenticated service policy; obtain separately permitted suitable bytes if the retained specimen cannot supply it.
CCF03 wrong key/root association fails trust/signature as applicable.
CCF04 wrong statement/data hash fails exact statement binding.
CCF05 one changed proof element/leaf/signature fails the intended check.
CCF06 all supplied proofs must pass and agree; a valid proof cannot mask a bad sibling.
CCF07 unknown/reserved VDS and wrong algorithm remain unsupported/refused with correct dimensions.
CCF08 duplicate labels, malformed CBOR, missing/detached-policy mismatch, oversize and adversarial nesting refuse without panic/unbounded work.
CCF09 trust-row and proof ordering do not create acceptance from conflicting evidence; explicit distrust is not masked.
CCF10 expired/unestablished associations and absent policy do not pass registration.
CCF11 existing RFC9162 vectors, supported legacy profiles and feature matrix remain unchanged.
CCF12 transparent-statement summary preserves each failed/unsupported dimension and actual receipt bytes.

The retained fixture already reports required_claims/uri_syntax failure. Preserve it. Do not turn that specimen into a full-positive registration by relaxing claims or rewriting its signed bytes. Labeled generated negative mutations are allowed; a synthetic positive cannot replace the authentic gate.

## Order and cut

May start in parallel with T02 and state work after adoption and primary-source check. Shared manifests are serialized by the dispatcher. At Oct 30 noon CDT return complete evidence or DEFERRED_FOR_THIS_FILING. No late merge simply to say -06 has CCF. If accepted later, identify repository-only source and scope; published 0.2.0 remains unchanged.

Escalate unavailable authentic full-positive evidence, uncertain certificate/time policy, inconsistent current profile, dependency/MSRV conflict, security defect outside scope or need to alter a historical field/fixture. No new real-ledger deployment is included without a bounded separate resource order.
