# Scoping note: CCF VDS receipt verification in pask-wire

Branch `feat/ccf-vds-verify`, base `9ba85f1034145de9e8670a83ffc26ca6608fcec6`
(main at the `pask-wire` 0.1.0 release). Tracks
[#100](https://github.com/wilder-robotics/pask-workspace/issues/100).
Fifth -05 freeze exception, ratified 28 Sep 2026 (desk record `fdb1344`,
register item `PASK-EX5-CCF`); merge-or-hold date 23 Oct 2026.

**This note is the only change on the branch. No verifier code yet.**

## Ships as

`pask-wire` **0.1.1** (or later). 0.1.0 is published from `9ba85f1` and stays
untouched. -05 §8 cites the version that actually verifies CCF receipts.

## Specification the identifier and procedure come from

`draft-ietf-scitt-receipts-ccf-profile-05`, "CCF Profile for COSE Receipts",
23 September 2026 (Birkholz, Delignat-Lavaud, Fournet, Chamayou),
https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-05.txt

- VDS identifier: `TBD_1`, **requested assignment 2**, name
  `CCF_LEDGER_SHA256` (§2, §5 Figure 10, §8.1.1). The IANA "COSE Verifiable
  Data Structure Algorithms" registry lists only 0 (Reserved) and 1
  (`RFC9162_SHA256`) as of 28 Sep 2026. The value is requested, not assigned.
  The PR must record the document and version it took the value from, and
  the constant must be named so that a later assignment is a rename, not a
  behaviour change.
- Proof structure (§2.2, §3): `vdp` (396) `-1` is an array of
  `ccf-inclusion-proof`, each a `bstr .cbor { 1: ccf-leaf, 2: [+ ccf-proof-element] }`
  where `ccf-leaf = [internal-transaction-hash: bstr .size 32,
  internal-evidence: tstr .size (1..1024), data-hash: bstr .size 32]` and
  `ccf-proof-element = [left: bool, hash: bstr .size 32]`. Neither tree size nor
  leaf index is carried in the proof.
- Root computation (§3.2 Figure 7): `h = SHA256(itx || SHA256(evidence) || data-hash)`,
  then for each `[left, hash]`: `h = SHA256(hash || h)` if left else `SHA256(h || hash)`.
- Service signature (§3.1, §3.2): the receipt is a `COSE_Sign1` whose payload
  MUST be detached; the verifier recomputes the root from each proof and uses
  it as the detached payload for `verify_cose`. Every proof in the array MUST
  compute to the same root. The signing key is the transparency service's
  key; the document leaves how a verifier obtains and trusts that key to the
  application. The captured dev-ledger receipt used `alg` ES384 with a 64-byte
  `kid` and no `x5chain`.

## Functions in pask-wire that dispatch on VDS today

| Location (at `9ba85f1`) | What it does now | Change needed |
|---|---|---|
| `crates/pask-wire/src/receipt.rs` `Receipt::from_cose_sign1` (line 463) | Parses `vds` (395), requires `vdp` (396) `-1` to be an array of byte strings, then decodes each as the RFC 9162 `[tree_size, leaf_index, path]` array. CCF proofs fail here with `inclusion proof must be a CBOR array` before `vds` is consulted. | Parse proofs per VDS: keep raw proof bytes and decode by dispatch, so an unsupported VDS is reported as unsupported rather than as a shape error. |
| `crates/pask-wire/src/receipt.rs` `verify_inclusion` (line 596, check at 604) | `if receipt.vds != RFC9162_SHA256` then `Err(Receipt("unsupported verifiable data structure; only RFC9162_SHA256 is implemented"))`. Signature is Ed25519 only. | Add a second arm for `CCF_LEDGER_SHA256` using the §3.2 procedure and an ES384 (P-384) signature check over the recomputed root. Any other value stays unsupported. Do not route CCF bytes through the RFC 9162 walk. |
| `crates/pask-wire/src/receipt_inspection.rs` support dispatch (line 491) | `vds == 2` yields `Unsupported / ccf_profile_not_implemented`; `alg != -8` yields `ts_algorithm`. | Move `vds == 2` to supported once verification exists; extend the algorithm support check to admit ES384 for the CCF arm only. |
| `crates/pask-wire/src/receipt_verification.rs` `verify_scitt_receipt` (line 247) | Calls `inspect_scitt_receipt`, then runs the RFC 9162 math and Ed25519 key association (`TsPublicKey::Unsupported` for non-Ed25519). | Thread the CCF arm through: P-384 `TsPublicKey`, root from the CCF procedure, same trust-context rules (no self-provisioning). |
| `crates/pask-wire/src/transparent_statement.rs` `verify_transparent_statement` (line 459) | Per-receipt call into `verify_scitt_receipt`; keeps each result. | No change expected beyond the new outcomes flowing through. |

Also touched by name only: `crates/pask-wire/src/lib.rs` exports (a new
`CCF_LEDGER_SHA256` constant next to `RFC9162_SHA256`).

## Test files the new fixtures would extend

- `crates/pask-wire/tests/receipt_fixtures.rs` and
  `crates/pask-wire/fixtures/receipts/` (JSON vectors, byte-identical to the
  generator). The `invalid-unsupported-vds.json` vector (vds 0) stays; new
  `valid-ccf-*.json` / `invalid-ccf-*.json` vectors are added from authentic
  bytes, not generated.
- `crates/pask-wire/tests/receipt_phase1_boundaries.rs` and
  `receipt_phase1_fixtures.rs` (envelope inspection: the
  `ccf_vds2_opaque_profile` sentinel becomes a supported case; a new
  unknown-VDS sentinel keeps the unsupported branch covered).
- `crates/pask-wire/tests/receipt_phase2.rs` (crypto and key association).
- `crates/pask-wire/tests/transparent_statement_phase3.rs` (outer statement with
  a CCF receipt attached).
- `crates/pask-ts-client/tests/e2e.rs`: `real_ledger_submit_and_retrieve_receipt`
  is promoted to verify the returned receipt under the service certificate,
  not just parse it.

## Fixture source

Authentic bytes only, from the pinned `scitt-ccf-ledger`
(`bffdf529185ba7767db5f2cfc4c1898ec8ad3364`). The first capture, including the
receipt, statement and service certificate, is in
`evidence/issue-100/2026-09-28/` on the `evidence/issue-100-ccf-interop`
branch (PR #101). Required negatives: tampered proof, wrong service key,
unsupported VDS value. Existing `RFC9162_SHA256` vectors must pass unchanged.

## Not in scope

Wire-format or payload changes, new profile requirements, consistency proofs
(§4), service trust establishment, key binding, IANA claims beyond
"requested".
