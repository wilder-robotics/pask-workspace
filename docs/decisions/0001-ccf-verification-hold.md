# 0001. CCF verification hold

- Status: Accepted by the architect (ChatGPT) on 2026-10-23.
- Implementation: not done.
- This record is a selection. It does not claim that CCF receipt verification exists in the tree.

## Selection

Hold CCF verification at the 2026-10-23 checkpoint.

Continue that work in a scoped pull request. Do not merge unfinished verification in order to meet a date. Do not reopen the filed -05 draft. Do not allocate a package version.

Initial support is experimental and opt-in. It must not advertise VDS value 2 as an IANA assignment.

Trust only service keys that the relying party has independently authorized. A receipt cannot authorize its own signing key. Arrival beside the receipt, a matching `kid`, a URL named by the receipt, a successful HTTPS fetch, and a self-signed certificate that verifies itself are each insufficient for trust.

The selection extends the existing `TsTrustContext` model in `crates/pask-wire/src/receipt_verification.rs`. Key selection is order-independent and preserves explicit distrust.

## Preserved record

[`docs/scoping/ccf-vds-verify.md`](../scoping/ccf-vds-verify.md) stays as the completed scoping note. It names a 23 Oct 2026 merge-or-hold date and a later `pask-wire` release as the place a verifier would ship. This decision does not edit that note. For work after 2026-10-23, the hold in this record is the disposition of that checkpoint.

[`KNOWN-LIMITATIONS.md`](../../KNOWN-LIMITATIONS.md) still records that CCF ledger receipts are retrieved and not verified. This decision does not change that limitation.
