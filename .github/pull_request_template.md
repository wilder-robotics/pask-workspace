<!--
Thanks for opening a pull request against pask-workspace.

Please fill out every section below. PRs missing sign-off, tests, or
context will be asked to update before review.

For substantive changes to the draft's normative content, please open
discussion on the SCITT WG mailing list (scitt@ietf.org) *before* this
PR — the mailing list is where those decisions live, per GOVERNANCE.md.
-->

## Summary

<!-- One-line description of what this PR changes and why. -->

## Type of change

<!-- Check exactly one. -->

- [ ] Editorial fix to the draft (typo, cross-reference, reference update)
- [ ] Normative change to the draft (schema, wire format, MUST/SHOULD language) — has this been discussed on the SCITT WG mailing list?
- [ ] Bug fix in the Rust reference implementation
- [ ] New feature or capability in the Rust reference implementation
- [ ] New conformance vector or update to existing vectors
- [ ] Documentation, governance, or repository housekeeping
- [ ] CI, tooling, or release automation
- [ ] Other (describe below)

## Related issues / drafts

<!-- Link any related GitHub issues, IETF mailing-list threads, or datatracker entries. -->

Closes #

## Testing

<!-- What did you run locally to verify the change? -->

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `xml2rfc` validates the draft (if draft touched)
- [ ] `idnits` passes (if draft touched)
- [ ] New tests or vectors added where behavior changed
- [ ] Not applicable (documentation-only, etc.)

## Draft-XML impact (only fill in if this PR touches `/draft/`)

- [ ] Does not change any MUST / SHOULD / MAY normative language
- [ ] Changes normative language — discussed on `scitt@ietf.org`, thread link:
- [ ] Changes the wire format or schema — code freeze status has been reviewed against `pask_code_freeze.md`

## RATS-semantics / reservation discipline check

<!-- The panel discipline: repo-owner and maintainer are NOT the same as RATS roles.
Confirm this PR does not blur that boundary. -->

- [ ] This PR does not introduce language implying the repository owner is an Issuer, Attester, Verifier, or Relying Party in the RATS sense.
- [ ] This PR does not introduce commercial-positioning language, named-counterparty targets, or "Pask solves X" claims.

## Sign-off

Every commit in this PR must include a `Signed-off-by:` line per the [Developer Certificate of Origin](https://developercertificate.org) and be [cryptographically signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) (GPG, S/MIME, or SSH signature). The DCO and signed-commits status checks will block merge otherwise.

- [ ] All commits are DCO-signed (`git commit -s`)
- [ ] All commits are cryptographically signed (verified badge visible in the commit list)

## Additional notes

<!-- Anything else the reviewer should know. -->
