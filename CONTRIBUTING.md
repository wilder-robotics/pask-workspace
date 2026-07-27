# Contributing to Pask

Thank you for your interest in Pask. This repository is the reference implementation and workspace for the IETF individual submission [`draft-wilder-scitt-physical-site-engagement-receipt`](https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engagement-receipt/) — a SCITT profile for signed, portable receipts of physical-site engagements involving robots, autonomous systems, and other machine actors.

Contributions from the community are welcome. This document describes how to file issues, propose changes, and participate in the standards process around Pask.

---

## Scope of contributions

We accept the following kinds of contributions:

- **Issues** — questions, bug reports, editorial suggestions on the draft, requests for clarification of normative language, or observations about the reference implementation.
- **Pull requests against the draft (`draft/` directory)** — editorial improvements to the `-XX` XML source, typo fixes, reference updates, cross-reference cleanups. Substantive normative changes are generally decided on the [IETF SCITT mailing list](mailto:scitt@ietf.org), not in this repo.
- **Pull requests against the reference implementation (Rust workspace)** — bug fixes, test-vector additions, adapter implementations against additional TEE platforms, documentation improvements.
- **Conformance vectors** — additions to [pask-conformance-vectors](https://github.com/wilder-robotics/pask-conformance-vectors), including negative-case vectors and platform-specific attestation vectors.

We do not accept contributions that:

- Add proprietary licensing conditions, additional grants, or terms incompatible with AGPL-3.0-only.
- Introduce dependencies on non-OSI-approved licenses.
- Introduce trademarks, product names, or commercial claims involving the Wilder Robotics name, the Pask name, or Wilder Management Inc. without prior discussion.

---

## Filing an issue

Before filing, please search existing issues (open and closed) to avoid duplicates.

**For questions about the draft:** open an issue in this repository, or send discussion to the SCITT WG mailing list at [scitt@ietf.org](mailto:scitt@ietf.org). WG-level discussion is preferred for substantive protocol questions; this issue tracker is preferred for editorial or reference-implementation-scoped questions.

**For security issues:** do not file a public issue. See [SECURITY.md](./SECURITY.md).

**For questions about the reference implementation:** open an issue in this repository with the label `implementation`.

---

## Proposing a change

1. Fork the repository under your own account or organization.
2. Create a feature branch: `git checkout -b your-feature-name`.
3. Commit your changes with [DCO-signed commits](https://developercertificate.org) — every commit must include a `Signed-off-by:` line. This is enforced by our CI. Use `git commit -s` to add the sign-off automatically.
4. Open a pull request against `main`. Fill out the PR template.
5. A CODEOWNER (see [CODEOWNERS](./CODEOWNERS)) will review. Substantive draft changes may be deferred to WG-level discussion.

### Commit-signing requirement

All commits merged to `main` must be [cryptographically signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) (GPG, S/MIME, or SSH signature). Signed commits are enforced by branch protection. Unsigned commits will fail the pre-merge check.

### DCO — Developer Certificate of Origin

Every commit must include a `Signed-off-by:` line certifying that you have the right to submit the contribution under the repository's license. The full DCO text is at [developercertificate.org](https://developercertificate.org). By signing off on a commit, you certify agreement with the DCO.

---

## Intellectual property and IETF process notice

This repository relates to activities in the Internet Engineering Task Force (IETF). All material in this repository is considered Contributions to the IETF Standards Process, as defined in the intellectual property policies of IETF currently designated as [BCP 78](https://www.rfc-editor.org/info/bcp78), [BCP 79](https://www.rfc-editor.org/info/bcp79), and the [IETF Trust Legal Provisions (TLP)](https://trustee.ietf.org/documents/trust-legal-provisions/) relating to IETF Documents.

By submitting a contribution (issue, pull request, or otherwise) you agree that your contribution is licensed under the terms of the repository's license (AGPL-3.0-only for code; the applicable IETF Trust boilerplate for draft text) and that you have made the disclosures required under BCP 78 and BCP 79.

---

## Code style and quality gates

- **Rust code:** must pass `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test`. These are enforced by CI.
- **Draft XML:** must pass `xml2rfc` validation and `idnits` compliance checks. These are enforced by CI.
- **Line length:** 72 columns for draft plain-text renderings, per IETF convention. No hard limit on Rust source.

---

## Governance and decision-making

Governance is documented in [GOVERNANCE.md](./GOVERNANCE.md). Substantive changes to the draft's normative content are decided in the IETF SCITT WG process, not in this repository. Editorial changes and reference-implementation changes are decided by the maintainer(s) named in [CODEOWNERS](./CODEOWNERS).

---

## Questions

Open an issue in this repository, or reach out to the maintainer(s) via the addresses listed in [GOVERNANCE.md](./GOVERNANCE.md).
