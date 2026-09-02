# Contributing to Pask

Thank you for your interest in Pask. This repository is the reference implementation and workspace for the IETF individual submission [`draft-wilder-scitt-physical-site-engage-receipt`](https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/) — a SCITT profile for signed, portable receipts of physical-site engagements involving robots, autonomous systems, and other machine actors.

Contributions from the community are welcome. This document describes how to file issues, propose changes, and participate in the standards process around Pask.

---

## Scope of contributions

We accept the following kinds of contributions:

- **Issues** — questions, bug reports, editorial suggestions on the draft, requests for clarification of normative language, or observations about the reference implementation.
- **Pull requests against the draft (`docs/` directory)** — editorial improvements to the `-XX` Markdown source, typo fixes, reference updates, cross-reference cleanups. Substantive normative changes are generally decided on the [IETF SCITT mailing list](mailto:scitt@ietf.org), not in this repo.
- **Pull requests against the reference implementation (Rust workspace)** — bug fixes, test-vector additions, adapter implementations against additional TEE platforms, documentation improvements.

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

Every commit must include a `Signed-off-by:` line certifying that you have the right to submit the contribution under the license of the crate you are modifying. The full DCO text is at [developercertificate.org](https://developercertificate.org). By signing off on a commit, you certify agreement with the DCO.

There is no Contributor License Agreement and no copyright assignment is taken. You keep the copyright in your contribution.

### Which license your contribution lands under

**This repository is not licensed uniformly**, so check before you start:

- `pask-wire`, `pask-attest`, and `pask-wire-cli` are **Apache-2.0**
- `pask-site` and `pask-adapter` are **AGPL-3.0-only**

[`LICENSING.md`](LICENSING.md) is authoritative and explains why. Two rules follow from it that a contributor can trip over:

1. **Never add a dependency from `pask-wire`, `pask-attest`, or `pask-wire-cli` onto an AGPL-3.0-only crate** — including an *optional* one behind a feature flag, which is how this trap was originally set. That is a license violation, not a style problem. If a spec-side crate seems to need something from an operational crate, the thing it needs is in the wrong crate.
2. **Never add a copyleft third-party dependency to a permissive crate.** Every current dependency of those two crates is permissive, and that is what makes the permissive license honest.

Both rules are checked in CI. If you are unsure which side a change belongs on, open an issue before writing the code.

---

## Intellectual property and IETF process notice

This repository relates to activities in the Internet Engineering Task Force (IETF). All material in this repository is considered Contributions to the IETF Standards Process, as defined in the intellectual property policies of IETF currently designated as [BCP 78](https://www.rfc-editor.org/info/bcp78), [BCP 79](https://www.rfc-editor.org/info/bcp79), and the [IETF Trust Legal Provisions (TLP)](https://trustee.ietf.org/documents/trust-legal-provisions/) relating to IETF Documents.

By submitting a contribution (issue, pull request, or otherwise) you agree that your contribution is licensed under the terms applicable to what you changed — Apache-2.0 for `pask-wire`, `pask-attest`, and `pask-wire-cli`, AGPL-3.0-only for `pask-site` and `pask-adapter`, and the applicable IETF Trust boilerplate for draft text — and that you have made the disclosures required under BCP 78 and BCP 79.

Note that the IETF Trust provisions govern the draft text independently of the code license. Changing a crate's copyright license does not alter the terms on which draft contributions are made.

---

## Code style and quality gates

- **Rust code:** must pass `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test`. These are enforced by CI.
- **Draft Markdown:** must convert with `kramdown-rfc2629`, validate with `xml2rfc`, and pass `idnits` compliance checks. These are enforced by CI.
- **Line length:** 72 columns for draft plain-text renderings, per IETF convention. No hard limit on Rust source.

---

## Governance and decision-making

Governance is documented in [GOVERNANCE.md](./GOVERNANCE.md). Substantive changes to the draft's normative content are decided in the IETF SCITT WG process, not in this repository. Editorial changes and reference-implementation changes are decided by the maintainer(s) named in [CODEOWNERS](./CODEOWNERS).

---

## Questions

Open an issue in this repository, or reach out to the maintainer(s) via the addresses listed in [GOVERNANCE.md](./GOVERNANCE.md).
