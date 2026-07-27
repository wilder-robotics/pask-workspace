# Pask Governance

**Repository:** `pask-workspace`
**Organization:** `wilder-robotics` (GitHub)
**Maintainer entity:** Wilder Management Inc. (Illinois, USA), operating under the Wilder Robotics assumed name (DBA)
**Effective:** 2026-07-28 (concurrent with the `-00` IETF filing)

This document describes how decisions are made about the Pask draft (`draft-wilder-scitt-physical-site-engagement-receipt-XX`) and the reference implementation hosted in this repository.

---

## 1. What Pask is

Pask is an IETF individual submission profiling [SCITT (Supply Chain Integrity, Transparency, and Trust)](https://datatracker.ietf.org/wg/scitt/documents/) for a specific application domain: signed, portable **engagement receipts** for physical-site events involving machine actors (robots, autonomous systems, IoT devices, semi-autonomous agents operating on real properties).

The scope is:

- The **draft** — an Internet-Draft in the SCITT problem space, filed as an individual submission (`draft-wilder-...`) with the intent of seeking SCITT WG adoption.
- The **reference implementation** — a Rust workspace implementing the draft's signing, verification, and profile-compliance logic, licensed under [AGPL-3.0-only with a documented commercial exception](./LICENSE-EXCEPTIONS.md).
- The **conformance test vectors** — hosted separately at [wilder-robotics/pask-conformance-vectors](https://github.com/wilder-robotics/pask-conformance-vectors).

---

## 2. Authorship vs. maintainership

**Authorship.** The Internet-Draft is authored by an individual, Rob Wilder, per the IETF individual-submission convention. The authors' addresses section of the draft names Rob Wilder personally with individual affiliation. Authorship of the draft is separate from ownership of this repository.

**Maintainership.** This repository is maintained by Wilder Management Inc., operating under the Wilder Robotics assumed name (DBA). Wilder Management Inc. is the parent legal entity; "Wilder Robotics" is the trade name under which the physical-AI infrastructure line, including Pask, is operated. Formation of a separate legal entity for the Wilder Robotics business line is planned and will be reflected in a future revision of this document when executed. Wilder Management Inc. holds the commercial licensing rights and the common-law trademark rights in "Pask" and "Wilder Robotics."

**Neither the draft's author nor the maintainer entity is any of the RATS roles named in the draft.** The Issuer, Attester, Verifier, and Relying Party roles are defined in §5 of the specification and are held by the deploying parties, not by the author or the maintainer of this repository.

---

## 3. Decision-making

Decisions in and around Pask fall into three tiers:

### Tier 1 — Normative content of the draft

Changes to normative language, schema, wire format, or role semantics are decided in the **IETF SCITT WG process**, not in this repository. Discussion venue is the [SCITT WG mailing list](mailto:scitt@ietf.org) and, where adopted, the [ietf-wg-scitt GitHub organization](https://github.com/ietf-wg-scitt).

While the draft remains an individual submission, the author has final authority over its normative content. Community input is welcomed via issues and mailing-list discussion.

### Tier 2 — Editorial content of the draft and reference implementation

Editorial fixes, reference updates, cross-reference cleanups, bug fixes in the Rust workspace, and additions to the conformance vectors are decided by the codeowner(s) named in [CODEOWNERS](./CODEOWNERS).

Community pull requests are welcomed. Merge requires codeowner approval and passing CI (formatting, linting, tests, DCO sign-off, signed commits).

### Tier 3 — Governance, licensing, and repository administration

Changes to `GOVERNANCE.md`, `LICENSE`, `LICENSE-EXCEPTIONS.md`, `CODEOWNERS`, or the repository's default branch protections are decided by the maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name), currently through the sole codeowner.

---

## 4. Maintainer succession and continuity

As of the `-00` filing, this repository has a **single codeowner**: Rob Wilder (GitHub: `@actionrob`).

A named backup maintainer will be added under the following conditions:

- Before the first enterprise commercial engagement involving Pask as a delivered artifact.
- Before, or concurrent with, `-01` revision if `-00` receives substantive WG engagement.
- Immediately, if requested by a working-group chair as a condition of adoption.

The maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name) commits to naming a backup within 30 days of the earlier of the above triggers. Until then, community contributors should expect a single-maintainer response cadence.

---

## 5. Licensing

**Reference implementation code:** [AGPL-3.0-only](./LICENSE), with a documented commercial exception published in [LICENSE-EXCEPTIONS.md](./LICENSE-EXCEPTIONS.md). The commercial exception permits Wilder Management Inc. (operating under the Wilder Robotics assumed name) to offer a proprietary hosted overlay ("Pask Enterprise") under separate commercial terms without triggering AGPL's network-use clause against paying customers who deploy the open-source layer for internal use.

**Draft text:** governed by the applicable IETF Trust Legal Provisions boilerplate embedded in the draft ([BCP 78](https://www.rfc-editor.org/info/bcp78), [BCP 79](https://www.rfc-editor.org/info/bcp79)).

**Trademarks:** "Pask" and "Wilder Robotics" are common-law trademarks used in commerce by Wilder Management Inc. under the Wilder Robotics assumed name. Use of these marks in derivative works, forks, or downstream products is governed by trademark law; the AGPL-3.0 grant does not extend to trademarks.

---

## 6. Contributions

See [CONTRIBUTING.md](./CONTRIBUTING.md). All contributors must:

- Sign off commits per the [Developer Certificate of Origin](https://developercertificate.org).
- Use [cryptographically signed commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) for changes merged to `main`.
- Agree that contributions are made under the IETF Contribution terms of BCP 78 / BCP 79 (for draft content) and AGPL-3.0-only (for code).

---

## 7. Security disclosure

See [SECURITY.md](./SECURITY.md). Security issues must not be filed as public issues.

---

## 8. Amendment

This document is amended by pull request against `main`, subject to codeowner approval. Amendments that change §3 (decision-making) or §4 (maintainer succession) require an explicit statement in the pull-request description acknowledging the change.

---

## 9. Contact

- **Repository issues:** [GitHub issues on this repository](https://github.com/wilder-robotics/pask-workspace/issues) (preferred for repo-scoped questions).
- **WG-level discussion:** [scitt@ietf.org](mailto:scitt@ietf.org).
- **Maintainer entity:** Wilder Management Inc., operating under the Wilder Robotics assumed name. Business inquiries: see [wilder-robotics.com](https://wilder-robotics.com).
- **Security disclosures:** see [SECURITY.md](./SECURITY.md).
