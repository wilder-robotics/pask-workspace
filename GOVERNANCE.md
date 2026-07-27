# Governance

This document describes how decisions are made in this repository.

**Maintainer entity:** Wilder Management Inc. (Illinois, USA), operating under the Wilder Robotics assumed name (DBA)
**Domain of authority:** the reference implementation of `draft-wilder-scitt-physical-site-engagement-receipt` and directly supporting artifacts in this repository. **Not the specification itself** — see §3.

---

## 1. Scope

This repository holds two categories of material:

- The **draft specification source** — `draft-wilder-scitt-physical-site-engagement-receipt-XX.xml` and its rendered outputs, tracked at the [IETF datatracker](https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engagement-receipt/).
- The **reference implementation** — a Rust workspace implementing the draft's signing, verification, and profile-compliance logic, licensed under [AGPL-3.0-only with a documented commercial exception](./COMMERCIAL-EXCEPTION.md).

Governance of these two categories is different, described in §3 and §4 below.

---

## 2. Roles

- **Sole codeowner:** listed in [CODEOWNERS](./CODEOWNERS). Currently a single person.
- **Contributors:** anyone who opens issues, discussions, or pull requests.
- **Reviewers:** appointed at the codeowner's discretion. As of `-00`, there are no additional reviewers beyond the sole codeowner.
- **Trusted contributors (future):** contributors invited to hold write access to specific subdirectories. As of `-00`, none exist.

---

## 3. Draft specification governance

The draft is an **IETF individual submission** at Internet-Draft stage. Substantive changes to normative language (MUST / SHOULD / MAY, schema, wire format, threat model) are decided in the IETF SCITT WG process:

- Discussion venue: [`scitt@ietf.org`](mailto:scitt@ietf.org).
- Formal artifacts: WG minutes, mailing-list threads, IETF datatracker entries.
- This repository's issue tracker and pull-request queue is **not** the decision venue for substantive normative changes to the draft. Editorial improvements (typos, cross-references, reference updates) are welcomed here.

Should the draft be adopted by the SCITT WG, governance of the draft transfers to the WG per BCP 25 / RFC 2418. The reference implementation continues to be governed under this document.

---

## 4. Reference-implementation governance

**Maintainership.** This repository is maintained by Wilder Management Inc., operating under the Wilder Robotics assumed name (DBA). Wilder Management Inc. is the parent legal entity; "Wilder Robotics" is the trade name under which the physical-AI infrastructure line, including Pask, is operated. Formation of a separate legal entity for the Wilder Robotics business line is planned and will be reflected in a future revision of this document when executed. Wilder Management Inc. holds the commercial licensing rights and the common-law trademark rights in "Pask" and "Wilder Robotics."

### 4.1 Merge authority

- Pull requests against `main` require approval from a CODEOWNER before merge.
- Enforcement: `main` is protected by a GitHub repository ruleset requiring PR review, CODEOWNER approval, resolved conversations, signed commits, and linear history.
- The codeowner may not self-approve; a second maintainer will be named per §4.3 to enable review of the codeowner's own PRs.

### 4.2 Constitutional changes

Changes to `GOVERNANCE.md`, `LICENSE`, `COMMERCIAL-EXCEPTION.md`, `CODEOWNERS`, or the repository's default branch protections are decided by the maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name), currently through the sole codeowner.

### 4.3 Succession plan

If the sole codeowner is unable to continue as maintainer, the following succession plan applies:

- **Trigger 1 — announced departure.** The codeowner MAY announce planned departure and name a successor via a pull request updating [CODEOWNERS](./CODEOWNERS), merged following the normal review process against the maintainer entity's approval.
- **Trigger 2 — unannounced unavailability.** If the codeowner is unreachable for 90 consecutive days (no PR review, no issue response, no email response from the address in [SECURITY.md](./SECURITY.md)), a person or organization documenting the 90-day gap MAY petition the SCITT WG chairs for a successor determination. This mirrors the IETF process for orphaned individual submissions.
- **Interim state during succession.** During any succession period, the repository remains at its last-good `main` commit. No emergency-merge process exists; if urgent security fixes are needed during a succession gap, contributors are encouraged to fork.

The maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name) commits to naming a backup within 30 days of the earlier of the above triggers. Until then, community contributors should expect a single-maintainer response cadence.

---

## 5. License and IP

**Draft text:** licensed under the [IETF Trust Legal Provisions](https://trustee.ietf.org/documents/trust-legal-provisions/) as applicable to Internet-Drafts. See the boilerplate in the draft itself.

**Reference implementation code:** [AGPL-3.0-only](./LICENSE), with a documented commercial exception published in [COMMERCIAL-EXCEPTION.md](./COMMERCIAL-EXCEPTION.md). The commercial exception permits Wilder Management Inc. (operating under the Wilder Robotics assumed name) to offer a proprietary hosted overlay ("Pask Enterprise") under separate commercial terms without triggering AGPL's network-use clause against paying customers who deploy the open-source layer for internal use.

**Contributions:** all contributions to this repository are accepted under the AGPL-3.0-only license (for code) and the IETF Trust Legal Provisions (for draft text), and by opening a pull request the contributor certifies compliance with the [Developer Certificate of Origin](https://developercertificate.org/) via a `Signed-off-by:` line on every commit.

**Trademarks:** "Pask" and "Wilder Robotics" are common-law trademarks used in commerce by Wilder Management Inc. under the Wilder Robotics assumed name. Use of these marks in derivative works, forks, or downstream products is governed by trademark law; the AGPL-3.0 grant does not extend to trademarks.

---

## 6. Communication channels

- **Repository issues:** the primary venue for editorial fixes to the draft, questions about the reference implementation, and bug reports.
- **SCITT WG mailing list ([`scitt@ietf.org`](mailto:scitt@ietf.org)):** the primary venue for substantive discussion of the draft's normative content.
- **IETF datatracker:** the canonical location for the draft itself, its history, and related IETF process artifacts.
- **Security reports:** see [SECURITY.md](./SECURITY.md).

---

## 7. Amendments

This document is amended by pull request against `main`. Amendments to §3 (Draft specification governance) that alter the relationship between this repository and the IETF SCITT WG process require coordination with the WG chairs before merge. All other amendments require CODEOWNER approval.

---

## 8. Contact

- **Maintainer entity:** Wilder Management Inc., operating under the Wilder Robotics assumed name. Business inquiries: see [wilder-robotics.com](https://wilder-robotics.com).
- **Codeowner:** as listed in [CODEOWNERS](./CODEOWNERS).
- **Security contact:** see [SECURITY.md](./SECURITY.md).
