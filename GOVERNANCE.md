# Governance

This document describes how decisions are made in this repository.

**Maintainer entity:** Wilder Management Inc. (Illinois, USA), operating under the Wilder Robotics assumed name (DBA)
**Domain of authority:** the reference implementation of `draft-wilder-scitt-physical-site-engage-receipt` and the supporting artifacts in this repository. Governance of the specification text is in section 3. The in-tree working draft is [`docs/draft-wilder-scitt-physical-site-engage-receipt-05.md`](docs/draft-wilder-scitt-physical-site-engage-receipt-05.md).

---

## 1. Scope

This repository holds two categories of material:

- The **draft specification source**. The working copy in this tree is [`docs/draft-wilder-scitt-physical-site-engage-receipt-05.md`](docs/draft-wilder-scitt-physical-site-engage-receipt-05.md). It is Markdown. CI generates RFCXML from that file when the draft changes, and the XML is not committed. The -05 file is a working draft and is not the posted revision. The canonical posted document is the IETF individual submission [`draft-wilder-scitt-physical-site-engage-receipt`](https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/). There is no `draft/` directory.
- The **reference implementation**. A Rust workspace of six crates. `pask-wire`, `pask-attest`, and `pask-wire-cli` are [Apache-2.0](LICENSE-APACHE-2.0). `pask-site`, `pask-adapter`, and `pask-ts-client` are [AGPL-3.0-only](LICENSE). [LICENSING.md](LICENSING.md) is the authoritative map. [COMMERCIAL-EXCEPTION.md](COMMERCIAL-EXCEPTION.md) applies only to the AGPL-3.0-only crates. The implementation is pre-alpha. [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) records what it does not do. In particular, section 2 records that the profile's three-party trust model is not demonstrated here, and section 5.2 records that Transparency Service registration is implemented in `pask-ts-client` and is not wired into the reference site.

Governance of these two categories is different, described in §3 and §4 below. Operating roles, task handoff, pull-request evidence, and agent limits are in §2 and §9 through §13. Accepted selections that are not yet implemented are in [`docs/decisions/`](docs/decisions/).

---

## 2. Roles

Rob Wilder's authority is above every participant, including the architect. ChatGPT's role is advisory and technical. ChatGPT's decisions and acceptance criteria stand unless Rob Wilder overrides them. Rob Wilder can override any of them.

The maintainer entity is unchanged. [CODEOWNERS](./CODEOWNERS) routes review to `actionrob`, the GitHub account controlled by Rob Wilder. On 2026-10-23 that account was the only collaborator this repository's API listed, and it holds repository admin.

The following operating roles apply to work dispatched on or after 2026-10-23. They describe how participants carry out work Rob Wilder has accepted. Section 3 remains the description of the IETF individual-submission process.

### 2.1 Rob Wilder

Rob Wilder approves merges and consequential decisions about scope, trust, disclosure, licensing, release, purchase, and deployment. He may delegate merging to his agents. When Rob Wilder has explicitly approved a pull request, Grok Bot may merge it, and that merge counts as Rob Wilder's merge. A merge approval is not a release approval, a certification, or a deployment approval.

### 2.2 ChatGPT

ChatGPT advises on architecture, the threat model, interfaces, profile semantics, specifications, acceptance criteria, and the technical disposition of security-sensitive changes. Those decisions and acceptance criteria stand unless Rob Wilder overrides them.

### 2.3 Cursor

Cursor holds production implementation, tests, ordinary refactoring, documentation updates, and CI repair inside an approved task. Cursor must not make an unapproved change to trust, wire semantics, licensing, assurance language, or acceptance criteria. Cursor does not approve its own pull request and does not merge.

### 2.4 Perplexity Computer

Perplexity Computer holds standards and vendor research, evidence acquisition, explicitly isolated prototypes, and independent reproduction or review of critical results. A prototype is a research artifact and must not be treated as a second production implementation. A research conclusion must not be treated as an architectural decision. This assignment replaces Perplexity Computer's former canonical-integrator role: Cursor prepares the source pull request, and CI tests the exact revision. The merge is Rob Wilder's, including a merge Grok Bot performs after Rob Wilder's explicit approval of that pull request.

### 2.5 Grok Bot

Grok Bot holds dispatch, task ownership, dependency tracking, reminders, and evidence-based status reporting. Grok Bot relays a specification without changing it. Grok Bot must not resolve an architectural question by paraphrasing it. Grok Bot is Rob Wilder's coordinator for merges: when Rob Wilder has explicitly approved a pull request, Grok Bot merges it, and that merge counts as Rob Wilder's merge.

### 2.6 Contributors

Anyone may open issues, discussions, or pull requests. Additional reviewers are appointed at the code owner's discretion. No trusted contributor holds write access to a subdirectory.

The earlier statement that no reviewer exists beyond the sole code owner is superseded for future work. A security-sensitive change carries ChatGPT's technical disposition and an independent evidence review. Those stand unless Rob Wilder overrides them. The merge is Rob Wilder's explicit approval of that pull request, which Grok Bot may carry out. See §4.1 and the options in the [settings report](docs/governance/github-settings-report-2026-10-23.md). GitHub, as read on 2026-10-23, does not require a separate approval.

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

Preserved assertion, superseded as a description of enforcement: this section previously stated that pull requests against `main` require CODEOWNER approval before merge, and that `main` is protected by a GitHub repository ruleset requiring pull-request review, CODEOWNER approval, resolved conversations, signed commits, and linear history.

Read on 2026-10-23 from ruleset `main-protection` (id 19786840), and written up in [docs/governance/github-settings-report-2026-10-23.md](docs/governance/github-settings-report-2026-10-23.md): a pull request is required, the required approving review count is zero, code-owner review is not required, conversation resolution is not required, and the ruleset has no signed-commit rule. Linear history is required. Branch deletion and non-fast-forward pushes are rejected. Stale-review dismissal on push is already enabled. This document does not change those settings. Rob Wilder applies and verifies every setting that a source pull request cannot change.

Settings choices are Rob Wilder's. The [settings report](docs/governance/github-settings-report-2026-10-23.md) records the live rules and lists options. Those options are not requirements. They leave a working path for merges Rob Wilder delegates to his agents. The report does not ask him to remove the bypass that path uses.

Rob Wilder may delegate merging to his agents. Grok Bot merges a pull request when Rob Wilder has explicitly approved that pull request, and that merge counts as Rob Wilder's merge. That is not a violation. Cursor does not merge and does not approve its own pull requests.

No second code owner is named in §4.3 yet. If code-owner review were turned on, a pull request authored by `actionrob` would have no second owner who could satisfy it. That is an observation, not an instruction to remove `actionrob`'s bypass. Cursor's own pull requests are still not approved or merged by Cursor.

Agents must not push implementation work directly to `main`. Any instruction that would send future task work straight to `main` is superseded by this paragraph. Commits already on `main` stay as history. §4.3 still provides no emergency-merge process.

### 4.2 Constitutional changes

Changes to `GOVERNANCE.md`, `LICENSE`, `COMMERCIAL-EXCEPTION.md`, `CODEOWNERS`, or the repository's default branch protections are decided by the maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name), currently through Rob Wilder. Delegated merge authority does not by itself edit those documents. Grant-changing license text needs Rob Wilder's explicit approval before merge. Owner review of that text is Rob Wilder's, assisted by his Wilder Legal & IP agent. Pask does not use outside counsel.

### 4.3 Succession plan

If the sole codeowner is unable to continue as maintainer, the following succession plan applies:

- **Trigger 1 — announced departure.** The codeowner MAY announce planned departure and name a successor via a pull request updating [CODEOWNERS](./CODEOWNERS), merged following the normal review process against the maintainer entity's approval.
- **Trigger 2 — unannounced unavailability.** If the codeowner is unreachable for 90 consecutive days (no PR review, no issue response, no email response from the address in [SECURITY.md](./SECURITY.md)), a person or organization documenting the 90-day gap MAY petition the SCITT WG chairs for a successor determination. This mirrors the IETF process for orphaned individual submissions.
- **Interim state during succession.** During any succession period, the repository remains at its last-good `main` commit. No emergency-merge process exists; if urgent security fixes are needed during a succession gap, contributors are encouraged to fork.

The maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name) commits to naming a backup within 30 days of the earlier of the above triggers. Until then, community contributors should expect a single-maintainer response cadence.

---

## 5. License and IP

**Draft text:** licensed under the [IETF Trust Legal Provisions](https://trustee.ietf.org/documents/trust-legal-provisions/) as applicable to Internet-Drafts. See the boilerplate in the draft itself.

**Reference implementation code:** this repository is not licensed uniformly. `pask-wire`, `pask-attest`, and `pask-wire-cli` are [Apache-2.0](LICENSE-APACHE-2.0) and are published on crates.io at 0.2.0. `pask-site`, `pask-adapter`, and `pask-ts-client` are [AGPL-3.0-only](LICENSE) and are not published. [LICENSING.md](LICENSING.md) states the rule: code whose purpose is interoperability is Apache-2.0, and code whose purpose is operating a deployment is AGPL-3.0-only. [`scripts/license_guard.sh`](scripts/license_guard.sh) checks that split in CI.

[COMMERCIAL-EXCEPTION.md](COMMERCIAL-EXCEPTION.md) applies only to the AGPL-3.0-only crates. The commercial exception permits Wilder Management Inc. (operating under the Wilder Robotics assumed name) to offer a proprietary hosted overlay ("Pask Enterprise") under separate commercial terms without triggering AGPL's network-use clause against paying customers who deploy the open-source layer for internal use. The Apache-2.0 crates do not need that agreement.

**Contributions:** a code contribution is accepted under the license of the crate it modifies. Draft text is accepted under the IETF Trust Legal Provisions. By opening a pull request the contributor certifies compliance with the [Developer Certificate of Origin](https://developercertificate.org/) via a `Signed-off-by:` line on every commit. See [CONTRIBUTING.md](CONTRIBUTING.md) and [LICENSING.md](LICENSING.md). A DCO sign-off is not a copyright assignment. Contributor rights are checked as part of owner review by Rob Wilder, assisted by his Wilder Legal & IP agent, before grant-changing license text merges.

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

---

## 9. Source of truth

GitHub is the authoritative index of decisions, source, tasks, and evidence identities. Not every evidence object belongs in the public repository. Private hardware samples, identifiers, commercial information, and unreleased tournament material stay in authorized private locations. A public task references an approved manifest or a public summary. This charter does not authorize publication of private evidence.

Proposed layout, used from 2026-10-23 forward:

- [`docs/decisions/`](docs/decisions/): accepted architecture decisions. A record there is a selection. It is not a claim that the selected behavior exists in the tree.
- [`docs/tasks/`](docs/tasks/): approved implementation specifications. The template and its fields are in [`docs/tasks/README.md`](docs/tasks/README.md).
- [`docs/research/`](docs/research/): findings, each with a status and source identities.

Cursor repository instructions for agents that implement those tasks are in [`.cursor/rules/governance.mdc`](.cursor/rules/governance.mdc). The instructions point here. They do not replace this document.

## 10. Task handoff

Each task has one issue, one approved specification revision, one implementation owner, and one active implementation branch.

A handoff names all of the following:

- Task id.
- Specification path and the specification commit.
- Base commit and the modules the owner may change.
- Invariants and explicit non-goals.
- Acceptance cases and the evidence those cases require.
- Dependencies and the assigned owner.
- Escalation conditions.

Perplexity Computer supplies research to that same issue. ChatGPT turns a consequential finding into a specification amendment. Grok Bot dispatches the amended revision. An ordinary edit, compile, test, or repair cycle inside an authorized task does not need a new escalation. Escalation is required when the meaning or the scope changes.

Grok Bot relays the approved text. A paraphrase is not a new specification.

## 11. Pull request evidence

Every pull request includes four parts. The template is [`.github/pull_request_template.md`](.github/pull_request_template.md).

1. **Decision and scope.** Task and specification revision, base commit, head commit, changed behavior, unchanged boundaries, and any dependency or license change.
2. **Acceptance matrix.** Each acceptance criterion mapped to a test or an evidence artifact. Failures, ignored tests, and `NOT_RUN` items are listed.
3. **Reproduction evidence.** Exact commands, toolchain, feature flags, operating system, exit codes, test counts, logs, and fixture identities.
4. **Risk and review.** Migrations, rollback, unresolved limitations, and reviewer findings.

A critical trust change requires independent reproduction by Perplexity Computer or by another reviewer Rob Wilder designates. Review by a second Cursor agent is not automatically independent evidence.

## 12. Security-sensitive changes

[CODEOWNERS](./CODEOWNERS) routes security-sensitive paths to `actionrob`. ChatGPT's technical disposition and the independent evidence review in §11 stand unless Rob Wilder overrides them. Code-owner review on GitHub is one of the options in the settings report, not a requirement of this document.

Cursor must escalate, and must stop rather than invent a disposition, when a change touches any of the following:

- Signed bytes.
- Trust anchors.
- Accepted algorithms.
- Profile versions.
- Enum meanings.
- Time policy.
- Key custody.
- Fixture expectations.
- Licensing.
- Public assurance claims.

Cursor must never weaken a negative test to make CI green.

Paths that carry those concerns are listed in [CODEOWNERS](./CODEOWNERS). The list includes the wire and attestation crates, the registration client, the write-in adapter, the reference site, the draft, the decision records, licensing files, and public limitation statements.

## 13. Agent permissions

Rob Wilder may delegate merging to his agents. Grok Bot merges a pull request when Rob Wilder has explicitly approved that pull request. That merge counts as Rob Wilder's merge and is not a violation. The settings report keeps the facts about required reviews and bypass actors, and its options leave the bypass that delegated merges use.

Cursor does not merge and does not approve its own pull requests. Cursor does not edit GitHub rulesets, branch protection, or team permissions. Those settings are reported for Rob Wilder, who applies whatever he chooses. The report for the 2026-10-23 read is [docs/governance/github-settings-report-2026-10-23.md](docs/governance/github-settings-report-2026-10-23.md).

Cursor's cloud environment receives only the repositories, test credentials, and outbound access a task needs. It does not receive production signing keys, cloud-administrator credentials, or live tournament access.

Public files, commit messages, and pull-request text may name Rob Wilder. Other human participants are not named. AI participants are named only as ChatGPT, Cursor, Perplexity Computer, Grok Bot, and the Wilder Legal & IP agent. Every commit carries a Developer Certificate of Origin `Signed-off-by` trailer. Commit identity stays on the allowlist in [`scripts/name_guard.sh`](scripts/name_guard.sh).
