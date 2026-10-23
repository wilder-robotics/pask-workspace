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

The maintainer entity is unchanged. [CODEOWNERS](./CODEOWNERS) routes review to `actionrob`, the GitHub account controlled by Rob Wilder. On 2026-10-23 that account was the only collaborator this repository's API listed, and it holds repository admin.

The following operating roles apply to work dispatched on or after 2026-10-23. They do not override §3, legal counsel, or a relying party's own trust policy.

### 2.1 Rob Wilder

Rob Wilder approves merges and consequential decisions about scope, trust, disclosure, licensing, release, purchase, and deployment. A merge approval is not a release approval, a certification, or a deployment approval.

### 2.2 ChatGPT

ChatGPT holds architecture, the threat model, interfaces, profile semantics, specifications, acceptance criteria, and the final technical disposition of security-sensitive changes. ChatGPT does not override owner decisions, legal counsel, or relying-party trust policy.

### 2.3 Cursor

Cursor holds production implementation, tests, ordinary refactoring, documentation updates, and CI repair inside an approved task. Cursor must not make an unapproved change to trust, wire semantics, licensing, assurance language, or acceptance criteria. Cursor must not approve its own pull request and must not merge.

### 2.4 Perplexity Computer

Perplexity Computer holds standards and vendor research, evidence acquisition, explicitly isolated prototypes, and independent reproduction or review of critical results. A prototype is a research artifact and must not be treated as a second production implementation. A research conclusion must not be treated as an architectural decision. This assignment replaces Perplexity Computer's former canonical-integrator role: Cursor prepares the source pull request, CI tests the exact revision, and Rob Wilder merges.

### 2.5 Grok Bot

Grok Bot holds dispatch, task ownership, dependency tracking, reminders, and evidence-based status reporting. Grok Bot relays a specification without changing it. Grok Bot must not resolve an architectural question by paraphrasing it.

### 2.6 Contributors

Anyone may open issues, discussions, or pull requests. Additional reviewers are appointed at the code owner's discretion. No trusted contributor holds write access to a subdirectory.

The earlier statement that no reviewer exists beyond the sole code owner is superseded for future work. A security-sensitive change needs ChatGPT's disposition and an independent evidence review. The merge itself needs Rob Wilder's approval once he applies the ruleset remediation in the [settings report](docs/governance/github-settings-report-2026-10-23.md). Until that remediation is applied, GitHub does not enforce a separate approval. See §4.1.

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

Enforcement Rob Wilder applies outside this repository's files:

- One approval on the final revision.
- Stale approvals stay dismissed when new commits are pushed.
- Code-owner review for the security-sensitive paths in [CODEOWNERS](./CODEOWNERS).
- Required status checks must pass, and review conversations must be resolved.
- Agents must not have a bypass. An administrator bypass must not be available to an agent.

The code owner does not approve their own pull request. No second code owner is named in §4.3 yet. After code-owner review is required, a pull request authored by `actionrob` still has no second owner who can satisfy it. Agent-authored pull requests are the case this charter can satisfy: the agent identity is not `actionrob`, and Rob Wilder approves.

Agents must not push implementation work directly to `main`. Any instruction that would send future task work straight to `main` is superseded by this paragraph. Commits already on `main` stay as history. §4.3 still provides no emergency-merge process.

### 4.2 Constitutional changes

Changes to `GOVERNANCE.md`, `LICENSE`, `COMMERCIAL-EXCEPTION.md`, `CODEOWNERS`, or the repository's default branch protections are decided by the maintainer entity (Wilder Management Inc., operating under the Wilder Robotics assumed name), currently through the sole codeowner. ChatGPT, Cursor, Perplexity Computer, and Grok Bot do not acquire that authority. Cursor must not edit grant text unless a later task says so after legal review.

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

**Contributions:** a code contribution is accepted under the license of the crate it modifies. Draft text is accepted under the IETF Trust Legal Provisions. By opening a pull request the contributor certifies compliance with the [Developer Certificate of Origin](https://developercertificate.org/) via a `Signed-off-by:` line on every commit. See [CONTRIBUTING.md](CONTRIBUTING.md) and [LICENSING.md](LICENSING.md).

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

[CODEOWNERS](./CODEOWNERS) routes security-sensitive paths to `actionrob`. GitHub's code-owner review, once Rob Wilder enables it, is the platform half of that control. The technical disposition still belongs to ChatGPT, and the independent evidence review in §11 still applies. Neither half is optional for a security-sensitive change.

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

Agents must not operate with Rob Wilder's administrator credentials. Agent-authored pull requests use a distinct agent identity so that approval by Rob Wilder is a separate person's approval.

Cursor's cloud environment receives only the repositories, test credentials, and outbound access a task needs. It does not receive production signing keys, cloud-administrator credentials, or live tournament access.

An agent must not use an administrator bypass, must not edit GitHub rulesets or branch protection, and must not merge. Settings that require those permissions are reported for Rob Wilder. The report for the 2026-10-23 read is [docs/governance/github-settings-report-2026-10-23.md](docs/governance/github-settings-report-2026-10-23.md).

Public files, commit messages, and pull-request text may name Rob Wilder. Other human participants are not named. AI participants are named only as ChatGPT, Cursor, Perplexity Computer, and Grok Bot. Every commit carries a Developer Certificate of Origin `Signed-off-by` trailer. Commit identity stays on the allowlist in [`scripts/name_guard.sh`](scripts/name_guard.sh).
