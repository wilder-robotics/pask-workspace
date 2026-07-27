# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Pask, the reference implementation in this repository, or the conformance vectors at [wilder-robotics/pask-conformance-vectors](https://github.com/wilder-robotics/pask-conformance-vectors), please **do not open a public issue**.

Instead, report it privately using one of the following:

- **Preferred:** [GitHub Security Advisory](https://github.com/wilder-robotics/pask-workspace/security/advisories/new) — use the "Report a vulnerability" button on this repository's Security tab. This creates a private disclosure thread visible only to the maintainers and yourself.
- **Email:** [security@wilder-robotics.com](mailto:security@wilder-robotics.com). Please include "Pask security" in the subject line.

If you require encrypted email, request our current PGP public key at the address above and we will respond with it before you send sensitive details.

## What to include

Where possible, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, including any code, receipts, attestation payloads, or configuration required.
- The affected component (draft normative content, Rust workspace crate, or conformance vector) and, if known, the affected version, commit SHA, or specification section.
- Any suggested mitigation or patch you have already identified.

## Response commitment

We aim to:

1. Acknowledge your report within **3 business days** of receipt.
2. Provide an initial triage assessment within **7 business days**.
3. Coordinate a disclosure timeline with you before any public advisory is published.

We follow a **coordinated disclosure** model. If you require a specific embargo window (for example, to align with a coordinated advisory across multiple implementations), please state it in your initial report.

## Scope

The following are in scope for this policy:

- The draft's normative content in [`/draft/`](./draft/) as it relates to security properties Pask is intended to provide (integrity, non-repudiation, replay resistance, privacy).
- The Rust reference implementation in [`/crates/`](./crates/).
- The conformance test vectors at [wilder-robotics/pask-conformance-vectors](https://github.com/wilder-robotics/pask-conformance-vectors).
- The build and release pipeline configured in [`.github/workflows/`](./.github/workflows/).

The following are **out of scope**:

- Security issues in third-party dependencies unless the issue is specific to how Pask uses them. For upstream dependency issues, please report to the upstream project first.
- Vulnerabilities in TEE hardware, attestation-verification services, or other infrastructure not authored in this repository.
- Denial-of-service issues that require an unrealistic attacker model (for example, unbounded compute or storage on the verifier).

## Recognition

With your permission, we will credit you in the published security advisory and in the release notes for the fix. If you prefer to remain anonymous, let us know in your initial report.

## Governance

The security-triage role is currently held by the sole codeowner listed in [CODEOWNERS](./CODEOWNERS). A backup security contact will be named according to the succession plan in [GOVERNANCE.md §4](./GOVERNANCE.md). This policy is amended by pull request against `main`, subject to codeowner approval.
