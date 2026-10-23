# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Pask, in the
reference implementation in this repository, or in the in-tree fixtures and
signed vectors, please **do not open a public issue**.

A separate conformance-vector repository (`pask-conformance-vectors`) does
not exist. Do not try to report it there. Fixture and vector issues belong
in this repository, through the private channel below.

Report privately using one of the following:

- **Preferred:** [GitHub Security Advisory](https://github.com/wilder-robotics/pask-workspace/security/advisories/new).
  Use the "Report a vulnerability" button on this repository's Security tab.
  That creates a private disclosure thread visible only to the maintainers
  and to you.
- **Email:** [security@wilder-robotics.com](mailto:security@wilder-robotics.com).
  Please include "Pask security" in the subject line.

If you require encrypted email, request the current PGP public key at the
address above. The reply will carry the key before you send sensitive
details.

## What to include

Where possible, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, including any code, receipts, attestation payloads, or
  configuration required.
- The affected component (draft text, a Rust crate, or an in-tree fixture)
  and, if known, the affected version, commit SHA, or specification section.
- Any suggested mitigation or patch you have already identified.

## Response commitment

We aim to:

1. Acknowledge your report within **3 business days** of receipt.
2. Provide an initial triage assessment within **7 business days**.
3. Coordinate a disclosure timeline with you before any public advisory is
   published.

We follow a coordinated disclosure model. If you need a specific embargo
window, for example to line up a coordinated advisory across more than one
implementation, please say so in the first report.

## Scope

The following are in scope for this policy:

- The working draft
  [`docs/draft-wilder-scitt-physical-site-engage-receipt-05.md`](docs/draft-wilder-scitt-physical-site-engage-receipt-05.md),
  including the security properties the profile text is written to discuss.
  That file is the in-tree working draft. It is not the posted revision.
  There is no `draft/` directory. RFCXML is generated in CI and is not
  committed.
- The Rust workspace in [`crates/`](crates/).
- In-tree fixtures under
  [`crates/pask-wire/fixtures/`](crates/pask-wire/fixtures/) and the signed
  vector file
  [`crates/pask-wire/pask_67_independent_signed_vectors.json`](crates/pask-wire/pask_67_independent_signed_vectors.json).
- The build and release pipeline in
  [`.github/workflows/`](.github/workflows/).

The following are out of scope:

- Security issues in third-party dependencies, unless the issue is specific
  to how Pask uses them. For an upstream dependency issue, report it to the
  upstream project first.
- Vulnerabilities in TEE hardware, attestation-verification services, or
  other infrastructure this repository does not author.
- Denial-of-service issues that require an unrealistic attacker model (for
  example, unbounded compute or storage on the verifier).

## What a report is not required to rediscover

This tree is pre-alpha. [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) already
records several gaps. Two that are easy to mistake for an unpublished
finding:

- Section 2: hardware-evidence appraisal is not implemented. A digest,
  a `teeClass` label, or a self-consistent measured-boot chain is not
  evidence verification.
- Section 5.2: Transparency Service registration is implemented in
  `pask-ts-client` and is not wired into the reference site. No production
  Transparency Service is operated here. Offline inclusion verification
  covers `RFC9162_SHA256` only. CCF-profile receipts retrieved in the
  development configuration are not verified.

A note that one of those entries is wrong is worth sending. A new flaw in
the checks the code does implement should use the private channel above.

## Recognition

With your permission, we will credit you in the published security advisory
and in the release notes for the fix. If you prefer to remain anonymous, say
so in the first report.

## Governance

The security-triage role is currently held by the sole codeowner listed in
[CODEOWNERS](CODEOWNERS). A backup security contact will be named according
to the succession plan in [GOVERNANCE.md](GOVERNANCE.md) section 4. This
policy is amended by pull request against `main`, subject to codeowner
approval.
