# Licensing

*Split settled 2026-09-02. This document describes the licensing of this repository as of that
date; a draft revision citing it should be read against the repository state of the revision.*

This repository is **not** licensed uniformly. The split is deliberate and follows the
difference between the crates that *are* the specification made executable and the
crates that are operational software.

## The map

| Crate | License | Why |
| --- | --- | --- |
| `pask-wire` | **Apache-2.0** | The wire format, COSE encoding, JCS canonicalization, and field semantics. This is the specification in code. It exists to be read, copied, and vendored by anyone implementing the profile |
| `pask-attest` | **Apache-2.0** | Attestation binding, typed claims, and verification. Also normative surface an implementer must reproduce |
| `pask-wire-cli` | **Apache-2.0** | The conformance tool. Produces receipts, verifies them, and emits the canonical example figure carried in the profile document. An implementer must be able to run this against their own implementation without a legal review |
| `pask-site` | **AGPL-3.0-only** | Deployment and operational machinery. Product surface |
| `pask-adapter` | **AGPL-3.0-only** | Property-system integrations, and the `pask-adapt` binary that writes a verified receipt into an operations system. Product surface |

Full texts: [`LICENSE`](LICENSE) is AGPL-3.0-only. [`LICENSE-APACHE-2.0`](LICENSE-APACHE-2.0) is
Apache-2.0. Each permissive crate also carries the Apache text in its own directory so that a
single vendored crate directory is unambiguous on its own.

Every source file carries an `SPDX-License-Identifier` comment matching its crate. The `license`
field in each crate's `Cargo.toml` matches the same. If a file, a manifest, and this table ever
disagree, that is a bug — report it.

## Why the spec-side crates are permissive

The purpose of publishing an Internet-Draft is to get other parties to implement the profile.
Independent implementations are what give a specification standing. A reference implementation
exists to be copied.

Network copyleft works directly against that. Large organizations commonly refuse AGPL by blanket
policy rather than case-by-case review, because the network clause is difficult to bound when the
product is itself a network service. An engineer who wants to check their receipts against the wire
format should not need to open a legal review to read `pask-wire`. Apache-2.0 removes that friction
and carries an explicit patent grant, which matters more than usual for a specification
implementation.

## Why Apache-2.0 and not MIT, or both

The Rust convention is `MIT OR Apache-2.0`. That was considered and rejected here for a specific
reason: `pask-wire` depends on `coset` (Apache-2.0 only) and `ryu-js` (Apache-2.0 or BSL-1.0). The
usual argument for adding MIT is GPLv2-only compatibility, and that compatibility is unavailable
regardless once those dependencies are in the graph. Offering an MIT branch would therefore imply a
freedom the dependency graph does not actually deliver. One license, honestly stated, is better than
two where one is misleading.

Apache-2.0 also matches the dominant license for IETF reference implementations, and its patent
grant is the property most relevant to a wire format other people are being asked to adopt.

## The dividing line

The split is not "two crates each way." It follows one rule, and new crates should be placed by
applying it rather than by matching the count:

> Code whose purpose is **interoperability** — implementing the profile, checking conformance,
> verifying a receipt independently — is Apache-2.0. Code whose purpose is **operating a
> deployment** — the site producer, the write-in adapters, the enterprise plumbing — is
> AGPL-3.0-only with a commercial licensing path.

There is a second reason, and it is the stronger one. A Pask receipt exists for the moment somebody
outside the vendor has to reconstruct what a machine did on a site. That party is frequently adverse
to the vendor, and often to everyone else in the chain. They will ask whether they can verify the
record themselves, without permission from anyone holding an interest in the outcome.

Nothing in any license ever prevented that. The wire format and the verification procedure are
specified in a published Internet-Draft, and anyone may write a verifier from the document without
touching this repository at all. What a license controls is whether the *first-party* verifier — the
one whose agreement with the specification is not in question — comes with conditions attached.
Under the previous arrangement it did. Under this one it does not:

> **Any party may run `pask-wire-cli verify`, and may modify and redistribute it, under Apache-2.0
> terms, with no commercial relationship with Wilder and no further permission.**

A verification path available only on terms set by the specification's author is worth
considerably less in the proceeding where it matters.

Those are different economic products. The protocol should be easy to implement; the operational
system does not have to be easy to clone. If a future crate is hard to place under that rule, that
is usually a sign the crate is doing two jobs and should be two crates.

### Why `pask-wire-cli` is permissive, and what moved

Until 2026-09-02 the CLI carried an optional `adapter` feature that pulled in `pask-adapter`.
Enabling `--features adapter` therefore mixed an AGPL-3.0-only crate into the binary. A permissive
license on that CLI would have been conditional on which Cargo features a user enabled, which is a
trap for downstream users and would have made the stated license false in a common build.

The fix was to move the code rather than to move the license. The `push` subcommand now lives in a
separate binary, `pask-adapt`, in the AGPL-3.0-only `pask-adapter` crate, built with
`--features cli`. `pask-wire-cli` depends only on `pask-wire` and is unconditionally Apache-2.0.

This matters more than it looks. The CLI is what an implementer actually runs: `canonical-example`
emits the exact example figure carried in the profile document, and `verify` checks a receipt
produced by someone else's code. Those are the conformance tools. Putting them behind a copyleft
review would have taxed precisely the people the draft is trying to attract.

## Dependency direction

The split is only sound in one direction, and this is checked:

- Permissive crates must **never** depend on an AGPL crate. `pask-wire` has no internal
  dependencies. `pask-attest` depends only on `pask-wire`.
- AGPL crates may freely depend on the permissive crates, and do.

**If you add a dependency from `pask-wire` or `pask-attest` onto `pask-site`, `pask-adapter`, or
`pask-wire-cli`, you have created a license violation.** Do not do it. If a spec-side crate appears
to need something from an operational crate, the thing it needs is in the wrong crate.

All third-party dependencies of the two permissive crates were checked as of 2026-09-02 and are
permissive: `coset` (Apache-2.0), `ed25519-dalek` (BSD-3-Clause), `p256`, `serde`, `serde_json`,
`sha2`, `time`, `thiserror`, `proptest`, `rand_core` (MIT or Apache-2.0), `ryu-js` (Apache-2.0 or
BSL-1.0). No copyleft dependency is present. Adding one to a permissive crate would silently break
the split.

## The commercial exception

[`COMMERCIAL-EXCEPTION.md`](COMMERCIAL-EXCEPTION.md) applies **only to the AGPL-3.0-only crates**.
There is nothing to except on the Apache-2.0 crates — Apache-2.0 imposes no copyleft obligation, so
no relief from one is needed or offered.

## Contributions

Inbound contributions are accepted under the license of the crate being modified, certified by
[DCO](https://developercertificate.org) sign-off on every commit and enforced in CI. There is no
Contributor License Agreement and no copyright assignment is taken. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

A practical consequence worth stating plainly: relicensing is simplest while Wilder Management Inc.
remains the sole copyright holder. Under a DCO model contributors retain copyright in their own
contributions, so a later license change can require their agreement and becomes materially harder
as contributors accumulate. It is not necessarily an absolute bar — contributed code can sometimes
be removed, rewritten, or consented to individually — but each of those is work, and the work grows
with the contributor list. The split recorded above was settled on 2026-09-02, while the repository
had no outside contributors, specifically so that it would not have to be renegotiated later.

## Trademarks, and what actually controls conformance

No license in this repository grants any right in the Wilder Robotics name, the Wilder Management
name, or any product name. Apache-2.0 is explicit about this in section 6, which withholds trademark
rights except for customary descriptive use. A copyright license is not a trademark license.

It is worth being precise about what that separation does and does not buy, because it is easy to
ask a trademark to do a job it was not built for. Four different things do four different jobs:

| Instrument | What it does |
|---|---|
| The profile document | Defines what conformance *is* |
| Conformance vectors and test suite | Tests it objectively |
| The Apache-2.0 implementations | Let anyone verify independently, unconditionally |
| A trademark or certification mark | Controls who may *represent* something as officially Pask-compatible or certified |

A trademark is not a conformance oracle. Someone may implement the profile badly and still
accurately describe their code as an implementation of it; what they may not do is present it under
a protected name or certification mark. Conversely, permission to use such a mark should be made to
depend on passing the defined conformance requirements — which is what makes the vectors, not the
mark, the thing that keeps an implementation honest.

Copyleft cannot perform this job either, which is part of why it was the wrong tool to have been
holding the line. The mark is the follow-on workstream; the vectors are the control.

---

## Who is licensing this

The copyright holder, and therefore the Licensor under Apache-2.0 and the party offering the
commercial exception, is **Wilder Management Inc.**, an Illinois corporation, trading under the
assumed name **Wilder Robotics**. Wilder Robotics is a d/b/a and not a separate legal entity; no
other entity has held or contributed copyright in this repository.

Source files previously carried a notice reading "Wilder Robotics" alone. That named the trade name
rather than the corporation, which is ordinary practice but leaves an avoidable question for anyone
reading the license as a legal instrument, since Apache-2.0 defines the Licensor as the copyright
owner or an entity authorised by the owner to grant the license. All 73 notices were corrected on
2026-09-02, while Wilder Management Inc. was the sole copyright holder and the correction required
no one else's agreement.

## Publication and protocol versions

These crates are not yet published to crates.io. When they are, the crate version and the protocol
revision it implements are not the same number and should never be assumed to track each other. Each
published crate must state the profile revision it implements — the `wilder.pser` profile version
and the corresponding draft revision — in its manifest metadata and in its documentation, so that
the mapping is unambiguous to a reader who has only the crate.

---

*Last updated 2026-09-02.*
