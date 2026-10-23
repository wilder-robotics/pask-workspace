# pask-workspace

Cargo workspace for Pask, a pre-alpha reference implementation of a SCITT
profile for Physical-Site Engagement Receipts. A receipt is a signed record
that describes physical work at a real-world site. This tree can build and
check those records under keys a caller supplies. It does not demonstrate the
profile's three-party trust model, and it does not operate a production
Transparency Service.

[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) is the account of what the
profile and this code do not do. If another document in this repository
disagrees with it, believe KNOWN-LIMITATIONS.md.

## About this repository

This repository is the reference implementation and workspace for
[`draft-wilder-scitt-physical-site-engage-receipt`](https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/),
an IETF individual submission. The working copy in this tree is
[`docs/draft-wilder-scitt-physical-site-engage-receipt-05.md`](docs/draft-wilder-scitt-physical-site-engage-receipt-05.md).
That -05 file is a working draft and is not the posted revision. The posted
revision is -04, which specifies profile `wilder.pser/0.6`. The -05 draft
specifies `wilder.pser/0.7`. An Internet-Draft has no IETF standing until a
working group adopts it. This one has not been adopted. Posting it is not an
endorsement, and it is not a standard.

The code's profile constant `SPEC_VERSION` is `wilder.pser/0.5`. The same
library also accepts `wilder.pser/0.6` and proposed `wilder.pser/0.7`. Package
versions, profile identifiers, and draft revision numbers are three different
numbers.

**Ownership vs. protocol roles.** This repository is owned by the
[Wilder Robotics](https://wilder-robotics.com) GitHub organization and
maintained by Wilder Management Inc., operating under the Wilder Robotics
assumed name. The draft is authored by Rob Wilder as an individual (see the
Authors' Addresses section of the draft). The repository owner, the
maintainer, and the author are not an Issuer, Attester, Verifier, or Relying
Party in the sense the specification uses those terms. Those roles belong to
the parties that deploy a system at a physical site.

For governance, see [GOVERNANCE.md](GOVERNANCE.md).
For contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).
For security disclosures, see [SECURITY.md](SECURITY.md).
For the license split, see [LICENSING.md](LICENSING.md).

## What the profile describes, and what this code does not establish

Physical-Site Engagement Receipts are a profile of the IETF SCITT
architecture ([RFC 9943](https://datatracker.ietf.org/doc/rfc9943/)). They
use [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html) COSE Receipts. The
payload is a canonical JSON vocabulary covering the site, the actor, the
engagement, attestation evidence, and an adapter write-in. The -05 draft also
binds separately retained content facts for `wilder.pser/0.7`. The draft is
the definition. This page does not restate it.

The profile is written around three parties: the site owner, who controls the
hardware; the silicon vendor, whose root of trust is supposed to vouch for a
key inside a measured platform; and the issuer, who writes the vocabulary,
registers each statement with a Transparency Service, and posts into the
operations layer through a write-only adapter. Section 2 of
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) records that this implementation
does not demonstrate that model:

- Hardware-evidence appraisal is not implemented. Attestation members and
  evidence digests are carried and type-checked. No vendor evidence is parsed
  or appraised, and no hardware custody is established.
- Nothing validates an attestation certificate chain to a vendor root. A
  configured root of trust can be self-signed.
- Evidence metadata is checked for shape. The bytes it names are not fetched
  or verified.
- Measured boot is checked for self-consistency against the digests listed
  beside it. It is not compared with a reference measurement.
- Nothing in the wire format or the code stops a well-formed receipt from
  being presented again.

A signature check under a key the caller supplied establishes that the
statement verifies under that key and that the payload passes the implemented
checks for its declared profile. It does not establish who controls the key,
or that the described event happened.

## Repository layout

```
pask-workspace/
├── docs/
│   └── draft-wilder-scitt-physical-site-engage-receipt-05.md
├── crates/
│   ├── pask-wire/          Apache-2.0, crates.io 0.2.0
│   ├── pask-attest/        Apache-2.0, crates.io 0.2.0
│   ├── pask-wire-cli/      Apache-2.0, crates.io 0.2.0
│   ├── pask-site/          AGPL-3.0-only, not published
│   ├── pask-adapter/       AGPL-3.0-only, not published
│   └── pask-ts-client/     AGPL-3.0-only, not published
├── schemas/                proposed local 0.7 vocabulary inputs
├── examples/               local demos, not published crates
├── evidence/               recorded experiment transcripts
├── tools/                  local generators for the proposed 0.7 vocabulary
├── scripts/                CI guards and the dev ledger script
├── .github/workflows/      CI
├── LICENSE                 AGPL-3.0-only text
├── LICENSE-APACHE-2.0
├── LICENSING.md
├── COMMERCIAL-EXCEPTION.md
├── KNOWN-LIMITATIONS.md
├── GOVERNANCE.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODEOWNERS
└── Cargo.toml              workspace default version 0.1.0
```

There is no `draft/` directory. RFCXML is generated in CI from the Markdown
under `docs/` and is not committed. There is no separate
`pask-conformance-vectors` repository. The vectors that exist are in this
tree, described below.

### `pask-wire`

Apache-2.0 library, published on crates.io at 0.2.0. It builds a canonical
payload, signs a statement, and runs the implemented checks for
`wilder.pser/0.5`, `wilder.pser/0.6`, and proposed `wilder.pser/0.7`. Passing
those checks is not complete profile conformance. See
[crates/pask-wire/README.md](crates/pask-wire/README.md).

Offline registration checks live in this crate. `verify_inclusion` checks an
`RFC9162_SHA256` inclusion proof and the Transparency Service signature over
the reconstructed root, with no network access. `attached_receipts` reads the
`receipts` header and keeps "no Receipt was attached" distinct from "the
header was present and unreadable". `derive_candidate_entry` and
`candidate_leaf_hash` implement the candidate-entry derivation specified for
inclusion-proof verification. These functions do not decide whether a
Transparency Service is trusted. That decision belongs to the relying party.

CCF-profile receipts are not verified. Full envelope and claims validation
above generic inclusion verification remains
[issue #71](https://github.com/wilder-robotics/pask-workspace/issues/71).
Details are in [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) sections 5.2
and 5.3.

### `pask-attest`

Apache-2.0 library, published at 0.2.0. It verifies a framed
`wilder.attest/0.1` quote against Ed25519 keys the caller placed in a root of
trust, and it returns typed claims. It does not parse or appraise vendor
hardware evidence. A `teeClass` value is a label, not an appraisal. See
[crates/pask-attest/README.md](crates/pask-attest/README.md).

### `pask-wire-cli`

Apache-2.0 command-line tool, published at 0.2.0. The binary is
`pask-wire-cli`. `canonical-example` emits the legacy 0.5 example.
`produce` and `verify` follow the `spec` field of the payload you give them,
including 0.7 when the payload says 0.7. `verify` checks the statement under
a caller-supplied Ed25519 key. It does not verify attached SCITT Receipts,
and it does not register a statement with a Transparency Service. See
[crates/pask-wire-cli/README.md](crates/pask-wire-cli/README.md).

### `pask-site`

AGPL-3.0-only reference site producer for `wilder.pser/0.5`. It is not
published (`publish = false`). It canonicalizes engagement evidence, signs a
receipt, and hands the signed bytes to a verify-before-push adapter. It does
not depend on `pask-ts-client`, so the reference site does not register the
statement and does not attach a Receipt.

The producer is a reference, not a deployment. Chain sequence and previous
hash are inputs on the request. They are not kept against a persistent log.
The adapter acknowledgement digest is supplied by the caller before the
adapter runs. Reference-site attestation values are stand-ins, not
measurements taken from a device. See
[crates/pask-site/README.md](crates/pask-site/README.md) and section 5 of
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md).

### `pask-adapter`

AGPL-3.0-only, not published. Write-only adapters that push a verified
receipt into an operations system, plus the `pask-adapt` binary (Cargo
feature `cli`). Write-only is enforced when the adapter runs. The
PropertyMeld adapter is a fail-closed stub. See section 7 of
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md).

### `pask-ts-client`

AGPL-3.0-only, not published. This is the registration client. It submits a
Signed Statement to a Transparency Service over SCRAPI (the HTTP registration
API), receives a COSE Receipt, and can attach that Receipt with
`attach_receipt`. `attach_receipt` checks container structure. It does not
check the Receipt's signature, inclusion proof, service trust, or hardware
evidence. `TsClient::submit` sends and returns bytes. It does not normalize
the envelope or verify the Receipt. Callers must supply a tag-18 statement
before submission.

`PASK_TS_URL` must be set. There is no default endpoint. This repository does
not operate a production Transparency Service. The reference site does not
call this crate. For local tests,
[scripts/run-dev-ts.sh](scripts/run-dev-ts.sh) can start a self-hosted
ledger. Receipts retrieved from that ledger are not verified as
`RFC9162_SHA256` inclusion. The reference verifier's registration coverage is
`RFC9162_SHA256` only. See section 5.2 of
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md).

## Test vectors

Wire-format fixtures live under
[crates/pask-wire/fixtures/](crates/pask-wire/fixtures/). An independent
signed vector set for candidate-entry derivation is
[crates/pask-wire/pask_67_independent_signed_vectors.json](crates/pask-wire/pask_67_independent_signed_vectors.json).
The canonical example is a Rust constant inside `pask-wire`. A separate
conformance-vector repository does not exist. These files are not a passed
conformance verdict. Verification gates V1 through V5 in section 8 of
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) are unmet.

One older note under
[crates/pask-wire/fixtures/receipts/README.md](crates/pask-wire/fixtures/receipts/README.md)
says this repository does not obtain Receipts. That sentence predates
`pask-ts-client`. Section 5.2 of KNOWN-LIMITATIONS.md is the current
description: submission code exists, and it is not wired into the reference
site.

## License

This repository is not licensed uniformly. Code whose purpose is
interoperability is Apache-2.0. Code whose purpose is operating a deployment
is AGPL-3.0-only. [LICENSING.md](LICENSING.md) is authoritative.
[scripts/license_guard.sh](scripts/license_guard.sh) enforces the split in CI.

| Crate | License | Registry |
| --- | --- | --- |
| [`pask-wire`](crates/pask-wire/) | [Apache-2.0](LICENSE-APACHE-2.0) | crates.io 0.2.0 |
| [`pask-attest`](crates/pask-attest/) | [Apache-2.0](LICENSE-APACHE-2.0) | crates.io 0.2.0 |
| [`pask-wire-cli`](crates/pask-wire-cli/) | [Apache-2.0](LICENSE-APACHE-2.0) | crates.io 0.2.0 |
| [`pask-site`](crates/pask-site/) | [AGPL-3.0-only](LICENSE) | not published |
| [`pask-adapter`](crates/pask-adapter/) | [AGPL-3.0-only](LICENSE) | not published |
| [`pask-ts-client`](crates/pask-ts-client/) | [AGPL-3.0-only](LICENSE) | not published |

The workspace `version` in [Cargo.toml](Cargo.toml) is 0.1.0. The three
AGPL-3.0-only crates inherit that version. The three Apache-2.0 crates set
their own version to 0.2.0. Crate 0.1.0 implemented 0.5 and 0.6 only. Crate
0.2.0 adds the implemented 0.7 processing. Neither release is a conformance
certificate.

[COMMERCIAL-EXCEPTION.md](COMMERCIAL-EXCEPTION.md) applies only to the
AGPL-3.0-only crates. It sets out the terms on which Wilder Management Inc.
(operating under the Wilder Robotics assumed name) grants a commercial license
outside the AGPL's network-copyleft obligations. No such agreement is needed
for the Apache-2.0 crates.

## Status

Pre-alpha. No production-readiness claim. No safety, insurance, or
regulatory-compliance claim.

- The permissive crates produce and check `wilder.pser/0.5`,
  `wilder.pser/0.6`, and proposed `wilder.pser/0.7` statements under a key
  the caller supplies. The reference site producer targets `wilder.pser/0.5`.
- Offline checking of an attached `RFC9162_SHA256` Receipt is implemented in
  `pask-wire`.
- Registration is implemented in `pask-ts-client` and is not called by the
  reference site. With no endpoint configured, that path does not register a
  statement, does not attach a Receipt, and does not produce a Transparent
  Statement. The profile makes registration mandatory, so an unregistered
  receipt is not a conforming receipt under the draft.
- Hardware provenance, replay defence, persistent chain history, and CCF
  receipt verification are not implemented. Section 9 of
  [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) lists the floor before any
  production claim.

CI builds and tests the workspace and runs the license, revision, name, and
compliance guards. A separate advisory job can submit a statement to a local
ledger and retrieve a Receipt. That job does not verify the Receipt. A green
run is not a conformance verdict.

## Contact

Rob Wilder, rob@wilder-robotics.com

Security disclosures: security@wilder-robotics.com (see
[SECURITY.md](SECURITY.md))
