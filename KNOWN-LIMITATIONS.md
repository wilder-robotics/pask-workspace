# Known limitations

| | |
| --- | --- |
| Applies to | `draft-wilder-scitt-physical-site-engage-receipt-04` (in tree) and this repository |
| Profile identifier in the implementation | `wilder.pser/0.5` (`SPEC_VERSION`); `wilder.pser/0.6` is also supported |
| Working-draft target | `wilder.pser/0.6`, specified by the in-tree -04 working draft |
| Last reviewed | 2026-09-13 |
| Status | Pre-alpha reference implementation |

This file is maintained alongside the code. It records what the profile and
the reference implementation **do not** do, in the present tense, so that an
implementer or reviewer does not have to discover it by reading the source.

Three things it is not. It is not a conformance statement — absence from this
file does not establish that a property has been implemented or demonstrated.
It is not a roadmap; where an item has a tracker, the tracker is linked and
nothing here promises a date. And it is not a disclosure of past error: the
`-00` payload figure was a schema template, and it is described below as one.

The Internet-Draft is an IETF individual submission. It has no IETF standing,
has not been adopted by any working group, and carries no production-readiness,
safety, insurance, or regulatory-compliance claim.

---

## 1. Document and implementation

### 1.1 The profile identifier is not published in any register

The implementation supports `wilder.pser/0.5` (`SPEC_VERSION` in the code) and
`wilder.pser/0.6` (also supported). The in-tree active draft is `-04`, which
defines `wilder.pser/0.6`. The most recently posted revision is `-03`, which
defines `wilder.pser/0.5`. The posted `-02` defines `wilder.pser/0.4`.

So an implementer working from a posted document and an implementer working
from this tree share `0.5` in common. The difference is additional support for
the unpublished `0.6` working contract in this tree, not automatic
incompatibility with `0.5`.

Neither identifier is published in any register. The value space is described
only by the drafts, so nothing outside this repository and those documents
resolves either string.

Supported versions, example output, published specification status, and
interoperable deployment evidence are separate concerns. The code emits 0.5
and 0.6 payloads; the generated example figure in the working draft uses 0.6;
the posted specification is `-03` (0.5); and no receipt produced by this
implementation has been registered with a production Transparency Service.

### 1.2 One figure is generated; the rest of the document is prose

The Section 4 payload figure in the current revision is emitted by `pask-wire`
and asserted byte-identical in CI, and every fenced example in the document is
now required to be accounted for — parsed by the reference parser, or listed
with a written reason it should not be. That guarantee covers the examples
only.

The normative member definitions in Section 4.1, the security considerations,
and the IANA request are maintained by hand and are not mechanically checked
against the implementation. Nothing in the build would observe a member
definition drifting away from the type that implements it.

`-00` presented its payload structure as a schema template — unquoted
placeholders showing member names and value shapes rather than a literal
instance. A template is not machine-checkable, which is why four attestation
members came to be described differently by `-00` and by the implementation.
`-01` reconciles all four and replaces the template with a generated instance.

### 1.3 Identifier consistency is implemented for 0.6; authenticated key association remains unresolved

The in-tree `-04` retains the required `attestation.bindingMode` member
with a closed two-value set. That member is implemented: the producer emits it,
the parser requires it, and validation refuses a value outside the set.

Under `wilder.pser/0.6`, the identifier-consistency check is now implemented
(#66). When `bindingMode` is `DIRECT_WITNESS`, `attestation.witnessKey` and
the protected CWT `iss` value MUST be textually equal. This check does not
apply to `DELEGATED_WITNESS` mode or to 0.5. It establishes only a naming
convention; it does not establish that the signature-verification key is
authentically associated with either identifier or that genuine TEE hardware
produced the signature.

The published `wilder.pser/0.5` draft requires rejection when
`attestation.witnessKey` and the protected `iss` denote different keys. The
implementation does not establish that authenticated key relationship. The
additional exact-string naming convention introduced for `wilder.pser/0.6` is
not applied retroactively to 0.5. Successful label comparison under 0.6 does
not establish authenticated association with the signature-verification key or
genuine hardware provenance. The broader assurance gap remains open for both
supported versions.

---

## 2. What the attestation layer does not verify

The three-party trust model is normative in the profile and is **not
demonstrated** by this implementation.

### 2.1 Hardware-evidence appraisal is not implemented

This revision introduces neither an `attestation.quote` payload member nor
an `attestationResult` member. The existing attestation payload retains
evidence digests, component measurements, and attestation-related claims.
The profile permits the platform attestation document to be supplied by
reference or inline in the Signed Statement's unprotected header.

Those conveyance options do not establish that the evidence is trustworthy.
Obtaining bytes matching an evidence digest is distinct from validating the
evidence and its binding to the relevant key under an accepted trust policy.
A digest is not, by itself, a retrieval address or appraisal result.

The reference implementation does not establish hardware provenance through
vendor-evidence appraisal. A relying party may arrange appraisal itself or
through an external Verifier. The absence of a dedicated in-payload result
member does not prevent that external appraisal. The future representation,
if any, of an additional quote or Attestation Result remains open under #28.

### 2.2 No certificate supply-chain verification

Nothing validates an attestation certificate chain to a vendor root. The
configured root of trust can be self-signed.

### 2.3 Evidence metadata is not evidence verification

`platformEvidence` and `sealedEvidence` carry a digest, an encoding, and a
size. The implementation checks that these members are well-formed. It does
not obtain, parse, or verify the evidence they describe.

### 2.4 Measured boot is self-consistency only

`measuredBoot.chain` is checked for consistency against the component digests
listed beside it. It is not compared against any reference measurement, so a
self-consistent chain of arbitrary values passes.

### 2.5 There is no replay defence

Nothing in the wire format or the implementation prevents a well-formed
receipt from being presented again.

---

## 3. Timestamps and validity

`attestation.validity` is REQUIRED and carries `notBefore` and `notAfter`.
Both `pask-wire` and `pask-attest` require `notAfter` to be **strictly** later
than `notBefore`; an equal-instant interval is rejected by both. The profile
states that rule normatively.

For `wilder.pser/0.6`, the implementation compares the asserted receipt-issuance
timestamp with the asserted attestation-validity interval using parsed instants
and inclusive endpoints. This checks consistency of the recorded times; it does
not independently establish actual issuance time or engagement time. The new
containment requirement is not imposed on `wilder.pser/0.5`.

0.5 receipts remain exempt from containment. A relying party that needs the
receipt timestamp to fall inside the attestation's validity window for 0.5
receipts must enforce that itself.

---

## 4. The TEE Class registry

The profile requests an IANA registry seeded with `intel.tdx`, `amd.sev-snp`,
`arm.cca`, `nvidia.h100-cc`, `nvidia.jetson-thor-cc`, and `aws.nitro-enclave`.
**The registry does not exist and IANA has allocated nothing.** The document
says so and specifies Specification Required as the registration policy, so
there is a defined route for a seventh value. There is no allocated value to
use today.

The implementation accepts exactly those six strings and rejects everything
else, including SKU-level and instruction-set-architecture names. An operator
whose confidential-compute environment is outside the six is excluded rather
than degraded.

The six sit at three different levels of abstraction, so the taxonomy is less
principled than a registry ought to be. Tracked at
[#29](https://github.com/wilder-robotics/pask-workspace/issues/29).

The `teeClass` values in the fixtures reflect a mapping choice, not measured
hardware. The reference site's fixtures use `arm.cca`.

---

## 5. What the reference producer simulates

The producer is a reference, not a deployment. Specifically:

- **Chain state is not produced.** `chain.prevHash` and `chain.seq` are not
  maintained against a persistent log.
- **Adapter acknowledgement is asserted before the adapter runs.** The
  `adapter.ackDigest` in a produced receipt does not attest that a downstream
  system accepted anything.
- **The evidence bundle is declarative.** It describes evidence rather than
  containing it.
- **Reference-site attestation values are stand-ins**, not measurements taken
  from a device.
- **Receipt identity collides on reissue.** Reissuing produces the same `id`.

### 5.1 Receipt-chain verification checks presented relationships, not independent history

Per-receipt verification validates each payload's chain hash and the required
sequence/previous-hash shape. `pask_wire::verify_chain` checks a presentation's
sequence-zero head, contiguous sequence numbers, and equality of each
subsequent `chain.prevHash` with the preceding presented payload's
`chain.hash`. It reports changes in `issuerAffiliation` rather than silently
collapsing them to one value or rejecting the chain solely for that change.
The chain helper does not repeat each payload's prior hash validation or
verify the Issuer signatures.

Contiguous numbering alone is not sufficient: a mismatching predecessor hash
is rejected. Existing tests exercise multi-receipt presentations and link
failures.

Successful verification of these relationships does not establish that the
presentation is complete, current, unique, or backed by an independent
persistent history. An internally consistent constructed or withheld history
can satisfy those structural checks. Persistent production state, relevant
signature and evidence checks, and external witnessing are separate from the
presented-payload relationship checks implemented by this function.

---

## 5.2 Transparency Service registration and Receipt attachment

The profile makes registration mandatory: an Issuer MUST register every receipt
it issues with at least one Transparency Service, and a relying party MUST NOT
accept an unregistered receipt as conforming.

**Submission code exists but is not deployed.** The `pask-ts-client` crate
provides a SCRAPI client that takes a Signed Statement, submits it to a
Transparency Service, receives a COSE Receipt, and attaches it to the statement
to form a Transparent Statement. The submission path is implemented but
defaults to no endpoint (`PASK_TS_URL` must be set explicitly). No production
Transparency Service is operated by this repository.

**Checking a registration is implemented.** `pask_wire::verify_inclusion`
verifies an `RFC9162_SHA256` inclusion proof and the Transparency Service
signature over the reconstructed root, entirely offline. `pask_wire::attached_receipts`
reads the `receipts` (394) header. `pask_wire::derive_candidate_entry` and
`pask_wire::candidate_leaf_hash` implement the candidate-entry derivation
specified in the -04 working draft.

Full envelope/claims validation above generic inclusion verification remains
tracked separately in
[#71](https://github.com/wilder-robotics/pask-workspace/issues/71). The
pask-ts-client sender byte-string wrapping problem remains tracked in
[#70](https://github.com/wilder-robotics/pask-workspace/issues/70).
Application-facing aggregate verification, published specification status, and
external-service interoperability remain separate from the implemented
candidate-entry derivation and test-only aggregate verification. Issues #70
and #71 remain open until their own criteria are satisfied.

Reviewed 2026-08-15. Revised 2026-09-03 when the reading half was implemented.
Revised 2026-09-13 when the submission path and candidate-entry derivation
were described against the actual merged source.

## 5.3 The candidate-entry byte encoding is specified (-04)

RFC 9942 Section 5.2 verification begins by obtaining "the bytes of a candidate
entry" and applying the inclusion proof to them. RFC 9942 does not say what a
candidate entry is; that is left to the profile.

The -04 working draft specifies the candidate-entry byte encoding for
inclusion-proof verification: the untagged four-element array `[P, {}, M, S]`
derived from the presented Transparent Statement. `derive_candidate_entry()`
implements this derivation. Registration and verification alignment is required,
not assumed. Transmitted envelopes use COSE tag 18; the untagged candidate entry
is a profile-internal representation.

The at-least-one-trusted-proof acceptance rule is specified: the profile's
inclusion requirement is satisfied only when at least one attached Receipt has
both a valid Transparency Service signature under an accepted service key and a
valid inclusion proof for the derived candidate entry. A structurally parseable
additional Receipt whose cryptographic verification fails does not defeat
another attached Receipt that satisfies the requirement.

`pask_wire::derive_candidate_entry` and `pask_wire::candidate_leaf_hash` are
implemented. The receipt reader (`crates/pask-wire/src/receipt.rs`) reads and
extracts byte-string-wrapped SCITT Receipt per RFC 9942 Section 4.3. Full
envelope/claims validation above generic inclusion verification remains tracked
in [#71](https://github.com/wilder-robotics/pask-workspace/issues/71). The
pask-ts-client sender byte-string wrapping problem remains tracked in
[#70](https://github.com/wilder-robotics/pask-workspace/issues/70).

The candidate-entry derivation and test-only aggregate verification are
distinguished from application-level aggregate verification, published
specification status, and external-service interoperability. Issues #70 and #71
remain open until their own criteria are satisfied.

## 6. Wire format and tooling

- **Production normalization replaces a supplied chain hash.** `from_json_for_production`
  recomputes `chain.hash` rather than rejecting a payload whose supplied value is
  wrong. `from_json` (the verification path) validates the supplied hash and
  rejects a mismatch. A caller using the production path cannot use the library
  to detect a bad hash; a caller using the verification path can.
- **COSE content-type parsing uses a temporary compatibility representation.**
  `parse_statement()` in `crates/pask-wire/src/envelope.rs` constructs a
  compatibility view while retaining the original protected-header contents for
  signature verification. Verified signed material is not rewritten. Preserve
  any concrete remaining round-trip limitation only with its specific evidence.
- **The command-line binary has a test that executes it.** `cli_binary.rs`
  exercises the binary's argument handling and output.
- **Independent signed vectors are published in-tree.**
  `pask_67_independent_signed_vectors.json` provides a published vector set for
  the #67 candidate-entry derivation. A formal conformance suite
  (`pask-conformance-vectors` repository) does not exist. The canonical vector
  lives inside `pask-wire` as a Rust constant, and the #67 vectors provide an
  independent signed set for the candidate-entry feature.

---

## 7. Adapters

- `WRITE_ONLY` is enforced at runtime, not guaranteed by the type system.
- Health checking reads the operations layer, so a healthy report does not
  establish that the write path works.
- The PropertyMeld adapter is a fail-closed stub.
- Local deduplication does not establish remote idempotency.
- Credentials can appear in debug output.

---

## 8. Verification maturity

Verification gates V1 through V5 are unmet. V1 requires the generated-figure
CI assertion to hold green for thirty consecutive days; its clock starts when
that assertion first lands on the default branch, which has not yet happened.

---

## 9. What would have to change before any production claim

Not a roadmap — a floor. At minimum: hardware-rooted evidence actually carried
and verified (§2), a published conformance vector set (§6), chain state
produced against a persistent log (§5), an allocated registry (§4), and V1
through V5 met (§8).

---

## Outer-statement subject type and SCITT conformance

Current outer engagement statements encode CWT `sub` (claim 2) as a CBOR
byte string, and the current reader requires that type. RFC 9943 requires
the CWT Subject claim; RFC 8392 defines its StringOrURI value as CBOR text.
Therefore, successful verification of these statements does not establish
full SCITT Signed Statement conformance.

A compatibility/version decision and implementation tests are required
before changing producer or reader behavior. Existing signed bytes must
not be silently converted. This gap is separate from the completed
candidate-entry scope of #67, the outgoing attachment repair in #70,
and inner-Receipt validation in #71.

References: [RFC 9943 section 6](https://www.rfc-editor.org/rfc/rfc9943.html#section-6),
[RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html),
[subject-type compatibility issue #76](https://github.com/wilder-robotics/pask-workspace/issues/76).

## Reporting

If you find a limitation that is not recorded here, please open an issue. An
inaccurate entry is worth reporting too — a limitations file that overstates
what is missing is as misleading as one that understates it.
