# Known limitations

| | |
| --- | --- |
| Applies to | `draft-wilder-scitt-physical-site-engage-receipt-05` (working draft, not posted) and this local candidate |
| Profile identifier in the implementation | `wilder.pser/0.5` (`SPEC_VERSION`); `wilder.pser/0.6` and proposed `wilder.pser/0.7` are also supported |
| Profile target of the current posted revision | `wilder.pser/0.6`, specified by `-04` |
| Last reviewed | 2026-09-30 (author corrections; new native checks pending) |
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

The implementation retains `wilder.pser/0.5` (`SPEC_VERSION` in the code)
and `wilder.pser/0.6` and has a separately reviewed local development path
for proposed `wilder.pser/0.7`. The most recently posted revision remains
`-04`, posted 2026-09-14, defining 0.6. The posted `-03` defines 0.5 and
the posted `-02` defines 0.4. The current -05 source is not posted.

These identifiers are profile labels, not an IANA registration or an
assurance of interoperability. The published 0.1.0 packages do not contain
this local 0.7 development work. The released CLI default example remains
0.5; the separate `canonical_example_07()` emitter supplies the 0.7 draft
figure. A new example API does not change the released CLI default.

### 1.2 Document checks have a bounded scope

The candidate connects its one payload figure to the dedicated 0.7 emitter
and accounts for every fenced block. Forty-eight vocabulary definition
blocks are compared with the two unchanged JSON artifacts; long meanings
and global string annotations are reconstructed from the adjacent prose.
Four explanatory fragments have explicit, exact expectations rather than
being silently skipped. These new document tests still need execution on
this candidate. Their presence is not a passed validation result.

Those checks do not verify every normative prose sentence. Producer duties,
cryptographic policy and relying-party interpretations require review and
appropriate execution evidence. Historically, `-00` used a schema template
as a payload figure; `-01` replaced it with a generated instance.

The draft identifies the published release for public implementation
status. Private closeout details, pending license decisions, and candidate
measurements live in the accompanying internal record, not in that section.

### 1.3 Identifier consistency is implemented for 0.6/0.7; authenticated key association remains unresolved

The in-tree working draft retains the required `attestation.bindingMode` member
with a closed two-value set. That member is implemented: the producer emits it,
the parser requires it, and validation refuses a value outside the set.

Under `wilder.pser/0.6` and proposed `wilder.pser/0.7`, the identifier-consistency check is implemented
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
genuine hardware provenance. The broader assurance gap remains open for all supported versions.

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
[#71](https://github.com/wilder-robotics/pask-workspace/issues/71).
The local sender repair for
[#70](https://github.com/wilder-robotics/pask-workspace/issues/70) emits tag-18
statements with byte-string-wrapped tagged Receipts, preserving encoded Receipt
bytes and signed P/M/S contents. It checks COSE container/header structure,
not Receipt claims, proofs, signatures, service trust, or hardware evidence.
Untagged statement input is explicit compatibility with local producers;
output is tagged. Untagged Receipts and decoded legacy existing attachments
are refused rather than silently upgraded. The reader retains read-only legacy
attachment compatibility; reading is not full Receipt validation.
The attachment sender validates the outer statement and the container/header structure of each supplied encoded Receipt. The attachment reader validates the outer statement and attachment-container structure, but extracts byte-string Receipt contents without validating their inner envelope. Duplicate labels, cross-map overlap, and trailing-data checks therefore apply at the layers described here, not uniformly to every issuer or Receipt verification API. Full inner-Receipt validation and service-trust checks remain #71 work.
The sender also refuses to append when receipts are protected.
`TsClient::submit` remains a byte-transparent HTTP transport, not an envelope
normalizer. Callers must tag current untagged local producer output before
submission; tagging the later attached output does not fix a prior untagged
request. The local mock exercises explicit tagged submission and commitment to
the derived candidate; agreement by an independent service remains unproven.

**Test configurations.** For testing, Pask registers with a self-hosted
scitt-ccf-ledger instance and runs its witness in an AMD SEV-SNP confidential
VM. These are the configurations we use to find out what Pask can and cannot
do with real hardware and a real log; they are not requirements of the
profile, not recommendations, and not the only conforming options. Results,
including what did not work, are published in KNOWN-LIMITATIONS.

**CCF ledger receipts are retrieved but not verified.** First real-ledger
observation, recorded 2026-09-28 and tracked in
[#100](https://github.com/wilder-robotics/pask-workspace/issues/100).

*What was tested.* A self-hosted `scitt-ccf-ledger` at pinned revision
`bffdf529185ba7767db5f2cfc4c1898ec8ad3364`, started by `scripts/run-dev-ts.sh`
on a Linux GitHub Actions runner, against `pask-workspace` at the tree of
main `9ba85f1` (the `pask-wire` 0.1.0 release). The pyscitt-signed statement
was registered by `TsClient::submit` and the returned receipt bytes were saved
unmodified.

*What happened.* The statement registered and a 508-byte tag-18 `COSE_Sign1`
receipt came back: `alg` ES384, protected `vds` (395) = `2`, a CWT claims map
(15) with `iss` `127.0.0.1:8000`, `sub` `scitt.ccf.signature.v1` and `iat`,
a `ccf.v1` map carrying the transaction id, an unprotected `vdp` (396) map
whose `-1` entry holds one byte-string-wrapped CCF inclusion proof, and a
detached payload. That is the shape described by
`draft-ietf-scitt-receipts-ccf-profile-05`. The VDS value `2`
(`CCF_LEDGER_SHA256`) is taken from that draft; it is requested by the draft
and is not yet in the IANA Verifiable Data Structure registry, which at the
time of writing lists only values `0` and `1`. Pask does not count this
receipt as verified inclusion:

- `pask_wire::inspect_scitt_receipt` reports `support` =
  `Unsupported` / `ccf_profile_not_implemented` and leaves signature and
  inclusion `NotEvaluated`. It also reports `required_claims` =
  `Failed` / `uri_syntax`, because the CCF `iss` value is a host:port string
  rather than a URI.
- `pask_wire::verify_inclusion` returns
  `attached receipt error: inclusion proof must be a CBOR array`. The RFC 9162
  proof-shape check runs before the VDS check on that path, so the low-level
  verifier names the proof shape rather than the unsupported VDS. Both paths
  refuse; neither path runs the RFC 9162 walk over CCF proof bytes.

*Reproduce.* From a Linux host with Docker, Python 3.12+, and the pinned
pyscitt CLI installed:

```sh
export PASK_TS_WORK_DIR=/tmp/pask-dev-ts
./scripts/run-dev-ts.sh
set -a; . "$PASK_TS_WORK_DIR/github.env"; set +a
cargo test -p pask-ts-client -- --ignored --nocapture
CCF_EVIDENCE_OUT=/tmp/ccf-evidence \
  cargo run --manifest-path evidence/issue-100/2026-09-28/tool/Cargo.toml
./scripts/run-dev-ts.sh --stop
```

The captured receipt, signed statement, service certificate, verifier output
and logs are under `evidence/issue-100/2026-09-28/` with a `SHA256SUMS`
manifest. The evidence tool is not a workspace member and changes no verifier
behaviour. This entry will be revised when CCF receipt verification lands
(#100); until then the reference verifier's registration coverage is
`RFC9162_SHA256` only.
Application-facing aggregate verification, published specification status, and
external-service interoperability remain separate from the implemented
candidate-entry derivation and test-only aggregate verification. Issues #70
and #71 remain open until their own criteria are satisfied.

Reviewed 2026-08-15. Revised 2026-09-03 when the reading half was implemented.
Revised 2026-09-13 when the submission path and candidate-entry derivation
were described against the actual merged source.
Revised 2026-09-14 for the local #70 sender and coordinated reader repair.
Controlled cryptographic fixtures are not SCITT-claims conformance evidence.

## 5.2a AMD SEV-SNP test configuration

For testing, Pask registers with a self-hosted scitt-ccf-ledger instance and
runs its witness in an AMD SEV-SNP confidential VM. These are the
configurations we use to find out what Pask can and cannot do with real
hardware and a real log; they are not requirements of the profile, not
recommendations, and not the only conforming options. Results, including what
did not work, are published in KNOWN-LIMITATIONS.

On 2026-09-29 (UTC) a witness key was generated inside an AMD SEV-SNP
confidential virtual machine, an attestation report (version 5, VMPL 0,
1,184 bytes) was requested whose REPORT_DATA field carries SHA-512 of that
key's public half in SubjectPublicKeyInfo form, the report and its AMD
ARK/ASK/VCEK chain were verified with snpguest v0.10.0 and independently,
and one `wilder.pser/0.6` statement was signed with that key using the
published `pask-wire-cli` 0.1.0. The `wilder.attest/0.1` quote wrapping the
evidence digests was verified with the published `pask-attest` 0.1.0. The
transcript and tools are under `evidence/sev-snp-witness/2026-09-28/`.

What worked: the published crates verified the quote and the statement; a
wrong key, an unknown witness identifier, a non-registry `teeClass` string,
and an out-of-window clock were each rejected with a distinct error.

What did not work, and is recorded as a limitation:

- `pask-attest` 0.1.0 does not parse or appraise SEV-SNP reports. It accepts
  `amd.sev-snp` as a class label and an opaque SHA-256 digest of evidence.
  A report with one altered byte was rejected by snpguest and by an
  independent signature check, but a quote carrying that report's digest
  would verify identically under `pask-attest`. The crate cannot reject
  synthetic evidence.
- `pask-attest` 0.1.0 does not require the evidence bytes to be present or
  resolvable. The same quote verified with no evidence on disk. The crate
  cannot detect absent evidence.
- The REPORT_DATA binding, the evidence manifest layout, and the derivation
  of measured-boot components from two report fields are experiment
  conventions. They are not defined by this profile or any draft revision.
- No approved boot-image baseline exists; no claim about the guest image's
  security state is made. One provider, one VM, one processor family, one
  point in time. This does not establish hardware key custody for any
  deployed Pask issuer.

Published: the command transcript and the helper tool used. Kept private:
the raw attestation report, certificate chain, evidence manifest, sealed
bundle, and the cloud and hardware identifiers they contain. Nothing about
this configuration alters the -05 freeze or the crates.io 0.1.0 release.

Recorded 2026-09-29.

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
in [#71](https://github.com/wilder-robotics/pask-workspace/issues/71).
The local [#70](https://github.com/wilder-robotics/pask-workspace/issues/70)
sender repair and its compatibility boundaries are described in §5.2.

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

## Reporting

If you find a limitation that is not recorded here, please open an issue. An
inaccurate entry is worth reporting too — a limitations file that overstates
what is missing is as misleading as one that understates it.

## Development correction: integer-token bound

The content-byte preflight now checks integer-form tokens against the
existing safe-integer range before JSON parsing can represent an overflowing
integer token as a floating value. This check includes nested and extra fields
and ignores digits inside strings. It does not alter the raw-evidence
comparator, normalize noncanonical fact bytes, or recover precision lost
before the input reached Pask. The new regression requires a failing-before
and passing-after native result; no such result is inferred from source review.

The generated-vocabulary distribution basis remains unresolved for both
tables. No SPDX declaration has been invented, and the earlier incomplete
name scan remains incomplete. These hold public readiness, not private
drafting or source review.
