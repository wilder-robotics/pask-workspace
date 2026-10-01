---
title: "A SCITT Profile for Physical-Site Engagement Receipts"
abbrev: "Physical-Site Engagement Receipt"
docname: draft-wilder-scitt-physical-site-engage-receipt-05
category: std
submissionType: IETF
ipr: trust200902
area: Security
workgroup: SCITT
keyword:
  - SCITT
  - COSE
  - receipts
  - transparency
  - physical AI
  - robotics
  - trusted execution environment
  - attestation
  - regulated site

author:
  -
    ins: R. Wilder
    name: Rob Wilder
    org: Wilder Robotics
    email: rob@wilder-robotics.com

normative:
  RFC8392:
  EPSG4979:
    title: "WGS 84 geographic 3D coordinate reference system (EPSG:4979)"
    author:
      - org: International Association of Oil and Gas Producers
    target: https://www.opengis.net/def/crs/EPSG/0/4979
    date: false
    seriesinfo:
      EPSG: "4979"
    ann: >-
      Undated coordinate-reference-system definition. The resolver URI
      does not identify an EPSG dataset release date or version. The
      position representation in this document states its scaling and
      axis interpretation explicitly and does not select a WGS 84
      realization or establish coordinate accuracy.
  RFC8785:
  RFC8949:
  RFC9052:
  RFC9162:
  RFC9597:
  RFC9942:
  RFC9943:

informative:
  RFC7942:
  RFC9334:
  I-D.noa-scitt-ai-agent-receipt:
    title: A SCITT Profile for AI-Agent Action Receipts
    author:
      - name: T. Toraman
        org: NordenSoft
    date: 2026-08-15
    target: https://datatracker.ietf.org/doc/html/draft-noa-scitt-ai-agent-receipt-01
    seriesinfo:
      Internet-Draft: draft-noa-scitt-ai-agent-receipt-01
  I-D.mih-scitt-agent-action-capsule:
    title: An Agent Action Capsule Profile for SCITT
    author:
      - ins: S. Mih
        org: Action State Group, Inc.
    date: 2026-09-26
    target: https://datatracker.ietf.org/doc/html/draft-mih-scitt-agent-action-capsule-05
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-05
  RFC6838:

--- abstract

This document defines a SCITT profile for *Physical-Site Engagement Receipts*
(PSER): tamper-evident, signed, offline-verifiable records that describe an
autonomous or human-directed physical engagement at a specific real-world site
governed by a defined operating envelope. Each receipt is a SCITT Signed
Statement as defined by the SCITT architecture, encoded as a COSE Single
Signer message, carrying a JCS-canonicalized JSON payload with a five-artifact
vocabulary describing (1) the *Site*, (2) the *Operator* and *Actor*, (3) the
*Engagement Window* and
*Envelope*, (4) the *Attestation Evidence* from a Trusted Execution
Environment (TEE), and (5) the *Adapter Write-In* recording that the receipt
was posted into an out-of-band operations layer. A Physical-Site Engagement
Receipt is registerable in any conforming SCITT Transparency Service,
obtaining a Receipt that proves the Statement's inclusion in that Service's
verifiable data structure. Registration does not establish that the Issuer
registered every receipt it issued.
Profile 0.7 additionally binds separately retained, attributed content facts
through a salted commitment and selected disclosures. Integrity and permitted
attribution do not establish the facts' truth or the asserting parties'
identity.

This profile deliberately makes a NARROW, checkable claim -- "this is a
tamper-evident, signature-verifiable record that a specific engagement
occurred at a specific site under a specific envelope, and its evidence was
sealed by a specific TEE" -- and explicitly does NOT claim that the engagement
was safe, correct, or wise, that the site conditions were as described, or
that any downstream operational outcome followed. Compliance verdicts derived
from the receipt (SLA credit, insurance underwriting, regulatory audit) are
the responsibility of the relying party and its policies, not of this profile.

The profile is designed around a three-party trust model in which no single
party can unilaterally forge or repudiate a receipt: the *Site Owner* controls
physical access to the TEE hardware and keeps it running (they can unplug the
box, and cannot forge what it signs); the *TEE silicon
vendor* attests the key material inside the TEE through its hardware root of
trust (silicon vouches for the key); and the *Issuer* writes the vocabulary,
registers Signed Statements with a Transparency Service, and posts the
resulting receipt into the site's operations layer via a WRITE_ONLY adapter.
This separation is normative in this profile: implementations MUST NOT collapse
these three roles into a single custodian, and relying parties MUST NOT trust a
receipt that lacks any one of them.

--- middle


# Introduction {#intro}

Autonomous mobile robots, semi-autonomous physical equipment, and
human-directed physical work crews increasingly operate at regulated
real-world sites -- warehouses, common-interest communities, industrial
facilities, healthcare campuses, and public infrastructure. Relying parties --
site owners, insurers, regulators, dispatchers, and downstream operations
platforms -- need portable, verifiable evidence of *what physically happened
at a site*, distinct from the digital-artifact supply-chain evidence
addressed by {{RFC9943}} and distinct from the per-action AI-agent evidence
addressed by {{I-D.noa-scitt-ai-agent-receipt}} and
{{I-D.mih-scitt-agent-action-capsule}}.

This profile fills that gap by defining the SCITT Statement content for one
*physical-site engagement*: a bounded interval during which a specific actor
operates at a specific site under a stated envelope, with the evidence
sealed inside a TEE and the receipt subsequently written into whatever
operations layer the site already uses (property-management system,
maintenance ticketing, insurance underwriting API, regulatory portal).

The profile's defensibility, and its value to relying parties, comes from
combining four elements that no single vendor category currently ships
together:

- *Site-hosted TEE trust anchor.* The signing key is bound to hardware
  physically located at the site under the site owner's control. Cloud-hosted
  transparency services can issue strong receipts, but the signing authority
  lives inside the cloud provider's environment; this profile REQUIRES that
  the authority live on the Site Owner's premises, attested by the TEE
  silicon vendor, and neither extractable by the Site Owner nor by the
  Issuer. This statement describes direct-witness mode. In delegated-witness
  mode ({{attestation-binding}}) the key that produces the COSE signature is
  the Issuer's own and need not be site-resident; what remains site-resident
  is the TEE that issues the delegation credential, and a relying party
  evaluating such a receipt obtains a weaker property than the one described
  here. A Verifier MUST determine which mode applies from
  `attestation.bindingMode` in the receipt before relying on the
  non-extractability property, and MUST NOT assume direct-witness mode.
  A receipt carrying no `attestation.bindingMode` is rejected on version
  validation under {{payload}} and no mode is inferred for it.
- *Physical-work evidence vocabulary.* The five-artifact schema (Site,
  Actor, Engagement, Attestation, Adapter Write-In) binds the receipt to
  what physically happened, not merely to a software event. This vocabulary
  is defined in {{payload}} and is stricter than a general-purpose SCITT
  Statement.
- *WRITE_ONLY adapter into existing operations layers.* Verified evidence
  is posted into the systems the buyer already uses -- property-management,
  maintenance, warehouse-management, claims, and asset-management platforms
  -- as recorded by the `adapter` field in {{payload}}. This profile
  explicitly does NOT define a new operations dashboard; it defines how
  receipts enter the operations layers a site already runs.
- *Transparency-service registration.* Neither the Issuer's `chain` nor the
  TEE establishes that a presented history is complete, or that it is the
  only history. A withheld suffix is internally consistent at every link,
  and a TEE establishes that it wrote the state it attests, not that that
  state is the most recent. Registration in a SCITT Transparency Service
  supplies the external reference against which relying parties and auditors
  can test those questions. A TEE on customer premises without external
  witnessing is therefore insufficient; SCITT registration is REQUIRED by
  this profile ({{scitt-registration}}).

Physical-Site Engagement Receipts are complementary to, and compose with,
existing SCITT-AI drafts. An AI agent that dispatches a physical robot MAY
emit an Agent Action Capsule per {{I-D.mih-scitt-agent-action-capsule}}
describing the dispatch decision, and the physical engagement that follows
MAY be recorded as one or more Physical-Site Engagement Receipts under this
profile, correlated via the SCITT `sub` claim.

## Requirements Notation

{::boilerplate bcp14-tagged}

## Non-goals {#non-goals}

This revision does not:

- Attest that the engagement was safe, correct, effective, or compliant with
  any specific regulation.
- Attest that the site conditions were as recorded.
- Attest that no unrecorded engagement occurred outside the instrumented
  boundary.
- Specify a deterministic offline replay of a physical engagement decision.
  Reproducing a recipient's checks over retained bytes is a different operation
  and is described for the local implementation in {{local-replay}}.
- Define the operations-layer schemas the Adapter Write-In targets.
- Define billing, SLA-credit, or insurance-pricing rules that a relying party
  may derive from a stream of receipts.
- Attest anything about the internal state, intent, or decision process of a
  human participant in an engagement, or about signals conveyed by a direct
  neural or brain-computer interface. This profile records that a bounded
  physical engagement occurred at a Site and identifies the parties that can
  attest to it. A direct neural interface is not an engagement performed by an
  Actor at a Site under {{terminology}}, and this document defines no member,
  no value, and no extension point for one.

These non-goals are NORMATIVE: implementations and relying parties MUST NOT
imply the stronger claims from a receipt.

# Terminology {#terminology}

This document uses the terms defined in {{RFC9943}} (Signed Statement,
Statement, Issuer, Subject, Transparency Service, Registration Policy,
Receipt) and {{RFC9942}} (Verifiable Data Structure, Verifiable Data
Structure Proof). In addition:

Site:
: The bounded real-world location at which the engagement occurred,
  identified by a stable Site Identifier under the Issuer's registration
  authority. The Site is the physical analog of a SCITT Subject.

Site Envelope:
: The operating constraints in force at the Site during the engagement --
  permitted actor classes, permitted engagement types, geospatial bounds,
  temporal bounds, and referenced site-rule documents. The Site Envelope is
  identified by a stable envelope identifier and a content digest.

Site Owner:
: The party that controls physical access to the TEE hardware producing
  receipts for a Site, and that is responsible for that hardware's continued
  operation there. The Site Owner is defined by those two capabilities and not
  by title, by legal ownership of the premises, or by any contractual label:
  the party holding them may or may not be the party named on the deed. The
  Site Owner is one of the three parties REQUIRED to participate in every
  receipt under {{trust-model}}. The Site Owner has no capability to author,
  alter, or suppress the content of a receipt, and none to extract the signing
  key material.

Actor:
: The physical entity that performed the engagement -- an autonomous
  robot, a semi-autonomous asset, a human operator, or a human-led crew --
  identified by a stable actor identifier under the Issuer's registration
  authority.

Operator:
: The organization or individual responsible for the Actor during the
  engagement, distinct from the Issuer of the receipt when a third-party
  witness signs.

Engagement:
: A bounded interval, delimited by an Engagement Window, during which the
  Actor performed physical work at the Site under the Site Envelope.

Engagement Window:
: The time interval \[start, end\] of the Engagement, expressed in RFC 3339
  UTC, with the same clock basis as the TEE-sealed evidence.

Attestation Evidence:
: The output of a TEE that observed the Actor and the Engagement,
  including a platform attestation, a measured-boot chain, and a digest
  over the sealed evidence bundle. The bundle itself is opaque to the
  Transparency Service.

Adapter Write-In:
: The record that the Signed Statement (or a reference to it) was posted
  into an out-of-band operations layer, together with the operation-layer
  system identifier, endpoint identifier, and a post-time digest of the
  operations-layer acknowledgement. The Adapter Write-In is what makes the
  receipt *useful* to the site's existing workflow without requiring the
  operations layer to be modified.

Physical-Site Engagement Receipt (PSER):
: A SCITT Signed Statement under this profile, carrying a canonical JSON
  payload conforming to {{payload}}, with the profile identifier
  `wilder.pser/0.7` and a SCITT Receipt attached as defined in
  {{RFC9942}}.

Chain-Verifier:
: A relying party, or a party acting on a relying party's behalf, that is
  presented with two or more Physical-Site Engagement Receipts as one
  contiguous chain and evaluates the chain-level properties defined in
  {{payload}}. Chain-Verifier is a role, not a distinct principal: any
  verifier MAY act as a Chain-Verifier, and the obligations this profile
  places on a Chain-Verifier apply only to a presentation of two or more
  receipts. A verifier presented with a single receipt incurs none of them.

# Profile identifier and media types

The profile identifier for this document is `wilder.pser/0.7` and MUST appear
as the top-level payload `spec` value. The protected COSE content type MUST
be `application/pser+json; profile=wilder.pser/0.7`, and it MUST agree with
the payload's declared profile.

This revision adds the required null-or-root `engagement.contentDigest` and
makes the Signed Statement's protected CWT `sub` a text string exactly equal
to `site.id`. It retains the 0.6 recorded-time containment and DIRECT_WITNESS
identifier-consistency rules. It does not add authenticated key association.

Statements declaring `wilder.pser/0.5` or `wilder.pser/0.6` retain their
earlier profile requirements. An implementation supporting legacy material
MUST NOT silently reinterpret it as 0.7, insert a missing content member,
rewrite its CWT types, or normalize its signed bytes. A 0.7 recipient MUST
report unknown or unsupported profiles as unsupported, not substitute a
known version with different rules.

The legacy implementation's byte-string `sub` form is preserved as
compatibility behavior, not represented as conforming to the CWT text
claim definition in {{RFC8392}} or the SCITT architecture in {{RFC9943}}.
Existing signatures are not repaired by changing the encoded claim type.

The `application/scitt-statement+cose` and `application/scitt-receipt+cose`
media types from {{RFC9943}} apply unchanged to the outer objects.
The retained content is not inline public geometry or a new SCITT log format.

# Receipt structure {#payload}

A Physical-Site Engagement Receipt is a SCITT Signed Statement per
{{RFC9943}} Section 6, encoded as a COSE_Sign1 per {{RFC9052}}. The payload
is a JSON object serialized with JCS {{RFC8785}} and carried as the
`COSE_Sign1` payload.

The following is a complete example instance. It is not a schema: every value
is literal, the whole object parses as JSON, and the `chain.hash` value is the
digest this profile specifies over the rest of the object. Normative member
definitions are in {{payload}}; the member definitions govern over an
illustrative example.

This figure is illustrative. Its digests are placeholders, the identifiers are
synthetic, and the `teeClass` value is one conforming registry entry chosen so
the example round-trips. The `chain.hash` value is computed over the
canonicalized payload with `chain.hash` absent. This profile does not prefer,
presume, or depend on any particular confidential-compute environment, and no
value in this figure should be read as a statement about deployed hardware.

~~~ json
{
  "actor": {
    "class": "AUTONOMOUS",
    "id": "actor:robot-alpha-01",
    "operator": "operator:wilder-robotics"
  },
  "adapter": {
    "ackDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "ackProvenance": "THIRD_PARTY",
    "endpoint": "endpoint:res-001",
    "mode": "WRITE_ONLY",
    "postedAt": "2026-10-15T14:00:05Z",
    "system": "example.ticketing"
  },
  "attestation": {
    "bindingMode": "DIRECT_WITNESS",
    "measuredBoot": {
      "chain": "sha256:98a6efd412bb768ea7f090e8228401c11bc72a7caae44170395445c097d5ffa1",
      "components": [
        {
          "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
          "name": "bl1"
        }
      ]
    },
    "platformEvidence": {
      "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "encoding": "opaque/1"
    },
    "sealedEvidence": {
      "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "encoding": "opaque/1",
      "sizeBytes": 4096
    },
    "teeClass": "arm.cca",
    "validity": {
      "notAfter": "2026-10-15T15:00:00Z",
      "notBefore": "2026-10-15T13:00:00Z"
    },
    "witnessKey": "key:tee:res-001-witness-01"
  },
  "chain": {
    "hash": "sha256:d9818729036b31e66078dade02bc83dc69cb5935ac226978d2fede70bde4a1bb",
    "prevHash": null,
    "seq": 0
  },
  "engagement": {
    "contentDigest": null,
    "envelopeConformance": "WITHIN",
    "evidenceDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "id": "eng:res-001:20261015-140000",
    "outcomeClass": "COMPLETED",
    "type": "patrol",
    "window": {
      "end": "2026-10-15T14:00:00Z",
      "start": "2026-10-15T13:30:00Z"
    }
  },
  "id": "uuid:00000000-0000-4000-8000-000000000001",
  "issuerAffiliation": "NOT_DISCLOSED",
  "site": {
    "class": "residential",
    "envelope": {
      "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "geobounds": null,
      "id": "env:res-001:2026-Q4",
      "temporal": {
        "ends": null,
        "starts": "2026-10-01T00:00:00Z"
      }
    },
    "id": "site:res-001"
  },
  "spec": "wilder.pser/0.7",
  "ts": "2026-10-15T14:00:00Z"
}
~~~
{: title="Physical-Site Engagement Receipt payload"}

## Field semantics

### `spec` (REQUIRED, string)

MUST be `wilder.pser/0.7` for receipts conforming to this document.
An unsupported value is outside the recipient's implemented profile set and
MUST be reported as unsupported. Implementations supporting 0.5 or 0.6 evaluate
those statements under their declared versions, without importing the new
content or subject-type requirements.

### `id` (REQUIRED, string)

A globally unique identifier for the receipt, assigned by the Issuer. RECOMMENDED
form is a URN or a `uuid:` prefix. `id` MUST NOT be reused within an Issuer.

### `ts` (REQUIRED, string)

RFC 3339 UTC timestamp at which the Issuer sealed the receipt. This is the
receipt-issuance time; it MAY differ from `engagement.window.end`.

For a receipt declaring `wilder.pser/0.6` or `wilder.pser/0.7`, the Verifier MUST check
`notBefore <= ts <= notAfter` using parsed instants and inclusive endpoints.
The comparison checks whether the asserted receipt-issuance timestamp lies
within the asserted attestation-validity interval. It does not independently
establish the actual time of issuance or whether the engagement occurred
within that interval. A timestamp at either endpoint passes this check only;
it does not establish overall receipt conformance.

This containment requirement does not apply to a receipt declaring
`wilder.pser/0.5`. An implementation supporting these profile versions
evaluates each under its declared version's requirements. A verifier-selected
clock-skew tolerance MUST NOT alter the profile's containment interval.

### `issuerAffiliation` (REQUIRED, string)

States whether the Issuer and the Site Owner are affiliated principals. The
admissible values are exactly:

- `AFFILIATED`: the Issuer and the Site Owner are the same principal, or are
  principals under common control, or one controls the other.
- `INDEPENDENT`: the Issuer and the Site Owner are principals under neither
  common control nor the control of one by the other.
- `NOT_DISCLOSED`: the relationship is not stated in the receipt.

The member is REQUIRED because the alternative is worse. An absent member would
itself have to be assigned a meaning, and every available meaning is wrong: read
as `INDEPENDENT` it manufactures a disclosure nobody made, and read as
`AFFILIATED` it accuses an Issuer of a relationship it may not have. Requiring
the member makes `NOT_DISCLOSED` a stated position rather than an inference drawn
from silence.

The value states the Issuer's own claim about itself. This profile does not
define a mechanism by which a Verifier establishes the claim to be true, and a
Verifier MUST NOT report a verified receipt as evidence that the stated
relationship holds. What verification establishes is that the claim was made,
by the Issuer, inside a receipt bound by the signature and the chain, and
therefore that it cannot later be revised without the revision being visible.
That is a narrower property than truth and it is the property this member
carries.

A Verifier MUST NOT read `NOT_DISCLOSED` as `INDEPENDENT`. Silence about a
relationship is not a denial of one, and a relying party told otherwise has been
supplied a claim no principal authored. This is the one collapse the member
exists to prevent, and it is the direction that overstates the receipt.

A Verifier MUST NOT read a value outside the admissible set as `AFFILIATED` and
MUST NOT normalize it to `NOT_DISCLOSED`. A Verifier that encounters an
unrecognized value MUST preserve the value as received and MUST surface it to
the relying party as unrecognized, distinct from all three admissible values.
This revision does not require a Verifier to reject a receipt on that basis,
because a value it does not recognize may be defined by a later revision; it
requires that the Verifier never silently resolve the ambiguity. The value set
is closed in this revision and is not registry-governed. A later revision that
adds a value does so additively, without redefining an existing one.

The relationship this member describes is a standing one between two principals
rather than a property of a single engagement, but standing relationships
change. Receipts presented as one chain may therefore disagree about it without
either receipt being defective. The chain-level obligation, which is to surface
such a change rather than to reject the presentation or to resolve it in favour
of either value, is stated with the other Chain-Verifier obligations under
`chain`.

This member is distinct from, and does not substitute for, the affiliation
disclosure required of an Issuer that registers with a Transparency Service it
operates or that is operated by an affiliated principal
({{scitt-registration}}), which is an Issuer-published fact resolved under
{{issuer-published}} rather than a member of this payload. That obligation concerns the relationship between the
Issuer and the Transparency Service; this member concerns the relationship
between the Issuer and the Site Owner. An Issuer may be independent of the Site
Owner and still operate its own Transparency Service, or be affiliated with the
Site Owner and register with an unaffiliated one. Neither value can be inferred
from the other.

### `site` (REQUIRED, object)

Identifies the physical location.

- `site.id` (REQUIRED, string): stable site identifier under the Issuer's
  registration authority. This is the physical analog of a Subject and
  MUST be used as the text value of the CWT `sub` claim for 0.7 in the protected
  header (see {{cose-header}}).
- `site.class` (REQUIRED, string): coarse site classification. Registry-
  governed; see {{iana}}.
- `site.envelope.id` (REQUIRED, string): stable identifier of the operating
  envelope in force during the engagement.
- `site.envelope.digest` (REQUIRED, string): JSON-DIGEST (SHA-256 of the JCS
  serialization) of the full envelope document. The full document MUST NOT
  appear in the public receipt; it is bound by digest only.
- `site.envelope.geobounds` (OPTIONAL, string): opaque reference to
  geospatial bounds. Any geospatial detail beyond the reference is bound by
  the envelope digest, not published.
- `site.envelope.temporal` (OPTIONAL, object): temporal window during which
  this envelope was in force. `null` values indicate "open-ended in that
  direction."

### `actor` (REQUIRED, object)

- `actor.id` (REQUIRED, string): stable identifier of the physical actor.
- `actor.class` (REQUIRED, string): one of `AUTONOMOUS`, `SEMI_AUTONOMOUS`,
  `HUMAN`, `CREW`.
- `actor.operator` (REQUIRED, string): stable identifier of the responsible
  operator organization or individual.

### `engagement` (REQUIRED, object)

- `engagement.id` (REQUIRED, string): stable identifier of the engagement.
- `engagement.window.start` and `engagement.window.end` (REQUIRED, string):
  RFC 3339 UTC bounds of the engagement. `end` MUST be >= `start`. Both MUST
  share a clock basis with `attestation.sealedEvidence` (see
  {{clock-basis}}).
- `engagement.type` (REQUIRED, string): coarse engagement classification
  (e.g. `patrol`, `service`, `inspection`, `delivery`, `installation`,
  `maintenance`, `presence`). Registry-governed; see {{iana}}.
- `engagement.outcomeClass` (REQUIRED, string): one of `COMPLETED`,
  `ABORTED`, `REFUSED`, `ERRORED`, `OBSERVED_ONLY`. `OBSERVED_ONLY` records
  that the Issuer witnessed the actor at the site but did not participate
  in dispatch.
- `engagement.envelopeConformance` (REQUIRED, string): one of `WITHIN`,
  `EXCEEDED_TEMPORAL`, `EXCEEDED_GEO`, `EXCEEDED_ACTOR`, `UNKNOWN`. The
  Issuer MUST NOT claim `WITHIN` unless it evaluated conformance against
  the envelope digest.
- `engagement.evidenceDigest` (REQUIRED, string): JSON-DIGEST of the
  engagement's internal evidence structure. The internal structure is
  opaque to this profile and MUST NOT appear in the receipt.
- `engagement.contentDigest` (REQUIRED for 0.7): JSON null or the
  `sha256:` root of the retained-content construction in
  {{content-commitment}}. It is distinct from `evidenceDigest` and the
  whole-envelope digest. A missing member is invalid for 0.7. A payload
  declaring 0.5 or 0.6 that contains this member is invalid under that
  version and MUST be rejected, including when its value is null. This
  does not authorize modifying an existing signed statement.

### `attestation` (REQUIRED, object)

Binds the receipt to the TEE that observed the engagement. This is the
mechanism that distinguishes a Physical-Site Engagement Receipt from a bare
signed timestamp: the sealed evidence attests that the Issuer observed the
engagement from inside a hardware-rooted, remotely attestable environment.
Verification of the Signed Statement and its attached Receipt alone does not
establish hardware provenance. That property additionally depends on obtaining
and validating the platform attestation evidence and its binding to the
relevant key under the relying party's trust policy.

- `attestation.teeClass` (REQUIRED, string): TEE class identifier.
  Registry-governed; see {{iana}}. The *TEE Class* registry is REQUESTED by
  this document and has NOT yet been allocated by IANA. Until allocation, the
  admissible values are exactly the initial values listed in {{iana}}.
  A Verifier MUST reject a `teeClass` value outside that set.

  These descriptions identify the environments named by the existing values.
  They do not, by themselves, define a complete evidence-format binding or
  establish implementation support. Evidence encoding, versioning, trust
  inputs, and appraisal requirements are addressed by the applicable evidence
  specification and the profile's attestation model
  (`attestation.platformEvidence`, {{payload}}).
- `attestation.platformEvidence` (REQUIRED, object): reference to the
  platform-native attestation document, in a format defined by the TEE
  class. The document itself MAY be conveyed by reference (URI + digest) or
  inline; when conveyed inline it SHOULD be in the unprotected header of
  the enclosing Signed Statement, not in the payload.
- `attestation.platformEvidence.digest` (REQUIRED, string): digest of the
  platform-native attestation document.
- `attestation.platformEvidence.encoding` (REQUIRED, string): opaque
  encoding label for that document. The set of labels a given TEE class
  admits is defined by that TEE class.
- `attestation.measuredBoot` (REQUIRED, object): the measured-boot state of
  the environment that produced the receipt.
- `attestation.measuredBoot.chain` (REQUIRED, string): JSON-DIGEST of the
  measured-boot chain.
- `attestation.measuredBoot.components` (REQUIRED, array): the measurements
  the chain digest commits to, in boot order. Each element is an object with
  a `name` (REQUIRED, string) naming the measured component and a `digest`
  (REQUIRED, string) carrying its measurement. Verifiers MUST NOT infer any
  meaning from `name` beyond identification.
- `attestation.sealedEvidence.digest` (REQUIRED, string): digest of the
  sealed evidence bundle.
- `attestation.sealedEvidence.sizeBytes` (REQUIRED, int): size of the
  sealed bundle in bytes. Included to enable bounded-storage verifiers to
  reject bundles they cannot process.
- `attestation.sealedEvidence.encoding` (REQUIRED, string): opaque encoding
  label. Registry-governed; see {{iana}}.
- `attestation.witnessKey` (REQUIRED, string): key identifier of the TEE
  signing key. This MAY differ from the Issuer's `iss` when the TEE
  operates as a delegated witness.

  Under the `wilder.pser/0.6` and `wilder.pser/0.7` DIRECT_WITNESS naming convention,
  `attestation.witnessKey` and the protected CWT `iss` value MUST be
  textually equal. A successful comparison establishes this naming
  convention only. It does not establish that the signature-verification
  key is authentically associated with either identifier or that genuine
  TEE hardware produced the signature. This convention does not require a
  global one-to-one mapping between all issuer identifiers and keys,
  prohibit key rotation, or redefine issuer identity as key material. The
  actual DIRECT_WITNESS relationship still concerns the key that produced
  the signature and the TEE signing key. Authenticated key association and
  hardware provenance require their respective evidence and trust
  mechanisms; they are not supplied by label equality. This naming
  restriction MUST NOT be silently applied as a changed conformance rule
  for `wilder.pser/0.5`.
- `attestation.bindingMode` (REQUIRED, string): the attestation-binding mode
  under which this receipt was produced, as defined in
  {{attestation-binding}}. The admissible values are exactly:

  - `DIRECT_WITNESS`: the key that produced the COSE signature is the TEE
    signing key. `attestation.bindingMode` is `DIRECT_WITNESS` only where
    `attestation.witnessKey` and `iss` denote the same key.
  - `DELEGATED_WITNESS`: the key that produced the COSE signature is the
    Issuer's own, and a TEE-issued delegation credential authorizes it.

  A Verifier MUST reject a `bindingMode` value outside that set, and MUST
  reject a receipt asserting `DIRECT_WITNESS` in which `attestation.witnessKey`
  and `iss` denote different keys. The value is closed in this revision and is
  not registry-governed.

  This member is REQUIRED, and carries in the receipt a fact that `-02` required
  a Verifier to obtain from the Issuer out of band. The mode was fixed at the
  moment the receipt was signed and was known to the signer; obtaining it from a
  separately published document made a per-receipt fact depend on a document
  that describes an Issuer rather than a receipt, and made the weaker of the two
  properties in {{terminology}} unavailable from the presented bytes. An absent
  value is not assigned a meaning, because assigning one reintroduces the
  assumption this member exists to prevent.
- `attestation.validity` (REQUIRED, object): the interval over which the
  attestation of the producing environment is asserted to hold.
- `attestation.validity.notBefore` (REQUIRED, string): RFC 3339 UTC
  timestamp at which the attestation becomes valid.
- `attestation.validity.notAfter` (REQUIRED, string): RFC 3339 UTC timestamp
  after which the attestation is no longer valid. `notAfter` MUST be strictly
  later than `notBefore`; a Verifier MUST reject a receipt whose `notAfter` is
  equal to or precedes its `notBefore`. A zero-length interval asserts
  validity for an instant of zero duration and has no legitimate producer.
  For a receipt declaring `wilder.pser/0.6` or `wilder.pser/0.7`, a Verifier MUST reject the
  receipt when the asserted `ts` is outside the asserted `[notBefore,
  notAfter]` interval, using parsed instants and inclusive endpoints. This
  checks consistency of the recorded instants, not independently established
  real-world issuance time. The published `wilder.pser/0.5` profile did not
  require timestamp containment; that historical requirement remains
  unchanged.

### `adapter` (REQUIRED, object)

Records that the receipt (or a reference to it) was written into an
out-of-band operations layer. This is the profile's core insight: a
receipt that no operations system can see is not useful, and modifying the
operations system to consume receipts natively is out of scope for most
regulated sites. The Adapter Write-In makes the receipt observably present
in the site's existing workflow.

- `adapter.system` (REQUIRED, string): operations-layer system identifier
  (e.g. a property-management system, maintenance ticketing platform,
  regulatory portal, insurance underwriting API). Registry-governed; see
  {{iana}}.
- `adapter.endpoint` (REQUIRED, string): opaque endpoint identifier within
  the system. Its interpretation is defined by the target system, not by
  this profile.
- `adapter.postedAt` (REQUIRED, string): RFC 3339 UTC timestamp at which
  the write-in was posted.
- `adapter.ackDigest` (REQUIRED, string): JSON-DIGEST of the operations-
  layer's acknowledgement response. If the operations layer returns no
  structured acknowledgement, the digest is taken over an Issuer-defined
  minimal ack object. That object is bound by the receipt's Merkle inclusion
  and is not published, so no Verifier can obtain it and none is required to.
  This is not a resolution obligation under {{issuer-published}}: a Verifier
  checks that `adapter.ackProvenance` is `ISSUER_ASSERTED` and treats the
  acknowledged content as authored by the Issuer. `-02` located the object's
  schema in an Issuer-published document, which stated an obligation against a
  document defined to be unfetchable.
- `adapter.ackProvenance` (REQUIRED, string): identifies which party authored
  the acknowledgement that `adapter.ackDigest` commits to. `adapter.ackDigest`
  alone cannot carry this: the digest of an acknowledgement authored by an
  independent operations layer and the digest of one authored by the Issuer
  itself are indistinguishable to a Verifier, and the two have materially
  different evidentiary weight. The admissible values are exactly:

  - `THIRD_PARTY`: the acknowledgement was returned by the operations layer
    named in `adapter.system`, which is a principal distinct from the Issuer.
  - `ISSUER_ASSERTED`: the operations layer returned no structured
    acknowledgement, and the digest is taken over the Issuer-defined minimal
    ack object described under `adapter.ackDigest`. The Issuer is the author of
    the acknowledged content.
  - `NONE`: no acknowledgement was obtained from any party.

  A Verifier MUST NOT read a value outside that set as `THIRD_PARTY`, and MUST
  NOT normalize it to `NONE`. Doing either reintroduces the collapse this
  member exists to prevent, in the direction that overstates the receipt. A
  Verifier that encounters an unrecognized value MUST preserve the value as
  received and MUST surface it to the relying party as unrecognized, distinct
  from all three admissible values. This revision does not require a Verifier
  to reject a receipt on that basis, because a value it does not recognize may
  be defined by a later revision; it requires that the Verifier never silently
  resolve the ambiguity in the receipt's favour.

  The value set is closed in this revision and is not registry-governed. A
  later revision that adds a value does so additively, without redefining an
  existing one.
- `adapter.mode` (REQUIRED, string): MUST be `WRITE_ONLY` in this revision.
  Read-in modes are explicitly out of scope; see {{security}}.

### `chain` (REQUIRED, object)

Hash-chains successive receipts by the same Issuer so that a verifier can
detect broken hash links, sequence discontinuities, and modification,
substitution or reordering among the receipts presented as one contiguous
chain. The chain does NOT establish that its last presented receipt is the
Issuer's latest: a prover that withholds a suffix presents a prefix that is
internally consistent at every link. See {{security}}.

The construction is defined normatively in this document. It follows the
convention established in {{I-D.noa-scitt-ai-agent-receipt}} Section 5,
which is cited for provenance only: no conformance requirement of this
profile depends on that document.

- `chain.seq` (REQUIRED, int): non-negative sequence number within the
  Issuer's chain for the identified Subject. The first receipt in a chain
  MUST carry `chain.seq` 0.
- `chain.prevHash` (REQUIRED, string or null): the value of the
  immediately preceding receipt's `chain.hash`, or `null` for the first
  receipt. A receipt whose `chain.seq` is 0 MUST carry `null`; a receipt
  whose `chain.seq` is nonzero MUST carry the preceding receipt's
  `chain.hash` value. Note that this is a digest over the preceding
  receipt EXCLUDING its `chain.hash` member, per the definition of
  `chain.hash` below; it is not a digest over the preceding receipt as
  transmitted.
- `chain.hash` (REQUIRED, string): JSON-DIGEST of the receipt's canonical
  form with the `chain.hash` member absent. An Issuer computes this value
  over the complete receipt including `chain.seq` and `chain.prevHash`, then
  inserts it; a verifier recomputes it by removing the member before
  canonicalizing. `chain.hash` is never an input to its own computation.

A Chain-Verifier presented with two or more receipts as one contiguous chain
MUST check, for each adjacent pair, that the later receipt's `chain.seq` is
exactly one greater than the earlier receipt's, and that the later receipt's
`chain.prevHash` equals the earlier receipt's `chain.hash`. A verifier that
does not perform both checks MUST NOT report the presentation as a verified
chain. These are chain-level obligations; an Issuer producing individual
receipts is unaffected by them.

A Chain-Verifier MUST additionally compare `issuerAffiliation` across each
adjacent pair. Where two receipts presented as one chain carry different values,
the Chain-Verifier MUST surface the change to the relying party, identified by
the `chain.seq` of the receipt carrying the later value. A change in
`issuerAffiliation` does not by itself invalidate the presentation, and a
Chain-Verifier MUST NOT report the presentation as unverified on that basis
alone.

The two preceding checks are structural. `chain.seq` and `chain.prevHash` are
wholly under the Issuer's control, so a violation of either admits no honest
explanation. `issuerAffiliation` is not structural: it states a relationship
between two principals in the world outside the receipt, and such relationships
change. An Issuer independent of a Site Owner at one engagement may be acquired
by that Site Owner before the next. Reporting that as an unverified chain would
place an ordinary corporate event in the same category as tampering, and the
only conforming response available to the Issuer would be to begin a new chain,
which resets `chain.seq` and `chain.prevHash` and so severs the record either
side of the change. That is the continuity the chain exists to carry.

What a Chain-Verifier MUST NOT do is reduce the presentation to a single
affiliation value. In particular it MUST NOT adopt the value carried by the
latest receipt as the value of the chain. Adopting the later value would allow a
chain to be relabelled after the fact by appending a single receipt, with
nothing in the presentation showing that the label had previously said something
else. Each reported value remains attached to the receipts that carry it.

A conforming three-receipt chain, the sequence-gap and broken-link cases these
checks are required to reject, and a two-receipt presentation whose members
disagree about `issuerAffiliation` and which is required to verify with the
change surfaced, are published as test data in the reference implementation
repository. Implementers are advised to confirm that an honest complete chain
verifies under their implementation before relying on any of these checks.

## COSE header requirements {#cose-header}

The protected header of a Signed Statement under this profile MUST include
the CWT Claims header parameter (label 15, {{RFC9597}}), carrying at least:

- `iss` (CWT claim label 1): a URI identifying the Issuer, encoded as a
  nonempty CBOR text string.
- `sub` (CWT claim label 2): a CBOR text string whose decoded UTF-8 value
  is exactly the payload's `site.id`.

For 0.7, a byte-string subject, a missing subject, or a different text value
MUST be rejected by the implemented subject check; no byte-to-text coercion,
case folding, or Unicode normalization is permitted. This makes the encoded
claim follow {{RFC8392}}, {{RFC9597}}, and {{RFC9943}}. The equality check
does not authenticate the Site.

The protected header `content_type` (label 3) MUST be
`application/pser+json; profile=wilder.pser/0.7`.

The Signed Statement's payload MUST be the JCS serialization of the JSON
object defined in {{payload}}. Detached payloads are NOT PERMITTED under
this revision.

## Resolving Issuer-published facts {#issuer-published}

Two obligations in this profile require a Verifier to obtain a fact the Issuer
publishes rather than carries in the receipt: the delegation credential of
{{attestation-binding}}, and the Transparency Service affiliation disclosure of
{{scitt-registration}}. Both are disclosures about the Issuer. Neither is an
identity claim, and neither is required to evaluate a receipt produced in
direct-witness mode by an Issuer registering with an unaffiliated Transparency
Service.

This revision does not specify a serialization format for these facts, and does
not define a document that carries them. `-02` referred to an "Issuer's
manifest" in four normative requirements without defining one, so a Verifier was
four times required to read something the profile never described. Naming the
obligations and their resolution behaviour, and leaving the encoding to a
subsequent revision or companion document, is deliberate: a format fixed before
any has been deployed is more likely to be repudiated by the next revision than
refined by it.

An Issuer-published fact is resolved as follows.

- The Issuer MUST make the fact retrievable at a stable identifier under its own
  control, and that identifier MUST be discoverable from `iss`.
- A Verifier MAY cache a resolved fact. A cached answer MUST NOT survive a
  change in the signing key it was resolved for; on such a change the Verifier
  MUST re-resolve.
- Where a fact does not resolve, whether because it is unreachable, absent, or
  unreadable, the fact is **undetermined**.

Undetermined is a third outcome, not a synonym for either answer. A Verifier
MUST surface an undetermined fact as undetermined. It MUST NOT resolve an
undetermined fact to whichever value favours the Issuer, and MUST NOT report
that a fact was absent where it was never successfully retrieved: those two
states are distinct and a relying party's policy may treat them differently. A
Verifier MUST NOT reject a receipt solely because an Issuer-published fact is
undetermined; whether an undetermined fact is disqualifying is a policy question
for the relying party and is out of scope for this profile. What the profile
requires is that the relying party be told.

Conformance vectors accompanying this revision MUST include, for each
Issuer-published fact, at least one case in which resolution fails, and the
expected outcome of such a case MUST NOT be acceptance.

## Attestation binding {#attestation-binding}

The `attestation.witnessKey` field carries the identity of the TEE signer.
This profile permits two attestation-binding modes. The mode under which a
receipt was produced MUST be carried in that receipt, in
`attestation.bindingMode` ({{payload}}), and MAY additionally be recorded in
the CWT Claims Set. It is not obtained from any Issuer-published document:

- *Direct-witness mode:* the signing key associated with the Issuer identified
  by `iss` is the TEE signing key. Under `wilder.pser/0.6` and `wilder.pser/0.7`,
  `attestation.witnessKey` and the protected CWT `iss` value MUST be textually
  equal under the naming convention defined in this profile. That comparison
  establishes identifier consistency only; it does not establish authenticated
  association with the key used to verify the signature or genuine hardware
  provenance. The published `wilder.pser/0.5` requirement to reject a
  DIRECT_WITNESS receipt whose identifiers denote different keys remains part
  of that earlier profile. The string comparison retained by 0.6 and 0.7 neither changes the
  earlier profile nor supplies the missing authenticated-key-association
  mechanism. The reference implementation's broader assurance limitation is
  recorded in {{impl-status}}.
- *Delegated-witness mode:* the Issuer's `iss` key is distinct from the
  TEE signer, and the TEE has issued a delegation credential authorizing
  the Issuer to sign this receipt on the TEE's behalf. The delegation
  credential is bound by the `attestation.sealedEvidence.digest` and is an
  Issuer-published fact resolved under {{issuer-published}}. Where it does not
  resolve, the authorization of the signing key is **undetermined** and the
  Verifier proceeds as required by that section. Delegated signing does not
  itself establish evidence appraisal.

## Evidence model and external appraisal {#evidence-model}

This revision retains the existing attestation payload structure and introduces
neither an `attestation.quote` member nor an `attestationResult` member. The
payload carries references, digests, and attestation-related claims;
`measuredBoot` also carries the listed component measurements. The existing
allowance for the platform attestation document to be supplied by reference or
inline in the enclosing Signed Statement's unprotected header is unchanged.

A relying party may appraise obtained Evidence itself or use a separate
Verifier channel. A digest commits to particular evidence bytes; it is not, by
itself, a retrieval address, a retrieval mechanism, or evidence appraisal.
Obtaining evidence whose digest matches a receipt is distinct from validating
that evidence and its binding to the relevant key.

An entity performs the RATS Verifier role only when it appraises Evidence
using the applicable trust inputs and appraisal policy and produces an
Attestation Result. A single entity may perform several roles, but their
combination must be stated rather than inferred from the signing mode.

Verification of the Signed Statement and attached Receipt alone does not
establish hardware provenance. The choice of any additional in-receipt
Attestation Result representation remains open. Its format, authentication,
evidence/key binding, freshness, and failure behavior are not specified by this
revision. Option D (retain evidence references and additionally support an
optional Attestation Result) is a future design direction, not an added 0.7
payload member. These functional distinctions follow the RATS role definitions
({{RFC9334}}).

## Clock basis {#clock-basis}

All timestamps in a Physical-Site Engagement Receipt MUST share a single
clock basis: the clock the TEE observed at the time it sealed the evidence
bundle. Implementations MUST NOT mix wall-clock timestamps with TEE-observed
timestamps within a single receipt. Verifiers MUST derive elapsed-time
computations from the receipt's own bytes, not from the verifier's local
wall clock.

# Retained content blocks and fact provenance {#content-blocks}

This section defines the retained-content construction for `wilder.pser/0.7`.
It does not modify a 0.5 or 0.6 statement. Those legacy profiles reject
`engagement.contentDigest`, including an explicit null value. A content
block is a collection of recorded assertions, not a second SCITT Statement,
a log Receipt, a geometry
document, or an assertion that all relevant observations were captured.

A content producer prepares the retained block; the Issuer binds its root in
`engagement.contentDigest`. These functions MAY be performed by the same
implementation. References below to a content producer describe that function,
not an additional trusted principal.

The construction distinguishes (1) what the Issuer signed, (2) membership of
disclosed records in that commitment, (3) permitted attribution and typed
metadata, (4) integrity of supplied evidence, (5) agreement under a supported
comparison, and (6) the relying party's application decision. A successful
check at one stage MUST NOT be substituted for another stage's result.

## Content commitment and explicit null {#content-commitment}

For profile 0.7, `engagement.contentDigest` is REQUIRED. Its value MUST be
either JSON `null` or `sha256:` followed by exactly 64 lowercase hexadecimal
digits representing the 32-byte root defined in {{content-hashing}}. An absent
member, a different JSON type, an uppercase digest, or another digest scheme
MUST NOT be interpreted as null or as a supported content commitment.

A null value means that this statement binds no retained-content root. It
does not assert that no evidence existed, that no fact was known, or that
the physical engagement had no relevant content. A relying party MAY require
a non-null commitment through an explicitly selected policy.

A non-null value is not the JSON-DIGEST of the complete block document and is
not an evidence-object digest. It is the separately domain-separated root
specified below. It does not replace `engagement.evidenceDigest`,
`attestation.sealedEvidence.digest`, `site.envelope.digest`, or `chain.hash`.
Changing `engagement.contentDigest` changes the payload and therefore requires
the existing payload-hash and signature procedures to be applied again.

Null, a committed empty block, and a nonempty commitment whose content is not
presented are different cases. An unbound presentation supplied with a null
statement MUST NOT manufacture a root, vocabulary, fact count, or absence
conclusion on behalf of that statement.

## Content data model {#content-model}

The construction identifier is the exact ASCII string
`pask-local-content-tree/1`. The word `local` is part of the identifier and
its hash input; it is not permission to substitute a local variant. This
working specification proposes the implemented identifier without silently
renaming its byte domain.

The supported scope is the exact ASCII string `PRESENTED_AT_SEAL`. It records
the Issuer's claim about the material committed when it sealed the statement.
It neither authenticates an observation's time nor proves that a source
actually supplied the material at that instant.

A content header contains this construction identifier, this scope, and an
exact vocabulary digest as defined in {{content-vocab}}. The fact count is
also bound in the header hash. A block contains zero through 256 fact records,
each with its own 32-octet salt. A salt is separate from the fact JSON.

Each fact record MUST be a UTF-8 JSON object with the following members:

| Member | Requirement |
|---|---|
| `name` | REQUIRED nonempty string, at most 128 ASCII bytes, drawn only from lowercase letters, digits, dot, and hyphen. |
| `value` | REQUIRED; its admitted type and values are determined by the selected vocabulary row. Presence is distinct from null. |
| `assertedBy` | REQUIRED string identifying a recorded attribution category. |
| `basis` | REQUIRED string identifying the recorded basis category. |
| `unit` | OPTIONAL; if supplied it must satisfy the selected row as specified below. |
| `evidence` | OPTIONAL unless required by the row or the global party rule; its allowed forms are defined in {{content-evidence}}. |
| `remoteOrigin` | Required or forbidden exactly as stated by the selected row. |

Additional members of the outer fact object are retained and included in the
commitment. They MUST NOT be stripped, rewritten, or silently endowed with
verification semantics. A value object is closed only where its selected
schema explicitly says so. In particular, the closed `site.pose` value does
not retrospectively close the older fact objects.

Fact names MUST be unique within a block. The producer MUST order facts by
ascending ASCII byte order of their names and assign zero-based indices in
that order. One name identifies one committed slot; this construction does
not encode a time series by repeating a fact name.

The complete fact bytes MUST equal their JCS serialization under {{RFC8785}}.
A verifier MUST reject malformed or noncanonical fact bytes, including
duplicate JSON member names, without normalizing them for a passing proof.
Canonicalization of prepared source data happens before commitment. Original
evidence bytes are governed separately by {{content-evidence}} and MUST NOT
be canonicalized merely to make a digest agree.

The construction uses the finite binary64/JCS number model. Exact
integer-form inputs (without fraction or exponent) are restricted to
[-9007199254740991, 9007199254740991]. Other admitted canonical finite
binary64 forms do not establish exact large-integer provenance. A value
outside the supported numeric domain MUST NOT be rounded into it. A
canonical finite non-integer can be committed but may violate its vocabulary
row. The present vocabularies impose
integer rules on their numeric value fields; that restriction is not a claim
that RFC 8785 prohibits all fractional numbers. Parsing cannot reconstruct
precision already lost upstream, and a report MUST NOT infer a source's
original numeric spelling from its canonical representation.

For this bounded construction, a fact is at most 16384 octets, aggregate
fact bytes are at most 1048576 octets, and fact JSON container nesting is at
most 16, counting the outer container as one. No membership proof has more
than eight sibling hashes. Out-of-bound material MUST NOT be reported as
successfully checked. Limits are not evidence of physical completeness,
constant memory use, constant time, or bounded acquisition outside the API.

A conforming producer MUST use fresh, independently generated, unpredictable
32-octet salts and MUST NOT reuse a salt within a block. It SHOULD avoid reuse
across blocks and protect undisclosed salts with the retained content.
The implementation checks salt length and reuse among material it can see;
it does not test entropy or establish secrecy or freshness. Deterministic
test salts do not demonstrate production salt generation.

## Byte-exact content hashing {#content-hashing}

All hashes in this subsection are SHA-256 over octet strings. `||` denotes
concatenation; `U64(x)` is an unsigned 64-bit, big-endian encoding; `len(x)`
is an octet length; and `B(t)` is the ASCII encoding of a stated literal.
Hexadecimal notation below denotes octets, not printable hex characters.

Let `D` be ASCII `PASK-LOCAL-CONTENT-TREE/1` followed by one zero octet.
Let `C = B("pask-local-content-tree/1")`, `S = B("PRESENTED_AT_SEAL")`,
`V` be the 32 raw digest octets decoded from the vocabulary digest, and
`N` be the fact count.

~~~ text
H = SHA-256(D || 0x00 || U64(N) ||
            U64(len(C)) || C || U64(len(S)) || S || V)

L_i = SHA-256(D || 0x01 || H || U64(i) || salt_i ||
              U64(len(F_i)) || F_i)

Empty(H) = SHA-256(D || 0x02 || H)
Node(A, B) = SHA-256(D || 0x03 || A || B)
Root = SHA-256(D || 0x04 || H || Tree(L_0, ..., L_(N-1)))
~~~
{: #content-hash-formulas}

`F_i` is the entire canonical fact record. `Tree` is defined recursively:
the empty tree is `Empty(H)`; a one-leaf tree is that leaf; otherwise split
the leaf sequence at the largest power of two strictly less than its length
and hash the left and right subtree roots with `Node`, in that order.

The result for `engagement.contentDigest` is `sha256:` plus the lowercase
hexadecimal encoding of `Root`. The construction binds the literal
construction/scope, vocabulary digest, count, indices, salts, lengths, and
complete disclosed fact bytes. It does not by itself bind a site or session;
the PSER signature associates the root with the surrounding payload.

This is a content-membership construction, not the SCITT log-leaf hash.
Its domain prefixes and root wrapping MUST NOT be replaced with a
Transparency Service's RFC9162 or CCF leaf procedure. The separate
candidate-entry rules in {{scitt-registration}} remain unchanged.

## Disclosure data and membership verification {#content-disclosure}

A disclosure presentation supplies a header, a count, and zero or more
disclosures. Each disclosure supplies the original canonical record bytes,
its 32-octet salt, index, and a sequence of 32-octet sibling hashes ordered
from leaf to root. Left/right placement is derived from the index, count,
and recursive split above; a caller-provided direction flag is not used.

The data model is independent of its transport. An encoding MUST preserve
the exact octets, integer values, and distinctions specified here.
{{local-replay}} describes the reference implementation's local file
container; that container is not a SCITT media type or a public registration
protocol.

Before asserting statement-bound content, a recipient MUST verify the
statement using its selected key and the applicable profile's payload/header
checks, and obtain the expected root from that checked payload. An unrelated
caller root, an unprotected-header hint, or a presentation's own calculated
root MUST NOT substitute for `engagement.contentDigest`. Key-to-identity
trust remains an additional question.

For each disclosed fact the recipient MUST check bounds, canonical bytes,
fact shape and name, index range, salt and hash widths, exact proof
consumption, and the reconstructed root. It MUST reject duplicate disclosed
indices, duplicate disclosed names, reused disclosed salts, and names whose
ordering disagrees with their indices. It MUST NOT silently discard an
invalid disclosure to turn the remaining batch into an apparently complete
presentation. A resource failure or unsupported construction is reported
as such, not converted into missing evidence.

A nonempty block with no disclosures supplies no verified header or count.
The result is not presented, not proof of absence. For a claimed empty block,
the recipient can recompute the header and empty root and compare it with
the expected root. A correctly proved empty block is distinct from null.

All committed slots are presented only when every in-range index is
accounted for once, all proofs match, and the disclosed name/salt/order
constraints hold. A selected subset proves only its disclosed slots.
It cannot validate hidden records, prove that hidden names or salts are
unique, or establish that the full block obeyed the producer rules.

Membership and semantic checks are independent. A record with a forbidden
attribution or invalid typed value can still be correctly committed.
Such a record MUST retain its adverse finding rather than be made
unprovable or silently omitted from the recipient's report. A producer or
recipient MUST NOT describe it as a conforming typed fact merely because
the hash or signature matches.

## Versioned content vocabularies {#content-vocab}

This document defines two closed, versioned rule sets in
{{content-vocabulary-tables}}. Their exact identifiers and source-file digests
are listed there. Vocabulary version numbers are independent of the PSER
profile, implementation package version, and Internet-Draft revision.

The vocabulary digest is SHA-256 of the exact published UTF-8 JSON artifact
bytes, including their retained formatting and terminal newline. It is NOT
the JSON-DIGEST of a newly serialized copy. The committed field uses
`sha256:` plus that hash. Exact artifacts accompany the specification for
reproduction; all rule definitions are also included in
{{content-vocabulary-tables}} so implementing the rules does not depend on
access to a private repository, a service, or a moving branch.

A recipient MUST select a supported table by the exact digest from the
verified content header. It MUST NOT select by display version alone, by a
recognized fact name, by an unbound header, or by a default. An unknown
digest is unsupported even when the content membership itself verifies.
Compiled tables MAY be used when they reproduce the specified rules for
that exact digest. A recipient need not fetch a vocabulary at run time.

The selected table governs all fact-dependent operations: name support,
party/basis classification, forbidden pairs, typed values, implicit units,
evidence requirements, remote-origin metadata, and required-name support.
Each block in a mixed presentation MUST select independently. A later table
MUST NOT reinterpret an earlier commitment.

The /1 table has 46 facts. The /2 table retains their rule definitions and
adds `site.pose`. The existing /1 digest identifies the spelling-migrated
table reproduced by the implementation; another historical file sharing
its display version does not acquire this digest's meaning.

### Attribution categories and permitted relation {#content-attribution}

`assertedBy` records a provenance category claimed in the fact; it is not
a party-specific signature, credential, or authentication mechanism.
The seven category labels and their global bases are:

| Category | Global permitted bases |
|---|---|
| `appliance-measured` | `measured`, `estimated` |
| `robot-attributed` | `measured`, `estimated`, `declared` |
| `operator-entered` | `estimated`, `declared` |
| `platform-recorded` | `measured`, `declared` |
| `site-policy` | `declared` |
| `manufacturer-declared` | `declared` |
| `undetermined` | `estimated`, `declared` |

The three basis values are exactly `measured`, `estimated`, and `declared`.
Their presence is the Issuer's recorded claim; neither a plausible label
nor a permitted combination establishes how the value was obtained.
In particular, `robot-attributed` MUST NOT be reported as robot-signed.
A manufacturer-declared limit and a robot-attributed limit remain different
recorded provenance even when both are permitted and both are declared.

For a known fact, known party and known basis, the combination is permitted
if and only if all of the following hold: the row admits the party, the row
admits the basis, the party's global list admits that basis, and the pair is
not in the row's `pairsForbidden`. No row overrides a global exclusion.
Unknown fact, party and basis are distinct unsupported classifications,
not a known forbidden attribution.

This relation classifies provenance choices only. Typed-value failures,
missing required evidence, malformed references, unit failures, resource
failures, and origin-metadata failures remain separate findings and MUST NOT
be erased by a permitted relation.

### Value dialect and additional metadata {#content-value-dialect}

The row schemas use the following finite dialect; they are not a claim to
implement a general JSON Schema vocabulary.

* `type` is one of `boolean`, `integer`, `string`, `object`, or
  `map-of-integer`.
* `nullable: true` admits JSON null; otherwise null is invalid. It does not
  make the containing member optional.
* Integer values have no fractional/exponent interpretation at the typed
  layer, use signed 64-bit bounds, and obey inclusive `minimum` and
  `maximum` where present. The narrower canonical-content number domain
  above still applies to committed records.
* String `enum` compares exact decoded text, without case folding or
  Unicode normalization. `maxLength` counts Unicode scalar values.
* The only patterns are a nonempty ASCII identifier consisting of letters,
  digits, colon, underscore, dot and hyphen; the lowercase `sha256:` digest
  spelling; and the fixed 24-character millisecond-UTC textual shape.
  The last is a lexical check, not a calendar or clock check.
* An `object` has the named `properties` and `required` members in its row.
  Unknown properties remain permitted unless the /2 row explicitly has
  `additionalProperties: false`. Present known properties are checked
  recursively. `map-of-integer` requires all member values to be integers.
* Object/map width is at most 256 and recursive schema-value evaluation
  has root-zero depth at most eight in this bounded dialect.

An implementation interpreting a /2 rule definition MUST NOT treat an
unrecognized schema keyword, an invalid keyword type or combination, or an
unsupported pattern as satisfied. It MUST report the rule definition as
unsupported or invalid, as applicable, rather than silently ignore it.
Rejecting such definitions during code generation is one way to enforce
this requirement. This does not retrospectively change /1's generation
recipe or its open object behavior. The exact schemas in {{content-vocabulary-tables}} are
the supported definitions; arbitrary schema extensions require a separately
specified vocabulary.

The row's `unit` supplies the semantic unit even when an optional fact-level
`unit` member is omitted. If supplied, that member MUST be the matching unit
string, or null only where the row is unitless. Malformed types or a different
unit MUST remain invalid. Omission does not promote a unit-bearing fact into
a unitless comparison.

`remoteOrigin` is control-origin metadata, with values `on-site`, `off-site`,
and `undetermined`. It is REQUIRED exactly for rows marked required and is
forbidden, including explicit null, elsewhere. The tag does not authenticate
acquisition location or source identity.

### Position observations (`site.pose`) {#site-pose}

#### Meaning and optionality

The `site.pose` fact represents one position observation of one site-declared reference point from one source sample. Despite the fact name, this representation does not include orientation, heading, speed, trajectory, or an orbital ephemeris.

Presence of `site.pose` is not a universal requirement for a receipt or for every mobile site. A separately supplied disclosure policy can require its presentation. The policy's origin and authority are separate from whether its stated disclosure requirements have been met.

The fact is retained and disclosed through the content-block mechanism. A witness signature that binds the content commitment binds the recorded observation and its attribution to that statement. It does not establish that the site occupied that position, that the named party produced the observation, or that the measurement is accurate.

One `site.pose` record is permitted per block under the existing unique-fact-name rule. This vocabulary entry does not define a time series.

#### Value representation

The `value` MUST be a closed object containing all eight members below.
Additional members MUST produce an invalid-typed-value finding; they MUST NOT
be removed or rewritten to make the value pass. Only the three explicitly
nullable members MAY be JSON `null`.

| Member | Type and admitted values | Meaning |
|---|---|---|
| `crs` | String, exactly `EPSG:4979` ({{EPSG4979}}) | Identifies the coordinate reference used by this scaled encoding. |
| `referencePoint` | String, 1–64 characters matching `^[A-Za-z0-9:_.-]+$` | The site-declared point actually positioned by the source. |
| `latE7` | Integer, -900000000 through 900000000 inclusive | Geodetic latitude in units of 10^-7 degree. |
| `lonE7` | Integer, -1800000000 through 1799999999 inclusive | Geodetic longitude in units of 10^-7 degree; the representation uses -180 degrees rather than +180 degrees. |
| `heightMm` | Integer, -20000000 through 100000000 inclusive, or `null` | Ellipsoidal height in millimetres, or no ellipsoidal height asserted. |
| `horizontalAccuracyMm` | Integer, 0 through 100000000 inclusive, or `null` | The coherent source sample's reported accuracy figure, or no such figure asserted. |
| `observedAt` | Millisecond-UTC string of the specified 24-character shape, or `null` | Source-reported sample instant, or no source instant asserted in this member. |
| `latLonDerivation` | String, `exact-integer-rescaling` or `rounded-half-even-to-1e-7-deg` | The stated preparation of the horizontal pair only. |

The coordinate meaning is latitude = `latE7 / 10^7` degrees, longitude = `lonE7 / 10^7` degrees, and, for non-null height, ellipsoidal height = `heightMm / 1000` metres. This is a scaled encoding referencing the coordinate system, not a change to its units. The row supplies neither a datum realization nor a coordinate transformation.

Null height means that height is not asserted. It does not mean zero, a complete three-dimensional observation, or a conversion to another coordinate system. Sea-level, chart-datum, or geoid-relative height is not interchangeable with ellipsoidal height.

The height and accuracy ranges are selected support limits for this row, not universal physical or geodetic validity rules. Integer resolution does not establish physical accuracy. Literal zero is a value wherever admitted. The string `unknown` is not a replacement for `null`. A null member inside a disclosed `site.pose` value is distinct from a null content commitment (no content root bound by this statement), from a withheld fact, from a name the block's vocabulary does not support, and from a fact absent from a complete block.

The definition of `referencePoint` belongs in the retained envelope document. This row does not require or implement resolution of that definition by the current recipient.

The accuracy figure's confidence level and metric are unspecified. The figure does not establish a verified radius, a 95-percent bound, cross-source comparability, or an automatic policy result. Preserve its source meaning in evidence; do not invent confidence metadata.

#### Preparation obligations and what the checker can establish

All populated components MUST describe one coherent source sample and reference point. An unrelated accuracy sample does not supply the accuracy of this position. A different reference point is not substituted without an explicitly described transformation; no such transformation is introduced here.

Before commitment, the producer MUST process horizontal source values in exact decimal arithmetic. Source latitude outside [-90, 90] degrees or longitude outside [-180, 180] degrees is rejected rather than clamped. Multiply each by 10^7. If both products are integers, use `exact-integer-rescaling`; otherwise round the horizontal pair by round-half-even, including negative ties, and use `rounded-half-even-to-1e-7-deg`. Write a rounded zero as canonical `0`; encode +180 degrees as -180 degrees. Verification does not repeat these transformations on presented fact bytes.

A coherent populated height or accuracy value MUST rescale exactly to integer millimetres and lie inside the row's supported range. For example, 12.345 m and 12.3450 m both yield 12345 mm exactly. A coherent known 12.3456 m value, or a coherent value outside the supported range, is not rounded, clamped, or silently reclassified as missing, and the producer MUST NOT emit that candidate `site.pose`. It MUST retain the raw source and record the not-representable condition in its acquisition or mapping record. Actual missing information, a different-datum height, or an incoherent accuracy sample is different and does not supply the member being asserted.

The producer MUST NOT default `observedAt` from the receipt's asserted sealing time, local acquisition time, or registration time. A source instant exactly expressible in UTC milliseconds can be represented without loss, including whole seconds as `.000` and an equivalent `.123000` fraction as `.123`. Nonzero sub-millisecond precision, unknown offset, or an unapplied non-UTC time scale is not silently rounded or truncated: use `null` and retain the original time and the reason outside that member. This does not assert that the source lacked a timestamp.

The admitted lexical shape is `YYYY-MM-DDTHH:MM:SS.mmmZ`. The current implementation checks this shape, not calendar validity or real-world clock correspondence. A string matching the pattern can still denote an impossible date or time.

These preparation and coherence rules are producer obligations in the proposed contract. The accepted implementation validates the resulting representation; it does not contain a navigation-source converter, a calendar validator, or a check that the claimed transformation actually occurred. Do not report those absent checks as executed functionality.

#### Attribution, evidence, and control-origin metadata

The following four party/basis pairs are admitted:

| `assertedBy` | Permitted `basis` |
|---|---|
| `appliance-measured` | `measured`, `estimated` |
| `platform-recorded` | `measured` |
| `operator-entered` | `declared` |

The other seventeen combinations of the seven existing parties and three bases are forbidden for this fact. In particular, platform-estimated is a forbidden known combination, not an unknown-vocabulary result. These restrictions do not widen any global rule.

The row's optional evidence setting does not waive the global evidence-reference requirement for `appliance-measured`. A supplied reference, available object, matching raw-byte digest, compared value, and authenticated party are separate findings.

The existing fact-level `remoteOrigin` member MUST NOT appear on `site.pose`, including with a null value. This prohibition concerns that control-origin tag. It does not establish on-site acquisition and does not forbid retaining off-site navigation evidence. Acquisition origin remains in the retained evidence or mapping record; this row adds no new signed acquisition-origin member.

#### Vocabulary selection and recipient reporting

The exact vocabulary digest in the proof-bound content header selects the supported rule table. A version label, fact name, unbound header, or caller hint is not a substitute for that digest. Unknown digests do not fall back to the older table.

The selected table governs all fact-dependent checks: party/basis rules, value schema, evidence requirements, origin metadata, implicit units, and the support of required fact names. Blocks in a mixed presentation are evaluated using their own committed vocabularies. Existing v1 semantics and commitments remain unchanged.

The reference implementation accepts a policy name recognized by either supported vocabulary, then determines support within each block. A name unknown to both remains an unsupported policy configuration. The following availability findings are distinct:

| Situation | Reference-implementation result |
|---|---|
| Required `site.pose` under a proved v1 block | `UNSUPPORTED_BY_VOCABULARY`; not policy satisfaction, not a claim of absence, not a forbidden attribution; the disclosure-policy result remains unestablished. |
| Required pose not disclosed by a v2 subset | `NOT_DISCLOSED_UNPROVEN`. |
| Pose absent from all slots of a complete v2 block | `ABSENT_FROM_COMMITTED_BLOCK`; no claim about physical-world absence. |
| Unknown vocabulary digest after valid membership | Vocabulary support is `Unsupported`; required-name availability is `NOT_EVALUATED`. An unbound header leaves table-dependent checks unevaluated. No table is chosen by label, fact name, or default. |
| Null commitment | Presentation is `NULL_COMMITMENT`; a requested fact is `NO_BLOCK_COMMITTED`. This statement binds no root; it does not prove that no uncommitted block existed. |
| Non-null commitment, block not presented | Presentation is `NOT_PRESENTED`; a requested fact is `COMMITTED_BLOCK_NOT_PRESENTED`. The unbound header does not select a vocabulary. |

A verified membership proof does not make an invalid value or forbidden attribution valid. A correctly matched evidence object does not become a verified position: the supported root-scalar comparator cannot compare a compound position object. Comparison enabled can therefore produce `NOT_COMPARABLE`; comparison disabled remains `NOT_RUN`.

A satisfied disclosure policy does not erase contradictory evidence, metadata failures, forbidden attributions, or unavailable trust inputs. It is not application acceptance.

## Evidence references and value comparison {#content-evidence}

A fact's evidence member, when non-null and present, MUST be an object
containing exactly one of:

~~~ json
{"digest":"sha256:<64 lowercase hexadecimal digits>"}
~~~
{: #content-evidence-digest-fragment}

or

~~~ json
{"pointer":"<nonempty locator of at most 2048 UTF-8 octets>"}
~~~
{: #content-evidence-pointer-fragment}

The angle-bracketed strings above describe placeholders, not valid literal
digest instances. The two members MUST NOT be combined in the same reference
under this vocabulary. Absent or null evidence means no reference is given.

A reference is REQUIRED if the row requires evidence OR the party is
`appliance-measured` or `robot-attributed`. A row marked optional does not
waive that global rule. A pointer can satisfy the reference-shape requirement
while still supplying no immutable byte-integrity binding.

To check evidence integrity, the expected digest MUST come from the proved
fact, not from the supplied object's own label or from hashing that same
object and treating the answer as an independent expectation. The recipient
hashes original supplied bytes with SHA-256. It MUST NOT normalize JSON,
transcode text, trim whitespace, or rewrite a numeric token before that hash.

Acquisition and integrity are separate: not requested, unavailable, and
present zero-length bytes are different states. A pointer alone, a returned
HTTP body, a matching filename, or a successful retrieval MUST NOT be
reported as a digest match. Any implementation that fetches data must define
its retrieval authorization, limits, and trust assumptions separately; the
local implementation here does not fetch.

The local digest-keyed evidence inventory rejects duplicate digest keys
rather than selecting the first or last copy, including identical duplicate
bytes or mixed availability declarations. Malformed inventory data MUST NOT
be converted into an apparently weaker but successful attribution-only
finding.

A recipient performing value comparison MUST identify the comparison rule,
its required inputs, and the result independently of byte integrity. It MUST
report a detected contradiction, and MUST NOT treat unsupported comparison
as agreement. A matching digest does not establish relevance, truthful
content, authentic origin, or consistency with the sealed fact value.

### Bounded unitless scalar comparison {#content-scalar-comparison}

The local reference comparator is
`json-root-unitless-scalar-exact/1`. Invoking it is an explicit policy choice,
not an assertion that every vocabulary row has this evidence encoding.

This comparator runs only after a raw digest match and after applicable fact
metadata checks. It supports a complete JSON root Boolean, text string, or
exact signed/unsigned 64-bit integer, with no unit. It does not select a
property from an object, transform units, compare a compound pose, infer
numeric types from strings, or normalize Unicode.

For this comparator, matching supported types and equal values give `MATCH`;
different values of the same supported type give `CONTRADICTION`. Unsupported
types, units, or type mismatch give `NOT_COMPARABLE`. A disabled comparison or
failed prerequisite gives `NOT_RUN`. Original integer-token `-0` is compared
as zero after syntax validation and after hashing its original bytes; `-0.0`,
fractional and exponent tokens do not become supported integers. JSON permits
only its defined surrounding whitespace; invalid syntax remains not comparable.

These comparator-specific constraints do not redefine the content
canonicalization rules. A raw evidence object can have a different spelling
from the recorded value; equal semantic values do not excuse a wrong raw
digest.

## Recipient results and disclosure policy {#content-recipient}

A recipient MUST retain separate outcomes for statement inspection, content
membership, vocabulary support, attribution/basis classification, typed
metadata, evidence integrity, value comparison, requested-fact availability,
and selected disclosure policy. There is no mandated universal `valid` or
`accepted` Boolean. A relying party MAY reach an application decision, but
MUST identify its policy and additional trust assumptions rather than
present that decision as the output of a narrower cryptographic check.

The reference implementation retains its existing inspection dimension:
`Passed`, `Failed`, `Unsupported`, `Unestablished`, and `NotEvaluated`.
Its content-fact provenance dimension is separate:

| Provenance finding | Meaning |
|---|---|
| `EVIDENCE_LINKED` | A permitted, well-formed committed fact has matching original evidence bytes. This may coexist with a value contradiction. |
| `ATTRIBUTION_ONLY` | The permitted committed attribution lacks checked evidence bytes; the separately recorded reason remains visible. |
| `ATTRIBUTION_FORBIDDEN` | The known fact/party/basis combination violates its selected rule relation. Other adverse findings remain visible too. |
| `FACT_UNAVAILABLE` | The requested-fact result lacks a disclosed fact under its particular availability conditions; the precise availability reason controls its meaning. |

An absent provenance classification is also meaningful. Unknown rules,
malformed metadata, bad integrity or inventory, and unmet prerequisites
MUST NOT be forced into `ATTRIBUTION_ONLY` or a physical absence claim merely
to populate this dimension.

The recipient obtains its expected root from the checked statement and
verifies the presentation before applying a vocabulary. When any disclosure
invalidates that presentation, it MUST NOT return a partially successful
set of statement-bound fact reports. Independently known statement or framing
results MAY remain visible.

A disclosure policy can require content, all committed slots, or named facts.
A requested name recognized by some implemented vocabulary but absent from
the selected block's vocabulary is unsupported for that block; it is not
a globally malformed policy and MUST NOT be silently satisfied. Names unknown
to every implemented table can be rejected as unsupported configuration.
With mixed-vocabulary input, support is decided per block.

The following distinctions MUST remain observable:

| Situation | Meaning |
|---|---|
| Null commitment | No root bound by this checked statement; no assertion about uncommitted material. |
| Non-null commitment, no usable disclosure | Committed content not presented; do not infer the hidden count or facts. |
| Known-vocabulary subset omits a requested fact | Nondisclosure; absence is unproven. |
| All committed slots under a supported vocabulary omit a requested fact | Absence from this particular committed block only. |
| Required name not defined by the proved vocabulary | Unsupported by that vocabulary, not forbidden attribution or proven absence. |
| Unknown vocabulary digest | Vocabulary unsupported; table-dependent required-name evaluation not evaluated. |
| Malformed disclosure or invalid proof | Invalid/unsupported presentation as applicable, not missing content. |
| Matching empty-block root | A proved empty committed block, not null. |

Meeting disclosure requirements MUST NOT erase forbidden attribution, invalid
metadata, integrity failure, value contradiction, or missing trust inputs.
It does not establish semantic completeness or application acceptance.

## Custody, concealment, and history {#content-custody}

The Site Owner is responsible for arranging retention and authorized retrieval
of the committed records, salts, disclosure material, vocabulary artifacts,
and referenced evidence needed for later examination. Storage MAY be delegated;
delegation does not itself establish accessibility or change the declared
custody responsibility. The applicable site policy SHOULD state retention,
access, and deletion arrangements. This profile defines no universal retention
period and grants no recipient a right to disclose private material.

Loss, refusal, or inability to retrieve committed content MUST remain an
availability finding. It MUST NOT be translated into null, rewritten into a
different block under the original root, or described as proof that no fact
existed. A malicious or compromised Issuer can sign null or omit a fact before
commitment. Requiring content through policy helps detect policy nonfulfilment;
it does not prove complete observation.

For two or more statements presented as one chain, the existing
Chain-Verifier rules apply: check adjacent sequence numbers and predecessor
hashes in the presented order and retain affiliation changes at the affected
records. This section introduces no replacement chain algorithm. Reordering,
deduplicating, or filling missing entries MUST NOT be hidden as verification.

A valid presented prefix does not prove latest or complete history. The
content root adds neither a trusted closing head nor evidence that a later
statement or event was not withheld. Reusing a block in two correctly signed
contexts is not prevented by membership. A context comparison checks the
provided signed labels against caller expectations; it does not authenticate
their origin or prove same-site continuity.

## Local replay implementation profile (informative) {#local-replay}

The reference workflow uses `pask-local-recipient-replay/1`, a local JSON
container with entries holding original statement/fact/evidence bytes encoded
as lowercase hexadecimal. Its supplied verification key is external to the
document. Policy and expected context remain explicitly supplied, unauthenticated
inputs. This container and its report schema are implementation interfaces, not
new COSE parameters, SCITT media types, or mandated network protocols.

SINGLE mode requires one entry and leaves chain contiguity unevaluated.
CHAIN mode verifies its entries under the supplied Ed25519 key, then checks the
presented sequence through the existing chain helper, including the selected
genesis-at-zero requirement. A valid singleton genesis is accepted in that
explicit mode. The workflow guards sequence overflow and neither sorts nor
fills the presentation. It retains per-statement content findings separately
from its chain result. It does not check a common site identity merely because
the links pass.

The executable uses exit zero to mean that a report was produced, not that
every finding passed. Invocation, input/framing/resource, key, and ordinary
I/O failures use exit two. A successful report can contain failed membership,
contradiction, or unsupported rules. The tested output-failure behavior does
not cover arbitrary panics, signals, blocking devices, or allocation failure.

The reference limits include 8 MiB of raw replay JSON, depth 32, 16 entries,
and 3 MiB of decoded binary material. Per-entry local evidence is limited to
256 objects, 64 KiB per object and 1 MiB in aggregate. That inventory can induce
up to 16 MiB of repeated evidence hashing per entry and up to 256 MiB per
16-entry batch. Decoded size is not total allocation or work. These are
implementation operating bounds, not a production performance guarantee.

The local replay does not validate attached SCITT Receipts, appraise hardware,
authenticate keys or policies, locate a signing key, or make an application
decision. The separately implemented Receipt-verification coordinator is not
silently invoked by this workflow.

# SCITT registration and Receipt attachment {#scitt-registration}

A Physical-Site Engagement Receipt Signed Statement is registered with a
SCITT Transparency Service per {{RFC9943}} Section 6.3. The TS applies its
Registration Policy against the protected header (in particular `iss`, `sub`,
and `content_type`) before registering.

Upon successful registration, the TS returns a Receipt as defined in
{{RFC9942}}. The Receipt is attached to the Signed Statement's unprotected
header as an element of the `receipts` array (CBOR label 394), producing a
SCITT Transparent Statement per {{RFC9943}} Section 7.

The same Signed Statement MAY be registered in multiple Transparency Services
and MAY carry multiple attached Receipts, one per Transparency Service, per
{{RFC9943}} Section 6.3.

Registration is mandatory in this profile. An Issuer MUST register every
Physical-Site Engagement Receipt it issues with at least one Transparency
Service. A relying party MUST NOT accept a Physical-Site Engagement Receipt
as conforming to this profile unless at least one attached Receipt from a
Transparency Service that relying party trusts verifies per {{RFC9942}}.
Verifying an attached Receipt does not demonstrate that the Issuer registered
every receipt it issued; a relying party that requires that assurance MUST
obtain it from the Transparency Service's own audit and consistency
mechanisms, not from an individual attached Receipt.

Requiring registration does not require a relying party to be online when it
verifies. An attached Receipt is a Verifiable Data Structure Proof per
{{RFC9942}}, checkable from the presented bytes together with the
Transparency Service's verification key, both of which MAY be held locally.
The offline-verifiable property stated in {{terminology}} is preserved: what
registration adds is a reference obtained before verification, not a network
dependency during it. This revision defines no conforming mode of
operation in which no Transparency Service is reachable at issuance time.

This revision specifies the candidate-entry byte encoding for inclusion-proof
verification. For this profile, the presented object MUST be a COSE_Sign1 with
four array elements: protected-header byte string, unprotected-header map,
attached-payload byte string, and signature byte string. The payload MUST be
present as a byte string; a null payload indicating detached content is not
permitted. The input may be an untagged COSE_Sign1 or a COSE_Sign1 wrapped
in tag 18. Other tag wrappers are not accepted by this derivation.

The verifier derives the candidate entry as the untagged four-element array
`[P, {}, M, S]`, where P, M, and S are the original protected-header, payload,
and signature byte-string contents. The candidate entry MUST use the core
deterministic encoding requirements of {{RFC8949}}, Section 4.2.1, for the
outer array, empty map, and byte-string framing. The contents of P, M, and S
are preserved unchanged; this requirement does not instruct the verifier to
parse and reserialize those contents. The outer array is definite-length, the
empty map is encoded as `0xa0`, and the three byte strings use the shortest
definite-length encodings of their lengths.

This derivation MUST preserve P, M, and S by content. It MUST NOT parse and
reserialize their contents to construct the candidate entry. The original
outer CBOR length encodings and any permitted outer tag are not preserved.
These derivation rules do not waive separate COSE header, signature, payload,
or profile validation. Parsing a header for validation is distinct from
rewriting its bytes for hashing. This follows RFC 9943 Section 6.3, which
requires the unprotected header of a Signed Statement to be set to an empty
map before inclusion in the Statement Sequence.

Transmitted envelopes use COSE tag 18 ({{RFC9052}}), and attached receipts are
encoded as byte strings containing tagged Receipt objects per {{RFC9942}}
Section 4.3. The untagged candidate entry is a profile-internal representation
used for hashing; it is not the transmitted wire form. A Transparency Service
that hashes a different representation (for example, the tag-18 form) cannot
satisfy this profile unless it commits to the candidate-entry representation
specified here. This is the profile imposing a requirement on a party it does
not control: an existing TS that hashes the tagged form cannot satisfy the
profile without adaptation.

A Transparency Service used to satisfy this profile's inclusion requirement
MUST issue a Receipt whose inclusion proof commits to the candidate-entry
representation specified in this section. The applicable registration path
and the verifier MUST use the same derivation and serialization rule.
Emptying the unprotected map alone does not establish agreement on the
remaining serialized bytes. The service's internal storage format is not
prescribed, but the candidate-entry bytes against which its proof verifies
are prescribed. Registration and verification alignment MUST be demonstrated
by byte-exact fixtures, including derivation from the presented Transparent
Statement without access to retained producer-side bytes.

Attaching, removing, or modifying receipts in the unprotected header does
not change the candidate entry: `candidate_entry(S) ==
candidate_entry(attach_receipt(S, R))` for any receipt R. This is the
property that makes inclusion proofs portable: the proof covers the
registered statement, not whatever receipts happen to be attached to it at
verification time.

The profile's inclusion requirement is satisfied only when at least one
attached Receipt has both a valid Transparency Service signature under an
accepted service key and a valid inclusion proof for the derived candidate
entry. A Receipt that is invalid, unsupported, or associated with an
untrusted service does not count toward that requirement. A structurally
parseable additional Receipt whose cryptographic verification fails MUST NOT,
solely by its presence, defeat another attached Receipt that satisfies the
inclusion requirement. A separately identified local policy may impose
stricter acceptance conditions. This rule does not relax validation of the
enclosing COSE structure or malformed attachment containers. Receipt
signature verification, inclusion-proof verification, and issuer-signature
verification are separate checks. Satisfying the inclusion requirement does
not establish full PSER conformance; every other applicable profile
requirement still applies. An absent proof and an invalid, unsupported, or
untrusted proof are not reported as successful inclusion.

For `RFC9162_SHA256`, the leaf hash is
`SHA256(0x00 || candidate_entry)`, using the leaf construction in
{{RFC9162}}, Section 2.1.1. Receipt representation and verification follow
the applicable `RFC9162_SHA256` procedures in {{RFC9942}}. This formula is
not applied by default to another or unknown VDS. Verification of another
supported VDS uses that VDS's specified procedure. This paragraph does not
add a PSER-wide prohibition on other SCITT VDS types. The current reference
implementation's support is limited to RFC9162_SHA256; unsupported VDS
values are reported as unsupported and cannot count as successfully verified
evidence.

This specification does not prescribe how a Transparency Service stores the
entry internally. Interoperability requires only that the inclusion proof
verifies when the verifier uses the candidate entry derived from the
presented Transparent Statement.

## Registration with an affiliated Transparency Service

An Issuer MAY register with a Transparency Service it operates itself, or
that is operated by a principal affiliated with it. Where it does so, the
Issuer MUST disclose that relationship as an Issuer-published fact resolved
under {{issuer-published}}, and a relying party MUST NOT treat such a
registration as evidence obtained from outside the Issuer for the purposes of
{{security}}. Where the disclosure does not resolve, the standing of the
registration is **undetermined**; a Verifier MUST NOT resolve it to the
unaffiliated case, which is the Issuer-favourable one. That obligation is separate from the
`issuerAffiliation` member of Section 4.1, which states the relationship
between the Issuer and the Site Owner rather than between the Issuer and the
Transparency Service; neither can be inferred from the other.

Registration with a Transparency Service operated by an unaffiliated principal
is the only case in which an
attached Receipt supplies a reference external to the party whose
completeness is in question. This profile does not prohibit the affiliated
case, because a self-operated Transparency Service still binds the Issuer to
a consistent published history and still admits third-party auditing; it
requires that the weaker standing of that case be visible rather than
implied.

# IANA considerations {#iana}

This document requests the following IANA actions.

## Media type registration

Register `application/pser+json` per {{RFC6838}}, with the required
`profile` parameter identifying the applicable PSER profile version.
This document specifies the value `wilder.pser/0.7`. The values
`wilder.pser/0.5` and `wilder.pser/0.6` identify the earlier profiles and retain
their requirements. Unsupported values do not become supported by looking
like a version number.

A version-shaped value does not by itself identify a supported profile.
Unknown or unsupported values are reported as unsupported and are not
interpreted using the rules of another version.

## COSE Header Parameters

This document does not register new COSE header parameter labels. It uses
only labels defined in {{RFC9052}}, {{RFC9597}}, and {{RFC9943}}.

## Content vocabulary identifiers

No new IANA registration is requested for the content construction,
document-defined fact names, or vocabulary labels in this revision. The
exact digest dispatch and closed rule definitions are specified in
{{content-vocab}} and {{content-vocabulary-tables}}. They create no
uncontrolled registry or wildcard interpretation rule.

## New IANA registries

This document requests the establishment of the following registries under a
new "SCITT Physical-Site Engagement Receipt Profile" registry group, with
policy "Specification Required":

1. *Site Class* -- values of `site.class`.
   Initial values: `residential`, `industrial`, `healthcare`, `infra`,
   `other`.

2. *Engagement Type* -- values of `engagement.type`.
   Initial values: `patrol`, `service`, `inspection`, `delivery`,
   `installation`, `maintenance`, `presence`.

3. *TEE Class* -- values of `attestation.teeClass`.
   Initial values: `intel.tdx`, `amd.sev-snp`, `arm.cca`,
   `nvidia.h100-cc`, `nvidia.jetson-thor-cc`, `aws.nitro-enclave`.

   These descriptions identify the environments named by the existing
   values. They do not, by themselves, define a complete evidence-format
   binding or establish implementation support.

   - `intel.tdx`: Intel Trust Domain Extensions, a VM-level isolation
     primitive.
   - `amd.sev-snp`: AMD Secure Encrypted Virtualization with Secure Nested
     Paging, a VM-level isolation primitive.
   - `arm.cca`: Arm Confidential Compute Architecture, a hardware
     isolation framework.
   - `nvidia.h100-cc`: NVIDIA H100 in Confidential Computing mode, a
     device-level isolation primitive.
   - `nvidia.jetson-thor-cc`: existing product-named identifier associated
     with NVIDIA Jetson Thor. Retained provisionally and unchanged; this
     profile does not establish the exact confidential-compute capability,
     evidence format, or appraisal binding represented by this value.
   - `aws.nitro-enclave`: AWS Nitro Enclave, a cloud-provider isolation
     primitive.

   A confidential-compute environment absent from the admissible set is not
   conforming and is not silently folded into an existing value. The
   registry is the route by which one becomes conforming, and its
   governance is stated above. This revision clarifies existing identifiers
   with descriptive context. It does not add, remove, or rename any value,
   and it does not resolve the evidence-format question for any value.

4. *Sealed Evidence Encoding* -- values of
   `attestation.sealedEvidence.encoding`.
   Initial values: `opaque/1`.

5. *Operations-Layer System* -- values of `adapter.system`. New values
   follow a `vendor.product` lowercase snake_case naming convention.

# Security considerations {#security}

## What this profile does NOT attest

Per {{intro}} and the NORMATIVE non-goals stated there, a Physical-Site
Engagement Receipt does NOT attest that:

- The engagement was safe, correct, effective, or compliant with any
  specific regulation.
- The site conditions were as recorded.
- No unrecorded engagement occurred outside the instrumented boundary.
- The operations layer targeted by the Adapter Write-In will use, act on,
  or preserve the receipt correctly.

Relying parties MUST NOT infer these claims from a receipt.

## Equivocation and tail-truncation {#equivocation}

The `chain` field defined in {{payload}} makes *in-band tampering*
detectable: modification, substitution, reordering, or omission of receipts
interior to a presented chain breaks a `chain.prevHash` link, `chain.seq`
contiguity, or a signature. This property holds against parties that do not
hold the Issuer's signing key. An Issuer that holds the key can sign an
alternative, internally consistent chain omitting receipts at any position.

The `chain` field does NOT detect *tail truncation* -- the withholding of the
most recent receipts -- in any presentation. A truncated chain is internally
consistent at every link, and no property of the presented bytes reveals the
withholding, because no receipt commits to a successor that did not exist
when it was signed. This is not a limitation of the hash or signature
algorithms: the presented bytes are identical whether or not a suffix exists.
The `chain` field likewise does NOT detect *equivocation*, in which an Issuer
signs two divergent chains for the same Subject.

Detecting either condition REQUIRES evidence obtained from outside the
presentation. Registration of a Signed Statement in a SCITT Transparency
Service {{RFC9943}} supplies such evidence to relying parties and auditors
that check against that Service. Registration does not by itself establish
completeness: a conforming Transparency Service does not compel an Issuer to
register every Signed Statement it issues ({{RFC9943}}, Section 9.3), and a
Receipt proves the inclusion of one Signed Statement rather than the absence
of others ({{RFC9942}}). A Transparency Service therefore does not detect
these conditions itself; it supplies the reference against which other
parties can.

A relying party that retains the highest `chain.seq` receipt it has verified
for a chain holds such a reference. A later presentation whose head precedes
that receipt, or which presents a different `chain.hash` at that `chain.seq`,
is evidence of truncation or equivocation relative to it. Relying parties
SHOULD retain these anchors. Detection reaches only as far as the anchor's
own age: a presentation ending after the retained anchor is not thereby shown
to be complete, and a presentation ending before it is not by itself proof of
misbehaviour, since it may be an earlier honest observation.

This profile does not define what a relying party does upon detecting such a
mismatch, how long anchors are retained, or what evidentiary weight a
mismatch carries. Those are matters for the relying party's own policy. A
relying party that reproduces this section in a contract, underwriting rule,
or adjudication SHOULD state its own remedy; this document supplies a
detection property, not a remedy.

## Corrective statements {#correction-security}

This revision does not define an interoperable corrective-statement wire format
or impose correction-related requirements on 0.5, 0.6, or 0.7 conformance. An
informative corrective-statement design is recorded in {{correction-envelope}}
for discussion. A correction does not reset the original's
`attestation.validity` interval. Conflicting corrections are surfaced, not
resolved. No automatic winning history is computed.

## Adapter Write-In is write-only in this revision

The Adapter Write-In records that the receipt was posted into an operations
layer. It does NOT permit the operations layer to write back into the
receipt or the TEE. The `adapter.mode` field is fixed to `WRITE_ONLY` in
this revision; a future revision MAY define a `WRITE_READ` mode with
additional security machinery. Implementations that reverse this direction
in a way that permits the operations layer to modify Issuer or TEE state
are NOT conforming to this profile.

## TEE compromise {#tee-compromise}

A compromised TEE can produce receipts that are cryptographically valid
under this profile but describe engagements that did not occur or did not
occur as described. Detection of TEE compromise is out of scope of this
profile and depends on the platform-native attestation supply chain
identified by `attestation.teeClass`. Relying parties SHOULD consult
{{RFC9943}} Section 9 for guidance on Issuer participation and key
management, and the TEE vendor's own security guidance for the specific
`teeClass`.

## Witness key lifecycle {#key-lifecycle}

A witness key signs inside a TEE that is physically hosted at a Site the
Issuer may not control. The parties that can act on a suspected compromise of
such a key are therefore not the same as those that can act on a compromise of
a key the signer holds itself, and this document states which party may make
which assertion. This revision addresses assertions about a **specific witness
key**. Compromise of a TEE class or platform is addressed in {{tee-compromise}}
and is not a key lifecycle event under this section.

### The two assertion classes {#assertion-classes}

This document defines two distinct assertions about a witness key. They are
named rather than numbered so that a later revision may define a third without
redefining either.

- **Cessation.** An assertion that the identified witness key MUST NOT be
  relied upon to produce further receipts. Cessation is forward-looking only.
- **Retroactive impeachment.** An assertion that receipts already produced by
  the identified witness key SHOULD NOT be relied upon, in whole or over a
  stated interval. Retroactive impeachment reaches backward, and it is the
  stronger of the two.

Authority over each is asymmetric, and the asymmetry follows the capabilities
the trust model already grants in {{trust-model}}:

- **Cessation MAY be asserted by the Site Owner or by the Issuer,
  independently of one another.** Neither party requires the other's
  concurrence. This grants no new capability: the Site Owner can already stop
  production of receipts by powering the hardware off or refusing to host it
  ({{trust-model}}), and an explicit cessation assertion only makes that
  existing capability legible to a relying party instead of leaving it to be
  inferred from an absence of receipts.
- **Retroactive impeachment MAY be asserted by the Issuer only.** The Site
  Owner controls whether receipts are produced but not their content
  ({{trust-model}}), and an impeachment is an assertion about content that has
  already been produced and registered. Extending it to the Site Owner would
  grant a party with no authorship capability an authority over authored
  records that the trust model deliberately withholds.

### Scope by attestation-binding mode

The two classes apply in both attestation-binding modes of
{{attestation-binding}}, and mean different things in each. An implementation
MUST determine the mode before interpreting an assertion.

- In **direct-witness mode**, `attestation.witnessKey` matches `iss`, so both
  classes concern a single key and the Site Owner's cessation authority and the
  Issuer's impeachment authority attach to the same key material.
- In **delegated-witness mode**, `attestation.witnessKey` is distinct from
  `iss`. An assertion MUST identify the key it covers. An assertion covering
  the TEE signing key does not, by itself, assert anything about the Issuer's
  `iss` key, and an assertion covering `iss` does not, by itself, assert
  anything about the TEE signing key. A Verifier MUST NOT extend either to the
  other, and MUST NOT treat an assertion whose covered key cannot be
  determined as covering both.

### Verifier behaviour {#assertion-verifier}

Neither assertion deletes, invalidates, or suppresses a registered receipt.
Registration is append-only and this document defines no mechanism by which a
registered Signed Statement is withdrawn from a Transparency Service. A
Verifier presented with a receipt for which it holds a relevant assertion:

- MUST surface the assertion to the relying party rather than resolving it
  internally;
- MUST identify which party made the assertion;
- MUST identify which of the two classes was asserted;
- MUST NOT suppress, discard, or downgrade the receipt on the basis of the
  assertion alone.

Neither assertion is self-authenticating, and this document does not adjudicate
a disputed one. Where the Site Owner and the Issuer disagree, the profile
supplies a detection property and not a remedy, in the same sense as
{{equivocation}}. Adjudication is a matter for the relying party's own policy
and for whatever legal or contractual regime governs the parties, and this
document deliberately declines to make that determination on a relying party's
behalf.

### No payload member in this revision

This revision defines **no payload member** carrying either assertion. An
assertion about a witness key is a separate Signed Statement about a key, not a
field inside a receipt about an engagement, and placing it in the receipt
payload would require a receipt to be reissued in order to change a fact about
its signer. Its content type and payload shape are deferred to a subsequent
revision, and this revision states that they are deferred rather than reserving
a member for them.

## Revocation decision clock {#revocation-clock}

A receipt validly signed at time T whose witness key becomes subject to an
assertion at a later time presents an ordering question, and the ordering MUST
NOT be decided from a timestamp the signer supplied. `ts`,
`adapter.postedAt`, and `attestation.validity` are all authored by the party
whose key is in question, and a signer able to forge a signature is able to
choose those values.

Registration is mandatory in this profile ({{scitt-registration}}), so every
conforming receipt carries at least one attached Receipt from a Transparency
Service, obtained from a party other than the signer. A Verifier that orders a
receipt against an assertion MUST derive the ordering from the registration of
each, as evidenced by their attached Receipts, and MUST NOT derive it from any
timestamp inside the receipt payload.

This revision does not define an encoding for a Transparency Service's
registration time, and does not require a Transparency Service to supply one.
Where the Verifier cannot establish from the attached Receipts that one
registration preceded the other, the ordering is **undetermined**, and the
Verifier MUST surface it as undetermined rather than selecting an order. It
MUST NOT fall back to a payload timestamp for this purpose, and MUST NOT
substitute its own local clock. Stating this plainly is deliberate: a relying
party writing policy against this profile needs to know that the profile
carries the timebase requirement and does not yet carry the mechanism.

## Three-party trust model {#trust-model}

The trust model described in this section applies to deployments where
the TEE that produces receipts is physically hosted at the Site. In such
deployments, the *site owner* both controls physical access to the TEE
hardware and is the party responsible for its continued operation. This
profile revision does not address deployments in which the TEE travels
with a mobile Actor (for example, a TEE integrated into a mobile robot's
compute platform), where the party controlling the attester's physical
platform is distinct from the party controlling the Site. Such on-device
attester topologies are not addressed here because a prerequisite is not yet
in place, and naming that prerequisite is more useful than restating the
deferral.

A travelling TEE is a delegated-witness deployment: the platform is controlled
by a party other than the Site Owner, so the authorization to sign on the TEE's
behalf must be evaluated by a Verifier rather than assumed from physical
custody of the hardware. That evaluation depends on resolving the delegation
credential, which this revision defines as an Issuer-published fact
({{issuer-published}}) whose serialization is not yet specified. Until the
encoding of that fact is fixed, a mobile-attester topology cannot be described
in a way two implementations would evaluate identically, and specifying the
topology first would produce a mode that reads as normative and cannot be
conformed to.

The security posture of this profile REQUIRES that three distinct parties
participate in every receipt, and that no single party can produce a valid
receipt alone:

- The *site owner* physically controls the TEE hardware. They can power it
  off, unplug it, or refuse to host it, but they CANNOT extract the signing
  key material or forge signatures with it. The site owner therefore
  controls whether receipts are produced at all, but not their content.
- The *TEE silicon vendor* provides the hardware root of trust that binds
  the signing key to a specific attested platform. Detection of a
  compromised or counterfeit TEE relies on this supply chain and is out of
  scope of this profile.
- The *Issuer* (typically the operator of a witness service) writes the
  Statement payload, causes the TEE to sign, registers the resulting Signed
  Statement with a Transparency Service, and performs the Adapter Write-In.
  The Issuer CANNOT sign without a live TEE. An Issuer that registers a
  receipt cannot prevent a relying party or auditor checking the
  Transparency Service from observing an equivocated chain. An Issuer that
  withholds a receipt from registration is not detected by this mechanism,
  which is why registration is mandatory in this profile
  ({{scitt-registration}}).

An implementation that collapses two or more of these roles into a single
principal (for example, a cloud service that owns the TEE hardware AND
signs AND registers with its own Transparency Service) is NOT conforming to
this profile, and relying parties MUST NOT treat receipts from such an
implementation as offering the trust properties defined here.

Customer-controlled signing keys held outside a TEE are explicitly WEAKER
than the model in this profile and MUST NOT be represented as equivalent.
A site owner with direct access to the signing key can backdate, forge, or
suppress receipts unilaterally, and no relying party -- insurer, regulator,
or counterparty -- can distinguish an authentic receipt from a fabricated
one in that setting.

## Site Owner and Transparency Service as one principal {#site-ts-affiliation}

This profile addresses two affiliation relationships. `issuerAffiliation`
({{payload}}) states the relationship between the Issuer and the Site Owner. The
disclosure of {{scitt-registration}} states the relationship between the Issuer
and the Transparency Service. Neither states the relationship between the Site
Owner and the Transparency Service, and this revision provides no member and no
Issuer-published fact that carries it.

The gap is not covered by the other two. An Issuer independent of both the Site
Owner and the Transparency Service satisfies both existing disclosures, while a
Site Owner that operates the Transparency Service the Issuer registers with
still obtains, at the registration step, the ability to suppress or withhold
entries concerning its own site. The external reference that
{{scitt-registration}} requires is then external to the Issuer but not to the
party whose conduct at the site is in question, which is the party a relying
party is usually evaluating.

A relying party that requires registration evidence external to the Site Owner
cannot establish that property from a receipt conforming to this revision, and
MUST obtain the relationship out of band. Stating this is deliberate: a policy
author reading {{scitt-registration}} could otherwise conclude that an
unaffiliated-Issuer registration establishes independence from the site, which
it does not.

## Identity attribution

Identity attribution above the key level -- linking `iss`, `actor.id`, and
`site.id` to real-world legal or natural persons -- requires an out-of-band
identity binding document. This profile does not specify that document's
format. `-02` called it an identity manifest, which collided with the unrelated
Issuer-published facts of {{issuer-published}}; the two were never the same
document and the shared name implied they were.

## Retained-content assurance limits {#content-security}

The signed root binds recorded bytes and metadata; it does not authenticate
the named asserting party or make the value true. A permitted category is
not a credential. Raw evidence can be correctly hashed yet irrelevant,
fabricated, stale, or contradictory. A relying party MUST NOT infer party
authentication, key residence, physical presence, or actual time from
membership, label equality, or raw-digest agreement alone.

A valid subset cannot establish that hidden facts are well-formed, unique,
or complete. A valid full block can still omit relevant events. Null can
conceal an Issuer's choice not to commit available material, and a valid
chain prefix can conceal a later suffix. These limits survive registration
of the presented material; no complete-history witness is added here.

Salts provide no secrecy once exposed and no hiding guarantee when weak or
predictable. Reused roots can link contexts. Consumers need bounded parsers,
work limits, and access policies in addition to proof verification. A small
inventory can be referenced repeatedly, so storage and hashing-work bounds
are not interchangeable.

## Position observations {#site-pose-security}

The recorded observation, its source attribution, and its preparation claims
are not authenticated merely because the witness signed their commitment.
Position spoofing, stale or fabricated samples, dishonest derivation labels,
untrusted clocks, and substituted source identity remain possible. The
implementation neither compares compound pose values with navigation evidence
nor establishes hardware custody or party identity.

Neither a pose nor its reference-point label changes the full retained
envelope commitment. This addition does not implement a geometry engine,
declare an older envelope's frame, evaluate containment, or turn an
Issuer-asserted `WITHIN` into a recipient-verified conclusion. It does not
add offline issuance, late-registration acceptance, blackout completeness,
nested-site authority, or cross-witness independence.

## Privacy

Site identifiers, actor identifiers, and engagement types MAY be sensitive.
Issuers SHOULD publish only the digests of envelope documents and internal
evidence structures, as this profile requires. Issuers MAY additionally
choose to encrypt the Statement payload under a per-relying-party key and
publish only the Signed Statement's Receipt to a public Transparency
Service, following the guidance in {{RFC9943}} Section 6.2 for sensitive
Statements.

Position observations can expose sensitive location. Disclosing `site.pose`
reveals its entire committed object at recorded precision; the construction
does not redact individual coordinates or prove undisclosed values.
Disclosures also reveal count, selected positions and ordering information,
names, salts, and sibling hashes. A repeated root or evidence digest can
enable linkage across statements. Retention and authorized access therefore
need explicit privacy policies even when raw content is not public.

# Implementation status {#impl-status}

This section follows {{RFC7942}}. It describes implementation experience,
not IETF endorsement, full conformance, or a requirement to use a particular
implementation. It is to be removed before publication as an RFC.

**Reference implementation.** `pask-workspace`, maintained by Wilder Robotics,
is a Rust workspace containing `pask-wire`, `pask-attest`, `pask-site`,
`pask-adapter`, `pask-wire-cli`, and `pask-ts-client`. Its source repository is
`https://github.com/wilder-robotics/pask-workspace`.

The public source snapshot identified here is commit
`9ba85f1034145de9e8670a83ffc26ca6608fcec6`, corresponding to the initial
0.1.0 releases of the three permissive crates. That snapshot supports the
0.5 and 0.6 profiles. It does not implement the 0.7 retained-content
construction, the additional vocabulary, or the subject-type correction
specified by this document. Package versions and profile versions are
independent; the released crates are not evidence of 0.7 support.

That snapshot implements the payload and signature paths, recorded-time
containment and DIRECT_WITNESS naming checks for 0.6, candidate-entry
derivation, bounded Ed25519/RFC9162 Receipt validation, and sender
byte-string wrapping. These components are not a claim of an end-to-end
registered deployment. Service-key trust inputs, required claims,
registration policy, and exact ledger representation require their own
evaluation.

The Signed Statement implementation checks that the Issuer identifier is
nonempty text but does not fully enforce the inherited URI requirement in
{{cose-header}}. This is an implementation limitation, not a relaxation of
the normative requirement. The string-consistency check does not establish
an authenticated association between that identifier and a signing key.

Neither the published implementation nor this implementation-status report
establishes authenticated asserting parties, navigation-source conversion,
compound pose/evidence comparison, reliable real-world clocks, recipient
geometry containment, hardware evidence appraisal, a complete mobile-site
protocol, or latest/complete history. A disclosure-policy result must not be
confused with application acceptance.

The informative corrective-statement design remains unimplemented and its
reference encodings remain unresolved. Planned experiments are not listed
as completed interoperability results.

The established repository split is Apache-2.0 for `pask-wire`, `pask-attest`,
and `pask-wire-cli`, and AGPL-3.0-only for the operational crates.

# Complementary positioning

This profile is orthogonal to:

- {{RFC9943}} (SCITT architecture) -- addresses digital supply chains;
  this profile addresses physical-site engagements.
- {{I-D.noa-scitt-ai-agent-receipt}} -- addresses per-action AI-agent
  receipts; this profile addresses per-engagement physical receipts. An
  AI agent that dispatches a physical engagement MAY emit both, correlated
  via `sub`.
- {{I-D.mih-scitt-agent-action-capsule}} -- addresses agent-action
  disposition (executed, blocked, denied, errored); this profile addresses
  what physically occurred after dispatch and does not carry disposition
  semantics.

The outer Signed Statement retains COSE_Sign1 and the SCITT registration
mechanisms. This revision separately defines retained-content commitments
and disclosure data. Registration policy, supported keys, and proof formats
still determine a particular service's interoperability; introducing content
does not establish universal service acceptance.

--- back

# Corrective Statements (Informative) {#correction-envelope}

This appendix is informative and records a corrective-statement design for
discussion. It does not define an interoperable corrective-statement wire format
or impose additional requirements on 0.5, 0.6, or 0.7 engagement receipts. The
corrective content type, versioning, and signed-statement reference encodings
remain unresolved. No correction implementation or completeness of correction
discovery is claimed.

A correction is a SCITT Signed Statement registered with a Transparency Service.
It is not a PSER engagement receipt. It carries its own `content_type`, distinct
from `application/pser+json; profile=wilder.pser/0.6`. It does not carry the
PSER `spec` member. It has its own versioning arrangement.

The correction payload would carry:

- **`target`** (required, string): identifies the original signed assertion
  being corrected. Encoding is not frozen in this revision. The reference
  encoding is unresolved; no corrective reference format is adopted here. The reference
  mechanism must work for both engagement receipts and corrective statements.
- **`kind`** (required, string): the kind of corrective assertion. Admissible
  values:
  - `AMENDMENT`: the signer asserts that its own earlier statement was wrong,
    incomplete, or should no longer be relied upon. Same `iss` as the original
    is allowed. If a different `iss` is used, continuity or authorization must
    be established before the verifier reports it as that issuer's amendment.
  - `CHALLENGE`: the signer disputes another issuer's identified statement.
    Different `iss` is expected. Different issuer identifiers do not establish
    organizational independence or authority.
  - `CORROBORATION`: the signer supports a specified amendment or challenge.
    NOT labeled "independent support." Independence is reported separately when
    supported by evidence or policy.
- **`content`** (required, object): the corrective assertion. Would carry:
  - `summary` (required, string): human-readable description of what is being
    corrected.
  - `fields` (optional, array): specific payload fields of the original that
    are disputed or amended.
- **`ts`** (required, string): RFC 3339 UTC timestamp at which the correction
  was signed.
- **`amends`** (optional, object): identifies a specific earlier correction
  being withdrawn or replaced. Would carry:
  - `ref` (required, string): reference to the earlier correction. Same
    encoding as `target`.
  - `operation` (required, string): `WITHDRAW` or `REPLACE`.
  - Withdrawal and replacement authority is checked against the statement
    being changed (the earlier correction), not just against the original
    receipt. Both `WITHDRAW` and `REPLACE` operations require this check. A
    claimed withdrawal or replacement is attributable as an action by the
    earlier statement's issuer only when that identity or authorization
    relationship is established. Otherwise it remains another party's
    assertion about that statement.
- **`supports`** (required for `CORROBORATION`, string): reference to a
  specific amendment or challenge being corroborated. Same encoding as
  `target`. Every `CORROBORATION` identifies the specific statement it
  supports.

The signer declares the kind. The verifier reports which identity and
relationship checks were established. The relying party assigns evidentiary
weight. No universal different-`iss` requirement applies. Same-`iss` amendments
are allowed. Different issuer identifiers do not establish organizational
independence or authority.

In this proposed model, a `CHALLENGE` would be evaluated against the public key
of the statement being challenged. Where both relevant signatures have been
successfully verified and a supported comparison establishes that the
verification keys are the same, the verifier would report that the declared
`CHALLENGE` fails the proposed distinct-key/kind-consistency condition. It would
preserve the signed declared kind and report the reason separately. The
statement's signature and any inclusion proof may still verify; the
kind-consistency failure would not rewrite either signed record, silently
convert the `CHALLENGE` to an `AMENDMENT`, or automatically invalidate the
original. It would not determine the truth of the disputed facts.

Kind consistency and its supporting key-relationship result would appear as
explicit, machine-readable findings in the primary result for each evaluated
corrective statement, and a failure or unestablished required relationship would
be visible in the main report summary. They would not be available only as
optional metadata. A broad summary that a correction is verified would not
conceal a failed or unestablished required kind-consistency check. When a
referenced statement, a successful signature verification, or the required
comparison inputs are unavailable, the relationship would be reported as
unestablished with a reason, not as different keys or as a successful
consistency result. Issuer-signature, inclusion, kind-consistency, authority,
original-statement, and local-policy findings would remain distinguishable.

For `CORROBORATION`, the verifier would report the signing-key relationship to
the statement named by `supports` and to the original anchor separately. Reuse
of the supported statement's key would not count as an additional distinct-key
source. Reuse of the original anchor's key alone would not force amendment
classification. Different keys would not, by themselves, establish
organizational independence.

These paragraphs describe proposed reporting behavior. They do not finalize an
output schema, field names, diagnostic-code registry, or corrective-statement
wire format, and do not add a correction-processing requirement to
`wilder.pser/0.6` engagement receipts.

An illustrative reporting example, not a specified schema:

~~~
Corrective statement C1, challenging original O1
Declared kind: CHALLENGE
C1 signature: verified
O1 signature: verified
C1 inclusion evidence: verified under accepted service key
Signing-key relationship C1/O1: same verified public key
Kind consistency: failed - same-key CHALLENGE
Organizational independence: not established by these checks
Effect on O1: no automatic invalidation or modification
Local policy: evaluated separately
~~~
{: #corrective-report-illustration}

When O1 is unavailable, the key relationship and required kind consistency are
unestablished with a reason. That is not portrayed as "different keys" or a
successful challenge. These are proposed reporting examples, not claims that
correction verification is implemented.

The verifier evaluates presented statements and their direct references. It does
not recursively discover corrections. It does not compute a "winning" history.
Where processing limits or missing references prevent a relationship from being
checked, the verifier reports that limitation rather than inventing a final
disposition. Availability, verification, and search coverage are reported as
distinct questions. No automatic winning history is computed.

This design is presented as a proposal. Reference encoding for `target`,
`amends`, and `supports` is not frozen and is coordinated with issue #67. The
reference implementation does not produce or verify correction records.
Discovery of corrections from an original receipt is not specified in this
revision. "Original-only" means no correction was presented; it does not mean
no correction exists. A correction does not reset the original's
`attestation.validity` interval. A correction's `ts` is not constrained by the
original's validity window.

# Content vocabulary rule tables (normative) {#content-vocabulary-tables}

This appendix supplies every rule needed for the two closed vocabularies.
The tables describe claims, not safety certification, evidence appraisal,
or authenticated parties. The JSON blocks below use the finite dialect in
{{content-value-dialect}}. They are machine-readable rule definitions;
they are not generic JSON Schema documents.

Each row's `meaning` string is printed in the preceding `Meaning:`
paragraph, and its other members appear in the JSON block. Restoring that
one string reconstructs the complete row; display line wrapping inserts
no new characters into the original string. The definitions and their
prose are checked against the exact companion artifacts.

For /2 use all 47 rows below. For /1 use the first 46 rows only, with all
listed fields unchanged. The `site.pose` row is absent from /1. Global
attribution, evidence, origin, and integer rules apply to both versions.

The 46-fact vocabulary `wilder.pser-content-vocab/1` has source-artifact
SHA-256:

`030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d`

The 47-fact vocabulary `wilder.pser-content-vocab/2` has source-artifact
SHA-256:

`2fb4e3a099003638d318333dee66fe2b710fb39b6dec78f570f6ecf31592a248`

The committed digest prepends `sha256:` to the corresponding hash.
The hash identifies the exact UTF-8 artifact, not the typography of this
appendix. Implementations can reproduce the rule table from this appendix
and recognize the named digest without retrieving an artifact at run time.
The byte-exact JSON artifacts are companion implementation material. The
complete rule definitions are also supplied here; an implementer does not
need access to a private repository to interpret the two vocabularies.
The artifact digests identify the unchanged source bytes, not a
re-serialization of the displayed definitions.

The /1 relation is 153 permitted and 813 forbidden among 966 known
fact/party/basis combinations. The /2 relation is 157 permitted and 830
forbidden among 987 combinations. Counts are cross-checks, not substitutes
for the complete row and global-rule intersection.

## Global interpretation {#content-vocabulary-global}

The seven party labels, three basis labels, global basis lists, and required
evidence parties are defined in {{content-attribution}} and
{{content-evidence}}. The following block contains the structured global
metadata. Its three string annotations are printed immediately afterward
as prose to keep the artwork within the text line limit. Reconstruct the
complete object by restoring those strings under their named `globalRules`
keys. This layout changes neither the source artifact nor its hash:

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "operator-entered",
    "platform-recorded",
    "site-policy",
    "manufacturer-declared",
    "undetermined"
  ],
  "basis": [
    "measured",
    "estimated",
    "declared"
  ],
  "globalRules": {
    "basisByParty": {
      "appliance-measured": [
        "measured",
        "estimated"
      ],
      "manufacturer-declared": [
        "declared"
      ],
      "operator-entered": [
        "estimated",
        "declared"
      ],
      "platform-recorded": [
        "measured",
        "declared"
      ],
      "robot-attributed": [
        "measured",
        "estimated",
        "declared"
      ],
      "site-policy": [
        "declared"
      ],
      "undetermined": [
        "estimated",
        "declared"
      ]
    },
    "evidenceRequiredByParty": [
      "appliance-measured",
      "robot-attributed"
    ]
  },
  "remoteOrigin": [
    "on-site",
    "off-site",
    "undetermined"
  ]
}
~~~
{: #vocabulary-global-definition}

Artifact annotation `numbers`: All numeric values are integers in the
stated unit; floats are rejected (RFC 8785 number interoperability).

Artifact annotation `operatorPseudonym`: crew.operator-pseudonym is
assigned and mapped by the teleoperation platform; the witness never
holds the mapping.

Artifact annotation `remoteOrigin`: Tag values on-site | off-site |
undetermined; required exactly where the table says, forbidden
elsewhere.

The artifact's parenthetical reference to RFC 8785 in its `numbers` annotation
does not mean RFC 8785 prohibits all fractional numbers. Numeric fields in
these fact schemas are integers; canonical commitment and raw evidence
comparison retain their separately defined number models.

The operator pseudonym is assigned and mapped by the teleoperation platform.
The witness does not receive the identity mapping under this vocabulary.
That custody condition is a producer/deployment obligation, not a result of
the string-pattern validator. Similarly, statements in a row's `meaning`
about a manufacturer, platform, or source's records remain claims whose
truth and custody are not established by typed validation.

`remoteOrigin` values and per-row requirement/forbiddance are interpreted as
control-origin metadata, not generic evidence-acquisition metadata.

No IANA registry is requested for these document-defined vocabulary labels
or fact names. Extensions require a separately specified rule set and a new
digest; a new label alone is not support or delegation of naming authority.

## Complete fact rules {#content-vocabulary-facts}

### 1. `unit.model` {#fact-unit-model}

Meaning: Model designation of the acting machine.

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "robot-attributed",
    "site-policy"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.model",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 64,
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-unit-model}

### 2. `unit.pseudonym` {#fact-unit-pseudonym}

Meaning: Stable pseudonym for the individual machine; the manufacturer
holds the mapping to the physical serial.

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "robot-attributed"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.pseudonym",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9:_.-]+$",
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-unit-pseudonym}

### 3. `unit.deployment-status` {#fact-unit-deployment-status}

Meaning: Whether the site's registry lists this machine as a deployed
unit or a planned one. Site-registry status, not proof of physical
presence.

~~~ json
{
  "assertedBy": [
    "site-policy"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.deployment-status",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "deployed",
      "planned",
      "unknown"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-unit-deployment-status}

### 4. `unit.software-build` {#fact-unit-software-build}

Meaning: Identity of the software actually running (build string or
measured digest).

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "manufacturer-declared"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.software-build",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 128,
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-unit-software-build}

### 5. `unit.safety-parameter-digest` {#fact-unit-safety-parameter-digest}

Meaning: Digest over the active safety-function parameterization.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.safety-parameter-digest",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "pattern": "^sha256:[0-9a-f]{64}$",
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-unit-safety-parameter-digest}

### 6. `unit.category` {#fact-unit-category}

Meaning: Category of the machine under the applicable safety standard;
opaque code, checked for form only.

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "site-policy"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.category",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 32,
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-unit-category}

### 7. `limits.rated-force` {#fact-limits-rated-force}

Meaning: Rated force limit. A rated limit is a declaration; it is
never measured.

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "robot-attributed"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "limits.rated-force",
  "remoteOrigin": "forbidden",
  "unit": "N",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-limits-rated-force}

### 8. `limits.rated-speed` {#fact-limits-rated-speed}

Meaning: Rated speed limit. Declaration only.

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "robot-attributed"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "limits.rated-speed",
  "remoteOrigin": "forbidden",
  "unit": "mm/s",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-limits-rated-speed}

### 9. `unit.mass-centre-height` {#fact-unit-mass-centre-height}

Meaning: Height of the centre of mass, to bound fall energy.

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "robot-attributed"
  ],
  "basis": [
    "declared",
    "estimated"
  ],
  "evidence": "optional",
  "name": "unit.mass-centre-height",
  "remoteOrigin": "forbidden",
  "unit": "mm",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-unit-mass-centre-height}

### 10. `unit.total-mass` {#fact-unit-total-mass}

Meaning: Total mass. Nameplate (declared) or weighed by site equipment
(appliance-measured).

~~~ json
{
  "assertedBy": [
    "manufacturer-declared",
    "appliance-measured",
    "robot-attributed"
  ],
  "basis": [
    "declared",
    "measured"
  ],
  "evidence": "optional",
  "name": "unit.total-mass",
  "pairsForbidden": [
    [
      "robot-attributed",
      "measured"
    ]
  ],
  "remoteOrigin": "forbidden",
  "unit": "g",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-unit-total-mass}

### 11. `unit.channel-rates` {#fact-unit-channel-rates}

Meaning: Declared native logging rate per safety channel, as a map of
channel label to hertz.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "manufacturer-declared"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "unit.channel-rates",
  "remoteOrigin": "forbidden",
  "unit": "Hz",
  "value": {
    "type": "map-of-integer"
  }
}
~~~
{: #vocabulary-rule-unit-channel-rates}

### 12. `mode.control` {#fact-mode-control}

Meaning: Who or what was issuing motion commands. Carries
remoteOrigin: whether the command source was off-site.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "platform-recorded",
    "operator-entered"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "mode.control",
  "remoteOrigin": "required",
  "unit": null,
  "value": {
    "enum": [
      "autonomous",
      "supervised-autonomous",
      "assisted-remote",
      "full-remote",
      "fallback-to-remote",
      "transition"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-mode-control}

### 13. `mode.control-handover-preceding` {#fact-mode-control-handover-preceding}

Meaning: Whether control changed hands within the 60 s before the
event, and which way. Carries remoteOrigin.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "platform-recorded"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "mode.control-handover-preceding",
  "remoteOrigin": "required",
  "unit": null,
  "value": {
    "properties": {
      "direction": {
        "enum": [
          "to-remote",
          "to-autonomy"
        ],
        "nullable": true,
        "type": "string"
      },
      "occurred": {
        "type": "boolean"
      },
      "secondsBefore": {
        "maximum": 60,
        "minimum": 0,
        "nullable": true,
        "type": "integer"
      }
    },
    "required": [
      "occurred",
      "direction",
      "secondsBefore"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-mode-control-handover-preceding}

### 14. `scene.event-instant` {#fact-scene-event-instant}

Meaning: Instant of the event at millisecond precision, on the
receipt's clock basis. Measured by a device, never typed.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "platform-recorded"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "required",
  "name": "scene.event-instant",
  "remoteOrigin": "forbidden",
  "unit": "ms UTC",
  "value": {
    "maxLength": 32,
    "pattern":
"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$",
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-scene-event-instant}

### 15. `scene.setting` {#fact-scene-setting}

Meaning: The kind of place the work happened in, as the site declares
it.

~~~ json
{
  "assertedBy": [
    "site-policy"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "scene.setting",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "industrial-segregated",
      "industrial-shared",
      "logistics",
      "service",
      "domestic",
      "other"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-scene-setting}

### 16. `scene.collaboration-regime` {#fact-scene-collaboration-regime}

Meaning: Collaborative operating regime in force; measured when the
machine reports its active regime, declared when the site's plan
states it.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "scene.collaboration-regime",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "monitored-stop",
      "hand-guiding",
      "speed-separation",
      "force-limited",
      "non-collaborative",
      "transitioning",
      "unknown"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-scene-collaboration-regime}

### 17. `scene.persons-in-zone` {#fact-scene-persons-in-zone}

Meaning: Whether people were inside the working zone.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "operator-entered"
  ],
  "basis": [
    "measured",
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "scene.persons-in-zone",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "type": "boolean"
  }
}
~~~
{: #vocabulary-rule-scene-persons-in-zone}

### 18. `scene.attendant-present` {#fact-scene-attendant-present}

Meaning: Whether an attending operator, local or remote, was present.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "operator-entered",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "scene.attendant-present",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "type": "boolean"
  }
}
~~~
{: #vocabulary-rule-scene-attendant-present}

### 19. `scene.surface-state` {#fact-scene-surface-state}

Meaning: Condition of the floor or ground.

~~~ json
{
  "assertedBy": [
    "operator-entered",
    "appliance-measured",
    "site-policy"
  ],
  "basis": [
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "scene.surface-state",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "nominal",
      "wet",
      "uneven",
      "obstructed",
      "unknown"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-scene-surface-state}

### 20. `event.kind` {#fact-event-kind}

Meaning: What kind of event this block describes.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "operator-entered",
    "undetermined"
  ],
  "basis": [
    "measured",
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "event.kind",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "protective-stop",
      "emergency-stop",
      "transient-contact",
      "sustained-contact",
      "stability-loss",
      "fall",
      "near-miss",
      "hardware-fault",
      "software-fault",
      "sensing-fault",
      "override-attempt",
      "cyber-anomaly",
      "software-update",
      "remote-handover",
      "other"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-event-kind}

### 21. `event.trigger` {#fact-event-trigger}

Meaning: What set the event off; free text bounded to 256 characters.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "operator-entered",
    "platform-recorded",
    "site-policy",
    "manufacturer-declared",
    "undetermined"
  ],
  "basis": [
    "measured",
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "event.trigger",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 256,
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-event-trigger}

### 22. `event.trace-window` {#fact-event-trace-window}

Meaning: High-rate series across the mechanical event. The value
describes the window; the series itself is the referenced retained
object.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "required",
  "name": "event.trace-window",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "properties": {
      "durationMs": {
        "minimum": 0,
        "type": "integer"
      },
      "rateHz": {
        "minimum": 1,
        "type": "integer"
      }
    },
    "required": [
      "durationMs",
      "rateHz"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-event-trace-window}

### 23. `event.scene-capture` {#fact-event-scene-capture}

Meaning: Perception capture around the event. Frames are a retained
object behind the reference; they never travel in the block.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "required",
  "name": "event.scene-capture",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "properties": {
      "biometricsExcluded": {
        "type": "boolean"
      },
      "modality": {
        "enum": [
          "video",
          "depth",
          "lidar",
          "mixed"
        ],
        "type": "string"
      },
      "postMs": {
        "minimum": 0,
        "type": "integer"
      },
      "preMs": {
        "minimum": 0,
        "type": "integer"
      }
    },
    "required": [
      "preMs",
      "postMs",
      "modality",
      "biometricsExcluded"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-event-scene-capture}

### 24. `event.shift-trace` {#fact-event-shift-trace}

Meaning: Low-rate series across the whole shift, to expose fatigue and
slow drift. Series is the referenced retained object.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "appliance-measured"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "required",
  "humanFactors": true,
  "name": "event.shift-trace",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "properties": {
      "durationMin": {
        "minimum": 0,
        "type": "integer"
      },
      "rateHz": {
        "minimum": 1,
        "type": "integer"
      }
    },
    "required": [
      "durationMin",
      "rateHz"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-event-shift-trace}

### 25. `event.override-attempt` {#fact-event-override-attempt}

Meaning: Any attempt to override a safety function in the prior five
minutes. Carries remoteOrigin as a separate tag.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "platform-recorded",
    "appliance-measured"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "event.override-attempt",
  "remoteOrigin": "required",
  "unit": null,
  "value": {
    "properties": {
      "attempted": {
        "type": "boolean"
      },
      "secondsBefore": {
        "maximum": 300,
        "minimum": 0,
        "nullable": true,
        "type": "integer"
      }
    },
    "required": [
      "attempted",
      "secondsBefore"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-event-override-attempt}

### 26. `event.software-update-preceding` {#fact-event-software-update-preceding}

Meaning: Whether the machine's software was updated in the prior 72
hours.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "manufacturer-declared",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "event.software-update-preceding",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "properties": {
      "hoursBefore": {
        "maximum": 72,
        "minimum": 0,
        "nullable": true,
        "type": "integer"
      },
      "occurred": {
        "type": "boolean"
      }
    },
    "required": [
      "occurred",
      "hoursBefore"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-event-software-update-preceding}

### 27. `stability.recovery-engaged` {#fact-stability-recovery-engaged}

Meaning: Whether balance recovery engaged. Only the machine can know
this.

~~~ json
{
  "assertedBy": [
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "required",
  "name": "stability.recovery-engaged",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "type": "boolean"
  }
}
~~~
{: #vocabulary-rule-stability-recovery-engaged}

### 28. `stability.margin-min` {#fact-stability-margin-min}

Meaning: Minimum stability margin reached (support-polygon margin).
Only the machine can assert it; an operator cannot.

~~~ json
{
  "assertedBy": [
    "robot-attributed"
  ],
  "basis": [
    "measured",
    "estimated"
  ],
  "evidence": "required",
  "name": "stability.margin-min",
  "remoteOrigin": "forbidden",
  "unit": "mm",
  "value": {
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-stability-margin-min}

### 29. `stability.carried-mass` {#fact-stability-carried-mass}

Meaning: Mass being carried.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "operator-entered",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared",
    "estimated"
  ],
  "evidence": "optional",
  "name": "stability.carried-mass",
  "remoteOrigin": "forbidden",
  "unit": "g",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-stability-carried-mass}

### 30. `stability.carried-speed-bound` {#fact-stability-carried-speed-bound}

Meaning: Upper bound of load velocity.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "stability.carried-speed-bound",
  "remoteOrigin": "forbidden",
  "unit": "mm/s",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-stability-carried-speed-bound}

### 31. `crew.session-minutes` {#fact-crew-session-minutes}

Meaning: How long the operator had been in session. Platform-recorded
only; the operator cannot self-report it.

~~~ json
{
  "assertedBy": [
    "platform-recorded"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "optional",
  "humanFactors": true,
  "name": "crew.session-minutes",
  "remoteOrigin": "forbidden",
  "unit": "min",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-crew-session-minutes}

### 32. `crew.supervision-ratio` {#fact-crew-supervision-ratio}

Meaning: Robots per operator at the time.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "site-policy"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "humanFactors": true,
  "name": "crew.supervision-ratio",
  "remoteOrigin": "forbidden",
  "unit": "robots/operator",
  "value": {
    "minimum": 1,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-crew-supervision-ratio}

### 33. `crew.certification-tier` {#fact-crew-certification-tier}

Meaning: Operator certification tier 1-3. Neither the operator nor the
machine can assert it.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "site-policy"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "humanFactors": true,
  "name": "crew.certification-tier",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maximum": 3,
    "minimum": 1,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-crew-certification-tier}

### 34. `crew.platform` {#fact-crew-platform}

Meaning: Which teleoperation platform was in the loop.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "site-policy"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "name": "crew.platform",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 128,
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-crew-platform}

### 35. `crew.operator-pseudonym` {#fact-crew-operator-pseudonym}

Meaning: Stable pseudonym for the individual operator; the platform
holds the mapping, the witness never does.

~~~ json
{
  "assertedBy": [
    "platform-recorded"
  ],
  "basis": [
    "declared"
  ],
  "evidence": "optional",
  "humanFactors": true,
  "name": "crew.operator-pseudonym",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9:_.-]+$",
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-crew-operator-pseudonym}

### 36. `link.rtt-mean` {#fact-link-rtt-mean}

Meaning: Mean round-trip latency over the prior 60 s.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "optional",
  "name": "link.rtt-mean",
  "remoteOrigin": "forbidden",
  "unit": "us",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-link-rtt-mean}

### 37. `link.rtt-p95` {#fact-link-rtt-p95}

Meaning: 95th-percentile round-trip latency over the prior 60 s.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "optional",
  "name": "link.rtt-p95",
  "remoteOrigin": "forbidden",
  "unit": "us",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-link-rtt-p95}

### 38. `link.rtt-jitter` {#fact-link-rtt-jitter}

Meaning: Round-trip latency variability over the prior 60 s.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "optional",
  "name": "link.rtt-jitter",
  "remoteOrigin": "forbidden",
  "unit": "us",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-link-rtt-jitter}

### 39. `link.loss-ratio` {#fact-link-loss-ratio}

Meaning: Packet loss over the prior 60 s, parts per million.

~~~ json
{
  "assertedBy": [
    "platform-recorded",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "optional",
  "name": "link.loss-ratio",
  "remoteOrigin": "forbidden",
  "unit": "ppm",
  "value": {
    "maximum": 1000000,
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-link-loss-ratio}

### 40. `contact.kind` {#fact-contact-kind}

Meaning: Transient or sustained contact.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "operator-entered"
  ],
  "basis": [
    "measured",
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "contact.kind",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "transient",
      "sustained"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-contact-kind}

### 41. `contact.body-zone` {#fact-contact-body-zone}

Meaning: Body region code under the applicable body model; opaque
code, checked for form only.

~~~ json
{
  "assertedBy": [
    "operator-entered",
    "appliance-measured",
    "robot-attributed"
  ],
  "basis": [
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "contact.body-zone",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maxLength": 32,
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-contact-body-zone}

### 42. `contact.force-peak` {#fact-contact-force-peak}

Meaning: Peak contact force actually measured. Measured only. A
reconstructed value can never be carried under this name.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed"
  ],
  "basis": [
    "measured"
  ],
  "evidence": "required",
  "name": "contact.force-peak",
  "remoteOrigin": "forbidden",
  "unit": "mN",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-contact-force-peak}

### 43. `contact.force-reconstructed` {#fact-contact-force-reconstructed}

Meaning: Contact force reconstructed where it was not measured.
Estimated only, under a separate name.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "robot-attributed",
    "operator-entered",
    "undetermined"
  ],
  "basis": [
    "estimated"
  ],
  "evidence": "optional",
  "name": "contact.force-reconstructed",
  "remoteOrigin": "forbidden",
  "unit": "mN",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-contact-force-reconstructed}

### 44. `contact.force-limit-active` {#fact-contact-force-limit-active}

Meaning: Force-limiting threshold in force at the time.

~~~ json
{
  "assertedBy": [
    "robot-attributed",
    "site-policy",
    "manufacturer-declared"
  ],
  "basis": [
    "measured",
    "declared"
  ],
  "evidence": "optional",
  "name": "contact.force-limit-active",
  "remoteOrigin": "forbidden",
  "unit": "mN",
  "value": {
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-contact-force-limit-active}

### 45. `outcome.severity-grade` {#fact-outcome-severity-grade}

Meaning: Severity 0 (near-miss) to 5 (fatality or permanent
disability). A human judgment; no device can assert it.

~~~ json
{
  "assertedBy": [
    "operator-entered",
    "undetermined"
  ],
  "basis": [
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "outcome.severity-grade",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "maximum": 5,
    "minimum": 0,
    "type": "integer"
  }
}
~~~
{: #vocabulary-rule-outcome-severity-grade}

### 46. `cause.category` {#fact-cause-category}

Meaning: Root-cause category. A judgment; no device, platform or site
policy can assert it.

~~~ json
{
  "assertedBy": [
    "operator-entered",
    "undetermined"
  ],
  "basis": [
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "cause.category",
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "enum": [
      "hardware",
      "software",
      "sensing",
      "configuration",
      "balance",
      "local-operator",
      "remote-operator",
      "credential-compromise",
      "platform-failure",
      "network-quality",
      "environmental",
      "cyber-vulnerability",
      "cyber-supply-chain",
      "cyber-network",
      "unknown",
      "under-investigation"
    ],
    "type": "string"
  }
}
~~~
{: #vocabulary-rule-cause-category}

### 47. `site.pose` {#fact-site-pose}

Meaning: Position only: one observation of one site-declared reference
point, from one source sample, scaled against EPSG:4979. Not
orientation, speed, trajectory or ephemeris. With heightMm null it is
a partial observation with no asserted height. The signature binds
that this observation was committed with this attribution; it does not
establish that the site was at this position, that the named source
produced it, or its accuracy.

~~~ json
{
  "assertedBy": [
    "appliance-measured",
    "platform-recorded",
    "operator-entered"
  ],
  "basis": [
    "measured",
    "estimated",
    "declared"
  ],
  "evidence": "optional",
  "name": "site.pose",
  "pairsForbidden": [
    [
      "platform-recorded",
      "declared"
    ],
    [
      "operator-entered",
      "estimated"
    ]
  ],
  "remoteOrigin": "forbidden",
  "unit": null,
  "value": {
    "additionalProperties": false,
    "properties": {
      "crs": {
        "enum": [
          "EPSG:4979"
        ],
        "type": "string"
      },
      "heightMm": {
        "maximum": 100000000,
        "minimum": -20000000,
        "nullable": true,
        "type": "integer"
      },
      "horizontalAccuracyMm": {
        "maximum": 100000000,
        "minimum": 0,
        "nullable": true,
        "type": "integer"
      },
      "latE7": {
        "maximum": 900000000,
        "minimum": -900000000,
        "type": "integer"
      },
      "latLonDerivation": {
        "enum": [
          "exact-integer-rescaling",
          "rounded-half-even-to-1e-7-deg"
        ],
        "type": "string"
      },
      "lonE7": {
        "maximum": 1799999999,
        "minimum": -1800000000,
        "type": "integer"
      },
      "observedAt": {
        "maxLength": 32,
        "nullable": true,
        "pattern":
"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$",
        "type": "string"
      },
      "referencePoint": {
        "maxLength": 64,
        "pattern": "^[A-Za-z0-9:_.-]+$",
        "type": "string"
      }
    },
    "required": [
      "crs",
      "referencePoint",
      "latE7",
      "lonE7",
      "heightMm",
      "horizontalAccuracyMm",
      "observedAt",
      "latLonDerivation"
    ],
    "type": "object"
  }
}
~~~
{: #vocabulary-rule-site-pose}


# Change log

## Changes in -05

This revision proposes profile `wilder.pser/0.7` while preserving the declared
meaning and signed bytes of the earlier profiles.

- Clarified that 0.5 and 0.6 reject `engagement.contentDigest`, even when
  null; the new member is confined to 0.7. The Issuer URI requirement is
  unchanged.

- Added required null-or-root `engagement.contentDigest`, the byte-exact
  retained-content construction, and selected/full disclosure verification.
- Defined the two closed, digest-selected vocabularies, their complete rule
  tables and finite value dialect. The seven recorded attribution categories
  are not authenticated party signatures.
- Separated raw-evidence integrity, supported value comparison, fact
  availability, and disclosure policy from membership and application
  acceptance; documented custody, null concealment, privacy, and suffix limits.
- Required the 0.7 protected CWT subject to be text exactly equal to `site.id`.
  The old implementation's byte-string compatibility path is preserved, not
  represented as CWT text conformance.
- Described the local portable recipient/chain workflow as implementation
  experience, not a new SCITT protocol or a physical-decision replay.
- Added optional `site.pose` only to vocabulary /2, without changing the
  operating-envelope commitment or adding public geometry. Producer
  conversion rules are distinct from the implemented typed-value checks.
- Added the CWT and EPSG reference needed for the new semantics. Corrective
  statements, hardware/key identity, offline issuance, blackout completeness,
  nested sites, and cross-witnessing remain outside this revision's additions.


## Changes in -04

This revision introduces `wilder.pser/0.6` as the profile version carrying the
timestamp containment requirement and the DIRECT_WITNESS identifier-consistency
convention. `wilder.pser/0.5` retains its published meaning; its profile does
not require timestamp containment or the naming convention. A receipt
declaring `wilder.pser/0.5` is not subject to these rules, regardless of when
it was produced.

This revision specifies the candidate-entry byte encoding for inclusion-proof
verification, replacing the -03 disclosure that deferred this to an agreed
convention. The candidate entry is the untagged four-element array `[P, {}, M,
S]` derived from the presented Transparent Statement. Registration and
verification alignment is required, not assumed. Transmitted envelopes use COSE
tag 18; the untagged candidate entry is a profile-internal representation. A
Transparency Service that hashes a different representation cannot satisfy this
profile unless it commits to the candidate-entry representation specified here.

The at-least-one-trusted-proof acceptance rule is specified: the profile's
inclusion requirement is satisfied only when at least one attached Receipt has
both a valid Transparency Service signature under an accepted service key and a
valid inclusion proof for the derived candidate entry. A structurally parseable
additional Receipt whose cryptographic verification fails does not defeat
another attached Receipt that satisfies the requirement. The aggregate
verification logic exists only as a test helper; application integration remains
open.

The TEE Class registry descriptions are clarified with informative context.
No values are added, removed, or renamed. The evidence-format question for each
value remains unresolved.

This revision does not introduce an `attestationResult` member into the
normative payload. The evidence-model question remains open. The complete
explanation of retained evidence mechanisms, external appraisal, and the
digest-versus-retrieval distinction is incorporated. Delegated signing does not
itself establish evidence appraisal.

This revision presents the corrective statement design as an informative
appendix proposal. The correction payload type, signing rule, correction kinds,
relationship model, processing rule, and verifier behavior are defined.
Reference encoding for `target`, `amends`, and `supports` is not frozen and is
coordinated with issue #67. The reference implementation does not produce or
verify correction records. Every `CORROBORATION` identifies the specific
statement it supports. Same-key `CHALLENGE` inconsistency is reported
separately. Withdrawal and replacement authority is checked against the
statement being changed. A correction does not reset the original's
`attestation.validity` interval.

## Changes in -03

This revision resolves a defect in `-02` in which one undefined noun carried
four unrelated obligations. `-02` placed four normative requirements on a
Verifier against "the Issuer's manifest" while stating, in its own identity
attribution section, that it did not specify that document's format. A Verifier
was therefore required four times to read a document the profile never
described. The four obligations were not variants of one thing, and are not
resolved by defining one document.

It adds one REQUIRED payload member and bumps the profile identifier from
`wilder.pser/0.4` to `wilder.pser/0.5`. It removes nothing and narrows no
existing requirement.

- **`attestation.bindingMode` (REQUIRED) is added**, carrying the
  attestation-binding mode in the receipt. In `-02` a Verifier was required to
  obtain the mode from an Issuer-published document before it could rely on the
  non-extractability property stated in the introduction. The mode is a
  per-receipt fact fixed at signing time and known to the signer, and locating
  it outside the receipt made a property of the presented bytes depend on a
  network retrieval. The introduction's requirement now reads against the
  member. The value set is closed and a `DIRECT_WITNESS` receipt whose
  `attestation.witnessKey` and `iss` differ is rejected.
- **The acknowledgement-object obligation is withdrawn as a Verifier
  requirement** and restated as wording. `-02` located the minimal ack object's
  schema in the Issuer's manifest in the same sentence that defined the object
  as bound by Merkle inclusion and not published. A document defined to be
  unfetchable cannot carry an obligation a Verifier can discharge. No mechanism
  changes; `adapter.ackProvenance` already distinguishes the case.
- **{{issuer-published}} is added**, naming the two obligations that are
  genuine external retrievals and stating how they resolve. Both are disclosures
  about the Issuer rather than identity claims. The section fixes a stable
  Issuer-controlled identifier discoverable from `iss`, permits caching, voids a
  cached answer on a signing-key change, and defines a failure to resolve as
  **undetermined**.
- **Undetermined is stated as a third outcome.** A Verifier MUST NOT resolve an
  undetermined fact to the Issuer-favourable value, MUST NOT report a fact as
  absent where it was never successfully retrieved, and MUST NOT reject a
  receipt solely on the ground that a fact is undetermined. This follows the
  treatment already given to undetermined registration ordering in
  {{revocation-clock}}. The distinction between a fact checked and found absent
  and a fact never checked is load-bearing: collapsing the two lets a Verifier
  report to a relying party something it has no basis to state.
- **No serialization format is specified for Issuer-published facts.** This
  revision defines the obligations and their resolution behaviour and defers the
  encoding. Fixing a format before one has been deployed invites repudiation in
  the following revision rather than refinement.
- **Conformance vectors accompanying this revision MUST include a failing
  resolution case for each Issuer-published fact**, and the expected outcome of
  such a case MUST NOT be acceptance.
- **The mobile-attester deferral in {{trust-model}} now names its
  prerequisite.** `-02` recorded that on-device attester topologies were
  expected to be addressed in a subsequent revision without stating what they
  waited on. A travelling TEE is a delegated-witness deployment, so it depends
  on resolving the delegation credential, whose encoding this revision
  deliberately leaves open.
- **{{site-ts-affiliation}} is added**, recording that the profile carries no
  disclosure of the relationship between the Site Owner and the Transparency
  Service. An Issuer unaffiliated with both satisfies the two existing
  disclosures while a Site-Owner-operated Transparency Service retains the
  ability to withhold entries concerning its own site. The gap is recorded
  rather than closed.
- **Editorial: the identity attribution section no longer calls its
  out-of-band document a manifest.** It was never the same document as the
  Issuer-published facts above, and the shared name implied it was.

## Changes in -02
- Corrected two internally inconsistent statements about the Site Owner that
  -00 and -01 both carried. The overview described the Site Owner as owning
  the hardware, while the trust model described the same party by capability;
  the overview now uses the capability language, matching the definition added
  to {{terminology}} in this revision.
- Bounded the introduction's non-extractability statement to direct-witness
  mode. -01 stated as a profile-wide REQUIREMENT that the signing authority be
  neither extractable by the Site Owner nor by the Issuer, while normatively
  defining a delegated-witness mode in which the Issuer signs with its own key.
  The statement is now scoped to the mode it describes, the weaker property of
  the other mode is stated, and a Verifier is required to determine the mode
  from the manifest rather than assume it.

This revision closes the reviewer-identified gap in the Adapter Write-In,
states a witness key lifecycle that `-01` did not address, and records one
scope boundary that `-01` left to internal doctrine. It adds two payload
members and bumps the profile identifier; it removes nothing.

- **`adapter.ackProvenance` (REQUIRED) is added** and the profile identifier
  and media-type parameter move from `wilder.pser/0.3` to `wilder.pser/0.4`.
  `-01` carried `adapter.ackDigest` with no way for a Verifier to tell an
  acknowledgement authored by an independent operations layer from one authored
  by the Issuer under the fallback in that member's own definition. The two are
  now distinguishable in the receipt rather than in out-of-band context. The
  member is REQUIRED rather than optional because an absent value would itself
  have to be assigned a meaning, which reintroduces the collapse.
- **A Verifier MUST NOT resolve an unrecognized `adapter.ackProvenance` value
  in the receipt's favour.** It is preserved as received and surfaced as
  unrecognized, and is neither read as `THIRD_PARTY` nor normalized to `NONE`.
- **`issuerAffiliation` (REQUIRED) is added**, stating whether the Issuer and
  the Site Owner are affiliated principals, with the three values
  `AFFILIATED`, `INDEPENDENT` and `NOT_DISCLOSED`. `-01` gave a relying party
  no way to tell from a receipt whether the party that signed it had an
  interest in what it said, while requiring in {{trust-model}} that the roles
  not be collapsed. The member is REQUIRED for the same reason
  `adapter.ackProvenance` is: an absent value would have to be assigned a
  meaning, and every candidate meaning either manufactures a disclosure or
  makes an accusation.
- **A Verifier MUST NOT read `NOT_DISCLOSED` as `INDEPENDENT`**, and MUST NOT
  read an unrecognized value as `AFFILIATED` or normalize it to
  `NOT_DISCLOSED`. The profile records the Issuer's claim about itself and
  defines no mechanism for verifying it; a verified receipt is evidence that
  the claim was made and bound, not that it is true.
- **A third Chain-Verifier obligation is added, and it is deliberately not a
  rejection.** Where receipts presented as one chain carry different
  `issuerAffiliation` values, the change MUST be surfaced and identified by
  sequence number, and the presentation remains verifiable. Unlike `chain.seq`
  and `chain.prevHash`, which are wholly under the Issuer's control and admit
  no honest violation, affiliation is a relationship in the world outside the
  receipt and can legitimately change. What is prohibited is reducing a
  presentation to a single affiliation value, and in particular adopting the
  latest receipt's value, which is what would permit a chain to be relabelled
  after the fact by appending one receipt.
- ***Site Owner* is added to {{terminology}}**, defined by capability rather
  than by title. `-01` used the term in prose at three places in
  {{trust-model}} without defining it, and this revision is the first to assign
  it a normative capability.
- **A witness key lifecycle is stated ({{key-lifecycle}})**, defining two named
  assertion classes. Cessation may be asserted by the Site Owner or the Issuer
  independently; retroactive impeachment may be asserted by the Issuer only.
  Neither deletes, invalidates, or suppresses a registered receipt. Both are
  scoped against the two attestation-binding modes of
  {{attestation-binding}}, and in delegated-witness mode an assertion MUST
  identify the key it covers.
- **No payload member carries either assertion in this revision.** The content
  type and payload shape of an assertion about a key are deferred, and this
  revision states the deferral rather than reserving a member.
- **A revocation decision clock is stated ({{revocation-clock}})**, requiring
  the ordering of a receipt against an assertion to be derived from
  registration rather than from any signer-supplied timestamp, and requiring an
  ordering that cannot be established to be surfaced as undetermined rather
  than guessed.
- **Compromise of a TEE class or platform is stated not to be a key lifecycle
  event** and remains out of scope ({{tee-compromise}}).
- **A scope boundary is added to {{non-goals}}:** the profile attests nothing
  about the internal state, intent, or decision process of a human
  participant, nor about signals conveyed by a direct neural or
  brain-computer interface. No member, value, or extension point is defined
  for one.
- **Two implementation-status statements in `-01` are corrected.** The
  Chain-Verifier checks defined by `-01` are now implemented, and the crate
  disagreement over a zero-length attestation validity interval is resolved
  with the rule stated in Section 4.1.

## Changes in -01

This revision made two groups of changes. The first reconciles the profile
identifier and four attestation members with the reference implementation and
changes how the example figure in Section 4 is produced. The second corrects
statements in `-00` that were found to be wrong or unsupported, and adds
normative requirements that `-00` implied without stating. Both groups are
enumerated below. Every normative change in this revision appears in one of
them.

### Reconciliation with the reference implementation

- The profile identifier and media-type parameter are `wilder.pser/0.4`. A
  producer built against `wilder.pser/0.2` is rejected on version validation
  rather than on an unknown member.
- `attestation.measuredBootChain` (string) is replaced by
  `attestation.measuredBoot`, an object carrying the chain digest and the
  component sequence that hashes to it.
- `attestation.platformEvidence` is an object carrying a digest and an
  encoding label, rather than a bare string.
- `attestation.validity` is added and is REQUIRED. It carries `notBefore` and
  `notAfter`. `notAfter` MUST be strictly later than `notBefore`; a
  zero-length interval is rejected. This revision does not require a Verifier
  to test `ts` against the interval, and says so rather than implying a check
  that does not happen.
- The *TEE Class* registry is stated to be requested and not yet allocated,
  and the route by which a value is added is stated explicitly, so that an
  implementer on an unlisted confidential-compute environment has a documented
  path rather than only a rejection.
- The TEE Class registry values name confidential-compute environments rather
  than instruction set architectures.
- The Section 4 example is a complete, literal instance emitted by the
  reference implementation, and is asserted byte-identical to that
  implementation in its continuous integration. The -00 figure was a schema
  template rendered in a JSON code block and did not parse as JSON.

### Corrections and added normative requirements

- The claim that the hash chain detects tail truncation is **withdrawn**. The
  `chain` field does not detect the withholding of the most recent receipts in
  any presentation, and does not detect equivocation. Section 7.2 is rewritten
  to state what the chain does and does not establish, and to attribute
  detection of either condition to evidence obtained from outside the
  presentation. The Abstract no longer asserts truncation detection, and the
  corresponding Section 1 scope bullet is rewritten. An appeal to TEE
  attestation as establishing recency is removed as unsound: a TEE
  establishes that it wrote the state it attests, not that that state is the
  most recent.
- The `chain` construction is now specified **normatively in this document**.
  `-00` deferred part of it to {{I-D.noa-scitt-ai-agent-receipt}}; that
  document is now cited for provenance only, and no conformance requirement of
  this profile depends on it.
- `chain.seq` is stated as **non-negative** rather than monotonic, and the
  first receipt in a chain MUST carry `chain.seq` 0. `-00` used "monotonic",
  which does not constrain a single receipt and did not state the head value.
- **Two chain-level verification requirements are added.** A Chain-Verifier
  presented with two or more receipts as one contiguous chain MUST check
  `chain.seq` contiguity and MUST check that each `chain.prevHash` equals the
  preceding receipt's `chain.hash`. `-00` described these properties as
  holding without requiring any party to check them. *Chain-Verifier* is
  defined in Section 2.
- **`chain.prevHash` is redefined to remove an inconsistency that made the
  chain check unsatisfiable.** `-00` and an earlier draft of this revision
  defined `chain.prevHash` as a digest of "the immediately preceding
  receipt", while defining `chain.hash` as a digest taken with the
  `chain.hash` member absent. Read literally, those two definitions do not
  produce equal values, so the adjacent-pair check added above would have
  rejected every honest chain. `chain.prevHash` now carries the preceding
  receipt's `chain.hash` value by reference to that member rather than by an
  independent digest definition, and the exclusion is restated in both
  places. This was found by constructing a three-receipt chain and
  evaluating the requirement against it.
- **Registration is now mandatory.** An Issuer MUST register every receipt it
  issues with at least one Transparency Service, and a relying party MUST NOT
  accept a receipt as conforming without a verifying attached Receipt from a
  Transparency Service it trusts. `-00` described registration as REQUIRED in
  its scope discussion without stating the requirement normatively. Where the
  Transparency Service is operated by the Issuer or an affiliate, that
  relationship MUST be disclosed and MUST NOT be treated as evidence external
  to the Issuer.
- A relying party **SHOULD** retain the highest verified `chain.seq` per chain
  as an anchor. The limits of that anchor, and the absence of any remedy
  defined by this profile, are stated explicitly.
- Section 7.5 no longer states that an Issuer cannot prevent an equivocated
  chain from being detected once registered. An Issuer that does not register
  is not detected by that mechanism; the mandatory-registration requirement is
  the response to that gap.

# Acknowledgments
{:numbered="false"}

The author thanks the SCITT WG for RFCs 9942 and 9943, and the authors of
{{I-D.noa-scitt-ai-agent-receipt}} and {{I-D.mih-scitt-agent-action-capsule}}
for establishing the SCITT-AI receipt idiom on which this profile builds.

The author thanks GitHub user giskard09 for a detailed public review of the
`-01` adapter and verifier semantics. That review identified that
`adapter.ackDigest` was structurally unable to distinguish an acknowledgement
authored by an independent operations layer from one authored by the Issuer,
and pressed for the distinction to be carried in the receipt rather than left
to out-of-band context. The `adapter.ackProvenance` member defined in
{{payload}} is the result. The requirement that a value outside its closed set
be surfaced as unrecognized, rather than read as `THIRD_PARTY` or normalized to
`NONE`, is also his.
