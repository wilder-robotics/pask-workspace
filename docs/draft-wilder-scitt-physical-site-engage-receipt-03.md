---
title: "A SCITT Profile for Physical-Site Engagement Receipts"
abbrev: "Physical-Site Engagement Receipt"
docname: draft-wilder-scitt-physical-site-engage-receipt-03
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
  RFC8785:
  RFC9052:
  RFC9597:
  RFC9942:
  RFC9943:

informative:
  RFC7942:
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
- Specify a deterministic offline REPLAY of any engagement decision.
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
  `wilder.pser/0.5` and a SCITT Receipt attached as defined in
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

The profile identifier for this document is `wilder.pser/0.5` and MUST appear
as the value of the top-level `spec` member of the payload defined in
{{payload}}.

The COSE `content_type` (protected header label 3, {{RFC9052}}) for a
Physical-Site Engagement Receipt Statement is
`application/pser+json; profile=wilder.pser/0.5`. IANA registration of this
media type is requested in {{iana}}.

The `application/scitt-statement+cose` and `application/scitt-receipt+cose`
media types from {{RFC9943}} apply unchanged to Statements and Receipts under
this profile.

# Receipt structure {#payload}

A Physical-Site Engagement Receipt is a SCITT Signed Statement per
{{RFC9943}} Section 6, encoded as a COSE_Sign1 per {{RFC9052}}. The payload
is a JSON object serialized with JCS {{RFC8785}} and carried as the
`COSE_Sign1` payload.

The following is a complete example instance. It is not a schema: every value
is literal, the whole object parses as JSON, and the `chain.hash` value is the
digest this profile specifies over the rest of the object. Normative member
definitions are in Section 4.1; where this example and Section 4.1 disagree,
Section 4.1 governs.

This figure is emitted by the reference implementation and asserted
byte-identical to it in that implementation's continuous integration. It is
not maintained by hand.

Its values are illustrative. The digests are placeholders, the identifiers are
synthetic, and the `teeClass` value is one conforming registry entry chosen so
the example round-trips. This profile does not prefer, presume, or depend on
any particular confidential-compute environment, and no value in this figure
should be read as a statement about deployed hardware.

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
    "hash": "sha256:6de1b8b2c641536b35fada1a7ee233c68284cf3788408a7160d5f525c309d2b3",
    "prevHash": null,
    "seq": 0
  },
  "engagement": {
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
  "spec": "wilder.pser/0.5",
  "ts": "2026-10-15T14:00:00Z"
}
~~~
{: title="Physical-Site Engagement Receipt payload"}

## Field semantics

### `spec` (REQUIRED, string)

MUST be `wilder.pser/0.5` for receipts conforming to this document. A verifier
MUST reject any Statement with a different `spec` value as out of scope of
this profile.

### `id` (REQUIRED, string)

A globally unique identifier for the receipt, assigned by the Issuer. RECOMMENDED
form is a URN or a `uuid:` prefix. `id` MUST NOT be reused within an Issuer.

### `ts` (REQUIRED, string)

RFC 3339 UTC timestamp at which the Issuer sealed the receipt. This is the
receipt-issuance time; it MAY differ from `engagement.window.end`.

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
  SHOULD be used as the value of the CWT `sub` claim in the protected
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

### `attestation` (REQUIRED, object)

Binds the receipt to the TEE that observed the engagement. This is the
mechanism that distinguishes a Physical-Site Engagement Receipt from a bare
signed timestamp: the sealed evidence attests that the Issuer observed the
engagement from inside a hardware-rooted, remotely attestable environment.

- `attestation.teeClass` (REQUIRED, string): TEE class identifier.
  Registry-governed; see {{iana}}. The *TEE Class* registry is REQUESTED by
  this document and has NOT yet been allocated by IANA. Until allocation, the
  admissible values are exactly the initial values listed in {{iana}}:
  `intel.tdx`, `amd.sev-snp`, `arm.cca`, `nvidia.h100-cc`,
  `nvidia.jetson-thor-cc`, `aws.nitro-enclave`. A Verifier MUST reject a
  `teeClass` value outside that set.

  A confidential-compute environment absent from that set is not
  accommodated by this revision, and an implementer on such an environment
  has no conforming value to emit. The extension route is the registration
  policy in {{iana}}: "Specification Required". A new value is added by
  publishing a specification that defines the `platformEvidence` format the
  class admits, and requesting registration against it. Once the registry is
  allocated, that route does not require a revision of this document.
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
  This revision does not
  require a Verifier to test `ts` against the interval.

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

- `iss` (CWT claim label 1): a URI identifying the Issuer.
- `sub` (CWT claim label 2): the value of `site.id` from the payload, so
  that SCITT registration policies can be expressed over the standard `sub`
  claim.

The protected header `content_type` (label 3) MUST be
`application/pser+json; profile=wilder.pser/0.5`.

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

- *Direct-witness mode:* the Issuer's `iss` key is itself the TEE signer.
  `attestation.witnessKey` matches `iss`.
- *Delegated-witness mode:* the Issuer's `iss` key is distinct from the
  TEE signer, and the TEE has issued a delegation credential authorizing
  the Issuer to sign this receipt on the TEE's behalf. The delegation
  credential is bound by the `attestation.sealedEvidence.digest` and is an
  Issuer-published fact resolved under {{issuer-published}}. Where it does not
  resolve, the authorization of the signing key is **undetermined** and the
  Verifier proceeds as required by that section.

## Clock basis {#clock-basis}

All timestamps in a Physical-Site Engagement Receipt MUST share a single
clock basis: the clock the TEE observed at the time it sealed the evidence
bundle. Implementations MUST NOT mix wall-clock timestamps with TEE-observed
timestamps within a single receipt. Verifiers MUST derive elapsed-time
computations from the receipt's own bytes, not from the verifier's local
wall clock.

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
`profile` parameter and profile value `wilder.pser/0.5`.

## COSE Header Parameters

This document does not register new COSE header parameter labels. It uses
only labels defined in {{RFC9052}}, {{RFC9597}}, and {{RFC9943}}.

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

## Privacy

Site identifiers, actor identifiers, and engagement types MAY be sensitive.
Issuers SHOULD publish only the digests of envelope documents and internal
evidence structures, as this profile requires. Issuers MAY additionally
choose to encrypt the Statement payload under a per-relying-party key and
publish only the Signed Statement's Receipt to a public Transparency
Service, following the guidance in {{RFC9943}} Section 6.2 for sensitive
Statements.

# Implementation status

This section records the status of known implementations of the protocol
defined by this specification at the time of posting, and is based on a
proposal described in {{RFC7942}}. The description of implementations in this
section is intended to assist the IETF in its decision processes in
progressing drafts to RFCs. This section is to be removed before publishing as
an RFC.

**Reference implementation.** `pask-workspace`, Rust, five crates
(`pask-wire`, `pask-attest`, `pask-site`, `pask-adapter`, `pask-wire-cli`).
Maturity: prototype. Coverage of this profile is partial and the gaps below are
normative requirements this revision states and the implementation does not yet
meet.

- **Transparency Service registration is not implemented.** No crate registers
  a Signed Statement with any Transparency Service, and none consumes an
  attached Receipt. Consequently every receipt this implementation has produced
  to date is non-conforming under Section 6 of this document, and no
  end-to-end verification path exists.
- **All three Chain-Verifier obligations of Section 4.1 are implemented** in
  `pask-wire` and exercised in continuous integration against the conforming
  and non-conforming chain test data referenced in Section 4.1, including the
  `issuerAffiliation` comparison added in this revision, which returns the
  points at which the value changed rather than a pass or fail. This corrects
  the statement in `-01`, which reported the two checks it defined as
  unimplemented and was accurate when filed.
- **Single-receipt structure, COSE encoding, JCS canonicalization, the field
  semantics of Section 4.1 and the attestation binding of Section 4.3 are
  implemented** and exercised in continuous integration. The example figure in
  Section 4 is emitted by the implementation and asserted byte-identical to it.
- **The crate disagreement reported in `-01` is resolved.** `-01` recorded
  that `pask-wire` admitted `notAfter == notBefore` where `pask-attest`
  required strictly greater, and that the document did not state which was
  correct. Section 4.1 of this document now states the rule, and both crates
  enforce it.
- **`adapter.ackProvenance` is implemented** in `pask-wire` and `pask-site`,
  including the requirement that an unrecognized value be preserved as
  received and surfaced as unrecognized rather than read as `THIRD_PARTY` or
  normalized to `NONE`. A conformance vector for that case ships with the
  implementation.
- **The witness key lifecycle assertions of Section 7.6 are not implemented.**
  No crate emits, consumes, or orders an assertion about a witness key. The
  section states normative Verifier behaviour that the implementation does not
  yet exhibit.

The author is aware of no other implementation of this profile.

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

This profile does NOT invent a new wire format. A Physical-Site Engagement
Receipt is a SCITT Signed Statement (COSE_Sign1) and verifies in any
conforming COSE implementation and composes with any SCITT Transparency
Service.

--- back

# Change log

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
