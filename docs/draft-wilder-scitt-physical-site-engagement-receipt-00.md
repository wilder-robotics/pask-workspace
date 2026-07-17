---
title: "A SCITT Profile for Physical-Site Engagement Receipts"
abbrev: "Physical-Site Engagement Receipt"
docname: draft-wilder-scitt-physical-site-engagement-receipt-00
category: std
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
  RFC2119:
  RFC8174:
  RFC8392:
  RFC8785:
  RFC9052:
  RFC9110:
  RFC9162:
  RFC9360:
  RFC9597:
  RFC9942:
  RFC9943:

informative:
  I-D.noa-scitt-ai-agent-receipt:
  I-D.mih-scitt-agent-action-capsule:
  RFC3161:
  RFC6838:

--- abstract

This document defines a SCITT profile for *Physical-Site Engagement Receipts*
(PSER): tamper-evident, signed, offline-verifiable records that describe an
autonomous or human-directed physical engagement at a specific real-world site
governed by a defined operating envelope. Each receipt is a SCITT Signed
Statement per {{RFC9943}}, encoded as a COSE_Sign1 {{RFC9052}}, carrying a
canonical ({{RFC8785}}) payload with a five-artifact vocabulary describing (1)
the *Site*, (2) the *Operator* and *Actor*, (3) the *Engagement Window* and
*Envelope*, (4) the *Attestation Evidence* from a Trusted Execution
Environment (TEE), and (5) the *Adapter Write-In* recording that the receipt
was posted into an out-of-band operations layer. A Physical-Site Engagement
Receipt is registerable in any conforming SCITT Transparency Service per
{{RFC9942}} to obtain non-equivocation and tail-truncation properties an
issuer's own chain cannot provide alone.

This profile deliberately makes a NARROW, checkable claim -- "this is a
tamper-evident, signature-verifiable record that a specific engagement
occurred at a specific site under a specific envelope, and its evidence was
sealed by a specific TEE" -- and explicitly does NOT claim that the engagement
was safe, correct, or wise, that the site conditions were as described, or
that any downstream operational outcome followed. Compliance verdicts derived
from the receipt (SLA credit, insurance underwriting, regulatory audit) are
the responsibility of the relying party and its policies, not of this profile.

The profile is designed around a three-party trust model in which no single
party can unilaterally forge or repudiate a receipt: the *site owner* physically
hosts and controls the TEE hardware (they own the box); the *TEE silicon
vendor* attests the key material inside the TEE through its hardware root of
trust (silicon vouches for the key); and the *Issuer* writes the vocabulary,
registers Signed Statements with a Transparency Service, and posts the
resulting receipt into the site's operations layer via a WRITE_ONLY adapter.
This separation is normative in this profile: implementations MUST NOT collapse
these three roles into a single custodian, and relying parties MUST NOT trust a
receipt that lacks any one of them.

--- middle

# Introduction

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
  the authority live on the site owner's premises, attested by the TEE
  silicon vendor, and neither extractable by the site owner nor by the
  Issuer.
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
- *Transparency-service registration.* Non-equivocation and cross-chain
  tail-truncation are detected by the SCITT Transparency Service, not by
  the TEE alone. A TEE on customer premises without external witnessing is
  insufficient; SCITT registration is REQUIRED to complete the trust model.

Physical-Site Engagement Receipts are complementary to, and compose with,
existing SCITT-AI drafts. An AI agent that dispatches a physical robot MAY
emit an Agent Action Capsule per {{I-D.mih-scitt-agent-action-capsule}}
describing the dispatch decision, and the physical engagement that follows
MAY be recorded as one or more Physical-Site Engagement Receipts under this
profile, correlated via the SCITT `sub` claim.

## Requirements Notation

{::boilerplate bcp14-tagged}

## Non-goals

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

These non-goals are NORMATIVE: implementations and relying parties MUST NOT
imply the stronger claims from a receipt.

# Terminology

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
: The time interval [start, end] of the Engagement, expressed in RFC 3339
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
  `wilder.pser/0.2` and a SCITT Receipt attached as defined in
  {{RFC9942}}.

# Profile identifier and media types

The profile identifier for this document is `wilder.pser/0.2` and MUST appear
as the value of the top-level `spec` member of the payload defined in
{{payload}}.

The COSE `content_type` (protected header label 3, {{RFC9052}}) for a
Physical-Site Engagement Receipt Statement is
`application/pser+json; profile=wilder.pser/0.2`. IANA registration of this
media type is requested in {{iana}}.

The `application/scitt-statement+cose` and `application/scitt-receipt+cose`
media types from {{RFC9943}} apply unchanged to Statements and Receipts under
this profile.

# Receipt structure {#payload}

A Physical-Site Engagement Receipt is a SCITT Signed Statement per
{{RFC9943}} Section 6, encoded as a COSE_Sign1 per {{RFC9052}}. The payload
is a JSON object serialized with JCS {{RFC8785}} and carried as the
`COSE_Sign1` payload.

The payload conforms to the following schema. All members are REQUIRED unless
marked OPTIONAL.

~~~ json
{
  "spec": "wilder.pser/0.2",
  "id": "<receipt id>",
  "ts": "<RFC 3339 UTC timestamp>",

  "site": {
    "id": "<stable site id>",
    "class": "<site class (residential|industrial|healthcare|infra|other)>",
    "envelope": {
      "id": "<stable envelope id>",
      "digest": "sha256:<hex>",
      "geobounds": "<geobounds ref or null>",
      "temporal": { "starts": "<RFC 3339|null>",
                    "ends": "<RFC 3339|null>" }
    }
  },

  "actor": {
    "id": "<stable actor id>",
    "class": "AUTONOMOUS|SEMI_AUTONOMOUS|HUMAN|CREW",
    "operator": "<operator id>"
  },

  "engagement": {
    "id": "<engagement id>",
    "window": { "start": "<RFC 3339 UTC>",
                "end":   "<RFC 3339 UTC>" },
    "type": "<engagement type>",
    "outcomeClass": "COMPLETED|ABORTED|REFUSED|ERRORED|OBSERVED_ONLY",
    "envelopeConformance":
      "WITHIN|EXCEEDED_TEMPORAL|EXCEEDED_GEO|EXCEEDED_ACTOR|UNKNOWN",
    "evidenceDigest": "sha256:<hex>"
  },

  "attestation": {
    "teeClass": "<TEE class identifier>",
    "platformEvidence": "<attestation-format ref>",
    "measuredBootChain": "sha256:<hex>",
    "sealedEvidence": {
      "digest": "sha256:<hex>",
      "sizeBytes": <int>,
      "encoding": "<opaque encoding label>"
    },
    "witnessKey": "<key id of the TEE signer>"
  },

  "adapter": {
    "system": "<operations-layer system id>",
    "endpoint": "<opaque endpoint id>",
    "postedAt": "<RFC 3339 UTC>",
    "ackDigest": "sha256:<hex>",
    "mode": "WRITE_ONLY"
  },

  "chain": {
    "seq": <int>,
    "prevHash": "sha256:<hex>|null",
    "hash": "sha256:<hex>"
  }
}
~~~
{: title="Physical-Site Engagement Receipt payload"}

## Field semantics

### `spec` (REQUIRED, string)

MUST be `wilder.pser/0.2` for receipts conforming to this document. A verifier
MUST reject any Statement with a different `spec` value as out of scope of
this profile.

### `id` (REQUIRED, string)

A globally unique identifier for the receipt, assigned by the Issuer. RECOMMENDED
form is a URN or a `uuid:` prefix. `id` MUST NOT be reused within an Issuer.

### `ts` (REQUIRED, string)

RFC 3339 UTC timestamp at which the Issuer sealed the receipt. This is the
receipt-issuance time; it MAY differ from `engagement.window.end`.

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
  Registry-governed; see {{iana}}. Examples the registry MAY seed:
  `intel.tdx`, `amd.sev-snp`, `arm.cca`, `nvidia.h100-cc`,
  `nvidia.jetson-thor-cc`, `aws.nitro-enclave`.
- `attestation.platformEvidence` (REQUIRED, string): reference to the
  platform-native attestation document, in a format defined by the TEE
  class. The document itself MAY be conveyed by reference (URI + digest) or
  inline; when conveyed inline it SHOULD be in the unprotected header of
  the enclosing Signed Statement, not in the payload.
- `attestation.measuredBootChain` (REQUIRED, string): JSON-DIGEST of the
  measured-boot chain.
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
  minimal ack object; the object schema is specified in the Issuer's
  manifest and is bound by the receipt's Merkle inclusion, not published.
- `adapter.mode` (REQUIRED, string): MUST be `WRITE_ONLY` in this revision.
  Read-in modes are explicitly out of scope; see {{security}}.

### `chain` (REQUIRED, object)

Hash-chains successive receipts by the same Issuer to detect in-band
tampering and tail truncation *within* a presented chain, following the
convention established in {{I-D.noa-scitt-ai-agent-receipt}} Section 5.
Equivocation across chains is detected only by SCITT Transparency Service
registration; see {{security}}.

- `chain.seq` (REQUIRED, int): monotonic sequence number within the
  Issuer's chain for the identified Subject.
- `chain.prevHash` (REQUIRED, string or null): JSON-DIGEST of the
  immediately preceding receipt in the chain, or `null` for the first
  receipt.
- `chain.hash` (REQUIRED, string): JSON-DIGEST of the receipt's canonical
  form, excluding the `chain.hash` field itself.

## COSE header requirements {#cose-header}

The protected header of a Signed Statement under this profile MUST include
the CWT Claims header parameter (label 15, {{RFC9597}}), carrying at least:

- `iss` (CWT claim label 1): a URI identifying the Issuer.
- `sub` (CWT claim label 2): the value of `site.id` from the payload, so
  that SCITT registration policies can be expressed over the standard `sub`
  claim.

The protected header `content_type` (label 3) MUST be
`application/pser+json; profile=wilder.pser/0.2`.

The Signed Statement's payload MUST be the JCS serialization of the JSON
object defined in {{payload}}. Detached payloads are NOT PERMITTED under
this revision.

## Attestation binding {#attestation-binding}

The `attestation.witnessKey` field carries the identity of the TEE signer.
This profile permits two attestation-binding modes, which MUST be conveyed
in the Issuer's manifest and MAY be recorded in the CWT Claims Set:

- *Direct-witness mode:* the Issuer's `iss` key is itself the TEE signer.
  `attestation.witnessKey` matches `iss`.
- *Delegated-witness mode:* the Issuer's `iss` key is distinct from the
  TEE signer, and the TEE has issued a delegation credential authorizing
  the Issuer to sign this receipt on the TEE's behalf. The delegation
  credential is bound by the `attestation.sealedEvidence.digest` and MUST
  be resolvable from the Issuer's manifest.

## Clock basis {#clock-basis}

All timestamps in a Physical-Site Engagement Receipt MUST share a single
clock basis: the clock the TEE observed at the time it sealed the evidence
bundle. Implementations MUST NOT mix wall-clock timestamps with TEE-observed
timestamps within a single receipt. Verifiers MUST derive elapsed-time
computations from the receipt's own bytes, not from the verifier's local
wall clock.

# SCITT registration and Receipt attachment

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

# IANA considerations {#iana}

This document requests the following IANA actions.

## Media type registration

Register `application/pser+json` per {{RFC6838}}, with the required
`profile` parameter and profile value `wilder.pser/0.2`.

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

## Equivocation and tail-truncation

The `chain` field defined in {{payload}} detects *in-band* tampering and
*tail truncation within a presented chain*. It does NOT detect *equivocation*
-- an Issuer signing two divergent chains for the same Subject -- nor
*cross-chain tail truncation*. Detection of equivocation and cross-chain
tail truncation REQUIRES registration in a SCITT Transparency Service or
equivalent external witness. This is unchanged from
{{I-D.noa-scitt-ai-agent-receipt}} Section 5.

## Adapter Write-In is write-only in this revision

The Adapter Write-In records that the receipt was posted into an operations
layer. It does NOT permit the operations layer to write back into the
receipt or the TEE. The `adapter.mode` field is fixed to `WRITE_ONLY` in
this revision; a future revision MAY define a `WRITE_READ` mode with
additional security machinery. Implementations that reverse this direction
in a way that permits the operations layer to modify Issuer or TEE state
are NOT conforming to this profile.

## TEE compromise

A compromised TEE can produce receipts that are cryptographically valid
under this profile but describe engagements that did not occur or did not
occur as described. Detection of TEE compromise is out of scope of this
profile and depends on the platform-native attestation supply chain
identified by `attestation.teeClass`. Relying parties SHOULD consult
{{RFC9943}} Section 9 for guidance on Issuer participation and key
management, and the TEE vendor's own security guidance for the specific
`teeClass`.

## Three-party trust model

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
  The Issuer CANNOT sign without a live TEE and CANNOT prevent an equivocated
  chain from being detected once registered.

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

## Identity attribution

Identity attribution above the key level -- linking `iss`, `actor.id`, and
`site.id` to real-world legal or natural persons -- requires an out-of-band
identity manifest. This profile does not specify the identity manifest
format.

## Privacy

Site identifiers, actor identifiers, and engagement types MAY be sensitive.
Issuers SHOULD publish only the digests of envelope documents and internal
evidence structures, as this profile requires. Issuers MAY additionally
choose to encrypt the Statement payload under a per-relying-party key and
publish only the Signed Statement's Receipt to a public Transparency
Service, following the guidance in {{RFC9943}} Section 6.2 for sensitive
Statements.

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

# Acknowledgments
{:numbered="false"}

The author thanks the SCITT WG for RFCs 9942 and 9943, and the authors of
{{I-D.noa-scitt-ai-agent-receipt}} and {{I-D.mih-scitt-agent-action-capsule}}
for establishing the SCITT-AI receipt idiom on which this profile builds.
