// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{Error, Result, sha256_prefixed, validate_sha256};

/// Supported PSER profile version.
pub const SPEC_VERSION: &str = "wilder.pser/0.4";

/// Wire strings for the three named `adapter.ackProvenance` values.
///
/// The value space is a closed set enumerated in the profile document rather
/// than an IANA registry, so these strings are the whole of it. A conforming
/// producer MUST emit one of them.
const ACK_PROVENANCE_THIRD_PARTY: &str = "THIRD_PARTY";
const ACK_PROVENANCE_ISSUER_ASSERTED: &str = "ISSUER_ASSERTED";
const ACK_PROVENANCE_NONE: &str = "NONE";

/// Wire strings for the three named `issuerAffiliation` values.
///
/// Closed set, enumerated in the profile document rather than an IANA registry.
/// A conforming producer MUST emit one of them.
const ISSUER_AFFILIATION_AFFILIATED: &str = "AFFILIATED";
const ISSUER_AFFILIATION_INDEPENDENT: &str = "INDEPENDENT";
const ISSUER_AFFILIATION_NOT_DISCLOSED: &str = "NOT_DISCLOSED";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Site {
    id: String,
    class: SiteClass,
    envelope: SiteEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SiteClass {
    Residential,
    Industrial,
    Healthcare,
    Infra,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteEnvelope {
    id: String,
    digest: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    geobounds: Option<String>,
    temporal: Temporal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Temporal {
    #[serde(deserialize_with = "deserialize_required_option")]
    starts: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    ends: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    id: String,
    class: ActorClass,
    operator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ActorClass {
    Autonomous,
    SemiAutonomous,
    Human,
    Crew,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Engagement {
    id: String,
    window: Window,
    r#type: String,
    outcome_class: OutcomeClass,
    envelope_conformance: EnvelopeConformance,
    evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    start: String,
    end: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum OutcomeClass {
    Completed,
    Aborted,
    Refused,
    Errored,
    ObservedOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EnvelopeConformance {
    Within,
    ExceededTemporal,
    ExceededGeo,
    ExceededActor,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Attestation {
    tee_class: String,
    measured_boot: MeasuredBoot,
    platform_evidence: PlatformEvidence,
    sealed_evidence: SealedEvidence,
    witness_key: String,
    validity: Validity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MeasuredBoot {
    chain: String,
    components: Vec<MeasuredBootComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MeasuredBootComponent {
    name: String,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PlatformEvidence {
    encoding: String,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Validity {
    not_before: String,
    not_after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SealedEvidence {
    digest: String,
    size_bytes: u64,
    encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Adapter {
    system: String,
    endpoint: String,
    posted_at: String,
    ack_digest: String,
    ack_provenance: AckProvenance,
    mode: AdapterMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum AdapterMode {
    #[serde(rename = "WRITE_ONLY")]
    WriteOnly,
}

/// How the acknowledgement recorded in `adapter.ackDigest` was obtained.
///
/// # Why this member exists
///
/// Under a write-only adapter posture there is no read path, so `ackDigest`
/// alone cannot tell a reader whether an independent operations layer
/// acknowledged the write-in or the Issuer authored a minimal acknowledgement
/// object itself when nothing structured came back. The digest proves a digest
/// was computed over something. It does not prove who produced the thing. This
/// member makes the distinction a property of the record instead of a property
/// of the Issuer's unpublished manifest.
///
/// Classification belongs to the profile. What a deployment then *does* about
/// an Issuer-asserted acknowledgement -- refuse, warn, or record and carry on
/// -- is a matter of that deployment's risk appetite and is deliberately not
/// specified here.
///
/// # Why an unrecognised value is preserved rather than rejected
///
/// [`Self::Unrecognized`] carries the exact string that was on the wire. Two
/// rules sit next to each other and they are separate requirements:
///
/// 1. The three named values remain distinguishable from each other.
/// 2. An unrecognised value is surfaced as unrecognised. It is not read as
///    [`Self::ThirdParty`] and it is not normalised to [`Self::NoAcknowledgement`].
///
/// The second rule is the one that is easy to get wrong, because the obvious
/// instinct is to fail closed on anything unrecognised. **That instinct is
/// correct for an enumeration feeding a pre-action gate and wrong here, and the
/// difference is the cost function underneath it.** At a gate, refusing costs
/// availability and the action simply does not happen. This member is a
/// descriptive property of a record that gets read afterwards, often by
/// somebody reconstructing an event months later. Refusing there means refusing
/// the record, and refusing the record destroys the reconstruction the record
/// exists to serve. Once the engagement has already happened, refusal is not
/// the conservative choice.
///
/// Normalising to [`Self::NoAcknowledgement`] is the same collapse pointing the
/// other way: it manufactures a positive claim that the operations layer
/// returned nothing, which is a substantive statement about what happened at the
/// site and may be false.
///
/// So the profile is **closed on the producing side and tolerant on the
/// consuming side.** A conforming producer MUST emit one of the three named
/// values; a verifier MUST NOT refuse a receipt solely because this member
/// carries something else, and MUST surface it as unrecognised.
///
/// # Serialization
///
/// `Serialize` and `Deserialize` are written by hand rather than derived.
/// `#[serde(other)]` would discard the unrecognised string, which fails rule 2:
/// the value has to stay available to the reader, not merely be distinguishable
/// as "not one of ours". Round-tripping is byte-exact, which matters because the
/// payload is signed over its JCS serialization -- a variant that re-serialised
/// to anything other than the original bytes would invalidate the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckProvenance {
    /// An independent operations layer produced the acknowledgement. Wire value
    /// `THIRD_PARTY`.
    ///
    /// Under a write-only posture this remains the Issuer's claim about a third
    /// party rather than an independently verified fact. The profile does not
    /// name this state `CONFIRMED` for exactly that reason.
    ThirdParty,
    /// The Issuer authored the acknowledgement object itself. Wire value
    /// `ISSUER_ASSERTED`.
    IssuerAsserted,
    /// No acknowledgement was obtained. Wire value `NONE`.
    ///
    /// Named `NoAcknowledgement` in Rust rather than `None`, which would shadow
    /// [`Option::None`] at every use site and produce compiler messages that
    /// read as if the option type were involved. The wire string is pinned by
    /// hand and is unaffected.
    NoAcknowledgement,
    /// A value outside the closed set, preserved exactly as it appeared.
    ///
    /// A receipt carrying this is not conforming. It still parses, still
    /// validates, and still presents this member to the reader, for the reasons
    /// in the type-level documentation.
    Unrecognized(String),
}

impl AckProvenance {
    /// Returns the wire string for this value.
    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::ThirdParty => ACK_PROVENANCE_THIRD_PARTY,
            Self::IssuerAsserted => ACK_PROVENANCE_ISSUER_ASSERTED,
            Self::NoAcknowledgement => ACK_PROVENANCE_NONE,
            Self::Unrecognized(raw) => raw,
        }
    }

    /// Returns `true` when the value is outside the closed set the profile names.
    ///
    /// A verifier that surfaces the acknowledgement-provenance state to a reader
    /// uses this rather than comparing against the named variants, so that an
    /// unrecognised value cannot be silently folded into one of them.
    #[must_use]
    pub const fn is_unrecognized(&self) -> bool {
        matches!(self, Self::Unrecognized(_))
    }
}

impl Serialize for AckProvenance {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire_str())
    }
}

impl<'de> Deserialize<'de> for AckProvenance {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            ACK_PROVENANCE_THIRD_PARTY => Self::ThirdParty,
            ACK_PROVENANCE_ISSUER_ASSERTED => Self::IssuerAsserted,
            ACK_PROVENANCE_NONE => Self::NoAcknowledgement,
            // Deliberately not an error. See the type-level documentation: this
            // is a record read after the fact, and refusing it destroys the
            // reconstruction it exists for. The raw string is retained so the
            // value stays distinguishable from both THIRD_PARTY and NONE.
            _ => Self::Unrecognized(raw),
        })
    }
}

/// Whether the Site Owner and the Issuer are affiliated parties.
///
/// # Why this member exists
///
/// Nothing else in a receipt tells a reader whether the party that controls the
/// site and the party that issued the receipt are related. A reader who cannot
/// see the relationship has no way to check it, and the natural reading of
/// silence is that the two are unrelated. That reading is a claim, and it is a
/// claim nobody made.
///
/// The failure is the same shape as an unrecognised [`AckProvenance`] read as
/// [`AckProvenance::ThirdParty`], one level up: an unknown resolved in the
/// receipt's favour rather than surfaced as unknown. So the fix is the same.
/// Name the unknown, and make naming it the default rather than the exception.
///
/// This does not overlap the profile's prohibition on collapsing two of the
/// three trust roles into one principal. That rule addresses one principal
/// wearing two hats. This member addresses the ordinary and far more common
/// case of three distinct principals, two of which are related.
///
/// # What the profile does and does not do with it
///
/// The Issuer signs the receipt, so this member is the Issuer's statement about
/// the Issuer's own standing. **The profile records that statement. It does not
/// verify it, and no verification of it is possible from the receipt bytes.**
///
/// That is a weaker guarantee than it first appears to be and it is still worth
/// having. A false value here is a false statement inside a signed, timestamped,
/// registered record, attributable to the key that signed it and discoverable by
/// anyone auditing the log. Silence is unfalsifiable and costs a dishonest
/// Issuer nothing at all. The whole profile rests on that trade.
///
/// # Why REQUIRED rather than optional
///
/// Identical reasoning to [`AckProvenance`]: an absent member would itself have
/// to be assigned a meaning, and every available meaning is wrong. Read as
/// independent, it manufactures the claim this member exists to prevent. Read as
/// affiliated, it defames an Issuer that simply predates the member. Read as
/// unknown, it duplicates [`Self::NotDisclosed`] while being indistinguishable
/// from a producer that forgot.
///
/// [`Self::NotDisclosed`] is the honest default value. A producer that has not
/// established the relationship, or that declines to state it, emits it
/// explicitly.
///
/// # Why an unrecognised value is preserved rather than rejected
///
/// See [`AckProvenance`]. The cost function is the same one: this is a
/// descriptive property of a record read after the fact, refusing the record
/// destroys the reconstruction it exists to serve, and normalising to
/// [`Self::NotDisclosed`] manufactures a positive claim that nobody disclosed
/// anything when in fact somebody may have disclosed something this build does
/// not recognise.
///
/// # A standing fact carried per receipt
///
/// Affiliation between two principals is a standing relationship, not a fact
/// about one engagement. Carrying it per receipt means a chain can disagree with
/// itself. A verifier that observes the value change within a single chain
/// surfaces the change rather than taking the later value as current, in the same
/// way an ordering that cannot be established is surfaced as undetermined rather
/// than guessed. This crate exposes [`Payload::issuer_affiliation`] so a chain
/// verifier can make that comparison; the comparison itself is a chain-level
/// concern and is not performed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerAffiliation {
    /// The Site Owner and the Issuer are affiliated parties, and the Issuer
    /// discloses it. Wire value `AFFILIATED`.
    ///
    /// The profile does not prohibit this arrangement. It requires that the
    /// weaker standing of a receipt issued under it be visible rather than
    /// implied, which is the same treatment already given to an Issuer that
    /// registers with a Transparency Service it operates itself.
    Affiliated,
    /// The Issuer asserts that it and the Site Owner are unaffiliated. Wire
    /// value `INDEPENDENT`.
    ///
    /// An assertion by the Issuer about the Issuer. Not independently verified,
    /// and not verifiable from the receipt bytes.
    Independent,
    /// The relationship is not disclosed. Wire value `NOT_DISCLOSED`.
    ///
    /// The default, and an honest one. It states that nobody made a claim, which
    /// is different from a claim of independence and must not be read as one.
    NotDisclosed,
    /// A value outside the closed set, preserved exactly as it appeared.
    ///
    /// A receipt carrying this is not conforming. It still parses, still
    /// validates, and still presents this member to the reader.
    Unrecognized(String),
}

impl IssuerAffiliation {
    /// Returns the wire string for this value.
    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::Affiliated => ISSUER_AFFILIATION_AFFILIATED,
            Self::Independent => ISSUER_AFFILIATION_INDEPENDENT,
            Self::NotDisclosed => ISSUER_AFFILIATION_NOT_DISCLOSED,
            Self::Unrecognized(raw) => raw,
        }
    }

    /// Returns `true` when the value is outside the closed set the profile names.
    ///
    /// A verifier that surfaces the affiliation state to a reader uses this
    /// rather than comparing against the named variants, so that an unrecognised
    /// value cannot be silently folded into one of them.
    #[must_use]
    pub const fn is_unrecognized(&self) -> bool {
        matches!(self, Self::Unrecognized(_))
    }

    /// Returns `true` when the receipt carries no disclosure of the relationship.
    ///
    /// Deliberately distinct from [`Self::is_unrecognized`]. A reader that
    /// collapses "nobody disclosed" and "disclosed something I do not recognise"
    /// into one state loses the difference between an Issuer that declined to
    /// speak and an Issuer that spoke in a vocabulary this build predates.
    #[must_use]
    pub const fn is_not_disclosed(&self) -> bool {
        matches!(self, Self::NotDisclosed)
    }
}

impl Serialize for IssuerAffiliation {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire_str())
    }
}

impl<'de> Deserialize<'de> for IssuerAffiliation {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            ISSUER_AFFILIATION_AFFILIATED => Self::Affiliated,
            ISSUER_AFFILIATION_INDEPENDENT => Self::Independent,
            ISSUER_AFFILIATION_NOT_DISCLOSED => Self::NotDisclosed,
            // Deliberately not an error, for the reasons in the type-level
            // documentation. The raw string is retained so the value stays
            // distinguishable from both INDEPENDENT and NOT_DISCLOSED.
            _ => Self::Unrecognized(raw),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Chain {
    seq: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    prev_hash: Option<String>,
    hash: String,
}

/// Reads only `spec` and rejects a version this build does not implement.
///
/// This runs **before** the full deserialization, and the ordering is the whole
/// point of it. Deserializing first and checking the version afterwards produces
/// an honest answer only while every revision happens to carry the same members.
/// The moment a revision requires a member an earlier one did not carry -- which
/// is exactly what `wilder.pser/0.4` does with `adapter.ackProvenance` -- a
/// receipt from the earlier revision fails on the missing member and the caller
/// is told a member is absent when the real and far more useful answer is that
/// the receipt is from a revision this build does not implement. One diagnosis
/// sends an operator looking for a malformed producer; the other tells them to
/// upgrade the verifier.
///
/// Measured on `wilder.pser/0.3` before this check existed: a receipt whose
/// version *and* member shape both differed reported
/// `unknown field ...`, while a receipt differing in version alone reported
/// `unsupported spec version` correctly. Only the first case was wrong, and only
/// the first case is the one a real version skew produces.
///
/// The permissive intermediate parse is deliberate: this stage must tolerate a
/// document it cannot fully model, or it could not report the version at all.
fn check_spec_version(bytes: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    struct SpecOnly {
        spec: String,
    }

    // A document too malformed to yield a `spec` string is not a version
    // problem. Say nothing and let the full parse produce the real diagnosis.
    if let Ok(probe) = serde_json::from_slice::<SpecOnly>(bytes)
        && probe.spec != SPEC_VERSION
    {
        return Err(Error::Validation("unsupported spec version"));
    }
    Ok(())
}

fn deserialize_required_option<'de, D, T>(
    deserializer: D,
) -> core::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Strongly typed `wilder.pser/0.4` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Payload {
    spec: String,
    id: String,
    ts: String,
    issuer_affiliation: IssuerAffiliation,
    site: Site,
    actor: Actor,
    engagement: Engagement,
    attestation: Attestation,
    adapter: Adapter,
    chain: Chain,
}

impl Payload {
    /// Parses JSON and validates every profile rule, including `chain.hash`.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON parsing or any profile validation rule fails.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        check_spec_version(bytes)?;
        let payload: Self =
            serde_json::from_slice(bytes).map_err(|error| Error::Json(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    /// Parses producer input, replaces the supplied `chain.hash`, and validates the result.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON parsing, hashing, or any profile validation rule fails.
    pub fn from_json_for_production(bytes: &[u8]) -> Result<Self> {
        check_spec_version(bytes)?;
        let mut payload: Self =
            serde_json::from_slice(bytes).map_err(|error| Error::Json(error.to_string()))?;
        payload.update_chain_hash()?;
        payload.validate()?;
        Ok(payload)
    }

    /// Returns the RFC 8785 JCS serialization of the complete payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cannot be serialized.
    pub fn to_jcs(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self).map_err(|error| Error::Json(error.to_string()))?;
        canonicalize_value(&value)
    }

    /// Returns the stable site identifier used as the CWT subject.
    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site.id
    }

    /// Returns the witness key identifier used as the CWT issuer by the CLI.
    #[must_use]
    pub fn witness_key(&self) -> &str {
        &self.attestation.witness_key
    }

    /// Returns the stored chain digest.
    #[must_use]
    pub fn chain_hash(&self) -> &str {
        &self.chain.hash
    }

    /// Returns the receipt's position in its chain.
    #[must_use]
    pub fn chain_seq(&self) -> u64 {
        self.chain.seq
    }

    /// Returns the preceding receipt's `chain.hash`, or `None` at sequence zero.
    #[must_use]
    pub fn chain_prev_hash(&self) -> Option<&str> {
        self.chain.prev_hash.as_deref()
    }

    /// Returns whether the Site Owner and the Issuer are affiliated parties.
    ///
    /// A value outside the closed set is returned as
    /// [`IssuerAffiliation::Unrecognized`] carrying the original string, never
    /// folded into one of the named values. [`IssuerAffiliation::NotDisclosed`]
    /// means nobody made a claim and MUST NOT be read as a claim of
    /// independence. See [`IssuerAffiliation`] for why.
    #[must_use]
    pub const fn issuer_affiliation(&self) -> &IssuerAffiliation {
        &self.issuer_affiliation
    }

    /// Returns how the acknowledgement in `adapter.ackDigest` was obtained.
    ///
    /// A value outside the closed set is returned as
    /// [`AckProvenance::Unrecognized`] carrying the original string, never
    /// folded into one of the named values. See [`AckProvenance`] for why.
    #[must_use]
    pub const fn adapter_ack_provenance(&self) -> &AckProvenance {
        &self.adapter.ack_provenance
    }

    /// Returns the stable actor identifier.
    #[must_use]
    pub fn actor_id(&self) -> &str {
        &self.actor.id
    }

    /// Returns the operator string associated with the actor.
    #[must_use]
    pub fn actor_operator(&self) -> &str {
        &self.actor.operator
    }

    /// Returns the stable engagement identifier.
    #[must_use]
    pub fn engagement_id(&self) -> &str {
        &self.engagement.id
    }

    /// Returns the engagement type string (RFC 3986 URI or short identifier per §6 of the draft).
    #[must_use]
    pub fn engagement_type(&self) -> &str {
        &self.engagement.r#type
    }

    /// Returns the RFC 3339 UTC start of the engagement window.
    #[must_use]
    pub fn engagement_window_start(&self) -> &str {
        &self.engagement.window.start
    }

    /// Returns the RFC 3339 UTC end of the engagement window.
    #[must_use]
    pub fn engagement_window_end(&self) -> &str {
        &self.engagement.window.end
    }

    /// Returns the SHA-256 digest of the raw evidence bundle referenced by this engagement.
    #[must_use]
    pub fn engagement_evidence_digest(&self) -> &str {
        &self.engagement.evidence_digest
    }

    /// Returns the TEE class identifier.
    #[must_use]
    pub fn attestation_tee_class(&self) -> &str {
        &self.attestation.tee_class
    }

    /// Returns the SHA-256 digest of the sealed evidence blob.
    #[must_use]
    pub fn sealed_evidence_digest(&self) -> &str {
        &self.attestation.sealed_evidence.digest
    }

    /// Returns the size in bytes of the sealed evidence blob.
    #[must_use]
    pub fn sealed_evidence_size_bytes(&self) -> u64 {
        self.attestation.sealed_evidence.size_bytes
    }

    /// Returns the sealed evidence encoding identifier.
    #[must_use]
    pub fn sealed_evidence_encoding(&self) -> &str {
        &self.attestation.sealed_evidence.encoding
    }

    /// Returns the operations-layer system identifier.
    ///
    /// This value selects which write-in adapter is responsible for pushing this receipt.
    /// Values are defined by the PSER profile registry (see §6 of the draft). Example
    /// values: `"buildium"`, `"propertymeld"`.
    #[must_use]
    pub fn adapter_system(&self) -> &str {
        &self.adapter.system
    }

    /// Returns the opaque per-system endpoint identifier.
    ///
    /// The value is interpreted by the target adapter, not by `pask-wire`. For the
    /// `buildium` adapter it is the Buildium rental property ID; for other adapters,
    /// consult the adapter documentation.
    #[must_use]
    pub fn adapter_endpoint(&self) -> &str {
        &self.adapter.endpoint
    }

    /// Returns the RFC 3339 UTC timestamp at which the write-in was posted.
    #[must_use]
    pub fn adapter_posted_at(&self) -> &str {
        &self.adapter.posted_at
    }

    /// Returns the SHA-256 digest of the operations-layer acknowledgement.
    #[must_use]
    pub fn adapter_ack_digest(&self) -> &str {
        &self.adapter.ack_digest
    }

    /// Returns whether the receipt is marked WRITE_ONLY.
    ///
    /// Every `wilder.pser/0.3` receipt that parses successfully MUST be WRITE_ONLY;
    /// this accessor exists so downstream adapters can enforce the property as
    /// defense-in-depth without pattern-matching the internal enum.
    #[must_use]
    pub fn adapter_is_write_only(&self) -> bool {
        matches!(self.adapter.mode, AdapterMode::WriteOnly)
    }

    pub(crate) fn parse_canonical(bytes: &[u8]) -> Result<Self> {
        let payload = Self::from_json(bytes)?;
        if payload.to_jcs()?.as_slice() != bytes {
            return Err(Error::NonCanonicalPayload);
        }
        Ok(payload)
    }

    fn update_chain_hash(&mut self) -> Result<()> {
        self.chain.hash = self.expected_chain_hash()?;
        Ok(())
    }

    fn expected_chain_hash(&self) -> Result<String> {
        let mut value =
            serde_json::to_value(self).map_err(|error| Error::Json(error.to_string()))?;
        let chain = value
            .get_mut("chain")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or(Error::Validation("chain must be an object"))?;
        chain.remove("hash");
        let canonical = canonicalize_value(&value)?;
        Ok(sha256_prefixed(&canonical))
    }

    fn validate(&self) -> Result<()> {
        if self.spec != SPEC_VERSION {
            return Err(Error::Validation("unsupported spec version"));
        }
        for value in [
            &self.id,
            &self.site.id,
            &self.site.envelope.id,
            &self.actor.id,
            &self.actor.operator,
            &self.engagement.id,
            &self.engagement.r#type,
            &self.attestation.tee_class,
            &self.attestation.platform_evidence.encoding,
            &self.attestation.sealed_evidence.encoding,
            &self.attestation.witness_key,
            &self.adapter.system,
            &self.adapter.endpoint,
        ] {
            if value.is_empty() {
                return Err(Error::Validation("required string must not be empty"));
            }
        }
        validate_utc(&self.ts)?;
        validate_optional_window(
            self.site.envelope.temporal.starts.as_deref(),
            self.site.envelope.temporal.ends.as_deref(),
        )?;
        let start = validate_utc(&self.engagement.window.start)?;
        let end = validate_utc(&self.engagement.window.end)?;
        if end < start {
            return Err(Error::Validation(
                "engagement window end precedes its start",
            ));
        }
        validate_utc(&self.adapter.posted_at)?;
        validate_sha256(&self.site.envelope.digest)?;
        validate_sha256(&self.engagement.evidence_digest)?;
        validate_sha256(&self.attestation.measured_boot.chain)?;
        validate_sha256(&self.attestation.platform_evidence.digest)?;
        validate_sha256(&self.attestation.sealed_evidence.digest)?;
        for component in &self.attestation.measured_boot.components {
            if component.name.is_empty() {
                return Err(Error::Validation(
                    "measured-boot component name must not be empty",
                ));
            }
            validate_sha256(&component.digest)?;
        }
        let validity_start = validate_utc(&self.attestation.validity.not_before)?;
        let validity_end = validate_utc(&self.attestation.validity.not_after)?;
        // Q3, ruled 2026-08-09: `pask-wire` and `pask-attest` MUST enforce the
        // identical rule. `pask-attest` rejects a zero-length window
        // (`validity.rs`, `not_after <= not_before`); this crate previously
        // accepted one, so a payload could pass one crate and fail the other.
        // That is the Axis-B defect class this revision exists to close, so it
        // is not left standing inside the revision that closes it.
        //
        // The single rule, stated once: notAfter MUST be strictly later than
        // notBefore. A zero-length window asserts validity for an instant of
        // zero duration and has no legitimate producer.
        //
        // Out of scope in `-01`: containment of `ts` within the window is NOT
        // required in this revision. The interval is carried and its internal
        // consistency is checked; nothing validates an event timestamp against
        // it. Stated plainly so no policy author writes a rule this
        // implementation does not enforce.
        if validity_end <= validity_start {
            return Err(Error::Validation(
                "attestation validity notAfter must be strictly later than notBefore",
            ));
        }
        validate_sha256(&self.adapter.ack_digest)?;
        match (self.chain.seq, self.chain.prev_hash.as_deref()) {
            (0, None) => {}
            (0, Some(_)) => {
                return Err(Error::Validation("sequence zero must have null prevHash"));
            }
            (_, Some(previous)) => validate_sha256(previous)?,
            (_, None) => {
                return Err(Error::Validation("nonzero sequence must include prevHash"));
            }
        }
        validate_sha256(&self.chain.hash)?;
        if self.chain.hash != self.expected_chain_hash()? {
            return Err(Error::Validation("chain.hash does not match payload"));
        }
        Ok(())
    }
}

/// Canonicalizes one JSON value according to RFC 8785.
///
/// # Errors
///
/// Returns an error for malformed JSON or values outside the finite I-JSON number domain.
pub fn canonicalize_json(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| Error::Json(error.to_string()))?;
    canonicalize_value(&value)
}

fn canonicalize_value(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => output.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => output.extend_from_slice(b"false"),
        serde_json::Value::Number(number) => {
            let text = if let Some(integer) = number.as_i64() {
                integer.to_string()
            } else if let Some(integer) = number.as_u64() {
                integer.to_string()
            } else {
                let number = number
                    .as_f64()
                    .ok_or(Error::Jcs("number is not representable as f64".to_owned()))?;
                if !number.is_finite() {
                    return Err(Error::Jcs("JCS numbers must be finite".to_owned()));
                }
                ryu_js::Buffer::new().format_finite(number).to_owned()
            };
            output.extend_from_slice(text.as_bytes());
        }
        serde_json::Value::String(string) => {
            let escaped =
                serde_json::to_string(string).map_err(|error| Error::Jcs(error.to_string()))?;
            output.extend_from_slice(escaped.as_bytes());
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            output.push(b'{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let escaped =
                    serde_json::to_string(key).map_err(|error| Error::Jcs(error.to_string()))?;
                output.extend_from_slice(escaped.as_bytes());
                output.push(b':');
                write_canonical(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_utc(value: &str) -> Result<OffsetDateTime> {
    if !value.ends_with('Z') {
        return Err(Error::Validation("timestamp must use UTC Z notation"));
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| Error::Validation("timestamp must be valid RFC 3339"))
}

fn validate_optional_window(starts: Option<&str>, ends: Option<&str>) -> Result<()> {
    let starts = starts.map(validate_utc).transpose()?;
    let ends = ends.map(validate_utc).transpose()?;
    if let (Some(start), Some(end)) = (starts, ends)
        && end < start
    {
        return Err(Error::Validation("temporal end precedes its start"));
    }
    Ok(())
}
