// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{Error, Result, sha256_prefixed, validate_sha256};

/// Supported PSER profile version.
pub const SPEC_VERSION: &str = "wilder.pser/0.2";

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quote: Option<Vec<u8>>,
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
    mode: AdapterMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum AdapterMode {
    #[serde(rename = "WRITE_ONLY")]
    WriteOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Chain {
    seq: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    prev_hash: Option<String>,
    hash: String,
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

/// Strongly typed `wilder.pser/0.2` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    spec: String,
    id: String,
    ts: String,
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
    /// Every `wilder.pser/0.2` receipt that parses successfully MUST be WRITE_ONLY;
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
        if validity_end < validity_start {
            return Err(Error::Validation(
                "attestation validity end precedes its start",
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
    if let (Some(start), Some(end)) = (starts, ends) {
        if end < start {
            return Err(Error::Validation("temporal end precedes its start"));
        }
    }
    Ok(())
}
