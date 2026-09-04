// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Receipt production from site configuration and engagement evidence.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::json;

use pask_wire::AckProvenance;

use crate::{Clock, EvidenceBundle, SiteConfig, SiteError, uuid::deterministic_uuid_v4};

/// Transient inputs for one site engagement.
#[derive(Clone, Debug)]
pub struct EngagementRequest {
    /// Engagement identifier.
    pub engagement_id: String,
    /// Engagement type.
    pub engagement_type: String,
    /// RFC 3339 UTC window start.
    pub window_start: String,
    /// RFC 3339 UTC window end.
    pub window_end: String,
    /// Outcome-class profile discriminant.
    pub outcome_class: String,
    /// Envelope-conformance profile discriminant.
    pub envelope_conformance: String,
    /// Evidence bundle for this engagement.
    pub evidence: EvidenceBundle,
    /// Lowercase `sha256:<64 hex>` adapter acknowledgement digest.
    pub adapter_ack_digest: String,
    /// How the acknowledgement covered by `adapter_ack_digest` was obtained.
    ///
    /// This is a per-engagement fact rather than a site setting, which is why it
    /// lives on the request and not on [`crate::SiteConfig`]. Whether the
    /// operations layer returned something structured is decided by that
    /// exchange, and it may differ between two engagements at the same site on
    /// the same day.
    ///
    /// A producer must state it rather than have it inferred. There is no
    /// default, deliberately: a defaulted value would let a caller ship
    /// `THIRD_PARTY` without ever having decided it was true, which is the exact
    /// collapse this member was added to prevent.
    pub adapter_ack_provenance: AckProvenance,
    /// RFC 3339 UTC adapter-posted timestamp.
    pub adapter_posted_at: String,
    /// Receipt-chain sequence number.
    pub chain_seq: u64,
    /// Previous chain hash, absent for a genesis receipt.
    pub chain_prev_hash: Option<String>,
}

/// Produces signed site receipts and exposes their verifying key.
pub trait SiteProducer: Send + Sync {
    /// Produces a signed receipt for one engagement.
    ///
    /// # Errors
    ///
    /// Returns a site error when evidence, JSON, or wire validation fails.
    fn produce(&self, request: &EngagementRequest) -> Result<Vec<u8>, SiteError>;

    /// Returns the public key corresponding to the producer's signing key.
    #[must_use]
    fn verifying_key(&self) -> VerifyingKey;
}

/// Ed25519 site producer backed by an injected clock and signing key.
pub struct Ed25519SiteProducer {
    config: SiteConfig,
    clock: Arc<dyn Clock>,
    signing_key: SigningKey,
}

impl Ed25519SiteProducer {
    /// Creates a producer from stable configuration and caller-owned inputs.
    #[must_use]
    pub fn new(config: SiteConfig, clock: Arc<dyn Clock>, signing_key: SigningKey) -> Self {
        Self {
            config,
            clock,
            signing_key,
        }
    }
}

impl SiteProducer for Ed25519SiteProducer {
    fn produce(&self, request: &EngagementRequest) -> Result<Vec<u8>, SiteError> {
        let evidence_jcs = request.evidence.to_jcs()?;
        let evidence_digest = pask_wire::sha256_prefixed(&evidence_jcs);
        let sealed_digest = evidence_digest.clone();
        let sealed_size = evidence_jcs.len() as u64;
        let measured_boot_components = self
            .config
            .attestation_measured_boot_components
            .iter()
            .map(|(name, digest)| {
                json!({
                    "name": name,
                    "digest": digest,
                })
            })
            .collect::<Vec<_>>();

        if request.evidence.engagement_id != request.engagement_id {
            return Err(SiteError::EvidenceMismatch);
        }

        let receipt_id = format!(
            "uuid:{}",
            deterministic_uuid_v4(request.engagement_id.as_bytes())
        );
        let timestamp = self.clock.now_rfc3339();
        let document = json!({
            "spec": pask_wire::SPEC_VERSION,
            "id": receipt_id,
            "ts": timestamp,
            "issuerAffiliation": self.config.issuer_affiliation.as_wire_str(),
            "site": {
                "id": self.config.site_id,
                "class": self.config.site_class,
                "envelope": {
                    "id": self.config.envelope_id,
                    "digest": self.config.envelope_digest,
                    "geobounds": self.config.envelope_geobounds,
                    "temporal": {
                        "starts": self.config.envelope_temporal_starts,
                        "ends": self.config.envelope_temporal_ends,
                    },
                },
            },
            "actor": {
                "id": self.config.actor_id,
                "class": self.config.actor_class,
                "operator": self.config.actor_operator,
            },
            "engagement": {
                "id": request.engagement_id,
                "window": {
                    "start": request.window_start,
                    "end": request.window_end,
                },
                "type": request.engagement_type,
                "outcomeClass": request.outcome_class,
                "envelopeConformance": request.envelope_conformance,
                "evidenceDigest": evidence_digest,
            },
            "attestation": {
                // Not configurable, and deliberately so. This producer signs
                // with the same key it names as the witness key, which is the
                // definition of direct-witness mode. Emitting
                // `DELEGATED_WITNESS` would assert that a TEE issued a
                // delegation credential authorising a separate issuer key, and
                // nothing here issues, holds or resolves such a credential. A
                // configuration switch would let a simulator claim a property
                // it cannot produce.
                "bindingMode": "DIRECT_WITNESS",
                "teeClass": self.config.attestation_tee_class,
                "measuredBoot": {
                    "chain": self.config.attestation_measured_boot_chain,
                    "components": measured_boot_components,
                },
                "platformEvidence": {
                    "encoding": self.config.attestation_platform_evidence_encoding,
                    "digest": self.config.attestation_platform_evidence_digest,
                },
                "sealedEvidence": {
                    "digest": sealed_digest,
                    "sizeBytes": sealed_size,
                    "encoding": "opaque/1",
                },
                "witnessKey": self.config.attestation_witness_key,
                "validity": {
                    "notBefore": self.config.attestation_validity_not_before,
                    "notAfter": self.config.attestation_validity_not_after,
                },
            },
            "adapter": {
                "system": self.config.adapter_system,
                "endpoint": self.config.adapter_endpoint,
                "postedAt": request.adapter_posted_at,
                "ackDigest": request.adapter_ack_digest,
                "ackProvenance": request.adapter_ack_provenance.as_wire_str(),
                "mode": "WRITE_ONLY",
            },
            "chain": {
                "seq": request.chain_seq,
                "prevHash": request.chain_prev_hash,
                "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            },
        });
        let bytes = serde_json::to_vec(&document)
            .map_err(|error| SiteError::JsonError(error.to_string()))?;
        let payload = pask_wire::Payload::from_json_for_production(&bytes)
            .map_err(|error| SiteError::WireError(error.to_string()))?;
        pask_wire::produce_ed25519(&payload, payload.witness_key(), &self.signing_key)
            .map_err(|error| SiteError::WireError(error.to_string()))
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}
