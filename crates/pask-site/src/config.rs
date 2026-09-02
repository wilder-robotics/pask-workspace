// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Stable site-producer configuration.

/// Identity and adapter configuration for a site producer.
#[derive(Clone, Debug)]
pub struct SiteConfig {
    /// Site identifier.
    pub site_id: String,
    /// Site class as a lowercase profile value.
    pub site_class: String,
    /// Envelope identifier.
    pub envelope_id: String,
    /// Lowercase `sha256:<64 hex>` envelope digest.
    pub envelope_digest: String,
    /// Optional envelope temporal-window start.
    pub envelope_temporal_starts: Option<String>,
    /// Optional envelope temporal-window end.
    pub envelope_temporal_ends: Option<String>,
    /// Optional envelope geobounds.
    pub envelope_geobounds: Option<String>,
    /// Whether the Site Owner and the Issuer are affiliated parties.
    ///
    /// This is a standing relationship between two principals, not a fact about
    /// one engagement, which is why it sits here and not on
    /// [`crate::ReceiptRequest`] alongside `adapter_ack_provenance`. Two
    /// engagements at the same site on the same day cannot disagree about it,
    /// and a chain in which the value changes is something a verifier is
    /// expected to surface rather than absorb.
    ///
    /// There is no default, deliberately. The safe value is
    /// [`pask_wire::IssuerAffiliation::NotDisclosed`] and a caller who wants it
    /// has to say so, because "nobody thought about it" and "we decline to
    /// state it" should be the same deliberate act rather than one hiding
    /// inside the other.
    pub issuer_affiliation: pask_wire::IssuerAffiliation,
    /// Actor identifier.
    pub actor_id: String,
    /// Actor class as a profile discriminant.
    pub actor_class: String,
    /// Actor operator string.
    pub actor_operator: String,
    /// TEE class identifier.
    pub attestation_tee_class: String,
    /// Platform-evidence encoding identifier.
    pub attestation_platform_evidence_encoding: String,
    /// Lowercase `sha256:<64 hex>` platform-evidence digest.
    pub attestation_platform_evidence_digest: String,
    /// Lowercase `sha256:<64 hex>` measured-boot-chain digest.
    pub attestation_measured_boot_chain: String,
    /// Ordered measured-boot component names and lowercase SHA-256 digests.
    pub attestation_measured_boot_components: Vec<(String, String)>,
    /// Witness key identifier.
    pub attestation_witness_key: String,
    /// RFC 3339 UTC attestation-validity start.
    pub attestation_validity_not_before: String,
    /// RFC 3339 UTC attestation-validity end.
    pub attestation_validity_not_after: String,
    /// Operations-layer adapter system.
    pub adapter_system: String,
    /// Opaque adapter endpoint identifier.
    pub adapter_endpoint: String,
}
