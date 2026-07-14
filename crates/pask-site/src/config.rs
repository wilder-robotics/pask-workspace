// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
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
    /// Actor identifier.
    pub actor_id: String,
    /// Actor class as a profile discriminant.
    pub actor_class: String,
    /// Actor operator string.
    pub actor_operator: String,
    /// TEE class identifier.
    pub attestation_tee_class: String,
    /// Platform-evidence reference.
    pub attestation_platform_evidence: String,
    /// Lowercase `sha256:<64 hex>` measured-boot-chain digest.
    pub attestation_measured_boot_chain: String,
    /// Witness key identifier.
    pub attestation_witness_key: String,
    /// Operations-layer adapter system.
    pub adapter_system: String,
    /// Opaque adapter endpoint identifier.
    pub adapter_endpoint: String,
}
