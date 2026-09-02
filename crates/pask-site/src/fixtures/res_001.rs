// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! RES-001 deterministic fixture constructors.
//!
//! # These values are illustrative
//!
//! No Pask witness device has been built. RES-001 exercises the signing
//! pipeline against a site that exists, but the confidential-compute
//! environment these fixtures describe does not: there is no box, and no
//! silicon has been selected.
//!
//! `TEE_CLASS` in particular is a syntactically valid registry value chosen so
//! the fixture compiles and round-trips. It is not a hardware disclosure, not
//! a procurement signal, and not a statement that this profile expects,
//! prefers, or has been validated against Arm CCA. Read it as `<some
//! conforming TEE class>`.
//!
//! Nothing in this profile depends on which of the registry values appears
//! here. If a value must be cited as fact, it has to come from a device that
//! exists.

use crate::{EngagementRequest, EvidenceBundle, EvidenceFile, SiteConfig};

const SITE_ID: &str = "site:res-001";
const SITE_CLASS: &str = "residential";
const ENVELOPE_ID: &str = "env:res-001:2026-Q4";
const ENVELOPE_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ENVELOPE_STARTS: &str = "2026-10-01T00:00:00Z";
const ACTOR_ID: &str = "actor:robot-alpha-01";
const ACTOR_CLASS: &str = "AUTONOMOUS";
const ACTOR_OPERATOR: &str = "operator:wilder-robotics";
/// Illustrative only — see the module documentation. No silicon has been
/// selected for the RES-001 witness and this value discloses nothing about it.
const TEE_CLASS: &str = "arm.cca";
const PLATFORM_EVIDENCE_ENCODING: &str = "opaque/1";
const PLATFORM_EVIDENCE_DIGEST: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const MEASURED_BOOT_CHAIN: &str =
    "sha256:aa49a431481bba8610ab19c319ffe44a19412c5629cf0e2bedb5f9b40ba7c08e";
const BOOTLOADER_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const KERNEL_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const WITNESS_KEY: &str = "key:tee:res-001-witness-01";
const VALIDITY_NOT_BEFORE: &str = "2026-10-15T13:00:00Z";
const VALIDITY_NOT_AFTER: &str = "2026-10-15T15:00:00Z";
const ADAPTER_SYSTEM: &str = "buildium";
const ADAPTER_ENDPOINT: &str = "rental-42";
const ENGAGEMENT_ID: &str = "eng:res-001:20261015-140000";
const ENGAGEMENT_TYPE: &str = "patrol";
const WINDOW_START: &str = "2026-10-15T13:30:00Z";
const WINDOW_END: &str = "2026-10-15T14:00:00Z";
const OUTCOME_CLASS: &str = "COMPLETED";
const ENVELOPE_CONFORMANCE: &str = "WITHIN";
const ADAPTER_POSTED_AT: &str = "2026-10-15T14:00:05Z";
const ADAPTER_ACK_DIGEST: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const OBSERVATION_01_PATH: &str = "files/observation-01.txt";
const OBSERVATION_02_PATH: &str = "files/observation-02.txt";
const OBSERVATION_01: &[u8] =
    include_bytes!("../../fixtures/res-001/evidence/files/observation-01.txt");
const OBSERVATION_02: &[u8] =
    include_bytes!("../../fixtures/res-001/evidence/files/observation-02.txt");

/// Returns the stable RES-001 site configuration.
#[must_use]
pub fn site_config() -> SiteConfig {
    SiteConfig {
        site_id: SITE_ID.to_owned(),
        site_class: SITE_CLASS.to_owned(),
        envelope_id: ENVELOPE_ID.to_owned(),
        envelope_digest: ENVELOPE_DIGEST.to_owned(),
        envelope_temporal_starts: Some(ENVELOPE_STARTS.to_owned()),
        envelope_temporal_ends: None,
        envelope_geobounds: None,
        issuer_affiliation: pask_wire::IssuerAffiliation::NotDisclosed,
        actor_id: ACTOR_ID.to_owned(),
        actor_class: ACTOR_CLASS.to_owned(),
        actor_operator: ACTOR_OPERATOR.to_owned(),
        // PASK-006 will replace these deterministic stand-ins with verified claims.
        attestation_tee_class: TEE_CLASS.to_owned(),
        attestation_platform_evidence_encoding: PLATFORM_EVIDENCE_ENCODING.to_owned(),
        attestation_platform_evidence_digest: PLATFORM_EVIDENCE_DIGEST.to_owned(),
        attestation_measured_boot_chain: MEASURED_BOOT_CHAIN.to_owned(),
        attestation_measured_boot_components: vec![
            ("bootloader".to_owned(), BOOTLOADER_DIGEST.to_owned()),
            ("kernel".to_owned(), KERNEL_DIGEST.to_owned()),
        ],
        attestation_witness_key: WITNESS_KEY.to_owned(),
        attestation_validity_not_before: VALIDITY_NOT_BEFORE.to_owned(),
        attestation_validity_not_after: VALIDITY_NOT_AFTER.to_owned(),
        adapter_system: ADAPTER_SYSTEM.to_owned(),
        adapter_endpoint: ADAPTER_ENDPOINT.to_owned(),
    }
}

/// Returns the sorted two-file RES-001 evidence bundle.
#[must_use]
pub fn evidence_bundle() -> EvidenceBundle {
    EvidenceBundle::new_sorted(
        ENGAGEMENT_ID,
        vec![
            EvidenceFile {
                path: OBSERVATION_02_PATH.to_owned(),
                size_bytes: OBSERVATION_02.len() as u64,
                digest: pask_wire::sha256_prefixed(OBSERVATION_02),
            },
            EvidenceFile {
                path: OBSERVATION_01_PATH.to_owned(),
                size_bytes: OBSERVATION_01.len() as u64,
                digest: pask_wire::sha256_prefixed(OBSERVATION_01),
            },
        ],
    )
}

/// Returns an RES-001 engagement request containing `evidence`.
#[must_use]
pub fn engagement_request(evidence: EvidenceBundle) -> EngagementRequest {
    EngagementRequest {
        engagement_id: ENGAGEMENT_ID.to_owned(),
        engagement_type: ENGAGEMENT_TYPE.to_owned(),
        window_start: WINDOW_START.to_owned(),
        window_end: WINDOW_END.to_owned(),
        outcome_class: OUTCOME_CLASS.to_owned(),
        envelope_conformance: ENVELOPE_CONFORMANCE.to_owned(),
        evidence,
        adapter_ack_digest: ADAPTER_ACK_DIGEST.to_owned(),
        // The reference fixture models the case where the operations layer
        // returned a structured acknowledgement of its own.
        adapter_ack_provenance: pask_wire::AckProvenance::ThirdParty,
        adapter_posted_at: ADAPTER_POSTED_AT.to_owned(),
        chain_seq: 0,
        chain_prev_hash: None,
    }
}
