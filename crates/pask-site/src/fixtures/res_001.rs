// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! RES-001 deterministic fixture constructors.

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
const TEE_CLASS: &str = "arm64.tee-v1";
const PLATFORM_EVIDENCE: &str = "ref:file:attest-2026-10-15T14:00:00Z.bin";
const MEASURED_BOOT_CHAIN: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const WITNESS_KEY: &str = "key:tee:res-001-witness-01";
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
        actor_id: ACTOR_ID.to_owned(),
        actor_class: ACTOR_CLASS.to_owned(),
        actor_operator: ACTOR_OPERATOR.to_owned(),
        // PASK-004 will replace these deterministic stand-ins with real TEE evidence.
        attestation_tee_class: TEE_CLASS.to_owned(),
        attestation_platform_evidence: PLATFORM_EVIDENCE.to_owned(),
        attestation_measured_boot_chain: MEASURED_BOOT_CHAIN.to_owned(),
        attestation_witness_key: WITNESS_KEY.to_owned(),
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
        adapter_posted_at: ADAPTER_POSTED_AT.to_owned(),
        chain_seq: 0,
        chain_prev_hash: None,
    }
}
