// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use pask_site::{EvidenceBundle, SiteProducer, fixtures::res_001};

#[test]
fn evidence_digest_matches_jcs_sha256() {
    let bundle = res_001::evidence_bundle();
    let bytes = serde_json::to_vec(&bundle).unwrap();
    let jcs = pask_wire::canonicalize_json(&bytes).unwrap();
    let digest = pask_wire::sha256_prefixed(&jcs);
    assert!(pask_wire::validate_sha256(&digest).is_ok());

    let request = res_001::engagement_request(bundle);
    let (producer, verifying_key) = common::producer();
    let statement = producer.produce(&request).unwrap();
    let payload = pask_wire::verify_ed25519(&statement, &verifying_key).unwrap();
    assert_eq!(payload.engagement_evidence_digest(), digest);
}

#[test]
fn sorted_files_produce_stable_digest() {
    let first = res_001::evidence_bundle();
    let mut reversed = first.files.clone();
    reversed.reverse();
    let second = EvidenceBundle::new_sorted(first.engagement_id.clone(), reversed);

    let first_bytes = serde_json::to_vec(&first).unwrap();
    let second_bytes = serde_json::to_vec(&second).unwrap();
    let first_jcs = pask_wire::canonicalize_json(&first_bytes).unwrap();
    let second_jcs = pask_wire::canonicalize_json(&second_bytes).unwrap();
    assert_eq!(first_jcs, second_jcs);
    assert_eq!(
        pask_wire::sha256_prefixed(&first_jcs),
        pask_wire::sha256_prefixed(&second_jcs)
    );
}
