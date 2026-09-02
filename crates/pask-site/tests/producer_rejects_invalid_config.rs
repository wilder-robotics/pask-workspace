// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_site::{Ed25519SiteProducer, FixedClock, SiteError, SiteProducer, fixtures::res_001};

#[test]
fn empty_site_id_is_rejected() {
    let (signing, _) = common::res_001_keypair();
    let mut config = res_001::site_config();
    config.site_id.clear();
    let producer = Ed25519SiteProducer::new(
        config,
        Arc::new(FixedClock::new("2026-10-15T14:00:00Z")),
        signing,
    );

    match producer.produce(&common::request()) {
        Err(SiteError::WireError(message)) => {
            assert!(message.contains("required string must not be empty"));
        }
        result => panic!("expected wire-format error, got {result:?}"),
    }
}

#[test]
fn evidence_engagement_id_mismatch_is_rejected() {
    let (producer, _) = common::producer();
    let mut request = common::request();
    request.engagement_id = "eng:res-001:20261015-150000".to_owned();
    assert!(matches!(
        producer.produce(&request),
        Err(SiteError::EvidenceMismatch)
    ));
}
