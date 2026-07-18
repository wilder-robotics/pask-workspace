// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use pask_site::SiteProducer;

#[test]
fn produces_verifiable_receipt() {
    let (producer, verifying_key) = common::producer();
    let request = common::request();
    let statement = producer.produce(&request).unwrap();
    let payload = pask_wire::verify_ed25519(&statement, &verifying_key).unwrap();

    assert!(payload.adapter_is_write_only());
    assert_eq!(payload.engagement_id(), "eng:res-001:20261015-140000");
}
