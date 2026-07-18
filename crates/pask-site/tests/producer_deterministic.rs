// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use pask_site::SiteProducer;

#[test]
fn two_produces_return_identical_bytes() {
    let (producer, _) = common::producer();
    let request = common::request();
    let first = producer.produce(&request).unwrap();
    let second = producer.produce(&request).unwrap();
    assert_eq!(first, second);
}
