// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{AdapterError, AdapterWriteIn, InMemoryDedupLog, mock::MockHttpTransport};
use pask_site::{ReferenceSite, SiteProducer};

#[test]
fn reference_site_uses_verify_before_push() {
    let (producer, verifying_key) = common::producer();
    let mut statement = producer.produce(&common::request()).unwrap();
    let middle = statement.len() / 2;
    statement[middle] ^= 1;

    let transport = Arc::new(MockHttpTransport::new(vec![common::success_response()]));
    let adapter = common::buildium(transport.clone(), Arc::new(InMemoryDedupLog::new()));
    let _site = ReferenceSite::new(producer, adapter.clone());
    assert!(matches!(
        adapter.push(&statement, &verifying_key),
        Err(AdapterError::VerificationFailed { .. })
    ));
    assert!(transport.recorded_calls().is_empty());
}
