// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{
    AdapterOutcome, AdapterWriteIn, HttpResponse, InMemoryDedupLog, RetryPolicy,
    mock::MockHttpTransport,
};

#[test]
fn dedup_prevents_double_post() {
    let (receipt, key) = common::signed_receipt();
    let transport = Arc::new(MockHttpTransport::new(vec![Ok(HttpResponse {
        status: 201,
        body: br#"{"Id":42}"#.to_vec(),
    })]));
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        RetryPolicy::default(),
    );

    let first = adapter
        .push(&receipt, &key)
        .expect("first push must succeed");
    let second = adapter
        .push(&receipt, &key)
        .expect("second push must short-circuit");

    assert!(matches!(
        first,
        AdapterOutcome::Pushed {
            adapter_receipt_id,
            ..
        } if adapter_receipt_id == "buildium-note-42"
    ));
    assert!(matches!(
        second,
        AdapterOutcome::AlreadyPushed {
            prior_receipt_id,
            ..
        } if prior_receipt_id == "buildium-note-42"
    ));
    assert_eq!(transport.recorded_calls().len(), 1);
}
