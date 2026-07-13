// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{
    AdapterError, AdapterOutcome, AdapterWriteIn, HttpMethod, HttpResponse, InMemoryDedupLog,
    RetryPolicy, mock::MockHttpTransport,
};

#[test]
fn rejects_tampered_receipt() {
    let (mut receipt, key) = common::signed_receipt();
    let last = receipt.last_mut().expect("receipt must not be empty");
    *last ^= 1;

    let transport = Arc::new(MockHttpTransport::default());
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        RetryPolicy::default(),
    );

    assert!(matches!(
        adapter.push(&receipt, &key),
        Err(AdapterError::VerificationFailed { .. })
    ));
    assert!(transport.recorded_calls().is_empty());
}

#[test]
fn accepts_valid_receipt() {
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

    let outcome = adapter
        .push(&receipt, &key)
        .expect("valid receipt must push");
    assert!(matches!(
        outcome,
        AdapterOutcome::Pushed {
            adapter_receipt_id,
            ..
        } if adapter_receipt_id == "buildium-note-42"
    ));

    let calls = transport.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, HttpMethod::Post);
}
