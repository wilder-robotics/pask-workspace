// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{
    AdapterError, AdapterWriteIn, HttpResponse, InMemoryDedupLog, RetryPolicy,
    mock::MockHttpTransport,
};

#[test]
fn payload_shape_conforms_to_spec() {
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
    adapter.push(&receipt, &key).expect("push must succeed");

    let calls = transport.recorded_calls();
    let body = calls[0].body.as_ref().expect("POST must have a JSON body");
    let object = body.as_object().expect("body must be an object");
    assert_eq!(object.len(), 3);
    assert_eq!(
        object.get("IsPrivate"),
        Some(&serde_json::Value::Bool(false))
    );

    let subject = object["Subject"]
        .as_str()
        .expect("Subject must be a string");
    assert!(subject.starts_with("Pask Receipt "));

    let note = object["Note"].as_str().expect("Note must be a string");
    let labels = [
        "Receipt ID:",
        "Site:",
        "Actor:",
        "Engagement:",
        "Window:",
        "Evidence digest:",
    ];
    let positions: Vec<_> = labels
        .iter()
        .map(|label| note.find(label).expect("required label must be present"))
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn adapter_mismatch_on_wrong_system() {
    let (receipt, key) = common::signed_receipt_for("propertymeld", "meld-1");
    let transport = Arc::new(MockHttpTransport::default());
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        RetryPolicy::default(),
    );

    assert!(matches!(
        adapter.push(&receipt, &key),
        Err(AdapterError::AdapterMismatch {
            expected: "buildium",
            actual,
        }) if actual == "propertymeld"
    ));
    assert!(transport.recorded_calls().is_empty());
}
