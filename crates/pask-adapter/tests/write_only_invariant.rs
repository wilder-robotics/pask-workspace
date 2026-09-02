// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{
    AdapterWriteIn, HttpMethod, HttpResponse, InMemoryDedupLog, RetryPolicy,
    mock::MockHttpTransport,
};

#[test]
fn only_post_and_health_get() {
    let (receipt, key) = common::signed_receipt();
    let transport = Arc::new(MockHttpTransport::new(vec![
        Ok(HttpResponse {
            status: 201,
            body: br#"{"Id":42}"#.to_vec(),
        }),
        Ok(HttpResponse {
            status: 200,
            body: Vec::new(),
        }),
    ]));
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        RetryPolicy::default(),
    );

    adapter.push(&receipt, &key).expect("push must succeed");
    adapter.healthcheck().expect("health check must succeed");

    let calls = transport.recorded_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].method, HttpMethod::Post);
    assert!(calls[0].url.ends_with("/v1/rentals/rental-42/notes"));
    assert_eq!(calls[1].method, HttpMethod::Get);
    assert!(calls[1].url.ends_with("/v1/administration/accountinfo"));

    for call in calls {
        match call.method {
            HttpMethod::Post => assert!(call.url.contains("/v1/rentals/")),
            HttpMethod::Get => {
                assert!(call.url.ends_with("/v1/administration/accountinfo"));
            }
        }
    }
}

#[test]
#[ignore = "pask-wire currently rejects every non-WRITE_ONLY mode"]
fn mode_defense_in_depth() {
    // The executable guards remain in each adapter push implementation for a
    // future protocol revision that can construct a verified non-WRITE_ONLY payload.
    // This test intentionally has no runtime assertions; the guards are
    // exercised by static inspection during code review.
}
