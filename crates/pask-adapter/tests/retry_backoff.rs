// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use pask_adapter::{
    AdapterError, AdapterOutcome, AdapterWriteIn, HttpResponse, InMemoryDedupLog, RetryPolicy,
    mock::MockHttpTransport,
};

fn policy(base_delay: Duration) -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        base_delay,
        max_delay: Duration::from_secs(5),
    }
}

#[test]
fn rate_limit_then_success() {
    let run = |base_delay: Duration| {
        let (receipt, key) = common::signed_receipt();
        let transport = Arc::new(MockHttpTransport::new(vec![
            Ok(HttpResponse {
                status: 429,
                body: Vec::new(),
            }),
            Ok(HttpResponse {
                status: 429,
                body: Vec::new(),
            }),
            Ok(HttpResponse {
                status: 201,
                body: br#"{"Id":42}"#.to_vec(),
            }),
        ]));
        let delays = Arc::new(Mutex::new(Vec::new()));
        let recorded_delays = delays.clone();
        let adapter = common::buildium(
            transport.clone(),
            Arc::new(InMemoryDedupLog::new()),
            policy(base_delay),
        )
        .with_sleep(Arc::new(move |delay| {
            recorded_delays
                .lock()
                .expect("delay lock must not be poisoned")
                .push(delay);
        }));

        let outcome = adapter
            .push(&receipt, &key)
            .expect("third attempt must succeed");
        assert!(matches!(outcome, AdapterOutcome::Pushed { .. }));
        assert_eq!(transport.recorded_calls().len(), 3);
        delays
            .lock()
            .expect("delay lock must not be poisoned")
            .clone()
    };

    assert_eq!(run(Duration::ZERO), vec![Duration::ZERO, Duration::ZERO]);
    assert_eq!(
        run(Duration::from_millis(100)),
        vec![Duration::from_millis(100), Duration::from_millis(200)]
    );
}

#[test]
fn server_error_exhaustion_becomes_dead_letter() {
    let (receipt, key) = common::signed_receipt();
    let response = || {
        Ok(HttpResponse {
            status: 503,
            body: Vec::new(),
        })
    };
    let transport = Arc::new(MockHttpTransport::new(vec![
        response(),
        response(),
        response(),
    ]));
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        policy(Duration::ZERO),
    );

    assert_eq!(
        adapter.push(&receipt, &key),
        Err(AdapterError::ServerError(503))
    );
    assert_eq!(transport.recorded_calls().len(), 3);
}

#[test]
fn transport_failure_exhaustion_becomes_dead_letter() {
    let (receipt, key) = common::signed_receipt();
    let failure = || Err(AdapterError::Transport("network down".to_owned()));
    let transport = Arc::new(MockHttpTransport::new(vec![
        failure(),
        failure(),
        failure(),
    ]));
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        policy(Duration::ZERO),
    );

    assert_eq!(
        adapter.push(&receipt, &key),
        Err(AdapterError::DeadLetter("network down".to_owned()))
    );
    assert_eq!(transport.recorded_calls().len(), 3);
}

#[test]
fn last_retryable_error_is_preserved() {
    let (receipt, key) = common::signed_receipt();
    let response = || {
        Ok(HttpResponse {
            status: 429,
            body: Vec::new(),
        })
    };
    let transport = Arc::new(MockHttpTransport::new(vec![
        response(),
        response(),
        response(),
    ]));
    let adapter = common::buildium(
        transport.clone(),
        Arc::new(InMemoryDedupLog::new()),
        policy(Duration::ZERO),
    );

    assert_eq!(adapter.push(&receipt, &key), Err(AdapterError::RateLimited));
    assert_eq!(transport.recorded_calls().len(), 3);
}
