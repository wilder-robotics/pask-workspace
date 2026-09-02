// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{
    AdapterError, AdapterWriteIn, BuildiumWriteIn, CredentialProvider, Credentials,
    InMemoryDedupLog, RetryPolicy, mock::MockHttpTransport,
};

struct MissingCredentials;

impl CredentialProvider for MissingCredentials {
    fn credentials(&self, adapter_name: &str) -> Result<Credentials, AdapterError> {
        Err(AdapterError::CredentialMissing {
            adapter: adapter_name.to_owned(),
        })
    }
}

#[test]
fn short_circuits_after_verify() {
    let (receipt, key) = common::signed_receipt();
    let transport = Arc::new(MockHttpTransport::default());
    let adapter = BuildiumWriteIn::new(
        "https://example.test",
        transport.clone(),
        Arc::new(MissingCredentials),
        Arc::new(InMemoryDedupLog::new()),
        RetryPolicy::default(),
    )
    .expect("test base URL must be valid");

    assert!(matches!(
        adapter.push(&receipt, &key),
        Err(AdapterError::CredentialMissing { .. })
    ));
    assert!(transport.recorded_calls().is_empty());
}
