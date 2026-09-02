// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

pub mod failing;

use std::{
    collections::VecDeque,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU32, Ordering},
    },
    time::SystemTime,
};

use ed25519_dalek::VerifyingKey;

use crate::{
    AdapterError, AdapterOutcome, AdapterWriteIn,
    buildium::{HttpRequest, HttpResponse, HttpTransport},
    verify_before_push,
};

pub use failing::{FailingAdapter, FailingMode};

/// Recording HTTP transport with queued results.
#[derive(Debug, Default)]
pub struct MockHttpTransport {
    calls: Mutex<Vec<HttpRequest>>,
    results: Mutex<VecDeque<Result<HttpResponse, AdapterError>>>,
}

impl MockHttpTransport {
    /// Creates a transport with results returned in queue order.
    #[must_use]
    pub fn new(results: Vec<Result<HttpResponse, AdapterError>>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            results: Mutex::new(results.into()),
        }
    }

    /// Returns a snapshot of all attempted requests.
    #[must_use]
    pub fn recorded_calls(&self) -> Vec<HttpRequest> {
        self.calls().clone()
    }

    fn calls(&self) -> MutexGuard<'_, Vec<HttpRequest>> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn results(&self) -> MutexGuard<'_, VecDeque<Result<HttpResponse, AdapterError>>> {
        self.results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl HttpTransport for MockHttpTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, AdapterError> {
        self.calls().push(request);
        self.results().pop_front().unwrap_or_else(|| {
            Err(AdapterError::InvalidResponse(
                "mock transport result queue is empty".to_owned(),
            ))
        })
    }
}

/// Simple verified adapter test double.
#[derive(Debug, Default)]
pub struct MockAdapter {
    pushes: AtomicU32,
}

impl MockAdapter {
    /// Returns the number of successful mock writes.
    #[must_use]
    pub fn pushes(&self) -> u32 {
        self.pushes.load(Ordering::SeqCst)
    }
}

impl AdapterWriteIn for MockAdapter {
    fn push(
        &self,
        signed_receipt: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<AdapterOutcome, AdapterError> {
        let payload = verify_before_push(signed_receipt, verifying_key)?;

        // This code path is defense-in-depth; the pask-wire validator makes it
        // unreachable through parsing. Preserved for a future protocol revision
        // that adds a non-WRITE_ONLY mode.
        if !payload.adapter_is_write_only() {
            return Err(AdapterError::WriteOnlyRequired {
                actual: "<non-write-only>".to_owned(),
            });
        }

        let attempt = self.pushes.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(AdapterOutcome::Pushed {
            adapter_name: "mock",
            adapter_receipt_id: format!("mock-receipt-{attempt}"),
            pushed_at: SystemTime::now(),
        })
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}
