// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::SystemTime,
};

use ed25519_dalek::VerifyingKey;

use crate::{AdapterError, AdapterOutcome, AdapterWriteIn, verify_before_push};

/// Failure behavior for `FailingAdapter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailingMode {
    /// Return rate-limit failures for the requested number of calls, then succeed.
    RateLimitThenSucceed(u32),

    /// Always return a server failure.
    AlwaysServerFailure,
}

/// Verified adapter test double with deterministic failures.
#[derive(Debug)]
pub struct FailingAdapter {
    mode: FailingMode,
    attempts: AtomicU32,
}

impl FailingAdapter {
    /// Creates a failing adapter in the selected mode.
    #[must_use]
    pub fn new(mode: FailingMode) -> Self {
        Self {
            mode,
            attempts: AtomicU32::new(0),
        }
    }

    /// Returns the number of calls made.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl AdapterWriteIn for FailingAdapter {
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

        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        match self.mode {
            FailingMode::RateLimitThenSucceed(failures) if attempt <= failures => {
                Err(AdapterError::RateLimited)
            }
            FailingMode::AlwaysServerFailure => Err(AdapterError::ServerError(503)),
            FailingMode::RateLimitThenSucceed(_) => Ok(AdapterOutcome::Pushed {
                adapter_name: "failing",
                adapter_receipt_id: format!("failing-receipt-{attempt}"),
                pushed_at: SystemTime::now(),
            }),
        }
    }

    fn name(&self) -> &'static str {
        "failing"
    }
}
