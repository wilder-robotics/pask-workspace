// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::{thread, time::Duration};

use crate::AdapterError;

/// Deterministic retry and exponential-backoff settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of calls, including the first call.
    pub max_attempts: u32,

    /// Delay after the first failed attempt.
    pub base_delay: Duration,

    /// Maximum scheduled delay.
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// Returns the delay scheduled after a failed attempt.
    #[must_use]
    pub fn delay_after(&self, failed_attempt: u32) -> Duration {
        self.base_delay
            .saturating_mul(1_u32 << (failed_attempt - 1).min(31))
            .min(self.max_delay)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
        }
    }
}

/// Executes a fallible operation using the supplied retry policy.
///
/// # Errors
///
/// Returns the final non-retryable or exhausted failure, or
/// `AdapterError::InvalidRetryPolicy` for zero attempts.
pub fn run_with_retry<T, F>(policy: &RetryPolicy, f: F) -> Result<T, AdapterError>
where
    F: FnMut(u32) -> Result<T, AdapterError>,
{
    run_with_retry_and_sleep(policy, f, thread::sleep)
}

/// Executes a fallible operation with an injected delay function.
///
/// # Errors
///
/// Returns the final non-retryable or exhausted failure, or
/// `AdapterError::InvalidRetryPolicy` for zero attempts.
pub fn run_with_retry_and_sleep<T, F, S>(
    policy: &RetryPolicy,
    mut f: F,
    mut sleep: S,
) -> Result<T, AdapterError>
where
    F: FnMut(u32) -> Result<T, AdapterError>,
    S: FnMut(Duration),
{
    if policy.max_attempts == 0 {
        return Err(AdapterError::InvalidRetryPolicy);
    }

    let mut last_retryable: Option<AdapterError> = None;
    for attempt in 1..=policy.max_attempts {
        match f(attempt) {
            Ok(value) => return Ok(value),
            Err(error) if error.is_retryable() && attempt < policy.max_attempts => {
                sleep(policy.delay_after(attempt));
                last_retryable = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_retryable.unwrap_or(AdapterError::InvalidRetryPolicy))
}
