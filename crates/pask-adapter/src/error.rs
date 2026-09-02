// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use thiserror::Error;

/// Failures returned by WRITE_ONLY adapters.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdapterError {
    /// The signed receipt did not verify.
    #[error("receipt verification failed: {message}")]
    VerificationFailed { message: String },

    /// Required adapter credentials were unavailable.
    #[error("credentials are missing for adapter {adapter}")]
    CredentialMissing { adapter: String },

    /// The receipt selected a different adapter.
    #[error("adapter mismatch: expected {expected}, received {actual}")]
    AdapterMismatch {
        expected: &'static str,
        actual: String,
    },

    /// The receipt was not marked WRITE_ONLY.
    #[error("WRITE_ONLY mode is required; received {actual}")]
    WriteOnlyRequired { actual: String },

    /// The remote service applied a rate limit.
    #[error("adapter request was rate limited")]
    RateLimited,

    /// The remote service returned a server failure.
    #[error("adapter server returned status {0}")]
    ServerError(u16),

    /// Transport failed before a valid response was received.
    #[error("adapter transport failed: {0}")]
    Transport(String),

    /// The remote service rejected the request.
    #[error("adapter request was rejected with status {0}")]
    BadRequest(u16),

    /// Request serialization failed.
    #[error("adapter request serialization failed: {0}")]
    Serialization(String),

    /// The remote service returned an unusable response.
    #[error("adapter returned an invalid response: {0}")]
    InvalidResponse(String),

    /// The configured base URL was invalid.
    #[error("invalid adapter base URL: {0}")]
    InvalidBaseUrl(String),

    /// An exhausted transport failure requires later processing.
    #[error("adapter request entered the dead-letter path: {0}")]
    DeadLetter(String),

    /// The adapter cannot be enabled before partner terms are established.
    #[error("partner agreement required for {adapter}: {reason}")]
    PartnerAgreementRequired {
        adapter: &'static str,
        reason: String,
    },

    /// A retry policy specified zero attempts.
    #[error("retry policy must specify at least one attempt")]
    InvalidRetryPolicy,
}

impl AdapterError {
    /// Returns whether the failure may be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::ServerError(500..=599) | Self::Transport(_)
        )
    }
}
