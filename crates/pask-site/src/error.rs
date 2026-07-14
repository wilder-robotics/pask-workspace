// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Site-producer error types.

/// Errors produced while constructing or pushing a site receipt.
#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    #[error("evidence bundle engagement id does not match request engagement id")]
    EvidenceMismatch,

    #[error("wire-format validation failed: {0}")]
    WireError(String),

    #[error("json encoding failed: {0}")]
    JsonError(String),

    #[error("adapter push failed: {0}")]
    AdapterError(#[from] pask_adapter::AdapterError),

    #[error("invalid site configuration: {0}")]
    InvalidConfig(String),
}
