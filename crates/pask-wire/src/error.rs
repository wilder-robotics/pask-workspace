// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

use alloc::string::String;
use core::fmt;

/// Errors returned while parsing, producing, or verifying a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// JSON parsing or data-model conversion failed.
    Json(String),
    /// JCS serialization failed.
    Jcs(String),
    /// The COSE envelope is malformed.
    Cose(&'static str),
    /// A signature could not be created or verified.
    Signature,
    /// A protected-header requirement was not met.
    Header(&'static str),
    /// A payload profile requirement was not met.
    Validation(&'static str),
    /// The embedded payload bytes are not their JCS serialization.
    NonCanonicalPayload,
    /// An attached SCITT Receipt or its inclusion proof is unusable.
    ///
    /// Distinct from [`Self::Signature`], which is reserved for a signature
    /// that was checked and did not verify. A relying party needs to tell a
    /// Receipt it could not read from one it read and disbelieved.
    Receipt(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => write!(formatter, "JSON error: {message}"),
            Self::Jcs(message) => write!(formatter, "JCS error: {message}"),
            Self::Cose(message) => write!(formatter, "COSE error: {message}"),
            Self::Signature => formatter.write_str("signature error"),
            Self::Header(message) => write!(formatter, "protected-header error: {message}"),
            Self::Validation(message) => write!(formatter, "payload validation error: {message}"),
            Self::NonCanonicalPayload => formatter.write_str("payload is not JCS canonical"),
            Self::Receipt(message) => write!(formatter, "attached receipt error: {message}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type used by this crate.
pub type Result<T> = core::result::Result<T, Error>;
