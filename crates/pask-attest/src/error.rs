// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use std::time::SystemTime;

/// A failure to parse, authenticate, or validate an attestation quote.
///
///     use pask_attest::AttestationError;
///
///     let error = AttestationError::InvalidSignature;
///     assert_eq!(error.to_string(), "attestation quote signature verification failed");
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The signature does not authenticate the framed canonical payload.
    #[error("attestation quote signature verification failed")]
    InvalidSignature,
    /// The caller's clock is later than the evidence window plus allowed skew.
    #[error("attestation evidence expired: not_after={not_after:?}, clock_now={now:?}")]
    ExpiredEvidence {
        /// The final valid instant carried by the quote.
        not_after: SystemTime,
        /// The instant returned by the injected clock.
        now: SystemTime,
    },
    /// The caller's clock is earlier than the evidence window minus allowed skew.
    #[error("attestation not yet valid: not_before={not_before:?}, clock_now={now:?}")]
    ClockSkew {
        /// The first valid instant carried by the quote.
        not_before: SystemTime,
        /// The instant returned by the injected clock.
        now: SystemTime,
    },
    /// No configured root is associated with the quote's witness-key identifier.
    #[error("attestation signed by unknown root of trust")]
    UnknownRootOfTrust,
    /// The quote framing or JSON shape is invalid.
    #[error("attestation quote malformed: {0}")]
    MalformedQuote(String),
    /// The quote names a TEE class outside the supported category taxonomy.
    #[error("unsupported TEE class '{0}' — allowed: arm64.tee-v1, x86_64.tee-v1")]
    UnsupportedTeeClass(String),
    /// The component sequence does not hash to the declared measured-boot chain.
    #[error("measured-boot chain hash does not match component digests")]
    MeasuredBootMismatch,
    /// A required field is absent from an otherwise parseable quote.
    #[error("attestation missing required claim: {0}")]
    MissingClaim(&'static str),
    /// A landed wire-format primitive rejected data or could not canonicalize it.
    #[error("wire-format error: {0}")]
    WireError(String),
}
