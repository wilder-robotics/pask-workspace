// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use crate::AttestationError;

const OPAQUE_ENCODING: &str = "opaque/1";

/// Metadata for a digest-addressed sealed evidence object.
///
///     use pask_attest::SealedEvidence;
///
///     fn inspect(evidence: &SealedEvidence) {
///         assert_eq!(evidence.encoding(), "opaque/1");
///         let _ = evidence.size_bytes();
///     }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEvidence {
    digest: String,
    size_bytes: u64,
    encoding: String,
}

impl SealedEvidence {
    pub(crate) fn from_wire(
        digest: String,
        size_bytes: u64,
        encoding: String,
    ) -> Result<Self, AttestationError> {
        if encoding != OPAQUE_ENCODING {
            return Err(AttestationError::MalformedQuote(
                "sealedEvidence.encoding must be 'opaque/1'".to_owned(),
            ));
        }
        pask_wire::validate_sha256(&digest)
            .map_err(|error| AttestationError::WireError(error.to_string()))?;
        Ok(Self {
            digest,
            size_bytes,
            encoding,
        })
    }

    /// Returns the validated SHA-256 digest string.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the byte length declared by the authenticated quote.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Returns the evidence encoding identifier.
    #[must_use]
    pub fn encoding(&self) -> &str {
        &self.encoding
    }
}
