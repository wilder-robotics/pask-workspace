// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use crate::AttestationError;

const OPAQUE_ENCODING: &str = "opaque/1";

/// A digest-addressed opaque platform-evidence object.
///
///     use pask_attest::PlatformEvidence;
///
///     fn inspect(evidence: &PlatformEvidence) {
///         assert_eq!(evidence.encoding(), "opaque/1");
///         assert!(evidence.digest().starts_with("sha256:"));
///     }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformEvidence {
    encoding: String,
    digest: String,
}

impl PlatformEvidence {
    pub(crate) fn from_wire(encoding: String, digest: String) -> Result<Self, AttestationError> {
        if encoding != OPAQUE_ENCODING {
            return Err(AttestationError::MalformedQuote(
                "platformEvidence.encoding must be 'opaque/1'".to_owned(),
            ));
        }
        pask_wire::validate_sha256(&digest)
            .map_err(|error| AttestationError::WireError(error.to_string()))?;
        Ok(Self { encoding, digest })
    }

    /// Returns the evidence encoding identifier.
    #[must_use]
    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    /// Returns the validated SHA-256 digest string.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
