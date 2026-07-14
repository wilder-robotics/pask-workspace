// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use crate::clock::Clock;
use crate::{Attestation, AttestationError, AttestationVerifier};

/// A feature-gated verifier that maps configured quote prefixes to attestations.
///
/// Configured values must already be verified [Attestation] instances, preserving
/// the sealed construction boundary while allowing deterministic integration tests.
///
///     # #[cfg(feature = "mock")]
///     # {
///     use pask_attest::MockAttestationVerifier;
///
///     let verifier = MockAttestationVerifier::new();
///     let _ = verifier;
///     # }
#[derive(Debug)]
pub struct MockAttestationVerifier {
    entries: Vec<(Vec<u8>, Attestation)>,
}

impl MockAttestationVerifier {
    /// Creates an empty mock verifier that rejects every quote.
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Maps a quote-byte prefix to an already verified attestation.
    #[must_use]
    pub fn with_attestation(mut self, quote_prefix: Vec<u8>, attestation: Attestation) -> Self {
        self.entries.push((quote_prefix, attestation));
        self
    }
}

impl AttestationVerifier for MockAttestationVerifier {
    fn verify(
        &self,
        quote_bytes: &[u8],
        _clock: &dyn Clock,
    ) -> Result<Attestation, AttestationError> {
        self.entries
            .iter()
            .find(|(prefix, _)| quote_bytes.starts_with(prefix))
            .map(|(_, attestation)| attestation.clone())
            .ok_or_else(|| {
                AttestationError::MalformedQuote(
                    "quote does not match a configured mock prefix".to_owned(),
                )
            })
    }
}
