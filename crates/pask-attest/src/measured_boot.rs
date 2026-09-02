// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use serde::Serialize;

use crate::AttestationError;

/// One ordered component in a measured-boot chain.
///
/// Values are exposed by [MeasuredBoot::components] after quote verification.
///
///     use pask_attest::BootComponent;
///
///     fn show(component: &BootComponent) {
///         assert!(!component.name().is_empty());
///         assert!(component.digest().starts_with("sha256:"));
///     }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BootComponent {
    name: String,
    digest: String,
}

impl BootComponent {
    /// Returns the component name carried by the authenticated quote.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated SHA-256 digest string.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// An ordered measured-boot component list bound to a chain digest.
///
///     use pask_attest::MeasuredBoot;
///
///     fn inspect(measured_boot: &MeasuredBoot) {
///         assert!(measured_boot.chain().starts_with("sha256:"));
///         let _ = measured_boot.components();
///     }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredBoot {
    chain: String,
    components: Vec<BootComponent>,
}

impl MeasuredBoot {
    pub(crate) fn from_wire(
        chain: String,
        components: Vec<(String, String)>,
    ) -> Result<Self, AttestationError> {
        pask_wire::validate_sha256(&chain)
            .map_err(|error| AttestationError::WireError(error.to_string()))?;

        let components = components
            .into_iter()
            .map(|(name, digest)| {
                pask_wire::validate_sha256(&digest)
                    .map_err(|error| AttestationError::WireError(error.to_string()))?;
                Ok(BootComponent { name, digest })
            })
            .collect::<Result<Vec<_>, AttestationError>>()?;

        Ok(Self { chain, components })
    }

    /// Returns the declared digest binding the ordered component list.
    #[must_use]
    pub fn chain(&self) -> &str {
        &self.chain
    }

    /// Returns the authenticated components in measured order.
    #[must_use]
    pub fn components(&self) -> &[BootComponent] {
        &self.components
    }

    /// Recomputes the canonical component-list digest and compares it to the chain.
    ///
    /// # Errors
    ///
    /// Returns [AttestationError::MeasuredBootMismatch] if the binding differs,
    /// or [AttestationError::WireError] if serialization or canonicalization fails.
    pub fn verify_chain(&self) -> Result<(), AttestationError> {
        let serialized = serde_json::to_vec(&self.components)
            .map_err(|error| AttestationError::WireError(error.to_string()))?;
        let canonical = pask_wire::canonicalize_json(&serialized)
            .map_err(|error| AttestationError::WireError(error.to_string()))?;
        let actual = pask_wire::sha256_prefixed(&canonical);

        if actual == self.chain {
            Ok(())
        } else {
            Err(AttestationError::MeasuredBootMismatch)
        }
    }
}
