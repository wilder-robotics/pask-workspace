// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use crate::{
    MeasuredBoot, PlatformEvidence, SealedEvidence, TeeClass, ValidityWindow, WitnessKeyId,
};

/// Zero-sized marker that limits trusted-attestation construction to this crate.
#[derive(Debug, Clone)]
pub(crate) struct SealToken(());

impl SealToken {
    fn issue() -> Self {
        Self(())
    }
}

/// A verified attestation that cannot be constructed or deserialized by callers.
///
/// Instances are returned only by [crate::AttestationVerifier::verify].
///
///     use pask_attest::Attestation;
///
///     fn inspect(attestation: &Attestation) {
///         assert!(!attestation.witness_key().as_str().is_empty());
///         let _ = attestation.tee_class();
///     }
#[derive(Debug, Clone)]
pub struct Attestation {
    tee_class: TeeClass,
    measured_boot: MeasuredBoot,
    platform_evidence: PlatformEvidence,
    sealed_evidence: SealedEvidence,
    witness_key: WitnessKeyId,
    validity: ValidityWindow,
    pub(crate) _sealed: SealToken,
}

impl Attestation {
    pub(crate) fn from_verified(
        tee_class: TeeClass,
        measured_boot: MeasuredBoot,
        platform_evidence: PlatformEvidence,
        sealed_evidence: SealedEvidence,
        witness_key: WitnessKeyId,
        validity: ValidityWindow,
    ) -> Self {
        Self {
            tee_class,
            measured_boot,
            platform_evidence,
            sealed_evidence,
            witness_key,
            validity,
            _sealed: SealToken::issue(),
        }
    }

    /// Returns the verified category-level TEE class.
    #[must_use]
    pub const fn tee_class(&self) -> TeeClass {
        self.tee_class
    }

    /// Returns the verified measured-boot claims.
    #[must_use]
    pub const fn measured_boot(&self) -> &MeasuredBoot {
        &self.measured_boot
    }

    /// Returns the verified platform-evidence claims.
    #[must_use]
    pub const fn platform_evidence(&self) -> &PlatformEvidence {
        &self.platform_evidence
    }

    /// Returns the verified sealed-evidence claims.
    #[must_use]
    pub const fn sealed_evidence(&self) -> &SealedEvidence {
        &self.sealed_evidence
    }

    /// Returns the authenticated witness-key identifier.
    #[must_use]
    pub const fn witness_key(&self) -> &WitnessKeyId {
        &self.witness_key
    }

    /// Returns the verified evidence validity interval.
    #[must_use]
    pub const fn validity(&self) -> &ValidityWindow {
        &self.validity
    }

    /// Returns an owned, read-only snapshot of all verified claims.
    #[must_use]
    pub fn claims(&self) -> AttestationClaims {
        AttestationClaims {
            tee_class: self.tee_class,
            measured_boot: self.measured_boot.clone(),
            platform_evidence: self.platform_evidence.clone(),
            sealed_evidence: self.sealed_evidence.clone(),
            witness_key: self.witness_key.clone(),
            validity: self.validity.clone(),
        }
    }
}

/// An owned snapshot of claims copied from a verified [Attestation].
///
/// Like [Attestation], this type has private fields and no deserializer.
///
///     use pask_attest::AttestationClaims;
///
///     fn inspect(claims: &AttestationClaims) {
///         let _ = claims.tee_class();
///         assert!(!claims.witness_key().as_str().is_empty());
///     }
#[derive(Debug, Clone)]
pub struct AttestationClaims {
    tee_class: TeeClass,
    measured_boot: MeasuredBoot,
    platform_evidence: PlatformEvidence,
    sealed_evidence: SealedEvidence,
    witness_key: WitnessKeyId,
    validity: ValidityWindow,
}

impl AttestationClaims {
    /// Returns the verified category-level TEE class.
    #[must_use]
    pub const fn tee_class(&self) -> TeeClass {
        self.tee_class
    }

    /// Returns the verified measured-boot claims.
    #[must_use]
    pub const fn measured_boot(&self) -> &MeasuredBoot {
        &self.measured_boot
    }

    /// Returns the verified platform-evidence claims.
    #[must_use]
    pub const fn platform_evidence(&self) -> &PlatformEvidence {
        &self.platform_evidence
    }

    /// Returns the verified sealed-evidence claims.
    #[must_use]
    pub const fn sealed_evidence(&self) -> &SealedEvidence {
        &self.sealed_evidence
    }

    /// Returns the authenticated witness-key identifier.
    #[must_use]
    pub const fn witness_key(&self) -> &WitnessKeyId {
        &self.witness_key
    }

    /// Returns the verified evidence validity interval.
    #[must_use]
    pub const fn validity(&self) -> &ValidityWindow {
        &self.validity
    }
}
