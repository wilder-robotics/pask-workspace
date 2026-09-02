// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-attest is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Verification of signed TEE attestation quotes for Pask receipts.
//!
//! An [`Attestation`] is only returned after an [`AttestationVerifier`] has
//! authenticated a quote and checked all of its claims.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod attestation;
pub mod clock;
mod error;
mod measured_boot;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod platform_evidence;
mod sealed_evidence;
mod tee_class;
mod validity;
mod verifier;
mod witness_key;

pub use attestation::{Attestation, AttestationClaims};
pub use error::AttestationError;
pub use measured_boot::{BootComponent, MeasuredBoot};
#[cfg(any(test, feature = "mock"))]
pub use mock::MockAttestationVerifier;
pub use platform_evidence::PlatformEvidence;
pub use sealed_evidence::SealedEvidence;
pub use tee_class::TeeClass;
pub use validity::{MAX_CLOCK_SKEW, ValidityWindow};
pub use verifier::{AttestationVerifier, Ed25519RootOfTrust};
pub use witness_key::WitnessKeyId;
