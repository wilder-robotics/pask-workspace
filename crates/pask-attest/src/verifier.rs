// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use std::collections::HashMap;
use std::str::FromStr;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::clock::Clock;
use crate::{
    Attestation, AttestationError, MeasuredBoot, PlatformEvidence, SealedEvidence, TeeClass,
    ValidityWindow, WitnessKeyId,
};

const QUOTE_SPEC: &str = "wilder.attest/0.1";
const FRAME_VERSION: [u8; 8] = [b'a', 0, 0, 0, 0, 0, 0, 1];
const SIGNATURE_LENGTH: usize = 64;
const MAX_QUOTE_SIZE: usize = 1024 * 1024;

/// Verifies TEE attestation quotes and returns typed, authenticated claims.
///
/// A successful implementation must authenticate the quote before constructing
/// an [Attestation], use only the supplied [Clock], and enforce bounded skew.
///
///     use pask_attest::{AttestationVerifier, Ed25519RootOfTrust};
///
///     fn accepts_verifier(verifier: &dyn AttestationVerifier) {
///         let _ = verifier;
///     }
///
///     let verifier = Ed25519RootOfTrust::new();
///     accepts_verifier(&verifier);
pub trait AttestationVerifier: Send + Sync {
    /// Authenticates and validates an opaque quote.
    ///
    /// # Errors
    ///
    /// Returns a distinct [AttestationError] for framing, trust, signature,
    /// claim, measured-boot, or time-window failures.
    fn verify(
        &self,
        quote_bytes: &[u8],
        clock: &dyn Clock,
    ) -> Result<Attestation, AttestationError>;
}

/// A root of trust containing Ed25519 keys indexed by witness-key identifier.
///
///     use pask_attest::Ed25519RootOfTrust;
///
///     let root = Ed25519RootOfTrust::new();
///     let _ = root;
#[derive(Debug)]
pub struct Ed25519RootOfTrust {
    keys: HashMap<String, VerifyingKey>,
}

impl Ed25519RootOfTrust {
    /// Creates an empty root of trust.
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Adds or replaces the trusted key for a witness-key identifier.
    #[must_use]
    pub fn with_key(mut self, witness_key_id: String, key: VerifyingKey) -> Self {
        self.keys.insert(witness_key_id, key);
        self
    }
}

impl AttestationVerifier for Ed25519RootOfTrust {
    fn verify(
        &self,
        quote_bytes: &[u8],
        clock: &dyn Clock,
    ) -> Result<Attestation, AttestationError> {
        let (jcs_bytes, signature) = parse_frame(quote_bytes)?;
        let raw: RawQuote = serde_json::from_slice(jcs_bytes)
            .map_err(|error| AttestationError::MalformedQuote(error.to_string()))?;

        let witness_key_id = raw
            .witness_key
            .as_deref()
            .ok_or(AttestationError::MissingClaim("witnessKey"))?;
        let key = self
            .keys
            .get(witness_key_id)
            .ok_or(AttestationError::UnknownRootOfTrust)?;
        key.verify_strict(jcs_bytes, &signature)
            .map_err(|_| AttestationError::InvalidSignature)?;

        let canonical = pask_wire::canonicalize_json(jcs_bytes)
            .map_err(|error| AttestationError::WireError(error.to_string()))?;
        if canonical.as_slice() != jcs_bytes {
            return Err(AttestationError::MalformedQuote(
                "quote JSON is not RFC 8785 canonical".to_owned(),
            ));
        }

        let spec = required(raw.spec, "spec")?;
        if spec != QUOTE_SPEC {
            return Err(AttestationError::MalformedQuote(
                "unsupported quote spec".to_owned(),
            ));
        }

        let tee_class = TeeClass::from_str(&required(raw.tee_class, "teeClass")?)?;
        let measured_boot = build_measured_boot(required(raw.measured_boot, "measuredBoot")?)?;
        measured_boot.verify_chain()?;
        let platform_evidence =
            build_platform_evidence(required(raw.platform_evidence, "platformEvidence")?)?;
        let sealed_evidence =
            build_sealed_evidence(required(raw.sealed_evidence, "sealedEvidence")?)?;
        let witness_key = WitnessKeyId::from_verified(required(raw.witness_key, "witnessKey")?);
        let validity = build_validity(required(raw.validity, "validity")?)?;
        let now = crate::validity::parse_rfc3339(&clock.now_rfc3339(), "clock.now")?;
        validity.check_clock(now)?;

        Ok(Attestation::from_verified(
            tee_class,
            measured_boot,
            platform_evidence,
            sealed_evidence,
            witness_key,
            validity,
        ))
    }
}

fn parse_frame(quote_bytes: &[u8]) -> Result<(&[u8], Signature), AttestationError> {
    if quote_bytes.len() > MAX_QUOTE_SIZE {
        return Err(AttestationError::MalformedQuote(
            "quote exceeds 1 MiB".to_owned(),
        ));
    }
    let minimum_length = FRAME_VERSION.len() + 1 + SIGNATURE_LENGTH;
    if quote_bytes.len() < minimum_length {
        return Err(AttestationError::MalformedQuote(
            "quote frame is truncated".to_owned(),
        ));
    }
    if quote_bytes[..FRAME_VERSION.len()] != FRAME_VERSION {
        return Err(AttestationError::MalformedQuote(
            "unsupported quote frame version".to_owned(),
        ));
    }

    let signature_offset = quote_bytes.len() - SIGNATURE_LENGTH;
    let jcs_bytes = &quote_bytes[FRAME_VERSION.len()..signature_offset];
    if jcs_bytes.is_empty() {
        return Err(AttestationError::MalformedQuote(
            "quote payload is empty".to_owned(),
        ));
    }
    let signature = Signature::try_from(&quote_bytes[signature_offset..]).map_err(|_| {
        AttestationError::MalformedQuote("quote signature must be 64 bytes".to_owned())
    })?;
    Ok((jcs_bytes, signature))
}

fn build_measured_boot(raw: RawMeasuredBoot) -> Result<MeasuredBoot, AttestationError> {
    let chain = required(raw.chain, "measuredBoot.chain")?;
    let components = required(raw.components, "measuredBoot.components")?
        .into_iter()
        .map(|component| {
            Ok((
                required(component.name, "measuredBoot.components[].name")?,
                required(component.digest, "measuredBoot.components[].digest")?,
            ))
        })
        .collect::<Result<Vec<_>, AttestationError>>()?;
    MeasuredBoot::from_wire(chain, components)
}

fn build_platform_evidence(raw: RawPlatformEvidence) -> Result<PlatformEvidence, AttestationError> {
    PlatformEvidence::from_wire(
        required(raw.encoding, "platformEvidence.encoding")?,
        required(raw.digest, "platformEvidence.digest")?,
    )
}

fn build_sealed_evidence(raw: RawSealedEvidence) -> Result<SealedEvidence, AttestationError> {
    SealedEvidence::from_wire(
        required(raw.digest, "sealedEvidence.digest")?,
        required(raw.size_bytes, "sealedEvidence.sizeBytes")?,
        required(raw.encoding, "sealedEvidence.encoding")?,
    )
}

fn build_validity(raw: RawValidity) -> Result<ValidityWindow, AttestationError> {
    let not_before = required(raw.not_before, "validity.notBefore")?;
    let not_after = required(raw.not_after, "validity.notAfter")?;
    ValidityWindow::from_rfc3339(&not_before, &not_after)
}

fn required<T>(value: Option<T>, claim: &'static str) -> Result<T, AttestationError> {
    value.ok_or(AttestationError::MissingClaim(claim))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawQuote {
    spec: Option<String>,
    tee_class: Option<String>,
    measured_boot: Option<RawMeasuredBoot>,
    platform_evidence: Option<RawPlatformEvidence>,
    sealed_evidence: Option<RawSealedEvidence>,
    witness_key: Option<String>,
    validity: Option<RawValidity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawMeasuredBoot {
    chain: Option<String>,
    components: Option<Vec<RawBootComponent>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawBootComponent {
    name: Option<String>,
    digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPlatformEvidence {
    encoding: Option<String>,
    digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawSealedEvidence {
    digest: Option<String>,
    size_bytes: Option<u64>,
    encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawValidity {
    not_before: Option<String>,
    not_after: Option<String>,
}
