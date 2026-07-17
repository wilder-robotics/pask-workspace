// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use alloc::{borrow::ToOwned, string::ToString, vec::Vec};
use coset::{
    Algorithm, AsCborValue, CborSerializable, ContentType, CoseSign1, CoseSign1Builder,
    HeaderBuilder, Label, cbor::Value, iana,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{
    Error, Payload, Result,
    cwt::{CWT_CLAIMS_LABEL, CwtClaims},
};

/// Required protected content type for the profile.
pub const CONTENT_TYPE: &str = "application/pser+json; profile=wilder.pser/0.2";

/// Produces an attached-payload `COSE_Sign1` statement using Ed25519.
///
/// # Errors
///
/// Returns an error if the issuer is empty or payload/envelope serialization fails.
pub fn produce_ed25519(payload: &Payload, issuer: &str, key: &SigningKey) -> Result<Vec<u8>> {
    produce(payload, issuer, iana::Algorithm::EdDSA, |data| {
        key.sign(data).to_bytes().to_vec()
    })
}

/// Parses and verifies an Ed25519 `COSE_Sign1` statement and its PSER payload.
///
/// # Errors
///
/// Returns an error for malformed envelopes, invalid headers or payloads, or a bad signature.
pub fn verify_ed25519(statement: &[u8], key: &VerifyingKey) -> Result<Payload> {
    verify(statement, iana::Algorithm::EdDSA, |signature, data| {
        let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
        key.verify(data, &signature).map_err(|_| Error::Signature)
    })
}

/// Produces an attached-payload `COSE_Sign1` statement using ES256.
///
/// # Errors
///
/// Returns an error if the issuer is empty or payload/envelope serialization fails.
#[cfg(feature = "es256")]
pub fn produce_es256(
    payload: &Payload,
    issuer: &str,
    key: &p256::ecdsa::SigningKey,
) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::Signer as _;

    produce(payload, issuer, iana::Algorithm::ES256, |data| {
        let signature: p256::ecdsa::Signature = key.sign(data);
        signature.to_bytes().to_vec()
    })
}

/// Parses and verifies an ES256 `COSE_Sign1` statement and its PSER payload.
///
/// # Errors
///
/// Returns an error for malformed envelopes, invalid headers or payloads, or a bad signature.
#[cfg(feature = "es256")]
pub fn verify_es256(statement: &[u8], key: &p256::ecdsa::VerifyingKey) -> Result<Payload> {
    use p256::ecdsa::signature::Verifier as _;

    verify(statement, iana::Algorithm::ES256, |signature, data| {
        let signature =
            p256::ecdsa::Signature::from_slice(signature).map_err(|_| Error::Signature)?;
        key.verify(data, &signature).map_err(|_| Error::Signature)
    })
}

fn produce<F>(
    payload: &Payload,
    issuer: &str,
    algorithm: iana::Algorithm,
    signer: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    if issuer.is_empty() {
        return Err(Error::Header("CWT iss must not be empty"));
    }
    let claims = CwtClaims {
        issuer: issuer.to_owned(),
        subject: payload.site_id().as_bytes().to_vec(),
    };
    let protected = HeaderBuilder::new()
        .algorithm(algorithm)
        .content_type(CONTENT_TYPE.to_owned())
        .value(CWT_CLAIMS_LABEL, claims.to_value())
        .build();
    let statement = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_jcs()?)
        .create_signature(&[], signer)
        .build();
    statement
        .to_vec()
        .map_err(|_| Error::Cose("failed to serialize COSE_Sign1"))
}

fn verify<F>(statement: &[u8], expected_algorithm: iana::Algorithm, verifier: F) -> Result<Payload>
where
    F: FnOnce(&[u8], &[u8]) -> Result<()>,
{
    let statement = parse_statement(statement)?;
    let payload_bytes = statement
        .payload
        .as_deref()
        .ok_or(Error::Cose("detached payloads are not permitted"))?;
    let payload = Payload::parse_canonical(payload_bytes)?;
    validate_headers(&statement, expected_algorithm, &payload)?;
    statement
        .verify_signature(&[], |signature, data| verifier(signature, data))
        .map_err(|_| Error::Signature)?;
    Ok(payload)
}

fn parse_statement(mut encoded: &[u8]) -> Result<CoseSign1> {
    let mut value: Value = coset::cbor::de::from_reader(&mut encoded)
        .map_err(|_| Error::Cose("failed to parse COSE_Sign1 CBOR"))?;
    if !encoded.is_empty() {
        return Err(Error::Cose("trailing bytes after COSE_Sign1"));
    }
    let Value::Array(items) = &mut value else {
        return Err(Error::Cose("COSE_Sign1 must be an array"));
    };
    let Some(Value::Bytes(protected)) = items.first_mut() else {
        return Err(Error::Cose("COSE_Sign1 protected header must be bytes"));
    };
    let original = protected.clone();
    let mut patched_content_type = false;
    if let Some(start) = protected
        .windows(CONTENT_TYPE.len())
        .position(|window| window == CONTENT_TYPE.as_bytes())
    {
        let slash = CONTENT_TYPE
            .rfind('/')
            .expect("the fixed profile content type contains a slash");
        protected[start + slash] = b'-';
        patched_content_type = true;
    }
    let mut statement = CoseSign1::from_cbor_value(value)
        .map_err(|_| Error::Cose("failed to parse COSE_Sign1 structure"))?;
    if patched_content_type {
        statement.protected.original_data = Some(original);
        statement.protected.header.content_type = Some(ContentType::Text(CONTENT_TYPE.to_owned()));
    }
    Ok(statement)
}

fn validate_headers(
    statement: &CoseSign1,
    expected_algorithm: iana::Algorithm,
    payload: &Payload,
) -> Result<()> {
    let header = &statement.protected.header;
    if header.alg != Some(Algorithm::Assigned(expected_algorithm)) {
        return Err(Error::Header("unexpected or missing signing algorithm"));
    }
    if header.content_type != Some(ContentType::Text(CONTENT_TYPE.to_string())) {
        return Err(Error::Header("unexpected or missing content_type"));
    }
    let mut claim_values = header
        .rest
        .iter()
        .filter_map(|(label, value)| (label == &Label::Int(CWT_CLAIMS_LABEL)).then_some(value));
    let claims = claim_values
        .next()
        .ok_or(Error::Header("CWT_Claims is missing"))?;
    if claim_values.next().is_some() {
        return Err(Error::Header("CWT_Claims is duplicated"));
    }
    let claims = CwtClaims::from_value(claims)?;
    if claims.issuer.is_empty() {
        return Err(Error::Header("CWT iss must not be empty"));
    }
    if claims.subject.as_slice() != payload.site_id().as_bytes() {
        return Err(Error::Header("CWT sub does not match site.id"));
    }
    if statement.unprotected.alg.is_some()
        || statement.unprotected.content_type.is_some()
        || statement
            .unprotected
            .rest
            .iter()
            .any(|(label, _)| label == &Label::Int(CWT_CLAIMS_LABEL))
    {
        return Err(Error::Header(
            "profile headers must not appear in the unprotected map",
        ));
    }
    Ok(())
}
