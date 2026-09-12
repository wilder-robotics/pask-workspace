// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

use alloc::{borrow::ToOwned, string::ToString, vec::Vec};
use coset::{
    Algorithm, AsCborValue, CborSerializable, ContentType, CoseSign1, CoseSign1Builder,
    HeaderBuilder, Label, cbor::Value, iana,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{
    Error, Payload, Result,
    cwt::{CWT_CLAIMS_LABEL, CwtClaims},
    payload::{SPEC_VERSION, SPEC_VERSION_06},
};

/// Required protected content type for the profile.
pub const CONTENT_TYPE: &str = "application/pser+json; profile=wilder.pser/0.5";

/// Content type for the 0.6 profile version.
pub const CONTENT_TYPE_06: &str = "application/pser+json; profile=wilder.pser/0.6";

/// Returns the required protected content type for the given profile version.
///
/// Returns `None` for unsupported versions. Used by both the producer and the
/// verifier so that version selection is one mapping, not two independent
/// checks that can disagree.
fn content_type_for_spec(spec: &str) -> Option<&'static str> {
    match spec {
        SPEC_VERSION => Some(CONTENT_TYPE),
        SPEC_VERSION_06 => Some(CONTENT_TYPE_06),
        _ => None,
    }
}

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
    // Select the protected content type from the payload's profile version.
    // The producer and verifier share one mapping via content_type_for_spec,
    // so a 0.6 payload always gets a 0.6 header and a 0.5 payload always gets
    // a 0.5 header.
    let ct = content_type_for_spec(payload.spec())
        .ok_or(Error::Validation("unsupported spec version for production"))?;
    let protected = HeaderBuilder::new()
        .algorithm(algorithm)
        .content_type(ct.to_owned())
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

/// COSE header label for content type.
const COSE_LABEL_CONTENT_TYPE: i64 = 3;

/// Parses a `COSE_Sign1` from CBOR bytes.
///
/// The content type is read structurally from COSE header label 3 in the
/// protected header map, not from a raw byte search of the header bytes.
///
/// The `coset` crate (0.4.x) enforces that content type text strings contain
/// exactly one '/' (the MIME type separator). The Pask content type includes
/// a profile parameter with a second '/' (e.g., "wilder.pser/0.5"), which
/// fails this check. To work around this, the protected header is parsed
/// separately as a CBOR map to locate the content type at label 3. If the
/// content type is found there and contains the profile version separator,
/// the second '/' in the raw bytes is replaced with '-' so `coset` can parse
/// the structure. The original bytes are preserved for signature verification
/// via `protected.original_data`, and the content type is normalized back to
/// its canonical form after parsing.
///
/// A profile string appearing in another protected header field (not label 3)
/// is not treated as a content type.
#[allow(clippy::collapsible_if)]
fn parse_statement(mut encoded: &[u8]) -> Result<CoseSign1> {
    let mut value: Value = coset::cbor::de::from_reader(&mut encoded)
        .map_err(|_| Error::Cose("failed to parse COSE_Sign1 CBOR"))?;
    if !encoded.is_empty() {
        return Err(Error::Cose("trailing bytes after COSE_Sign1"));
    }

    let Value::Array(items) = &mut value else {
        return Err(Error::Cose("COSE_Sign1 must be an array"));
    };
    let Some(Value::Bytes(protected_original)) = items.first() else {
        return Err(Error::Cose("COSE_Sign1 protected header must be bytes"));
    };
    let protected_original = protected_original.clone();

    // Structurally parse the protected header as a CBOR map to locate the
    // content type at COSE label 3. This is not a raw byte search: we
    // deserialize the protected header and look at the actual header field.
    let protected_map: Value = coset::cbor::de::from_reader(&mut &protected_original[..])
        .map_err(|_| Error::Cose("protected header is not valid CBOR"))?;

    let mut ct_needs_compat = false;
    let mut ct_normalized: Option<&'static str> = None;
    let mut ct_label_count = 0;

    if let Value::Map(entries) = &protected_map {
        for (label, val) in entries {
            if let Value::Integer(label_int) = label {
                if i128::from(*label_int) == COSE_LABEL_CONTENT_TYPE as i128 {
                    ct_label_count += 1;
                    if let Value::Text(ct_str) = val {
                        for ct in [CONTENT_TYPE, CONTENT_TYPE_06] {
                            if ct_str == ct {
                                // Canonical form with two '/' characters.
                                // coset rejects this, so we need the
                                // compatibility step.
                                ct_needs_compat = true;
                                ct_normalized = Some(ct);
                                break;
                            }
                            let hyphen_form = ct.replace('/', "-");
                            if ct_str == &hyphen_form {
                                // Producer deviation: second '/' already
                                // encoded as '-'. coset can parse this, but
                                // we normalize after parsing.
                                ct_needs_compat = true;
                                ct_normalized = Some(ct);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if ct_label_count > 1 {
        return Err(Error::Header("duplicate content_type in protected header"));
    }

    // If the content type contains the profile version separator '/', replace
    // it with '-' in the protected header bytes so coset can parse the
    // structure. This operates on the actual content type field at label 3,
    // which we have verified structurally above. A matching string in another
    // protected field is not affected.
    if ct_needs_compat {
        let ct = ct_normalized.expect("checked above");
        // Replace the second '/' (in the profile version) with '-' in the
        // raw protected header bytes. The first '/' (MIME type separator) is
        // preserved so coset's single-'/' check passes.
        let slash_pos = ct
            .rfind('/')
            .expect("content type contains a profile version separator");
        let ct_bytes = ct.as_bytes();

        if let Value::Array(items) = &mut value {
            if let Some(Value::Bytes(protected)) = items.first_mut() {
                // Search for the content type string in the protected header
                // bytes. This is safe because we have already verified that
                // the content type is at COSE label 3 in the CBOR map.
                if let Some(start) = protected
                    .windows(ct_bytes.len())
                    .position(|w| w == ct_bytes)
                {
                    protected[start + slash_pos] = b'-';
                }
            }
        }
    }

    let mut statement = CoseSign1::from_cbor_value(value)
        .map_err(|_| Error::Cose("failed to parse COSE_Sign1 structure"))?;

    // Restore the original protected header bytes for signature verification
    // and normalize the content type to its canonical form (with '/').
    if ct_needs_compat {
        let ct = ct_normalized.expect("checked above");
        statement.protected.original_data = Some(protected_original);
        statement.protected.header.content_type = Some(ContentType::Text(ct.to_owned()));
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
    // Require exact agreement between the payload's profile version and the
    // protected content type. A 0.6 payload must carry a 0.6 header, and a
    // 0.5 payload must carry a 0.5 header. The verifier does not accept a
    // mismatch even when both versions are individually supported.
    let expected_ct = content_type_for_spec(payload.spec())
        .ok_or(Error::Validation("unsupported spec version"))?;
    if header.content_type != Some(ContentType::Text(expected_ct.to_string())) {
        return Err(Error::Header(
            "protected content_type does not match payload spec version",
        ));
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
    // Issue #66: Under wilder.pser/0.6, when bindingMode is DIRECT_WITNESS,
    // attestation.witnessKey and the protected CWT `iss` value MUST be textually
    // equal. This check does not apply to DELEGATED_WITNESS mode or to earlier
    // profile versions. It establishes only a naming convention; it does not
    // establish that the signature-verification key is authentically associated
    // with either identifier or that genuine TEE hardware produced the
    // signature.
    if payload.spec() == crate::payload::SPEC_VERSION_06
        && matches!(
            payload.attestation_binding_mode(),
            crate::BindingMode::DirectWitness
        )
        && claims.issuer != payload.witness_key()
    {
        return Err(Error::Header(
            "DIRECT_WITNESS witnessKey and CWT iss must be textually equal under wilder.pser/0.6",
        ));
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
