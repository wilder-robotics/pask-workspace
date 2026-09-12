// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Tests for issues #30 (timestamp containment), #66 (DIRECT_WITNESS
//! identifier-consistency check), M-01 (producer/verifier version agreement),
//! and M-02 (structural protected-header parsing).
//!
//! These tests exercise the wilder.pser/0.6 profile version, which carries
//! two new requirements not present in 0.5:
//!
//! 1. Issue #30: The receipt-issuance timestamp ts MUST fall within the
//!    attestation validity interval [notBefore, notAfter] using inclusive
//!    endpoints. This check does not apply to 0.5.
//!
//! 2. Issue #66: When bindingMode is DIRECT_WITNESS, attestation.witnessKey
//!    and the protected CWT iss value MUST be textually equal. This check
//!    does not apply to DELEGATED_WITNESS mode or to 0.5.
//!
//! Both checks are version-scoped: 0.5 payloads continue to pass without
//! containment or identifier matching. This is not a retroactive redefinition
//! of the 0.5 profile contract.
//!
//! M-01 tests verify that the producer selects the protected content type
//! from the payload's profile version, and the verifier requires exact
//! agreement between the protected content type and the payload's spec.
//!
//! M-02 tests verify that the parser reads the content type structurally
//! from COSE header label 3, not from a raw byte search.

use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, cbor::Value, iana};
use ed25519_dalek::{Signer, SigningKey};

use pask_wire::{
    BindingMode, CONTENT_TYPE, CONTENT_TYPE_06, Error, Payload, SPEC_VERSION, SPEC_VERSION_06,
    produce_ed25519, testvectors::MINIMAL_VALID_PAYLOAD, verify_ed25519,
};

/// Returns the minimal valid payload with spec set to 0.6.
fn minimal_06() -> String {
    MINIMAL_VALID_PAYLOAD.replace(SPEC_VERSION, SPEC_VERSION_06)
}

/// Returns a 0.6 payload with ts set to the given value.
/// Only replaces the ts field, not the engagement window end.
fn with_ts(ts: &str) -> String {
    minimal_06().replace(
        "\"ts\": \"2026-10-15T14:00:00Z\"",
        &format!("\"ts\": \"{ts}\""),
    )
}

/// Parses a mutated 0.6 payload through production normalization.
fn parse_06(json: &str) -> pask_wire::Result<Payload> {
    Payload::from_json_for_production(json.as_bytes())
}

/// Builds a signed COSE_Sign1 statement with a specific protected content
/// type, overriding what `produce_ed25519` would select. Used for version
/// mismatch tests where the header and payload must disagree.
fn build_statement_with_ct(
    payload: &Payload,
    content_type: &str,
    issuer: &str,
    key: &SigningKey,
) -> Vec<u8> {
    let cwt_claims = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Text(issuer.to_string())),
        (
            Value::Integer(2i64.into()),
            Value::Bytes(payload.site_id().as_bytes().to_vec()),
        ),
    ]);
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .content_type(content_type.to_string())
        .value(15, cwt_claims)
        .build();
    let statement = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_jcs().expect("payload must serialize"))
        .create_signature(&[], |data| key.sign(data).to_bytes().to_vec())
        .build();
    statement.to_vec().expect("statement must serialize")
}

/// Builds a signed COSE_Sign1 from a raw protected-header CBOR map. Used for
/// negative parser tests that need malformed headers (duplicates, missing
/// fields, extra fields).
fn build_statement_with_raw_protected(
    protected_map: Value,
    payload: &Payload,
    _issuer: &str,
    key: &SigningKey,
) -> Vec<u8> {
    let mut protected_bytes = Vec::new();
    coset::cbor::ser::into_writer(&protected_map, &mut protected_bytes)
        .expect("protected header must serialize");

    let payload_bytes = payload.to_jcs().expect("payload must serialize");

    // Build the signature structure: ["Signature1", protected_bstr, aad_bstr, payload_bstr]
    let sig_struct = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(payload_bytes.clone()),
    ]);
    let mut sig_struct_bytes = Vec::new();
    coset::cbor::ser::into_writer(&sig_struct, &mut sig_struct_bytes)
        .expect("sig structure must serialize");
    let signature = key.sign(&sig_struct_bytes).to_bytes().to_vec();

    let cose_value = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(vec![]),
        Value::Bytes(payload_bytes),
        Value::Bytes(signature),
    ]);

    let mut statement_bytes = Vec::new();
    coset::cbor::ser::into_writer(&cose_value, &mut statement_bytes)
        .expect("statement must serialize");
    statement_bytes
}

/// Extracts the content type text string from a produced statement by
/// parsing the protected header structurally at COSE label 3.
#[allow(clippy::collapsible_if)]
fn extract_content_type(statement: &[u8]) -> Option<String> {
    let value: Value = coset::cbor::de::from_reader(&mut &statement[..]).ok()?;
    let Value::Array(items) = value else {
        return None;
    };
    let protected_bytes = items.first()?.as_bytes()?;
    let protected_map: Value = coset::cbor::de::from_reader(&mut &protected_bytes[..]).ok()?;
    let Value::Map(entries) = protected_map else {
        return None;
    };
    for (label, val) in entries {
        if let Value::Integer(label_int) = label {
            if i128::from(label_int) == 3 {
                if let Value::Text(ct) = val {
                    return Some(ct.clone());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Issue #30: Timestamp containment under wilder.pser/0.6
// ---------------------------------------------------------------------------

#[test]
fn containment_passes_when_ts_is_inside_interval() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload with ts inside interval must pass");
    assert_eq!(payload.spec(), SPEC_VERSION_06);
}

#[test]
fn containment_passes_at_inclusive_lower_bound() {
    let payload = parse_06(&with_ts("2026-10-15T13:00:00Z"))
        .expect("ts at notBefore is an inclusive endpoint and must pass");
    assert_eq!(payload.spec(), SPEC_VERSION_06);
}

#[test]
fn containment_passes_at_inclusive_upper_bound() {
    let payload = parse_06(&with_ts("2026-10-15T15:00:00Z"))
        .expect("ts at notAfter is an inclusive endpoint and must pass");
    assert_eq!(payload.spec(), SPEC_VERSION_06);
}

#[test]
fn containment_fails_when_ts_precedes_not_before() {
    let error = parse_06(&with_ts("2026-10-15T12:59:59Z"))
        .expect_err("ts before notBefore must fail under 0.6");
    assert!(
        matches!(error, Error::Validation(msg) if msg.contains("validity interval")),
        "expected containment failure, got: {error}"
    );
}

#[test]
fn containment_fails_when_ts_exceeds_not_after() {
    let error = parse_06(&with_ts("2026-10-15T15:00:01Z"))
        .expect_err("ts after notAfter must fail under 0.6");
    assert!(
        matches!(error, Error::Validation(msg) if msg.contains("validity interval")),
        "expected containment failure, got: {error}"
    );
}

#[test]
fn containment_not_required_under_0_5() {
    // ts = 12:00 is OUTSIDE the [13:00, 15:00] validity interval.
    // Under 0.5, containment is not checked, so this must pass.
    let out_of_window = MINIMAL_VALID_PAYLOAD.replace(
        "\"ts\": \"2026-10-15T14:00:00Z\"",
        "\"ts\": \"2026-10-15T12:00:00Z\"",
    );
    let payload = Payload::from_json_for_production(out_of_window.as_bytes())
        .expect("0.5 does not require containment even when ts is outside the interval");
    assert_eq!(payload.spec(), SPEC_VERSION);
}

#[test]
fn otherwise_valid_fixture_fails_containment_under_0_6() {
    let json = with_ts("2026-10-15T12:00:00Z");
    let error = parse_06(&json).expect_err("0.6 must reject ts outside interval");
    assert!(
        matches!(error, Error::Validation(msg) if msg.contains("validity interval")),
        "expected containment failure, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// Issue #66: DIRECT_WITNESS identifier-consistency check
// ---------------------------------------------------------------------------

fn with_delegated_witness() -> String {
    minimal_06().replace("\"DIRECT_WITNESS\"", "\"DELEGATED_WITNESS\"")
}

#[test]
fn direct_witness_with_matching_identifiers_passes() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement = produce_ed25519(&payload, payload.witness_key(), &key)
        .expect("produce succeeds with matching identifiers");
    let verified = verify_ed25519(&statement, &key.verifying_key())
        .expect("verification must pass when witnessKey equals iss");
    assert_eq!(verified, payload);
}

#[test]
fn direct_witness_with_mismatched_identifiers_fails() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement = produce_ed25519(&payload, "key:tee:different-identifier", &key)
        .expect("produce succeeds (production does not check)");
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("mismatched witnessKey and iss must fail under 0.6 DIRECT_WITNESS");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("textually equal")),
        "expected identifier mismatch failure, got: {error}"
    );
}

#[test]
fn delegated_witness_with_mismatched_identifiers_passes() {
    let payload =
        parse_06(&with_delegated_witness()).expect("0.6 DELEGATED_WITNESS payload parses");
    assert_eq!(
        payload.attestation_binding_mode(),
        &BindingMode::DelegatedWitness
    );
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement =
        produce_ed25519(&payload, "key:tee:different-identifier", &key).expect("produce succeeds");
    let verified = verify_ed25519(&statement, &key.verifying_key())
        .expect("DELEGATED_WITNESS does not require witnessKey == iss");
    assert_eq!(verified, payload);
}

#[test]
fn direct_witness_mismatch_not_checked_under_0_5() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    assert_eq!(
        payload.attestation_binding_mode(),
        &BindingMode::DirectWitness
    );
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement =
        produce_ed25519(&payload, "key:tee:different-identifier", &key).expect("produce succeeds");
    let verified = verify_ed25519(&statement, &key.verifying_key())
        .expect("0.5 does not require witnessKey == iss");
    assert_eq!(verified, payload);
}

// ---------------------------------------------------------------------------
// M-01: Producer/verifier version agreement
// ---------------------------------------------------------------------------

#[test]
fn producer_05_payload_carries_05_content_type() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement =
        produce_ed25519(&payload, payload.witness_key(), &key).expect("produce succeeds");
    let ct =
        extract_content_type(&statement).expect("content type must be present in protected header");
    assert_eq!(ct, CONTENT_TYPE, "0.5 payload must carry 0.5 content type");
}

#[test]
fn producer_06_payload_carries_06_content_type() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement =
        produce_ed25519(&payload, payload.witness_key(), &key).expect("produce succeeds");
    let ct =
        extract_content_type(&statement).expect("content type must be present in protected header");
    assert_eq!(
        ct, CONTENT_TYPE_06,
        "0.6 payload must carry 0.6 content type"
    );
}

#[test]
fn version_agreement_05_05_passes() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement =
        produce_ed25519(&payload, payload.witness_key(), &key).expect("produce succeeds");
    verify_ed25519(&statement, &key.verifying_key())
        .expect("0.5 payload with 0.5 header must verify");
}

#[test]
fn version_agreement_06_06_passes() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement =
        produce_ed25519(&payload, payload.witness_key(), &key).expect("produce succeeds");
    verify_ed25519(&statement, &key.verifying_key())
        .expect("0.6 payload with 0.6 header must verify");
}

#[test]
fn version_mismatch_05_payload_06_header_rejected() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement = build_statement_with_ct(&payload, CONTENT_TYPE_06, payload.witness_key(), &key);
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("0.5 payload with 0.6 header must be rejected");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("content_type does not match")),
        "expected version mismatch failure, got: {error}"
    );
}

#[test]
fn version_mismatch_06_payload_05_header_rejected() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement = build_statement_with_ct(&payload, CONTENT_TYPE, payload.witness_key(), &key);
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("0.6 payload with 0.5 header must be rejected");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("content_type does not match")),
        "expected version mismatch failure, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// M-02: Structural protected-header parsing
// ---------------------------------------------------------------------------

#[test]
fn missing_content_type_rejected() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);

    let protected_map = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer((-8i64).into())),
        (
            Value::Integer(15i64.into()),
            Value::Map(vec![
                (
                    Value::Integer(1i64.into()),
                    Value::Text(payload.witness_key().to_string()),
                ),
                (
                    Value::Integer(2i64.into()),
                    Value::Bytes(payload.site_id().as_bytes().to_vec()),
                ),
            ]),
        ),
    ]);

    let statement =
        build_statement_with_raw_protected(protected_map, &payload, payload.witness_key(), &key);
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("missing content type must be rejected");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("content_type does not match")),
        "expected content type mismatch failure, got: {error}"
    );
}

#[test]
fn wrong_content_type_rejected() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);

    let statement =
        build_statement_with_ct(&payload, "application/json", payload.witness_key(), &key);
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("wrong content type must be rejected");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("content_type does not match")),
        "expected content type mismatch failure, got: {error}"
    );
}

#[test]
fn duplicate_content_type_rejected() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);

    // Build a protected header map with two label-3 entries. CBOR allows
    // duplicate map keys; the parser must detect and reject this.
    let protected_map = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer((-8i64).into())),
        (
            Value::Integer(3i64.into()),
            Value::Text(CONTENT_TYPE.replace('/', "-")),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Text(CONTENT_TYPE.replace('/', "-")),
        ),
        (
            Value::Integer(15i64.into()),
            Value::Map(vec![
                (
                    Value::Integer(1i64.into()),
                    Value::Text(payload.witness_key().to_string()),
                ),
                (
                    Value::Integer(2i64.into()),
                    Value::Bytes(payload.site_id().as_bytes().to_vec()),
                ),
            ]),
        ),
    ]);

    let statement =
        build_statement_with_raw_protected(protected_map, &payload, payload.witness_key(), &key);
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("duplicate content type must be rejected");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("duplicate content_type")),
        "expected duplicate content type failure, got: {error}"
    );
}

#[test]
fn profile_string_in_unrelated_field_not_treated_as_content_type() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);

    // Build a protected header where:
    // - Label 3 (content type) is a non-Pask value ("application/json")
    // - Label 99 (custom extension) contains the full Pask content type string
    //
    // The old byte-search parser would have found the Pask content type string
    // in the raw bytes and treated it as the content type. The structural
    // parser must read label 3 only and reject the statement.
    let protected_map = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer((-8i64).into())),
        (
            Value::Integer(3i64.into()),
            Value::Text("application/json".to_string()),
        ),
        (
            Value::Integer(99i64.into()),
            Value::Text(CONTENT_TYPE.to_string()),
        ),
        (
            Value::Integer(15i64.into()),
            Value::Map(vec![
                (
                    Value::Integer(1i64.into()),
                    Value::Text(payload.witness_key().to_string()),
                ),
                (
                    Value::Integer(2i64.into()),
                    Value::Bytes(payload.site_id().as_bytes().to_vec()),
                ),
            ]),
        ),
    ]);

    let statement =
        build_statement_with_raw_protected(protected_map, &payload, payload.witness_key(), &key);
    let error = verify_ed25519(&statement, &key.verifying_key())
        .expect_err("profile string in unrelated field must not be treated as content type");
    assert!(
        matches!(error, Error::Header(msg) if msg.contains("content_type does not match")),
        "expected content type mismatch failure, got: {error}"
    );
}
