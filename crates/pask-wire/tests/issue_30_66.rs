// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Tests for issues #30 (timestamp containment) and #66 (DIRECT_WITNESS
//! identifier-consistency check).
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

use ed25519_dalek::SigningKey;
use pask_wire::{
    BindingMode, Error, Payload, SPEC_VERSION, SPEC_VERSION_06, produce_ed25519,
    testvectors::MINIMAL_VALID_PAYLOAD,
    verify_ed25519,
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

// ---------------------------------------------------------------------------
// Issue #30: Timestamp containment under wilder.pser/0.6
// ---------------------------------------------------------------------------

#[test]
fn containment_passes_when_ts_is_inside_interval() {
    // ts = 14:00, interval = [13:00, 15:00] -> inside
    let payload = parse_06(&minimal_06()).expect("0.6 payload with ts inside interval must pass");
    assert_eq!(payload.spec(), SPEC_VERSION_06);
}

#[test]
fn containment_passes_at_inclusive_lower_bound() {
    // ts = notBefore = 13:00 -> inclusive endpoint, must pass
    let payload = parse_06(&with_ts("2026-10-15T13:00:00Z"))
        .expect("ts at notBefore is an inclusive endpoint and must pass");
    assert_eq!(payload.spec(), SPEC_VERSION_06);
}

#[test]
fn containment_passes_at_inclusive_upper_bound() {
    // ts = notAfter = 15:00 -> inclusive endpoint, must pass
    let payload = parse_06(&with_ts("2026-10-15T15:00:00Z"))
        .expect("ts at notAfter is an inclusive endpoint and must pass");
    assert_eq!(payload.spec(), SPEC_VERSION_06);
}

#[test]
fn containment_fails_when_ts_precedes_not_before() {
    // ts = 12:59, notBefore = 13:00 -> before the interval
    let error = parse_06(&with_ts("2026-10-15T12:59:59Z"))
        .expect_err("ts before notBefore must fail under 0.6");
    assert!(
        matches!(error, Error::Validation(msg) if msg.contains("validity interval")),
        "expected containment failure, got: {error}"
    );
}

#[test]
fn containment_fails_when_ts_exceeds_not_after() {
    // ts = 15:01, notAfter = 15:00 -> after the interval
    let error = parse_06(&with_ts("2026-10-15T15:00:01Z"))
        .expect_err("ts after notAfter must fail under 0.6");
    assert!(
        matches!(error, Error::Validation(msg) if msg.contains("validity interval")),
        "expected containment failure, got: {error}"
    );
}

#[test]
fn containment_not_required_under_0_5() {
    // Same ts outside interval, but spec = 0.5 -> must pass (no containment check)
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 does not require containment");
    assert_eq!(payload.spec(), SPEC_VERSION);
}

#[test]
fn otherwise_valid_fixture_fails_containment_under_0_6() {
    // The 0.5 minimal fixture has ts=14:00 inside [13:00,15:00], so it passes
    // under both versions. But if we move ts outside the interval and bump to
    // 0.6, it must fail. This confirms the check is version-specific.
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

/// Returns a 0.6 payload with bindingMode set to DELEGATED_WITNESS.
fn with_delegated_witness() -> String {
    minimal_06().replace("\"DIRECT_WITNESS\"", "\"DELEGATED_WITNESS\"")
}

#[test]
fn direct_witness_with_matching_identifiers_passes() {
    let payload = parse_06(&minimal_06()).expect("0.6 payload parses");
    let key = SigningKey::generate(&mut rand_core::OsRng);

    // Produce with witnessKey as the CWT iss -> matching identifiers
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

    // Produce with a different iss than witnessKey -> mismatch
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
    let payload = parse_06(&with_delegated_witness()).expect("0.6 DELEGATED_WITNESS payload parses");
    assert_eq!(payload.attestation_binding_mode(), &BindingMode::DelegatedWitness);
    let key = SigningKey::generate(&mut rand_core::OsRng);

    // Produce with a different iss than witnessKey -> check not applied for DELEGATED_WITNESS
    let statement = produce_ed25519(&payload, "key:tee:different-identifier", &key)
        .expect("produce succeeds");
    let verified = verify_ed25519(&statement, &key.verifying_key())
        .expect("DELEGATED_WITNESS does not require witnessKey == iss");
    assert_eq!(verified, payload);
}

#[test]
fn direct_witness_mismatch_not_checked_under_0_5() {
    // 0.5 DIRECT_WITNESS with mismatched identifiers -> check not applied
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes())
        .expect("0.5 payload parses");
    assert_eq!(payload.attestation_binding_mode(), &BindingMode::DirectWitness);
    let key = SigningKey::generate(&mut rand_core::OsRng);

    let statement = produce_ed25519(&payload, "key:tee:different-identifier", &key)
        .expect("produce succeeds");
    let verified = verify_ed25519(&statement, &key.verifying_key())
        .expect("0.5 does not require witnessKey == iss");
    assert_eq!(verified, payload);
}
