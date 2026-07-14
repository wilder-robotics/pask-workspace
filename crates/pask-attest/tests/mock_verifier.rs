#![cfg(feature = "mock")]

mod common;

use pask_attest::{AttestationError, AttestationVerifier, MockAttestationVerifier};

use common::{MIDPOINT_SECS, WITNESS_KEY, clock_at, verified_attestation};

#[test]
fn mock_verifier_returns_configured_attestation() {
    let verifier = MockAttestationVerifier::new()
        .with_attestation(b"mock:known".to_vec(), verified_attestation());
    let attestation = verifier
        .verify(b"mock:known:payload", &clock_at(MIDPOINT_SECS))
        .unwrap();
    assert_eq!(attestation.witness_key().as_str(), WITNESS_KEY);
}

#[test]
fn mock_verifier_rejects_unconfigured_quote() {
    let verifier = MockAttestationVerifier::new()
        .with_attestation(b"mock:known".to_vec(), verified_attestation());
    let error = verifier
        .verify(b"mock:other", &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MalformedQuote(_)));
}
