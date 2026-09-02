// SPDX-License-Identifier: Apache-2.0

mod common;

use pask_attest::{AttestationError, AttestationVerifier};
use serde_json::Value;

use common::{
    MIDPOINT_SECS, WITNESS_KEY, clock_at, recompute_chain, root, sample_claims, signed_quote,
    signing_key,
};

#[test]
fn chain_matches_components_ok() {
    let key = signing_key(5);
    let claims = sample_claims(WITNESS_KEY);
    let result =
        root(&key, WITNESS_KEY).verify(&signed_quote(&claims, &key), &clock_at(MIDPOINT_SECS));
    assert!(result.is_ok());
}

#[test]
fn tampered_component_digest_fails_chain() {
    let key = signing_key(5);
    let mut claims = sample_claims(WITNESS_KEY);
    claims["measuredBoot"]["components"][0]["digest"] =
        Value::String(format!("sha256:{}", "aa".repeat(32)));
    let error = root(&key, WITNESS_KEY)
        .verify(&signed_quote(&claims, &key), &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MeasuredBootMismatch));
}

#[test]
fn reordered_components_fail_chain() {
    let key = signing_key(5);
    let mut claims = sample_claims(WITNESS_KEY);
    claims["measuredBoot"]["components"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let error = root(&key, WITNESS_KEY)
        .verify(&signed_quote(&claims, &key), &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MeasuredBootMismatch));
}

#[test]
fn empty_components_with_correct_chain_ok() {
    let key = signing_key(5);
    let mut claims = sample_claims(WITNESS_KEY);
    claims["measuredBoot"]["components"] = Value::Array(Vec::new());
    recompute_chain(&mut claims);
    let attestation = root(&key, WITNESS_KEY)
        .verify(&signed_quote(&claims, &key), &clock_at(MIDPOINT_SECS))
        .unwrap();
    assert!(attestation.measured_boot().components().is_empty());
}
