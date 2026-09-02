// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use pask_attest::{AttestationError, AttestationVerifier, Ed25519RootOfTrust};
use proptest::prelude::*;

use common::{
    FRAME_VERSION, MIDPOINT_SECS, WITNESS_KEY, clock_at, recompute_chain, root, sample_claims,
    signed_quote, signing_key, valid_quote,
};

#[test]
fn well_formed_frame_parses_ok() {
    let key = signing_key(1);
    let result =
        root(&key, WITNESS_KEY).verify(&valid_quote(&key, WITNESS_KEY), &clock_at(MIDPOINT_SECS));
    assert!(result.is_ok());
}

#[test]
fn truncated_frame_rejected() {
    let key = signing_key(1);
    let mut quote = valid_quote(&key, WITNESS_KEY);
    quote.truncate(10);
    let error = root(&key, WITNESS_KEY)
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MalformedQuote(_)));
}

#[test]
fn oversize_frame_rejected() {
    let quote = vec![0_u8; 1024 * 1024 + 1];
    let error = Ed25519RootOfTrust::new()
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MalformedQuote(_)));
}

#[test]
fn wrong_spec_version_byte_rejected() {
    let key = signing_key(1);
    let mut quote = valid_quote(&key, WITNESS_KEY);
    quote[7] = 2;
    let error = root(&key, WITNESS_KEY)
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MalformedQuote(_)));
}

#[test]
fn zero_length_signature_rejected() {
    let mut quote = FRAME_VERSION.to_vec();
    quote.extend_from_slice(&[0_u8; 64]);
    let error = Ed25519RootOfTrust::new()
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::MalformedQuote(_)));
}

proptest! {
    #[test]
    fn random_bytes_never_parse_ok(bytes in prop::collection::vec(any::<u8>(), 128)) {
        let result = Ed25519RootOfTrust::new()
            .verify(&bytes, &clock_at(MIDPOINT_SECS));
        prop_assert!(result.is_err());
    }

    #[test]
    fn quote_parser_round_trip(component_name in "[a-z]{1,20}", digest_byte in any::<u8>()) {
        let key = signing_key(9);
        let mut claims = sample_claims(WITNESS_KEY);
        claims["measuredBoot"]["components"][0]["name"] =
            serde_json::Value::String(component_name.clone());
        let digest_pair = format!("{digest_byte:02x}");
        claims["measuredBoot"]["components"][0]["digest"] = serde_json::Value::String(
            format!("sha256:{}", digest_pair.repeat(32)),
        );
        recompute_chain(&mut claims);
        let quote = signed_quote(&claims, &key);
        let attestation = root(&key, WITNESS_KEY)
            .verify(&quote, &clock_at(MIDPOINT_SECS))
            .unwrap();
        prop_assert_eq!(
            attestation.measured_boot().components()[0].name(),
            component_name
        );
    }
}
