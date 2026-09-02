// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use pask_attest::{AttestationError, AttestationVerifier};

use common::{MIDPOINT_SECS, WITNESS_KEY, clock_at, root, signing_key, valid_quote};

#[test]
fn valid_signature_and_known_key_verifies() {
    let key = signing_key(2);
    let attestation = root(&key, WITNESS_KEY)
        .verify(&valid_quote(&key, WITNESS_KEY), &clock_at(MIDPOINT_SECS))
        .unwrap();
    assert_eq!(attestation.witness_key().as_str(), WITNESS_KEY);
}

#[test]
fn tampered_jcs_bytes_fail_signature() {
    let key = signing_key(2);
    let mut quote = valid_quote(&key, WITNESS_KEY);
    let offset = quote
        .windows(b"arm.cca".len())
        .position(|window| window == b"arm.cca")
        .expect("quote carries the teeClass value verbatim");
    quote[offset] = b'b';
    let error = root(&key, WITNESS_KEY)
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::InvalidSignature));
}

#[test]
fn unknown_witness_key_id_returns_unknown_root_of_trust() {
    let key = signing_key(2);
    let quote = valid_quote(&key, "key:tee:unknown");
    let error = root(&key, WITNESS_KEY)
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::UnknownRootOfTrust));
}

#[test]
fn signature_from_wrong_key_but_known_id_returns_invalid_signature() {
    let trusted_key = signing_key(2);
    let other_key = signing_key(3);
    let quote = valid_quote(&other_key, WITNESS_KEY);
    let error = root(&trusted_key, WITNESS_KEY)
        .verify(&quote, &clock_at(MIDPOINT_SECS))
        .unwrap_err();
    assert!(matches!(error, AttestationError::InvalidSignature));
}
