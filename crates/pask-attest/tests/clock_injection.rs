// SPDX-License-Identifier: Apache-2.0

mod common;

use pask_attest::{AttestationError, AttestationVerifier};

use common::{MIDPOINT_SECS, WITNESS_KEY, clock_at, root, signing_key, valid_quote};

#[test]
fn verifier_never_reads_wall_clock() {
    let key = signing_key(6);
    let error = root(&key, WITNESS_KEY)
        .verify(
            &valid_quote(&key, WITNESS_KEY),
            &common::TestClock(std::time::SystemTime::UNIX_EPOCH),
        )
        .unwrap_err();
    assert!(matches!(error, AttestationError::ClockSkew { .. }));
}

#[test]
fn two_verifiers_with_different_clocks_disagree() {
    let key = signing_key(6);
    let quote = valid_quote(&key, WITNESS_KEY);
    let verifier = root(&key, WITNESS_KEY);
    let accepted = verifier.verify(&quote, &clock_at(MIDPOINT_SECS));
    let rejected = verifier.verify(
        &quote,
        &common::TestClock(std::time::SystemTime::UNIX_EPOCH),
    );
    assert!(accepted.is_ok());
    assert!(matches!(rejected, Err(AttestationError::ClockSkew { .. })));
}
