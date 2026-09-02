// SPDX-License-Identifier: Apache-2.0

mod common;

use pask_attest::{AttestationError, AttestationVerifier};
use proptest::prelude::*;

use common::{
    MIDPOINT_SECS, NOT_AFTER_SECS, NOT_BEFORE_SECS, WITNESS_KEY, clock_at, root, signing_key,
    valid_quote,
};

#[test]
fn within_window_ok() {
    let key = signing_key(4);
    let result =
        root(&key, WITNESS_KEY).verify(&valid_quote(&key, WITNESS_KEY), &clock_at(MIDPOINT_SECS));
    assert!(result.is_ok());
}

#[test]
fn expired_returns_expired_evidence() {
    let key = signing_key(4);
    let error = root(&key, WITNESS_KEY)
        .verify(
            &valid_quote(&key, WITNESS_KEY),
            &clock_at(NOT_AFTER_SECS + 61),
        )
        .unwrap_err();
    assert!(matches!(error, AttestationError::ExpiredEvidence { .. }));
}

#[test]
fn not_yet_valid_returns_clock_skew() {
    let key = signing_key(4);
    let error = root(&key, WITNESS_KEY)
        .verify(
            &valid_quote(&key, WITNESS_KEY),
            &clock_at(NOT_BEFORE_SECS - 61),
        )
        .unwrap_err();
    assert!(matches!(error, AttestationError::ClockSkew { .. }));
}

#[test]
fn within_skew_before_not_before_ok() {
    let key = signing_key(4);
    let result = root(&key, WITNESS_KEY).verify(
        &valid_quote(&key, WITNESS_KEY),
        &clock_at(NOT_BEFORE_SECS - 60),
    );
    assert!(result.is_ok());
}

#[test]
fn within_skew_after_not_after_ok() {
    let key = signing_key(4);
    let result = root(&key, WITNESS_KEY).verify(
        &valid_quote(&key, WITNESS_KEY),
        &clock_at(NOT_AFTER_SECS + 60),
    );
    assert!(result.is_ok());
}

proptest! {
    #[test]
    fn validity_window_boundary_conditions(offset in -120_i64..=120_i64) {
        let key = signing_key(4);
        let not_before = i64::try_from(NOT_BEFORE_SECS).unwrap();
        let now = u64::try_from(not_before + offset).unwrap();
        let result = root(&key, WITNESS_KEY).verify(
            &valid_quote(&key, WITNESS_KEY),
            &clock_at(now),
        );
        if offset < -60 {
            let is_clock_skew = matches!(result, Err(AttestationError::ClockSkew { .. }));
            prop_assert!(is_clock_skew);
        } else {
            prop_assert!(result.is_ok());
        }
    }
}
