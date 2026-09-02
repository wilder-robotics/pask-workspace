// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use pask_attest::AttestationError;

#[test]
fn all_error_variants_have_distinct_display() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let errors = [
        AttestationError::InvalidSignature,
        AttestationError::ExpiredEvidence {
            not_after: SystemTime::UNIX_EPOCH,
            now,
        },
        AttestationError::ClockSkew {
            not_before: now,
            now: SystemTime::UNIX_EPOCH,
        },
        AttestationError::UnknownRootOfTrust,
        AttestationError::MalformedQuote("malformed".to_owned()),
        AttestationError::UnsupportedTeeClass("unsupported".to_owned()),
        AttestationError::MeasuredBootMismatch,
        AttestationError::MissingClaim("claim"),
        AttestationError::WireError("wire".to_owned()),
    ];
    let messages = errors
        .iter()
        .map(ToString::to_string)
        .collect::<HashSet<_>>();
    assert_eq!(messages.len(), errors.len());
}
