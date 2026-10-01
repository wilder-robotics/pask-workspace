// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! F4 regressions. The first test is also executable unchanged on the accepted
//! predecessor: retain its actual failing-before result, not an author inference.
#![cfg(feature = "alloc")]

use pask_wire::proposed_content::{
    CONSTRUCTION, ContentError, ContentHeader, DisclosedFact, SCOPE, SaltedFact, prepare_content,
    verify_content_disclosures,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const VOCAB: &str = "sha256:030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d";

fn header() -> ContentHeader<'static> {
    ContentHeader {
        construction: CONSTRUCTION,
        scope: SCOPE,
        vocabulary_digest: VOCAB,
    }
}

fn raw_fact(value: &str) -> Vec<u8> {
    format!(
        r#"{{"assertedBy":"site-policy","basis":"declared","name":"sample.fact","value":{value}}}"#
    )
    .into_bytes()
}

fn rejection(record: &[u8]) -> Option<ContentError> {
    prepare_content(
        &header(),
        &[SaltedFact {
            record,
            salt: [1; 32],
        }],
    )
    .err()
}

#[test]
fn f4_over_u64_integer_token_is_rejected_before_float_conversion() {
    assert_eq!(
        rejection(&raw_fact("100000000000000000000")),
        Some(ContentError::UnsupportedNumber)
    );
}

#[test]
fn safe_integer_endpoints_and_zero_are_supported() {
    for value in ["0", "1", "-1", "9007199254740991", "-9007199254740991"] {
        assert_eq!(rejection(&raw_fact(value)), None, "{value}");
    }
}

#[test]
fn adjacent_and_parser_overflow_integer_tokens_are_unsupported() {
    for value in [
        "9007199254740992",
        "-9007199254740992",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "18446744073709551616",
        "100000000000000000000",
        "-100000000000000000000",
    ] {
        assert_eq!(
            rejection(&raw_fact(value)),
            Some(ContentError::UnsupportedNumber),
            "{value}"
        );
    }
}

#[test]
fn very_long_integer_tokens_use_the_same_bounded_rejection() {
    for sign in ["", "-"] {
        let value = format!("{sign}{}", "9".repeat(4096));
        assert_eq!(
            rejection(&raw_fact(&value)),
            Some(ContentError::UnsupportedNumber)
        );
    }
}

#[test]
fn nested_arrays_and_extra_fields_do_not_bypass_the_bound() {
    for value in [
        "[0,100000000000000000000]",
        r#"{"a":[{"b":-100000000000000000000}]}"#,
    ] {
        assert_eq!(
            rejection(&raw_fact(value)),
            Some(ContentError::UnsupportedNumber)
        );
    }
    let extra = br#"{"assertedBy":"site-policy","basis":"declared","extra":100000000000000000000,"name":"sample.fact","value":0}"#;
    assert_eq!(rejection(extra), Some(ContentError::UnsupportedNumber));
}

#[test]
fn quoted_digits_and_escaped_quotes_are_not_numeric_tokens() {
    for text in [
        "100000000000000000000",
        "\"100000000000000000000\"",
        "backslash\\ then \"999999999999999999999999\"",
        "unicode Δ { -100000000000000000000 }",
    ] {
        let value = json!({
            "assertedBy":"site-policy", "basis":"declared",
            "name":"sample.fact", "value":text
        });
        let bytes = pask_wire::canonicalize_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(rejection(&bytes), None, "{text}");
    }
}

#[test]
fn escaped_string_does_not_hide_a_later_real_integer() {
    let bytes = br#"{"assertedBy":"site-policy","basis":"declared","extra":"quote\"999999999999999999999","name":"sample.fact","value":100000000000000000000}"#;
    assert_eq!(rejection(bytes), Some(ContentError::UnsupportedNumber));
}

#[test]
fn existing_canonical_finite_fraction_and_exponent_forms_remain_supported() {
    for value in ["0.5", "-0.125", "1e+30", "-1e+30", "1e-7"] {
        assert_eq!(rejection(&raw_fact(value)), None, "{value}");
    }
}

#[test]
fn noncanonical_forms_still_do_not_become_passing_facts() {
    for value in ["-0", "1.0", "1e0", "1e20", "1E+30", "1e30"] {
        assert!(rejection(&raw_fact(value)).is_some(), "{value}");
    }
}

#[test]
fn malformed_numbers_are_not_accepted_by_the_preflight() {
    for value in [
        "-", "+1", "01", "-01", "1e", "1e+", "1.", "1..0", "--1", "NaN", "Infinity",
    ] {
        assert!(rejection(&raw_fact(value)).is_some(), "{value}");
    }
}

#[test]
fn correctly_computed_hostile_root_cannot_bypass_fact_number_check() {
    fn h(parts: &[&[u8]]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"PASK-LOCAL-CONTENT-TREE/1\0");
        for part in parts {
            hash.update(part);
        }
        hash.finalize().into()
    }
    let record = raw_fact("100000000000000000000");
    let vocabulary = hex::decode(&VOCAB[7..]).unwrap();
    let hh = h(&[
        &[0],
        &1u64.to_be_bytes(),
        &(CONSTRUCTION.len() as u64).to_be_bytes(),
        CONSTRUCTION.as_bytes(),
        &(SCOPE.len() as u64).to_be_bytes(),
        SCOPE.as_bytes(),
        &vocabulary,
    ]);
    let leaf = h(&[
        &[1],
        &hh,
        &0u64.to_be_bytes(),
        &[1; 32],
        &(record.len() as u64).to_be_bytes(),
        &record,
    ]);
    let root = format!("sha256:{}", hex::encode(h(&[&[4], &hh, &leaf])));
    let disclosure = DisclosedFact {
        record: &record,
        salt: [1; 32],
        index: 0,
        siblings: vec![],
    };
    assert_eq!(
        verify_content_disclosures(&root, &header(), 1, &[disclosure]).err(),
        Some(ContentError::UnsupportedNumber)
    );
}

#[test]
fn raw_evidence_comparator_source_is_not_used_to_normalize_facts() {
    // -0 is a raw-evidence integer-equivalence case, not canonical fact bytes.
    assert_eq!(
        rejection(&raw_fact("-0")),
        Some(ContentError::NonCanonicalFact)
    );
    assert_eq!(rejection(&raw_fact("0")), None);
}
