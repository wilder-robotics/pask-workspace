// SPDX-License-Identifier: Apache-2.0
//! Local regression cases for presented bytes and exact scalar comparison.
//! The Python vector oracle is separate from the Rust implementation under test.
#![cfg(feature = "alloc")]
use pask_wire::proposed_constraints::{ConstraintResult, EvidenceState, inspect_fact};
use pask_wire::proposed_evidence::{
    EvidenceIntegrity, EvidenceReference, MAX_PRESENTED_EVIDENCE_BYTES, PresentedEvidence,
    ScalarComparison, ValueComparison, inspect_presented_evidence,
};
use pask_wire::sha256_prefixed;
use serde_json::{Value, json};

fn compare(data: &[u8], recorded: &Value) -> pask_wire::proposed_evidence::EvidenceReport {
    let expected = sha256_prefixed(data);
    inspect_presented_evidence(
        EvidenceReference::Sha256(&expected),
        PresentedEvidence::Bytes(data),
        Some(ScalarComparison {
            recorded_value: recorded,
            declared_unit: None,
        }),
    )
}

#[test]
fn all_56_python_vectors_match_actual_rust_reports() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proposed07/evidence-scalar-v1.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 56);
    for case in cases {
        let raw = hex::decode(case["raw_hex"].as_str().unwrap()).unwrap();
        let reference = match case["reference"].as_str().unwrap() {
            "absent" => EvidenceReference::Absent,
            "pointer" => EvidenceReference::PointerOnly,
            "digest" => EvidenceReference::Sha256(case["expected_digest"].as_str().unwrap()),
            _ => panic!("unknown fixture reference"),
        };
        let presented = match case["presentation"].as_str().unwrap() {
            "not-requested" => PresentedEvidence::NotRequested,
            "unavailable" => PresentedEvidence::Unavailable,
            "bytes" => PresentedEvidence::Bytes(&raw),
            _ => panic!("unknown fixture presentation"),
        };
        let request = case["compare"]
            .as_bool()
            .unwrap()
            .then_some(ScalarComparison {
                recorded_value: &case["recorded_value"],
                declared_unit: case["declared_unit"].as_str(),
            });
        let report = inspect_presented_evidence(reference, presented, request);
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn correctly_hashed_evidence_can_contradict_the_recorded_value() {
    let report = compare(b"8", &json!(7));
    assert_eq!(report.integrity, EvidenceIntegrity::Matched);
    assert_eq!(report.comparison, ValueComparison::Contradiction);
    assert_eq!(report.checked_bytes, 1);
    assert_eq!(report.receipt_binding, "NOT_EVALUATED");
    assert!(!report.attributed_party_authenticated);
}

#[test]
fn digest_failure_prevents_comparison_even_when_values_would_agree() {
    let recorded = json!(8);
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&sha256_prefixed(b"7")),
        PresentedEvidence::Bytes(b"8"),
        Some(ScalarComparison {
            recorded_value: &recorded,
            declared_unit: None,
        }),
    );
    assert_eq!(report.integrity, EvidenceIntegrity::Mismatch);
    assert_eq!(report.comparison, ValueComparison::NotRun);
}

#[test]
fn equal_lexical_values_do_not_bypass_changed_raw_byte_digest() {
    let recorded = json!(7);
    let digest = sha256_prefixed(b"7");
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&digest),
        PresentedEvidence::Bytes(b" 7 \n"),
        Some(ScalarComparison {
            recorded_value: &recorded,
            declared_unit: None,
        }),
    );
    assert_eq!(report.integrity, EvidenceIntegrity::Mismatch);
    assert_eq!(report.comparison, ValueComparison::NotRun);
    assert_eq!(
        compare(b" 7 \n", &recorded).comparison,
        ValueComparison::Match
    );
}

#[test]
fn empty_present_bytes_are_not_missing_bytes() {
    let digest = sha256_prefixed(b"");
    let absent = inspect_presented_evidence(
        EvidenceReference::Sha256(&digest),
        PresentedEvidence::Unavailable,
        None,
    );
    let present = inspect_presented_evidence(
        EvidenceReference::Sha256(&digest),
        PresentedEvidence::Bytes(b""),
        None,
    );
    assert_eq!(absent.integrity, EvidenceIntegrity::BytesUnavailable);
    assert_eq!(present.integrity, EvidenceIntegrity::Matched);
}

#[test]
fn not_requested_is_distinct_from_unavailable() {
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&sha256_prefixed(b"7")),
        PresentedEvidence::NotRequested,
        None,
    );
    assert_eq!(report.integrity, EvidenceIntegrity::NotRequested);
}

#[test]
fn pointer_only_cannot_authenticate_its_own_presented_bytes() {
    let report = inspect_presented_evidence(
        EvidenceReference::PointerOnly,
        PresentedEvidence::Bytes(b"7"),
        None,
    );
    assert_eq!(
        report.integrity,
        EvidenceIntegrity::DigestBindingUnavailable
    );
    assert_eq!(report.checked_bytes, 0);
}

#[test]
fn absent_reference_does_not_infer_an_expected_hash() {
    let report = inspect_presented_evidence(
        EvidenceReference::Absent,
        PresentedEvidence::Bytes(b"7"),
        None,
    );
    assert_eq!(report.integrity, EvidenceIntegrity::NoReference);
    assert_eq!(report.checked_bytes, 0);
}

#[test]
fn malformed_digest_spellings_are_not_normalized() {
    let good = sha256_prefixed(b"7");
    for bad in [
        good.to_uppercase(),
        format!("{good} "),
        good.replace("sha256:", "SHA256:"),
        good[..70].to_string(),
        format!("sha256:{}", "g".repeat(64)),
    ] {
        let report = inspect_presented_evidence(
            EvidenceReference::Sha256(&bad),
            PresentedEvidence::Bytes(b"7"),
            None,
        );
        assert_eq!(
            report.integrity,
            EvidenceIntegrity::MalformedDigest,
            "{bad}"
        );
        assert_eq!(report.checked_bytes, 0);
    }
}

#[test]
fn evidence_byte_limit_is_inclusive_and_precedes_hashing() {
    let at_limit = vec![b'x'; MAX_PRESENTED_EVIDENCE_BYTES];
    let over_limit = vec![b'x'; MAX_PRESENTED_EVIDENCE_BYTES + 1];
    for (raw, expected) in [
        (&at_limit, EvidenceIntegrity::Matched),
        (&over_limit, EvidenceIntegrity::InputLimitExceeded),
    ] {
        let report = inspect_presented_evidence(
            EvidenceReference::Sha256(&sha256_prefixed(raw)),
            PresentedEvidence::Bytes(raw),
            None,
        );
        assert_eq!(report.integrity, expected);
        if expected == EvidenceIntegrity::InputLimitExceeded {
            assert_eq!(report.checked_bytes, 0);
        }
    }
}

#[test]
fn matched_oversized_recorded_text_does_not_trigger_unbounded_comparison() {
    let value = json!("x".repeat(MAX_PRESENTED_EVIDENCE_BYTES + 1));
    let report = compare(b"7", &value);
    assert_eq!(report.integrity, EvidenceIntegrity::Matched);
    assert_eq!(report.comparison, ValueComparison::NotComparable);
    assert_eq!(report.comparison_reason, "recorded_scalar_limit");
}

#[test]
fn missing_unit_evidence_is_not_an_assumed_unit_match() {
    let value = json!(7);
    let digest = sha256_prefixed(b"7");
    for unit in ["N", "mm/s", ""] {
        let report = inspect_presented_evidence(
            EvidenceReference::Sha256(&digest),
            PresentedEvidence::Bytes(b"7"),
            Some(ScalarComparison {
                recorded_value: &value,
                declared_unit: Some(unit),
            }),
        );
        assert_eq!(report.integrity, EvidenceIntegrity::Matched);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "unit_binding_not_supported");
    }
}

#[test]
fn boolean_text_and_integer_types_are_not_coerced() {
    for (bytes, value) in [
        (&b"true"[..], json!(1)),
        (&b"1"[..], json!(true)),
        (&b"\"1\""[..], json!(1)),
    ] {
        let report = compare(bytes, &value);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "scalar_type_mismatch");
    }
}

#[test]
fn integer_comparison_is_exact_above_the_binary64_precision_boundary() {
    assert_eq!(
        compare(b"9007199254740992", &json!(9007199254740993_u64)).comparison,
        ValueComparison::Contradiction
    );
    assert_eq!(
        compare(b"18446744073709551615", &json!(u64::MAX)).comparison,
        ValueComparison::Match
    );
}

#[test]
fn floats_are_not_invented_as_a_supported_comparison() {
    assert_eq!(
        compare(b"7.0", &json!(7)).comparison,
        ValueComparison::NotComparable
    );
    assert_eq!(
        compare(b"7", &json!(7.0)).comparison,
        ValueComparison::NotComparable
    );
}

#[test]
fn arrays_objects_and_duplicate_object_keys_are_not_interpreted() {
    for raw in [
        &b"[7]"[..],
        &b"{\"value\":7}"[..],
        &b"{\"value\":7,\"value\":8}"[..],
        &b"{"[..],
    ] {
        let report = compare(raw, &json!(7));
        assert_eq!(report.integrity, EvidenceIntegrity::Matched);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "compound_evidence_not_supported");
    }
}

#[test]
fn trailing_and_malformed_scalar_input_never_counts_as_a_match() {
    for raw in [&b"7 8"[..], &b"tru"[..], &b"\"unterminated"[..], &b""[..]] {
        let report = compare(raw, &json!(7));
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "invalid_scalar_json");
    }
}

#[test]
fn constraints_remain_separate_from_a_successful_evidence_comparison() {
    let fact = json!({"name":"crew.operator-pseudonym", "assertedBy":"robot-attributed",
        "basis":"declared", "value":"operator:1", "evidence":{"digest":sha256_prefixed(b"\"operator:1\"")}});
    let constraints = inspect_fact(&fact, EvidenceState::NotResolved);
    let evidence = compare(b"\"operator:1\"", &fact["value"]);
    assert_eq!(
        constraints.classification,
        ConstraintResult::AttributionForbidden
    );
    assert_eq!(evidence.integrity, EvidenceIntegrity::Matched);
    assert_eq!(evidence.comparison, ValueComparison::Match);
    assert_eq!(evidence.fact_constraints, "NOT_EVALUATED");
    assert!(!evidence.attributed_party_authenticated);
}

#[test]
fn neither_recorded_value_nor_original_bytes_are_rewritten() {
    let fact_value = json!("model-A");
    let bytes = b" \"model-\\u0041\" \n".to_vec();
    let before_value = fact_value.clone();
    let before_bytes = bytes.clone();
    let report = compare(&bytes, &fact_value);
    assert_eq!(report.comparison, ValueComparison::Match);
    assert_eq!(fact_value, before_value);
    assert_eq!(bytes, before_bytes);
}

#[test]
fn hash_only_mode_does_not_claim_json_validation_or_value_comparison() {
    let bytes = b"\xff arbitrary opaque bytes";
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&sha256_prefixed(bytes)),
        PresentedEvidence::Bytes(bytes),
        None,
    );
    assert_eq!(report.integrity, EvidenceIntegrity::Matched);
    assert_eq!(report.comparison, ValueComparison::NotRun);
    assert_eq!(report.comparator, None);
    assert_eq!(report.comparison_reason, "comparison_not_requested");
}

#[test]
fn integer_negative_zero_matches_zero_and_preserves_raw_bytes() {
    for raw in [&b"-0"[..], &b" \t\r\n-0 \n\r\t"[..]] {
        let before = raw.to_vec();
        let report = compare(raw, &json!(0));
        assert_eq!(report.integrity, EvidenceIntegrity::Matched);
        assert_eq!(report.comparison, ValueComparison::Match);
        assert_eq!(report.comparison_reason, "exact_scalar_agreement");
        assert_eq!(report.checked_bytes, raw.len());
        assert_eq!(raw, before.as_slice());
        assert_eq!(report.digest_origin, "CALLER_SUPPLIED_UNAUTHENTICATED");
        assert_eq!(report.receipt_binding, "NOT_EVALUATED");
        assert_eq!(report.fact_constraints, "NOT_EVALUATED");
        assert!(!report.attributed_party_authenticated);
    }
}

#[test]
fn negative_zero_is_an_exact_integer_contradiction_for_nonzero_values() {
    for recorded in [json!(1), json!(-1), json!(u64::MAX), json!(i64::MIN)] {
        let report = compare(b"-0", &recorded);
        assert_eq!(report.integrity, EvidenceIntegrity::Matched);
        assert_eq!(report.comparison, ValueComparison::Contradiction);
        assert_eq!(report.comparison_reason, "exact_scalar_disagreement");
    }
}

#[test]
fn negative_zero_spelling_never_replaces_raw_digest_input() {
    assert_ne!(sha256_prefixed(b"-0"), sha256_prefixed(b"0"));
    for (raw, other) in [(&b"-0"[..], &b"0"[..]), (&b"0"[..], &b"-0"[..])] {
        let digest = sha256_prefixed(other);
        let recorded = json!(0);
        let report = inspect_presented_evidence(
            EvidenceReference::Sha256(&digest),
            PresentedEvidence::Bytes(raw),
            Some(ScalarComparison {
                recorded_value: &recorded,
                declared_unit: None,
            }),
        );
        assert_eq!(report.integrity, EvidenceIntegrity::Mismatch);
        assert_eq!(report.comparison, ValueComparison::NotRun);
        assert_eq!(report.checked_bytes, raw.len());
    }
    let digest = sha256_prefixed(b"-0");
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&digest),
        PresentedEvidence::Bytes(b"-0"),
        None,
    );
    assert_eq!(report.integrity, EvidenceIntegrity::Matched);
    assert_eq!(report.comparison, ValueComparison::NotRun);
    assert_eq!(report.comparison_reason, "comparison_not_requested");
}

#[test]
fn negative_zero_does_not_expand_floating_point_support() {
    for raw in [&b"-0.0"[..], &b"-0e0"[..], &b"-0E+0"[..], &b"0.0"[..]] {
        let report = compare(raw, &json!(0));
        assert_eq!(report.integrity, EvidenceIntegrity::Matched);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "evidence_scalar_not_supported");
    }
    // A pre-parsed floating Number has no retained integer-token evidence.
    // Do not infer an integer from its zero magnitude or IEEE sign bit.
    for recorded in [json!(-0.0), json!(0.0)] {
        let report = compare(b"-0", &recorded);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "recorded_scalar_not_supported");
    }
}

#[test]
fn negative_zero_keeps_scalar_type_and_unit_boundaries() {
    for (raw, recorded) in [
        (&br#""-0""#[..], json!(0)),
        (&b"-0"[..], json!(false)),
        (&b"-0"[..], json!("-0")),
    ] {
        let report = compare(raw, &recorded);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "scalar_type_mismatch");
    }
    let digest = sha256_prefixed(b"-0");
    let recorded = json!(0);
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&digest),
        PresentedEvidence::Bytes(b"-0"),
        Some(ScalarComparison {
            recorded_value: &recorded,
            declared_unit: Some("N"),
        }),
    );
    assert_eq!(report.integrity, EvidenceIntegrity::Matched);
    assert_eq!(report.comparison_reason, "unit_binding_not_supported");
}

#[test]
fn negative_zero_requires_valid_complete_json_before_recognition() {
    for raw in [
        &b"-00"[..],
        &b"+0"[..],
        &b"--0"[..],
        &b"-0 0"[..],
        &b"-0."[..],
        &b"-0e"[..],
        &b"\x0c-0"[..],
        &b"-0\x0c"[..],
        &b"\x0b-0"[..],
        &b"\xc2\xa0-0"[..],
        &b"-0\xff"[..],
    ] {
        let report = compare(raw, &json!(0));
        assert_eq!(report.integrity, EvidenceIntegrity::Matched);
        assert_eq!(report.comparison, ValueComparison::NotComparable);
        assert_eq!(report.comparison_reason, "invalid_scalar_json", "{raw:?}");
    }
}

#[test]
fn negative_zero_obeys_the_existing_exact_evidence_byte_limit() {
    let mut raw = vec![b' '; MAX_PRESENTED_EVIDENCE_BYTES - 2];
    raw.extend_from_slice(b"-0");
    let at = compare(&raw, &json!(0));
    assert_eq!(at.integrity, EvidenceIntegrity::Matched);
    assert_eq!(at.checked_bytes, MAX_PRESENTED_EVIDENCE_BYTES);
    assert_eq!(at.comparison, ValueComparison::Match);
    raw.push(b' ');
    let over = compare(&raw, &json!(0));
    assert_eq!(over.integrity, EvidenceIntegrity::InputLimitExceeded);
    assert_eq!(over.checked_bytes, 0);
    assert_eq!(over.comparison, ValueComparison::NotRun);
}

#[test]
fn fixed_width_digest_decoder_rejects_invalid_nibbles_at_every_position() {
    let valid = sha256_prefixed(b"-0");
    for index in 7..71 {
        for bad_digit in ["g", "F"] {
            let mut malformed = valid.clone();
            malformed.replace_range(index..index + 1, bad_digit);
            let report = inspect_presented_evidence(
                EvidenceReference::Sha256(&malformed),
                PresentedEvidence::Bytes(b"-0"),
                None,
            );
            assert_eq!(report.integrity, EvidenceIntegrity::MalformedDigest);
            assert_eq!(report.checked_bytes, 0);
        }
    }
    let report = inspect_presented_evidence(
        EvidenceReference::Sha256(&valid),
        PresentedEvidence::Bytes(b"-0"),
        None,
    );
    assert_eq!(report.integrity, EvidenceIntegrity::Matched);
}
