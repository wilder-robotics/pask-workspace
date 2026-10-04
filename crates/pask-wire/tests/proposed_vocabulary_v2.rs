// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
#![cfg(feature = "alloc")]

use pask_wire::proposed_constraints::*;
use pask_wire::proposed_content::{
    CONSTRUCTION, ContentError, ContentHeader, SCOPE, SaltedFact, prepare_content,
};
use pask_wire::{canonicalize_json, sha256_prefixed};
use serde_json::{Value, json};

fn pose() -> Value {
    json!({"name":"site.pose","assertedBy":"platform-recorded","basis":"measured",
        "value":{"crs":"EPSG:4979","referencePoint":"antenna:1","latE7":411234568,
        "lonE7":-877654321,"heightMm":null,"horizontalAccuracyMm":null,
        "observedAt":"2026-09-28T18:00:00.000Z",
        "latLonDerivation":"rounded-half-even-to-1e-7-deg"}})
}
fn check(fact: &Value) -> ConstraintReport {
    inspect_fact_with_vocabulary(Vocabulary::V2, fact, EvidenceState::NotResolved)
}
fn invalid(fact: &Value) -> bool {
    check(fact)
        .metadata_findings
        .contains(&"invalid_typed_value")
}
fn canonical(value: &Value) -> Vec<u8> {
    canonicalize_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn header(digest: &str) -> ContentHeader<'_> {
    ContentHeader {
        construction: CONSTRUCTION,
        scope: SCOPE,
        vocabulary_digest: digest,
    }
}

#[test]
fn exact_v2_json_hash_matches_the_compiled_table() {
    assert_eq!(
        sha256_prefixed(include_bytes!(
            "../../../schemas/proposed/pser-0.7/content-vocabulary-v2-candidate.json"
        )),
        format!("sha256:{}", Vocabulary::V2.sha256())
    );
    assert_eq!(Vocabulary::V2.version(), "wilder.pser-content-vocab/2");
    assert_eq!(Vocabulary::V2.facts().len(), 47);
}

#[test]
fn all_987_classifications_match_the_explicit_expected_table() {
    let expected: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/proposed07/expected-relation-v2.json"
    ))
    .unwrap();
    assert_eq!(expected.len(), 987);
    let mut allowed = 0;
    for row in expected {
        let result = classify_with_vocabulary(
            Vocabulary::V2,
            row["name"].as_str().unwrap(),
            row["party"].as_str().unwrap(),
            row["basis"].as_str().unwrap(),
        );
        assert_eq!(
            result == ConstraintResult::Permitted,
            row["allowed"].as_bool().unwrap(),
            "{row}"
        );
        allowed += usize::from(result == ConstraintResult::Permitted);
    }
    assert_eq!(allowed, 157);
    assert_eq!(987 - allowed, 830);
}

#[test]
fn all_966_legacy_classifications_remain_identical_in_both_tables() {
    let expected: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/proposed07/expected-relation.json")).unwrap();
    assert_eq!(expected.len(), 966);
    for row in expected {
        let n = row["name"].as_str().unwrap();
        let p = row["party"].as_str().unwrap();
        let b = row["basis"].as_str().unwrap();
        assert_eq!(
            classify(n, p, b),
            classify_with_vocabulary(Vocabulary::V1, n, p, b)
        );
        assert_eq!(
            classify(n, p, b),
            classify_with_vocabulary(Vocabulary::V2, n, p, b)
        );
    }
}

#[test]
fn old_rule_schemas_and_all_metadata_requirements_are_identical() {
    for old in FACTS {
        let new = Vocabulary::V2.fact(old.name).unwrap();
        assert_eq!(old.parties, new.parties);
        assert_eq!(old.bases, new.bases);
        assert_eq!(old.forbidden, new.forbidden);
        assert_eq!(old.unit, new.unit);
        assert_eq!(old.evidence_required, new.evidence_required);
        assert_eq!(old.remote_required, new.remote_required);
        assert_eq!(old.value_json, new.value_json);
    }
    assert_eq!(Vocabulary::V1.parties(), Vocabulary::V2.parties());
    assert_eq!(Vocabulary::V1.bases(), Vocabulary::V2.bases());
}

#[test]
fn all_21_pose_pairs_are_explicitly_classified() {
    let allowed = [
        ("appliance-measured", "measured"),
        ("appliance-measured", "estimated"),
        ("platform-recorded", "measured"),
        ("operator-entered", "declared"),
    ];
    let mut count = 0;
    for party in PARTIES {
        for basis in BASES {
            let permitted = allowed.contains(&(*party, *basis));
            assert_eq!(
                classify_with_vocabulary(Vocabulary::V2, "site.pose", party, basis),
                if permitted {
                    ConstraintResult::Permitted
                } else {
                    ConstraintResult::AttributionForbidden
                }
            );
            count += 1;
        }
    }
    assert_eq!(count, 21);
}

#[test]
fn unknown_party_basis_and_legacy_pose_remain_distinct() {
    assert_eq!(
        classify_with_vocabulary(Vocabulary::V2, "site.pose", "new-party", "measured"),
        ConstraintResult::UnknownParty
    );
    assert_eq!(
        classify_with_vocabulary(
            Vocabulary::V2,
            "site.pose",
            "platform-recorded",
            "new-basis"
        ),
        ConstraintResult::UnknownBasis
    );
    assert_eq!(
        classify("site.pose", "platform-recorded", "measured"),
        ConstraintResult::UnknownFact
    );
    assert_eq!(
        classify_with_vocabulary(Vocabulary::V2, "unknown", "platform-recorded", "measured"),
        ConstraintResult::UnknownFact
    );
}

#[test]
fn digest_dispatch_never_uses_an_unprefixed_hash_or_version_label() {
    for vocabulary in [Vocabulary::V1, Vocabulary::V2] {
        assert_eq!(
            vocabulary_for_digest(&format!("sha256:{}", vocabulary.sha256())),
            Some(vocabulary)
        );
        assert_eq!(vocabulary_for_digest(vocabulary.sha256()), None);
        assert_eq!(vocabulary_for_digest(vocabulary.version()), None);
        assert_eq!(
            vocabulary_for_digest(&format!("SHA256:{}", vocabulary.sha256())),
            None
        );
        assert_eq!(
            vocabulary_for_digest(&format!("sha256:{}", vocabulary.sha256().to_uppercase())),
            None
        );
    }
    assert_eq!(
        vocabulary_for_digest(&format!("sha256:{}", "f".repeat(64))),
        None
    );
}

#[test]
fn canonical_valid_pose_with_explicit_nulls_passes_metadata() {
    assert!(check(&pose()).metadata_findings.is_empty());
    assert!(!check(&pose()).attributed_party_authenticated);
}

#[test]
fn each_of_eight_required_members_must_exist() {
    let original = pose();
    let names: Vec<_> = original["value"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(names.len(), 8);
    for name in names {
        let mut fact = original.clone();
        fact["value"].as_object_mut().unwrap().remove(&name);
        assert!(invalid(&fact), "missing {name}");
    }
}

#[test]
fn extra_pose_fields_are_invalid_and_are_not_stripped() {
    for name in ["speedMmS", "heading", "version"] {
        let mut fact = pose();
        fact["value"][name] = json!(10);
        let before = fact.clone();
        assert!(invalid(&fact));
        assert_eq!(fact, before);
    }
}

#[test]
fn legacy_objects_stay_open_under_both_vocabularies() {
    let fact = json!({"name":"event.trace-window","assertedBy":"platform-recorded",
        "basis":"measured","value":{"durationMs":100,"rateHz":10,"extra":99}});
    let old = report_json(&fact, EvidenceState::NotResolved);
    assert_eq!(
        old,
        report_json_with_vocabulary(Vocabulary::V1, &fact, EvidenceState::NotResolved)
    );
    assert_eq!(
        old,
        report_json_with_vocabulary(Vocabulary::V2, &fact, EvidenceState::NotResolved)
    );
    assert!(
        !inspect_fact(&fact, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"invalid_typed_value")
    );
}

#[test]
fn latitude_boundaries_and_adjacent_values() {
    for (value, valid) in [
        (-900000001_i64, false),
        (-900000000, true),
        (0, true),
        (900000000, true),
        (900000001, false),
    ] {
        let mut fact = pose();
        fact["value"]["latE7"] = json!(value);
        assert_eq!(!invalid(&fact), valid, "{value}");
    }
}

#[test]
fn longitude_uses_the_half_open_interval() {
    for (value, valid) in [
        (-1800000001_i64, false),
        (-1800000000, true),
        (0, true),
        (1799999999, true),
        (1800000000, false),
    ] {
        let mut fact = pose();
        fact["value"]["lonE7"] = json!(value);
        assert_eq!(!invalid(&fact), valid, "{value}");
    }
}

#[test]
fn height_boundaries_and_null_are_not_zero_coercion() {
    for (value, valid) in [
        (-20000001_i64, false),
        (-20000000, true),
        (0, true),
        (100000000, true),
        (100000001, false),
    ] {
        let mut fact = pose();
        fact["value"]["heightMm"] = json!(value);
        assert_eq!(!invalid(&fact), valid, "{value}");
    }
    let fact = pose();
    assert!(fact["value"]["heightMm"].is_null());
    assert!(!invalid(&fact));
}

#[test]
fn accuracy_boundaries_zero_and_null() {
    for (value, valid) in [
        (-1_i64, false),
        (0, true),
        (100000000, true),
        (100000001, false),
    ] {
        let mut fact = pose();
        fact["value"]["horizontalAccuracyMm"] = json!(value);
        assert_eq!(!invalid(&fact), valid, "{value}");
    }
    assert!(!invalid(&pose()));
}

#[test]
fn null_is_allowed_only_on_the_three_declared_members() {
    for name in [
        "crs",
        "referencePoint",
        "latE7",
        "lonE7",
        "latLonDerivation",
    ] {
        let mut fact = pose();
        fact["value"][name] = Value::Null;
        assert!(invalid(&fact), "{name}");
    }
    for name in ["heightMm", "horizontalAccuracyMm", "observedAt"] {
        let mut fact = pose();
        fact["value"][name] = Value::Null;
        assert!(!invalid(&fact), "{name}");
    }
}

#[test]
fn unknown_strings_are_not_nullable_values() {
    for name in ["heightMm", "horizontalAccuracyMm", "observedAt"] {
        let mut fact = pose();
        fact["value"][name] = json!("unknown");
        assert!(invalid(&fact));
    }
}

#[test]
fn crs_and_derivation_are_exact_enumerations() {
    for value in ["EPSG:4326", "epsg:4979", "WGS84"] {
        let mut fact = pose();
        fact["value"]["crs"] = json!(value);
        assert!(invalid(&fact));
    }
    for value in ["rounded", "exact", ""] {
        let mut fact = pose();
        fact["value"]["latLonDerivation"] = json!(value);
        assert!(invalid(&fact));
    }
}

#[test]
fn reference_point_bounds_and_ascii_identifier_shape() {
    for (value, valid) in [
        ("a".repeat(64), true),
        ("a".repeat(65), false),
        (String::new(), false),
        ("hull ref".into(), false),
        ("ant:1-_.".into(), true),
        ("antenna:é".into(), false),
    ] {
        let mut fact = pose();
        fact["value"]["referencePoint"] = json!(value);
        assert_eq!(!invalid(&fact), valid);
    }
}

#[test]
fn timestamp_is_lexical_only_and_does_not_accept_finer_values_directly() {
    for (value, valid) in [
        ("2026-09-28T18:00:00.000Z", true),
        ("2026-02-30T25:61:61.000Z", true),
        ("2026-09-28T18:00:00Z", false),
        ("2026-09-28T18:00:00.0000Z", false),
        ("2026-09-28T18:00:00.123456Z", false),
        ("2026-09-28T18:00:00.000+00:00", false),
    ] {
        let mut fact = pose();
        fact["value"]["observedAt"] = json!(value);
        assert_eq!(!invalid(&fact), valid, "{value}");
    }
}

#[test]
fn integer_fields_reject_floats_strings_and_booleans() {
    for name in ["latE7", "lonE7", "heightMm", "horizontalAccuracyMm"] {
        for value in [json!(1.5), json!("1"), json!(true), json!([]), json!({})] {
            let mut fact = pose();
            fact["value"][name] = value;
            assert!(invalid(&fact), "{name}");
        }
    }
}

#[test]
fn parsed_numeric_spellings_do_not_override_the_typed_integer_rule() {
    for token in ["1.0", "-0", "1e3"] {
        let mut fact = pose();
        fact["value"]["latE7"] = serde_json::from_str(token).unwrap();
        assert!(invalid(&fact), "typed Value from {token}");
    }
}

#[test]
fn canonical_content_rejects_noncanonical_integer_spellings() {
    let digest = format!("sha256:{}", Vocabulary::V2.sha256());
    let original = String::from_utf8(canonical(&pose())).unwrap();
    for token in ["-0", "411234568.0", "1e3"] {
        let changed = original.replace("\"latE7\":411234568", &format!("\"latE7\":{token}"));
        assert_ne!(changed, original);
        let fact = SaltedFact {
            record: changed.as_bytes(),
            salt: [1; 32],
        };
        assert!(matches!(
            prepare_content(&header(&digest), &[fact]),
            Err(ContentError::NonCanonicalFact)
        ));
    }
}

#[test]
fn fractional_canonical_json_can_be_committed_but_fails_pose_type() {
    let digest = format!("sha256:{}", Vocabulary::V2.sha256());
    let mut fact = pose();
    fact["value"]["latE7"] = json!(411234567.5);
    let bytes = canonical(&fact);
    let salted = SaltedFact {
        record: &bytes,
        salt: [1; 32],
    };
    assert!(prepare_content(&header(&digest), &[salted]).is_ok());
    assert!(invalid(&fact));
}

#[test]
fn appliance_evidence_requirement_survives_the_optional_row() {
    let mut fact = pose();
    fact["assertedBy"] = json!("appliance-measured");
    assert!(
        check(&fact)
            .metadata_findings
            .contains(&"required_evidence_reference_missing")
    );
    fact["evidence"] = json!({"digest":format!("sha256:{}", "a".repeat(64))});
    assert!(check(&fact).metadata_findings.is_empty());
}

#[test]
fn other_permitted_pose_parties_do_not_invent_evidence() {
    for (party, basis) in [
        ("platform-recorded", "measured"),
        ("operator-entered", "declared"),
    ] {
        let mut fact = pose();
        fact["assertedBy"] = json!(party);
        fact["basis"] = json!(basis);
        let result = check(&fact);
        assert!(result.metadata_findings.is_empty());
        assert_eq!(result.evidence, "NO_VALID_REFERENCE");
    }
}

#[test]
fn every_present_remote_origin_is_forbidden_including_null() {
    for value in [
        Value::Null,
        json!("off-site"),
        json!("on-site"),
        json!("undetermined"),
        json!(3),
        json!({}),
    ] {
        let mut fact = pose();
        fact["remoteOrigin"] = value;
        assert!(
            check(&fact)
                .metadata_findings
                .contains(&"remote_origin_constraint")
        );
    }
}

#[test]
fn extra_fact_metadata_remains_bound_without_closing_the_fact_wrapper() {
    let mut fact = pose();
    fact["sourceNote"] = json!("off-site raw input; not authenticated");
    assert!(check(&fact).metadata_findings.is_empty());
}

#[test]
fn malformed_unit_metadata_still_fails_separately() {
    for unit in [json!("m"), json!(3), json!(true), json!([])] {
        let mut fact = pose();
        fact["unit"] = unit;
        assert!(check(&fact).metadata_findings.contains(&"unit_mismatch"));
    }
    let mut fact = pose();
    fact["unit"] = Value::Null;
    assert!(check(&fact).metadata_findings.is_empty());
}

#[test]
fn two_pose_records_in_one_block_remain_forbidden() {
    let bytes = canonical(&pose());
    let digest = format!("sha256:{}", Vocabulary::V2.sha256());
    let records = [
        SaltedFact {
            record: &bytes,
            salt: [1; 32],
        },
        SaltedFact {
            record: &bytes,
            salt: [2; 32],
        },
    ];
    assert!(matches!(
        prepare_content(&header(&digest), &records),
        Err(ContentError::DuplicateFactName)
    ));
}

#[test]
fn retained_fact_budget_applies_before_closed_object_processing() {
    let mut fact = pose();
    fact["extra"] = json!("a".repeat(MAX_FACT_JSON_BYTES));
    assert!(check(&fact).metadata_findings.contains(&"input_byte_limit"));
}
