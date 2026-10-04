// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "alloc")]
use pask_wire::proposed_constraints::*;
use serde_json::json;

#[test]
fn all_966_classifications_match_explicit_relation() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/proposed07/expected-relation.json")).unwrap();
    let mut allowed = 0;
    for row in expected.as_array().unwrap() {
        let result = classify(
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
    assert_eq!(expected.as_array().unwrap().len(), 966);
    assert_eq!(allowed, 153); // Reviewed relation: 191 per-fact -> 154 global -> 153 final.
}

#[test]
fn six_singletons_and_mass_prohibition() {
    let singles: Vec<_> = FACTS.iter().filter(|f| f.parties.len() == 1).collect();
    assert_eq!(singles.len(), 6);
    for f in singles {
        for p in PARTIES {
            for b in BASES {
                if *p != f.parties[0] {
                    assert_eq!(
                        classify(f.name, p, b),
                        ConstraintResult::AttributionForbidden
                    );
                }
            }
        }
    }
    assert_eq!(
        classify("unit.total-mass", "robot-attributed", "measured"),
        ConstraintResult::AttributionForbidden
    );
}

#[test]
fn rated_matrix_and_evidence_distinctions() {
    for name in ["limits.rated-force", "limits.rated-speed"] {
        for p in ["manufacturer-declared", "robot-attributed"] {
            for b in BASES {
                assert_eq!(
                    classify(name, p, b) == ConstraintResult::Permitted,
                    *b == "declared"
                );
            }
            let fact = json!({"name":name,"assertedBy":p,"basis":"declared","value":10});
            let report = inspect_fact(&fact, EvidenceState::NotResolved);
            assert!(!report.attributed_party_authenticated);
            assert_eq!(
                report
                    .metadata_findings
                    .contains(&"required_evidence_reference_missing"),
                p == "robot-attributed"
            );
        }
    }
    let fact = json!({"name":"limits.rated-force","assertedBy":"robot-attributed",
        "basis":"declared","value":10,"evidence":{"digest":format!("sha256:{}", "a".repeat(64))}});
    assert!(
        inspect_fact(&fact, EvidenceState::Unavailable)
            .metadata_findings
            .is_empty()
    );
    assert_eq!(
        inspect_fact(&fact, EvidenceState::Unavailable).evidence,
        "REFERENCED_BYTES_UNAVAILABLE"
    );
    assert_eq!(
        inspect_fact(&fact, EvidenceState::IntegrityFailed).evidence,
        "INTEGRITY_FAILURE"
    );
    assert_eq!(
        inspect_fact(&fact, EvidenceState::IntegrityMatched).receipt_binding,
        "NOT_EVALUATED"
    );
}

#[test]
fn unknowns_old_spelling_and_forbidden_are_distinct() {
    assert_eq!(
        classify("unit.model", "robot-signed", "declared"),
        ConstraintResult::UnknownParty
    );
    assert_eq!(
        classify("invented", "site-policy", "declared"),
        ConstraintResult::UnknownFact
    );
    assert_eq!(
        classify("unit.model", "site-policy", "invented"),
        ConstraintResult::UnknownBasis
    );
    let f = json!({"name":"crew.operator-pseudonym","assertedBy":"robot-attributed",
        "basis":"declared","value":"operator:1"});
    assert_eq!(
        inspect_fact(&f, EvidenceState::NotResolved).classification,
        ConstraintResult::AttributionForbidden
    );
}

#[test]
fn typed_bounds_units_objects_patterns_and_references() {
    let mut fact = json!({"name":"limits.rated-force","assertedBy":"manufacturer-declared",
        "basis":"declared","value":-1});
    assert!(
        inspect_fact(&fact, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"invalid_typed_value")
    );
    fact["value"] = json!(1.5);
    assert!(
        inspect_fact(&fact, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"invalid_typed_value")
    );
    fact["value"] = json!(true);
    assert!(
        inspect_fact(&fact, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"invalid_typed_value")
    );
    fact["value"] = json!(4);
    fact["unit"] = json!("wrong");
    assert!(
        inspect_fact(&fact, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"unit_mismatch")
    );
    fact.as_object_mut().unwrap().remove("unit");
    fact["evidence"] = json!({"digest":"sha256:bad"});
    assert!(
        inspect_fact(&fact, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"malformed_evidence_reference")
    );
    let f = json!({"name":"mode.control-handover-preceding","assertedBy":"platform-recorded",
        "basis":"declared","value":{"occurred":true,"direction":"to-remote","secondsBefore":61}});
    let r = inspect_fact(&f, EvidenceState::NotResolved);
    assert!(r.metadata_findings.contains(&"invalid_typed_value"));
    assert!(r.metadata_findings.contains(&"remote_origin_constraint"));
    let f = json!({"name":"crew.operator-pseudonym","assertedBy":"platform-recorded",
        "basis":"declared","value":"has spaces"});
    assert!(
        inspect_fact(&f, EvidenceState::NotResolved)
            .metadata_findings
            .contains(&"invalid_typed_value")
    );
}
