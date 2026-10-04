// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
#![cfg(feature = "alloc")]

use ed25519_dalek::SigningKey;
use pask_wire::proposed_constraints::{ConstraintResult, Vocabulary};
use pask_wire::proposed_content::{
    CONSTRUCTION, ContentHeader, SCOPE, SaltedFact, prepare_content,
};
use pask_wire::proposed_evidence::{EvidenceIntegrity, ValueComparison};
use pask_wire::proposed_recipient::{FactProvenance, PresentationState, RequestedAvailability};
use pask_wire::proposed_replay::{
    DOCUMENT_SCHEMA, ReplayMode, ReplayReport, inspect_replay_document,
};
use pask_wire::{
    InspectionStatus as Status, Payload, canonicalize_json, produce_ed25519, sha256_prefixed,
};
use serde_json::{Value, json};

fn key() -> SigningKey {
    // PUBLIC deterministic test seed; protects nothing and identifies nobody.
    SigningKey::from_bytes(&[127; 32])
}
fn canonical(value: &Value) -> Vec<u8> {
    canonicalize_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn digest(vocabulary: Vocabulary) -> String {
    format!("sha256:{}", vocabulary.sha256())
}
fn pose() -> Value {
    json!({"name":"site.pose","assertedBy":"platform-recorded","basis":"measured",
        "value":{"crs":"EPSG:4979","referencePoint":"antenna:1","latE7":411234568,
        "lonE7":-877654321,"heightMm":null,"horizontalAccuracyMm":null,
        "observedAt":null,"latLonDerivation":"rounded-half-even-to-1e-7-deg"}})
}
fn model(value: &str) -> Value {
    json!({"name":"unit.model","assertedBy":"site-policy","basis":"declared","value":value})
}
fn sign(root: Option<&str>) -> Vec<u8> {
    let mut value: Value =
        serde_json::from_str(&pask_wire::canonical_example_06().unwrap()).unwrap();
    value["spec"] = json!("wilder.pser/0.7");
    value["engagement"]["contentDigest"] = json!(root);
    let payload = Payload::from_json_for_production(&serde_json::to_vec(&value).unwrap()).unwrap();
    produce_ed25519(&payload, payload.witness_key(), &key()).unwrap()
}
fn entry(
    values: &[Value],
    vocabulary_digest: &str,
    selected: Option<&[&str]>,
    objects: &[(&str, &[u8])],
    required: &[&str],
    compare: bool,
) -> Value {
    let raw: Vec<_> = values.iter().map(canonical).collect();
    let salted: Vec<_> = raw
        .iter()
        .enumerate()
        .map(|(i, bytes)| SaltedFact {
            record: bytes,
            salt: [(i + 1) as u8; 32],
        })
        .collect();
    let header = ContentHeader {
        construction: CONSTRUCTION,
        scope: SCOPE,
        vocabulary_digest,
    };
    let prepared = prepare_content(&header, &salted).unwrap();
    let names: Vec<_> = match selected {
        Some(names) => names.to_vec(),
        None => values
            .iter()
            .map(|value| value["name"].as_str().unwrap())
            .collect(),
    };
    let disclosures: Vec<_> = names.iter().map(|name| {
        let disclosed = prepared.disclose(name).unwrap();
        json!({"record_hex":hex::encode(disclosed.record),"salt_hex":hex::encode(disclosed.salt),
            "index":disclosed.index,"siblings_hex":disclosed.siblings.iter().map(hex::encode).collect::<Vec<_>>()})
    }).collect();
    let objects: Vec<_> = objects.iter().map(|(digest, bytes)|
        json!({"digest":digest,"state":"BYTES","bytes_hex":hex::encode(bytes)})).collect();
    json!({"statement_hex":hex::encode(sign(Some(&prepared.root_digest()))),
        "presentation":{"construction":CONSTRUCTION,"scope":SCOPE,"vocabulary_digest":vocabulary_digest,
        "fact_count":prepared.fact_count(),"disclosures":disclosures},
        "objects":objects,"policy":{"expected_context":null,"require_presented_content":false,
        "require_all_committed_slots":false,"required_fact_names":required,"compare_unitless_scalars":compare}})
}
fn evaluate(entries: &[Value]) -> ReplayReport {
    let document = json!({"schema":DOCUMENT_SCHEMA,"entries":entries});
    inspect_replay_document(
        &serde_json::to_vec(&document).unwrap(),
        &key().verifying_key(),
        if entries.len() == 1 {
            ReplayMode::Single
        } else {
            ReplayMode::Chain
        },
    )
    .unwrap()
}
fn single(value: &Value) -> pask_wire::proposed_recipient::RecipientReport {
    evaluate(std::slice::from_ref(value)).records.remove(0)
}

#[test]
fn v2_pose_is_bound_and_disclosed_without_party_authentication() {
    let result = single(&entry(
        &[pose()],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        true,
    ));
    assert_eq!(result.statement_check.status, Status::Passed);
    assert_eq!(result.membership.status, Status::Passed);
    assert_eq!(result.vocabulary.status, Status::Passed);
    assert_eq!(
        result.vocabulary.code,
        "committed_vocabulary_v2_matches_compiled_rule_source"
    );
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::Disclosed
    );
    assert_eq!(result.disclosure_policy.status, Status::Passed);
    assert!(!result.facts[0].attributed_party_authenticated);
    assert_eq!(result.application_acceptance.status, Status::Unestablished);
}

#[test]
fn v1_pose_is_unknown_even_when_its_membership_is_valid() {
    let result = single(&entry(
        &[pose()],
        &digest(Vocabulary::V1),
        None,
        &[],
        &[],
        true,
    ));
    assert_eq!(result.membership.status, Status::Passed);
    assert_eq!(result.vocabulary.status, Status::Passed);
    assert_eq!(
        result.facts[0].constraint.classification,
        ConstraintResult::UnknownFact
    );
    assert_eq!(result.facts[0].provenance, None);
}

#[test]
fn required_pose_on_v1_is_per_block_unsupported_not_global_policy_failure() {
    let result = single(&entry(
        &[model("A")],
        &digest(Vocabulary::V1),
        None,
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(result.policy_configuration.status, Status::Passed);
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::UnsupportedByVocabulary
    );
    assert_eq!(result.requested_facts[0].provenance, None);
    assert!(!result.requested_facts[0].semantic_absence_established);
    assert_eq!(result.disclosure_policy.status, Status::Unestablished);
    assert_eq!(
        result.disclosure_policy.code,
        "required_fact_not_supported_by_committed_vocabulary"
    );
}

#[test]
fn unknown_pose_in_v1_cannot_satisfy_required_fact_by_name_alone() {
    let result = single(&entry(
        &[pose()],
        &digest(Vocabulary::V1),
        None,
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(result.facts[0].name, "site.pose");
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::UnsupportedByVocabulary
    );
    assert_ne!(result.disclosure_policy.status, Status::Passed);
}

#[test]
fn pose_withheld_under_v2_is_different_from_unsupported_under_v1() {
    let result = single(&entry(
        &[pose(), model("A")],
        &digest(Vocabulary::V2),
        Some(&["unit.model"]),
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(result.presentation_state, PresentationState::SelectedSlots);
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::NotDisclosedUnproven
    );
    assert_eq!(result.disclosure_policy.status, Status::Unestablished);
    assert_ne!(
        result.disclosure_policy.code,
        "required_fact_not_supported_by_committed_vocabulary"
    );
}

#[test]
fn pose_absent_from_v2_complete_block_is_not_absent_from_the_world() {
    let result = single(&entry(
        &[model("A")],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::AbsentFromCommittedBlock
    );
    assert!(!result.requested_facts[0].semantic_absence_established);
    assert_eq!(result.disclosure_policy.status, Status::Failed);
}

#[test]
fn null_commitment_does_not_select_a_vocabulary_from_unbound_presentation() {
    let mut value = entry(
        &[pose()],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        false,
    );
    value["statement_hex"] = json!(hex::encode(sign(None)));
    let result = single(&value);
    assert_eq!(result.presentation_state, PresentationState::NullCommitment);
    assert_eq!(result.vocabulary.status, Status::NotEvaluated);
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::NoBlockCommitted
    );
}

#[test]
fn no_presented_block_does_not_infer_the_new_fact_is_absent() {
    let mut value = entry(
        &[pose()],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        false,
    );
    value["presentation"] = Value::Null;
    let result = single(&value);
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::CommittedBlockNotPresented
    );
    assert_eq!(result.vocabulary.status, Status::NotEvaluated);
}

#[test]
fn unsupported_vocabulary_does_not_choose_a_table_from_pose_name() {
    let unknown = format!("sha256:{}", "f".repeat(64));
    let result = single(&entry(
        &[pose()],
        &unknown,
        None,
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(result.membership.status, Status::Passed);
    assert_eq!(result.vocabulary.status, Status::Unsupported);
    assert!(result.facts.is_empty());
    assert_eq!(
        result.requested_facts[0].availability,
        RequestedAvailability::NotEvaluated
    );
    assert_ne!(result.disclosure_policy.status, Status::Passed);
}

#[test]
fn mixed_vocabulary_batches_select_per_entry_without_order_leakage() {
    let entries = vec![
        entry(
            &[model("A")],
            &digest(Vocabulary::V1),
            None,
            &[],
            &["site.pose"],
            false,
        ),
        entry(
            &[pose()],
            &digest(Vocabulary::V2),
            None,
            &[],
            &["site.pose"],
            false,
        ),
        entry(
            &[pose()],
            &format!("sha256:{}", "f".repeat(64)),
            None,
            &[],
            &["site.pose"],
            false,
        ),
    ];
    let forward = evaluate(&entries);
    assert_eq!(
        forward.records[0].requested_facts[0].availability,
        RequestedAvailability::UnsupportedByVocabulary
    );
    assert_eq!(
        forward.records[1].requested_facts[0].availability,
        RequestedAvailability::Disclosed
    );
    assert_eq!(forward.records[2].vocabulary.status, Status::Unsupported);
    let reversed: Vec<_> = entries.into_iter().rev().collect();
    let backward = evaluate(&reversed);
    for (a, b) in forward.records.iter().zip(backward.records.iter().rev()) {
        assert_eq!(
            serde_json::to_value(a).unwrap(),
            serde_json::to_value(b).unwrap()
        );
    }
    // These synthetic independent genesis statements are not a contiguous chain.
    // Record-level dispatch is independent of the separate chain outcome.
}

#[test]
fn matched_raw_pose_object_is_not_a_compared_pose_or_verified_position() {
    let bytes = br#"{"navigation":"opaque source sample"}"#;
    let d = sha256_prefixed(bytes);
    let mut p = pose();
    p["evidence"] = json!({"digest":d});
    let result = single(&entry(
        &[p],
        &digest(Vocabulary::V2),
        None,
        &[(&d, bytes)],
        &[],
        true,
    ));
    assert_eq!(
        result.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(
        result.facts[0].evidence.comparison,
        ValueComparison::NotComparable
    );
    assert_eq!(
        result.facts[0].evidence.comparison_reason,
        "recorded_scalar_not_supported"
    );
    assert_eq!(
        result.facts[0].provenance,
        Some(FactProvenance::EvidenceLinked)
    );
    assert!(!result.facts[0].attributed_party_authenticated);
}

#[test]
fn comparison_off_retains_pose_integrity_but_does_not_compare() {
    let bytes = b"source";
    let d = sha256_prefixed(bytes);
    let mut p = pose();
    p["evidence"] = json!({"digest":d});
    let result = single(&entry(
        &[p],
        &digest(Vocabulary::V2),
        None,
        &[(&d, bytes)],
        &[],
        false,
    ));
    assert_eq!(
        result.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(result.facts[0].evidence.comparison, ValueComparison::NotRun);
}

#[test]
fn mismatched_pose_evidence_never_enters_comparison() {
    let d = sha256_prefixed(b"original");
    let mut p = pose();
    p["evidence"] = json!({"digest":d});
    let result = single(&entry(
        &[p],
        &digest(Vocabulary::V2),
        None,
        &[(&d, b"changed")],
        &[],
        true,
    ));
    assert_eq!(
        result.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Mismatch)
    );
    assert_eq!(result.facts[0].evidence.comparison, ValueComparison::NotRun);
}

#[test]
fn required_appliance_reference_missing_stays_visible_with_disclosure_success() {
    let mut p = pose();
    p["assertedBy"] = json!("appliance-measured");
    let result = single(&entry(
        &[p],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(result.disclosure_policy.status, Status::Passed);
    assert!(
        result.facts[0]
            .constraint
            .metadata_findings
            .contains(&"required_evidence_reference_missing")
    );
    assert_eq!(result.application_acceptance.status, Status::Unestablished);
}

#[test]
fn forbidden_platform_estimate_is_not_unsupported_vocabulary() {
    let mut p = pose();
    p["basis"] = json!("estimated");
    let result = single(&entry(
        &[p],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        false,
    ));
    assert_eq!(result.vocabulary.status, Status::Passed);
    assert_eq!(
        result.facts[0].constraint.classification,
        ConstraintResult::AttributionForbidden
    );
    assert_eq!(
        result.facts[0].provenance,
        Some(FactProvenance::AttributionForbidden)
    );
    assert_eq!(result.summary.attribution_forbidden, 1);
}

#[test]
fn extra_field_is_bound_but_invalid_and_not_silently_dropped() {
    let mut p = pose();
    p["value"]["speedMmS"] = json!(5);
    let result = single(&entry(
        &[p],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        true,
    ));
    assert_eq!(result.membership.status, Status::Passed);
    assert!(
        result.facts[0]
            .constraint
            .metadata_findings
            .contains(&"invalid_typed_value")
    );
    assert_eq!(result.facts[0].provenance, None);
    assert_eq!(result.disclosure_policy.status, Status::Passed);
    assert_eq!(result.application_acceptance.status, Status::Unestablished);
}

#[test]
fn v2_old_unit_bearing_fact_respects_implicit_unit_when_unit_omitted() {
    let bytes = b"100";
    let d = sha256_prefixed(bytes);
    let mass = json!({"name":"unit.total-mass","assertedBy":"manufacturer-declared","basis":"declared",
        "value":100,"evidence":{"digest":d}});
    assert_eq!(
        Vocabulary::V2.fact("unit.total-mass").unwrap().unit,
        Some("g")
    );
    let result = single(&entry(
        &[mass],
        &digest(Vocabulary::V2),
        None,
        &[(&d, bytes)],
        &[],
        true,
    ));
    assert_eq!(
        result.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(
        result.facts[0].evidence.comparison,
        ValueComparison::NotComparable
    );
}

#[test]
fn wrong_supplied_key_prevents_rule_application() {
    let value = entry(
        &[pose()],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["site.pose"],
        true,
    );
    let doc = serde_json::to_vec(&json!({"schema":DOCUMENT_SCHEMA,"entries":[value]})).unwrap();
    let wrong = SigningKey::from_bytes(&[126; 32]);
    let result = inspect_replay_document(&doc, &wrong.verifying_key(), ReplayMode::Single).unwrap();
    assert_ne!(result.records[0].statement_check.status, Status::Passed);
    assert!(result.records[0].facts.is_empty());
}

#[test]
fn changing_vocabulary_header_without_new_signature_and_root_fails_membership() {
    let mut value = entry(&[pose()], &digest(Vocabulary::V2), None, &[], &[], false);
    value["presentation"]["vocabulary_digest"] = json!(digest(Vocabulary::V1));
    let result = single(&value);
    assert_eq!(result.membership.status, Status::Failed);
    assert_eq!(result.vocabulary.status, Status::NotEvaluated);
    assert!(result.facts.is_empty());
}

#[test]
fn required_name_unknown_to_every_compiled_table_preserves_configuration_failure() {
    let result = single(&entry(
        &[pose()],
        &digest(Vocabulary::V2),
        None,
        &[],
        &["invented.fact"],
        false,
    ));
    assert_eq!(result.policy_configuration.status, Status::Failed);
    assert_eq!(
        result.policy_configuration.code,
        "required_fact_name_not_supported"
    );
}

#[test]
fn caller_cannot_override_table_with_extra_fact_version_metadata() {
    let mut p = pose();
    p["version"] = json!("wilder.pser-content-vocab/1");
    let result = single(&entry(&[p], &digest(Vocabulary::V2), None, &[], &[], false));
    assert_eq!(
        result.facts[0].constraint.classification,
        ConstraintResult::Permitted
    );
    assert_eq!(
        result.vocabulary.code,
        "committed_vocabulary_v2_matches_compiled_rule_source"
    );
}

#[test]
fn whole_fact_disclosure_contains_all_position_fields() {
    let original = pose();
    let value = entry(
        std::slice::from_ref(&original),
        &digest(Vocabulary::V2),
        None,
        &[],
        &[],
        false,
    );
    let bytes = hex::decode(
        value["presentation"]["disclosures"][0]["record_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), original);
    assert_eq!(original["value"].as_object().unwrap().len(), 8);
}

#[test]
fn pose_does_not_add_recipient_containment_or_time_assurance() {
    let result = single(&entry(
        &[pose()],
        &digest(Vocabulary::V2),
        None,
        &[],
        &[],
        true,
    ));
    assert_eq!(result.real_world_clock.status, Status::Unestablished);
    assert_eq!(result.full_profile.status, Status::Unestablished);
    let rendered = serde_json::to_value(&result).unwrap();
    assert!(rendered.get("containment").is_none());
    assert!(rendered.get("within").is_none());
}

#[test]
fn failed_pose_metadata_does_not_erase_an_independent_value_contradiction() {
    let mut p = pose();
    p["value"]["heading"] = json!(10);
    let bytes = br#""B""#;
    let d = sha256_prefixed(bytes);
    let mut m = model("A");
    m["evidence"] = json!({"digest":d});
    let result = single(&entry(
        &[p, m],
        &digest(Vocabulary::V2),
        None,
        &[(&d, bytes)],
        &["site.pose"],
        true,
    ));
    assert_eq!(result.summary.value_contradictions, 1);
    assert_eq!(result.summary.invalid_or_unsupported_metadata, 1);
    assert_eq!(result.disclosure_policy.status, Status::Passed);
    assert_eq!(result.application_acceptance.status, Status::Unestablished);
}

#[test]
fn new_pose_does_not_replace_the_full_retained_envelope_commitment() {
    let mut first = pose();
    let mut second = pose();
    first["value"]["latE7"] = json!(1);
    second["value"]["latE7"] = json!(2);
    let a = entry(&[first], &digest(Vocabulary::V2), None, &[], &[], false);
    let b = entry(&[second], &digest(Vocabulary::V2), None, &[], &[], false);
    let read = |value: &Value| -> Value {
        let bytes = hex::decode(value["statement_hex"].as_str().unwrap()).unwrap();
        let payload = pask_wire::verify_ed25519(&bytes, &key().verifying_key()).unwrap();
        serde_json::from_slice(&payload.to_jcs().unwrap()).unwrap()
    };
    let pa = read(&a);
    let pb = read(&b);
    assert_eq!(
        pa["site"]["envelope"]["digest"],
        pb["site"]["envelope"]["digest"]
    );
    assert_ne!(
        pa["engagement"]["contentDigest"],
        pb["engagement"]["contentDigest"]
    );
    let mut envelope = json!({"boundary":"retained opaque geometry","permittedActors":["robot:A"]});
    let original = sha256_prefixed(&canonical(&envelope));
    envelope["permittedActors"] = json!(["robot:B"]);
    assert_ne!(original, sha256_prefixed(&canonical(&envelope)));
    // Synthetic full-document digest check, not physical containment or authority.
}

#[test]
fn eleven_static_mobile_documents_match_native_expectations() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/proposed07/mobile-v2");
    let catalog: Value =
        serde_json::from_slice(&std::fs::read(root.join("catalog.json")).unwrap()).unwrap();
    let cases = catalog["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    let public = std::fs::read_to_string(root.join("public-key.hex")).unwrap();
    let key = pask_wire::proposed_replay::replay_key_from_hex(public.trim()).unwrap();
    for case in cases {
        let bytes = std::fs::read(root.join(case["file"].as_str().unwrap())).unwrap();
        assert_eq!(
            sha256_prefixed(&bytes),
            format!("sha256:{}", case["sha256"].as_str().unwrap())
        );
        let mode = if case["mode"] == "chain" {
            ReplayMode::Chain
        } else {
            ReplayMode::Single
        };
        let report =
            serde_json::to_value(inspect_replay_document(&bytes, &key, mode).unwrap()).unwrap();
        for check in case["checks"].as_array().unwrap() {
            let mut observed = &report;
            for part in check["path"].as_array().unwrap() {
                observed = if let Some(index) = part.as_u64() {
                    &observed[index as usize]
                } else {
                    &observed[part.as_str().unwrap()]
                };
            }
            assert_eq!(
                observed, &check["equals"],
                "case {} path {}",
                case["id"], check["path"]
            );
        }
    }
}
