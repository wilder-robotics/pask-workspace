// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
#![cfg(feature = "alloc")]

use pask_wire::InspectionStatus as Status;
use pask_wire::proposed_replay::*;
use serde_json::{Value, json};

fn directory() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proposed07/replay")
}
fn key() -> ed25519_dalek::VerifyingKey {
    replay_key_from_hex(include_str!("fixtures/proposed07/replay/public-key.hex").trim()).unwrap()
}
fn load(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(directory().join(format!("{name}.json"))).unwrap())
        .unwrap()
}
fn evaluate(value: &Value, mode: ReplayMode) -> Result<ReplayReport, ReplayError> {
    inspect_replay_document(&serde_json::to_vec(value).unwrap(), &key(), mode)
}
fn error(value: &Value) -> ReplayError {
    evaluate(value, ReplayMode::Single).unwrap_err()
}
fn project(report: &Value, field: &str) -> Value {
    let records = report["records"].as_array().unwrap();
    let source = match field {
        "statement_statuses" => Some(("statement_check", "status")),
        "membership" => Some(("membership", "status")),
        "disclosure_policy" => Some(("disclosure_policy", "status")),
        "contradictions" => Some(("summary", "value_contradictions")),
        "forbidden" => Some(("summary", "attribution_forbidden")),
        "evidence_failures" => Some(("summary", "evidence_failures")),
        _ => None,
    };
    if let Some((a, b)) = source {
        return json!(records.iter().map(|r| r[a][b].clone()).collect::<Vec<_>>());
    }
    match field {
        "chain_status" => report["chain"]["check"]["status"].clone(),
        "affiliation_changes" => json!(
            report["chain"]["affiliation_changes"]
                .as_array()
                .unwrap()
                .len()
        ),
        "presentation_states" => json!(
            records
                .iter()
                .map(|r| r["presentation_state"].clone())
                .collect::<Vec<_>>()
        ),
        "requested_availability" => json!(
            records
                .iter()
                .map(|r| r["requested_facts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| f["availability"].clone())
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()
        ),
        _ => panic!("unexpected fixture projection"),
    }
}

#[test]
fn fixed_python_signed_documents_meet_native_report_expectations() {
    let catalog: Value =
        serde_json::from_str(include_str!("fixtures/proposed07/replay/catalog.json")).unwrap();
    assert_eq!(catalog["cases"].as_array().unwrap().len(), 21);
    for case in catalog["cases"].as_array().unwrap() {
        let bytes = std::fs::read(directory().join(case["file"].as_str().unwrap())).unwrap();
        assert_eq!(
            pask_wire::sha256_prefixed(&bytes),
            format!("sha256:{}", case["sha256"].as_str().unwrap())
        );
        let mode = if case["mode"] == "chain" {
            ReplayMode::Chain
        } else {
            ReplayMode::Single
        };
        let report =
            serde_json::to_value(inspect_replay_document(&bytes, &key(), mode).unwrap()).unwrap();
        for (field, expected) in case["expected"].as_object().unwrap() {
            assert_eq!(
                &project(&report, field),
                expected,
                "case {} field {}",
                case["id"],
                field
            );
        }
        assert_eq!(
            report["latest_or_complete_history"]["status"],
            "unestablished"
        );
        assert_eq!(report["application_acceptance"]["status"], "unestablished");
        assert_eq!(report["registration"]["status"], "not-evaluated");
        assert!(report.get("accepted").is_none());
        assert!(report.get("valid").is_none());
    }
}
#[test]
fn duplicate_top_level_schema_rejects() {
    let text = serde_json::to_string(&load("single-match")).unwrap();
    let duplicate = format!("{{\"schema\":\"{}\",{}", DOCUMENT_SCHEMA, &text[1..]);
    assert_eq!(
        inspect_replay_document(duplicate.as_bytes(), &key(), ReplayMode::Single).unwrap_err(),
        ReplayError::DocumentJson
    );
}
#[test]
fn escaped_duplicate_policy_key_rejects() {
    let text = serde_json::to_string(&load("single-match")).unwrap();
    let duplicate = text.replace(
        "\"require_presented_content\":true",
        "\"require_presented_content\":true,\"require_presented_\\u0063ontent\":false",
    );
    assert_ne!(text, duplicate);
    assert_eq!(
        inspect_replay_document(duplicate.as_bytes(), &key(), ReplayMode::Single).unwrap_err(),
        ReplayError::DocumentJson
    );
}
#[test]
fn second_expected_root_is_not_a_transport_member() {
    let mut v = load("single-match");
    v["entries"][0]["presentation"]["root"] = json!("sha256:untrusted");
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn document_cannot_choose_the_verification_key() {
    let mut v = load("single-match");
    v["public_key_hex"] = json!("00".repeat(32));
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn document_cannot_select_a_different_mode() {
    let mut v = load("single-match");
    v["mode"] = json!("single");
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn absent_presentation_member_is_not_null() {
    let mut v = load("single-match");
    v["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("presentation");
    assert_eq!(error(&v), ReplayError::DocumentJson);
    v["entries"][0]["presentation"] = Value::Null;
    assert!(evaluate(&v, ReplayMode::Single).is_ok());
}
#[test]
fn explicit_context_member_is_required() {
    let mut v = load("single-match");
    v["entries"][0]["policy"]
        .as_object_mut()
        .unwrap()
        .remove("expected_context");
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn unknown_policy_field_rejects() {
    let mut v = load("single-match");
    v["entries"][0]["policy"]["accept_all"] = json!(true);
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn empty_entry_set_rejects_even_for_chain() {
    let v = json!({"schema":DOCUMENT_SCHEMA,"entries":[]});
    assert_eq!(
        evaluate(&v, ReplayMode::Chain).unwrap_err(),
        ReplayError::EntryCount
    );
}
#[test]
fn over_limit_entry_set_rejects() {
    let mut v = load("single-match");
    let entry = v["entries"][0].clone();
    v["entries"] = json!(vec![entry; MAX_ENTRIES + 1]);
    assert_eq!(
        evaluate(&v, ReplayMode::Chain).unwrap_err(),
        ReplayError::EntryCount
    );
}
#[test]
fn single_mode_cannot_skip_extra_entries() {
    assert_eq!(
        evaluate(&load("chain-three"), ReplayMode::Single).unwrap_err(),
        ReplayError::ModeCardinality
    );
}
#[test]
fn odd_hex_rejects() {
    let mut v = load("single-match");
    v["entries"][0]["statement_hex"] = json!("d20");
    assert_eq!(error(&v), ReplayError::InvalidHex);
}
#[test]
fn uppercase_hex_rejects_instead_of_normalizing() {
    let mut v = load("single-match");
    let text = v["entries"][0]["statement_hex"]
        .as_str()
        .unwrap()
        .to_uppercase();
    v["entries"][0]["statement_hex"] = json!(text);
    assert_eq!(error(&v), ReplayError::InvalidHex);
}
#[test]
fn bytes_state_requires_an_explicit_hex_string() {
    let mut v = load("single-match");
    v["entries"][0]["objects"][0]["bytes_hex"] = Value::Null;
    assert_eq!(error(&v), ReplayError::ObjectState);
}
#[test]
fn unavailable_state_forbids_carried_bytes() {
    let mut v = load("single-match");
    v["entries"][0]["objects"][0]["state"] = json!("UNAVAILABLE");
    assert_eq!(error(&v), ReplayError::ObjectState);
}
#[test]
fn empty_present_bytes_are_not_unavailable() {
    let mut v = load("single-match");
    v["entries"][0]["objects"][0]["bytes_hex"] = json!("");
    let r = evaluate(&v, ReplayMode::Single).unwrap();
    assert_eq!(
        r.records[0].facts[0].evidence.integrity,
        Some(pask_wire::proposed_evidence::EvidenceIntegrity::Mismatch)
    );
    assert_eq!(r.records[0].facts[0].evidence.checked_bytes, 0);
}
#[test]
fn duplicate_objects_remain_an_inventory_finding_not_first_match() {
    let mut v = load("single-match");
    let object = v["entries"][0]["objects"][0].clone();
    v["entries"][0]["objects"]
        .as_array_mut()
        .unwrap()
        .push(object);
    let r = evaluate(&v, ReplayMode::Single).unwrap();
    assert_eq!(r.records[0].local_object_inventory.status, Status::Failed);
    assert_eq!(r.records[0].membership.status, Status::Passed);
}
#[test]
fn untrusted_input_paths_are_not_a_schema_feature() {
    let mut v = load("single-match");
    v["entries"][0]["objects"][0]["path"] = json!("../../private");
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn invalid_json_whitespace_rejects() {
    let mut raw = vec![0x0b];
    raw.extend(serde_json::to_vec(&load("single-match")).unwrap());
    assert_eq!(
        inspect_replay_document(&raw, &key(), ReplayMode::Single).unwrap_err(),
        ReplayError::DocumentJson
    );
}
#[test]
fn trailing_second_document_rejects() {
    let mut raw = serde_json::to_vec(&load("single-match")).unwrap();
    raw.extend_from_slice(b" {}");
    assert_eq!(
        inspect_replay_document(&raw, &key(), ReplayMode::Single).unwrap_err(),
        ReplayError::DocumentJson
    );
}
#[test]
fn over_limit_raw_input_rejects_before_deserialization() {
    let raw = vec![b' '; MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        inspect_replay_document(&raw, &key(), ReplayMode::Single).unwrap_err(),
        ReplayError::DocumentBytes
    );
}
#[test]
fn depth_gate_applies_even_to_unknown_fields() {
    let text = format!(
        "{{\"unknown\":{}0{}}}",
        "[".repeat(MAX_DOCUMENT_DEPTH),
        "]".repeat(MAX_DOCUMENT_DEPTH)
    );
    assert_eq!(
        inspect_replay_document(text.as_bytes(), &key(), ReplayMode::Single).unwrap_err(),
        ReplayError::DocumentDepth
    );
}
#[test]
fn nested_delimiters_in_strings_are_not_nesting() {
    let mut v = load("single-match");
    v["entries"][0]["policy"]["expected_context"] =
        json!({"site_id":"[".repeat(100),"engagement_id":"}".repeat(100)});
    let r = evaluate(&v, ReplayMode::Single).unwrap();
    assert_eq!(r.records[0].context_comparison.status, Status::Failed);
}
#[test]
fn fixed_salt_width_is_enforced() {
    let mut v = load("single-match");
    v["entries"][0]["presentation"]["disclosures"][0]["salt_hex"] = json!("00".repeat(31));
    assert_eq!(error(&v), ReplayError::InvalidHex);
}
#[test]
fn extra_proof_elements_over_transport_limit_reject() {
    let mut v = load("single-match");
    v["entries"][0]["presentation"]["disclosures"][0]["siblings_hex"] =
        json!(vec!["00".repeat(32); 9]);
    assert_eq!(error(&v), ReplayError::FieldBound);
}
#[test]
fn excessive_context_rejects_before_recipient() {
    let mut v = load("single-match");
    v["entries"][0]["policy"]["expected_context"] =
        json!({"site_id":"x".repeat(8193),"engagement_id":"x"});
    assert_eq!(error(&v), ReplayError::FieldBound);
}
#[test]
fn aggregate_decoded_limit_is_separate_from_raw_document_limit() {
    let mut v = load("single-null");
    let mut entry = v["entries"][0].clone();
    entry["statement_hex"] = json!("00".repeat(800_000));
    v["entries"] = json!(vec![entry; 4]);
    let raw = serde_json::to_vec(&v).unwrap();
    assert!(raw.len() < MAX_DOCUMENT_BYTES);
    assert_eq!(
        inspect_replay_document(&raw, &key(), ReplayMode::Chain).unwrap_err(),
        ReplayError::DecodedBudget
    );
}
#[test]
fn malformed_late_entry_cannot_yield_a_partial_batch_report() {
    let mut v = load("chain-three");
    v["entries"][2]["statement_hex"] = json!("!");
    assert_eq!(
        evaluate(&v, ReplayMode::Chain).unwrap_err(),
        ReplayError::InvalidHex
    );
}
#[test]
fn chain_success_does_not_override_bad_content_proof() {
    let mut v = load("chain-three");
    v["entries"][1]["presentation"]["disclosures"][0]["salt_hex"] = json!("00".repeat(32));
    let r = evaluate(&v, ReplayMode::Chain).unwrap();
    assert_eq!(r.chain.check.status, Status::Passed);
    assert_eq!(r.records[1].membership.status, Status::Failed);
    assert_eq!(r.records[1].chain_contiguity.status, Status::NotEvaluated);
}
#[test]
fn chain_failure_does_not_erase_individual_membership() {
    let r = evaluate(&load("chain-wrong-predecessor"), ReplayMode::Chain).unwrap();
    assert_eq!(r.chain.check.status, Status::Failed);
    assert!(
        r.records
            .iter()
            .all(|r| r.membership.status == Status::Passed)
    );
}
#[test]
fn wrong_explicit_key_prevents_chain_evaluation() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
    let r = inspect_replay_document(
        &serde_json::to_vec(&load("chain-three")).unwrap(),
        &key,
        ReplayMode::Chain,
    )
    .unwrap();
    assert_eq!(r.chain.check.status, Status::Unestablished);
    assert_eq!(r.chain.verified_payloads, 0);
}
#[test]
fn input_encoding_and_statement_bytes_have_separate_digests() {
    let v = load("single-match");
    let compact = serde_json::to_vec(&v).unwrap();
    let pretty = serde_json::to_vec_pretty(&v).unwrap();
    let a = inspect_replay_document(&compact, &key(), ReplayMode::Single).unwrap();
    let b = inspect_replay_document(&pretty, &key(), ReplayMode::Single).unwrap();
    assert_ne!(a.input_document_digest, b.input_document_digest);
    assert_eq!(a.records[0].statement_digest, b.records[0].statement_digest);
    assert_eq!(
        a.records[0].statement_digest,
        Some(pask_wire::sha256_prefixed(
            &hex::decode(v["entries"][0]["statement_hex"].as_str().unwrap()).unwrap()
        ))
    );
}
#[test]
fn a_valid_prefix_never_establishes_latest_history() {
    let r = evaluate(&load("chain-prefix"), ReplayMode::Chain).unwrap();
    assert_eq!(r.chain.check.status, Status::Passed);
    assert_eq!(r.latest_or_complete_history.status, Status::Unestablished);
}
#[test]
fn public_key_parser_rejects_spelling_changes() {
    let encoded = include_str!("fixtures/proposed07/replay/public-key.hex").trim();
    assert!(replay_key_from_hex(encoded).is_ok());
    assert!(replay_key_from_hex(&encoded.to_uppercase()).is_err());
    assert!(replay_key_from_hex(&format!(" {encoded}")).is_err());
    assert!(replay_key_from_hex(&encoded[..62]).is_err());
}
#[test]
fn integer_transport_fields_do_not_coerce_float_values() {
    let mut v = load("single-match");
    v["entries"][0]["presentation"]["fact_count"] = json!(1.0);
    assert_eq!(error(&v), ReplayError::DocumentJson);
}
#[test]
fn legacy_receipt_can_be_single_checked_without_inventing_content_support() {
    let r = evaluate(&load("single-legacy06"), ReplayMode::Single).unwrap();
    assert_eq!(r.records[0].statement_check.status, Status::Passed);
    assert_eq!(r.records[0].profile_support.status, Status::Unsupported);
    assert_eq!(r.chain.check.status, Status::NotEvaluated);
}
#[test]
fn disclosure_order_is_preserved_as_input_not_sorting_the_chain() {
    let mut v = load("chain-three");
    v["entries"].as_array_mut().unwrap().reverse();
    let r = evaluate(&v, ReplayMode::Chain).unwrap();
    assert_eq!(r.chain.check.status, Status::Failed);
}
