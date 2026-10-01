// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
#![cfg(feature = "alloc")]

use coset::cbor::Value as Cbor;
use ed25519_dalek::SigningKey;
use pask_wire::proposed_constraints::ConstraintResult;
use pask_wire::proposed_content::{
    CONSTRUCTION, ContentHeader, DisclosedFact, SCOPE, SaltedFact, prepare_content,
};
use pask_wire::proposed_evidence::{EvidenceIntegrity, PresentedEvidence, ValueComparison};
use pask_wire::proposed_recipient::*;
use pask_wire::{
    InspectionStatus as Status, Payload, canonicalize_json, produce_ed25519, sha256_prefixed,
};
use serde_json::{Value, json};

const VOCAB: &str = "sha256:030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d";
fn key() -> SigningKey {
    // Public deterministic fixture key; protects nothing.
    SigningKey::from_bytes(&[91; 32])
}
fn header() -> ContentHeader<'static> {
    ContentHeader {
        construction: CONSTRUCTION,
        scope: SCOPE,
        vocabulary_digest: VOCAB,
    }
}
fn canonical(value: &Value) -> Vec<u8> {
    canonicalize_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn model(value: &str) -> Value {
    json!({"name":"unit.model","assertedBy":"site-policy","basis":"declared","value":value})
}
fn fact(name: &str, party: &str, basis: &str, value: Value, digest: Option<&str>) -> Value {
    let mut result = json!({"name":name,"assertedBy":party,"basis":basis,"value":value});
    if let Some(digest) = digest {
        result["evidence"] = json!({"digest":digest});
    }
    result
}
fn policy() -> RecipientPolicy<'static> {
    RecipientPolicy {
        compare_unitless_scalars: true,
        ..RecipientPolicy::default()
    }
}
fn signed(root: Option<&str>, version: &str) -> Vec<u8> {
    let mut payload: Value =
        serde_json::from_str(&pask_wire::canonical_example_06().unwrap()).unwrap();
    payload["spec"] = json!(version);
    if version == "wilder.pser/0.7" {
        payload["engagement"]["contentDigest"] = json!(root);
    }
    let payload =
        Payload::from_json_for_production(&serde_json::to_vec(&payload).unwrap()).unwrap();
    produce_ed25519(&payload, payload.witness_key(), &key()).unwrap()
}
fn evaluate(
    values: &[Value],
    selected: Option<&[&str]>,
    objects: &[LocalEvidenceObject<'_>],
    policy: &RecipientPolicy<'_>,
) -> RecipientReport {
    let records: Vec<_> = values.iter().map(canonical).collect();
    let facts: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(i, record)| SaltedFact {
            record,
            salt: [(i + 1) as u8; 32],
        })
        .collect();
    let prepared = prepare_content(&header(), &facts).unwrap();
    let disclosures: Vec<_> = match selected {
        Some(names) => names
            .iter()
            .map(|name| prepared.disclose(name).unwrap())
            .collect(),
        None => values
            .iter()
            .map(|value| prepared.disclose(value["name"].as_str().unwrap()).unwrap())
            .collect(),
    };
    let statement = signed(Some(&prepared.root_digest()), "wilder.pser/0.7");
    inspect_proposed_recipient_ed25519(
        &statement,
        &key().verifying_key(),
        Some(ContentPresentation {
            header: header(),
            fact_count: prepared.fact_count(),
            disclosures: &disclosures,
        }),
        objects,
        policy,
    )
}
fn object<'a>(digest: &'a str, bytes: &'a [u8]) -> LocalEvidenceObject<'a> {
    LocalEvidenceObject {
        digest,
        availability: PresentedEvidence::Bytes(bytes),
    }
}
fn encoding(value: &Cbor) -> Vec<u8> {
    let mut result = Vec::new();
    coset::cbor::ser::into_writer(value, &mut result).unwrap();
    result
}
fn alter(statement: &[u8], change: impl FnOnce(&mut Vec<Cbor>)) -> Vec<u8> {
    let mut value: Cbor = coset::cbor::de::from_reader(statement).unwrap();
    let Cbor::Array(items) = &mut value else {
        panic!("test producer array")
    };
    change(items);
    encoding(&value)
}

#[test]
fn matched_digest_and_value_are_bound_but_not_authenticated_party() {
    let bytes = b"\"Alpha\"";
    let digest = sha256_prefixed(bytes);
    let mut f = model("Alpha");
    f["evidence"] = json!({"digest":digest});
    let r = evaluate(&[f], None, &[object(&digest, bytes)], &policy());
    assert_eq!(r.statement_check.status, Status::Passed);
    assert_eq!(r.content_binding.status, Status::Passed);
    assert_eq!(r.presentation_state, PresentationState::AllCommittedSlots);
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::EvidenceLinked));
    assert_eq!(r.facts[0].evidence.comparison, ValueComparison::Match);
    assert!(r.facts[0].evidence.expected_digest_from_disclosed_fact);
    assert!(!r.facts[0].attributed_party_authenticated);
    assert_eq!(r.issuer_identity_trust.status, Status::Unestablished);
    assert_eq!(r.full_profile.status, Status::Unestablished);
}

#[test]
fn matching_evidence_bytes_can_contradict_the_bound_value() {
    let bytes = b"\"Beta\"";
    let digest = sha256_prefixed(bytes);
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, bytes)], &policy());
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::EvidenceLinked));
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(
        r.facts[0].evidence.comparison,
        ValueComparison::Contradiction
    );
    assert_eq!(r.summary.value_contradictions, 1);
}

#[test]
fn raw_digest_mismatch_is_not_attribution_only_even_if_value_agrees() {
    let expected = sha256_prefixed(b"\"Alpha\" ");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&expected),
    );
    let r = evaluate(&[f], None, &[object(&expected, b"\"Alpha\"")], &policy());
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Mismatch)
    );
    assert_eq!(r.facts[0].evidence.comparison, ValueComparison::NotRun);
    assert_eq!(r.facts[0].provenance, None);
    assert_eq!(r.summary.evidence_failures, 1);
}

#[test]
fn missing_referenced_object_differs_from_bad_integrity() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[], &policy());
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::AttributionOnly));
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::BytesUnavailable)
    );
    assert_eq!(r.summary.evidence_failures, 0);
}

#[test]
fn optional_no_reference_is_attribution_only() {
    let r = evaluate(&[model("Alpha")], None, &[], &policy());
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::AttributionOnly));
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::NoReference)
    );
}

#[test]
fn required_missing_reference_is_metadata_failure_not_permitted_attribution_only() {
    let f = fact(
        "unit.model",
        "robot-attributed",
        "declared",
        json!("Alpha"),
        None,
    );
    let r = evaluate(&[f], None, &[], &policy());
    assert_eq!(
        r.facts[0].constraint.classification,
        ConstraintResult::Permitted
    );
    assert!(
        r.facts[0]
            .constraint
            .metadata_findings
            .contains(&"required_evidence_reference_missing")
    );
    assert_eq!(r.facts[0].provenance, None);
}

#[test]
fn pointer_is_not_fetched_or_promoted_to_digest_binding() {
    let mut f = model("Alpha");
    f["evidence"] = json!({"pointer":"https://example.invalid/evidence"});
    let r = evaluate(&[f], None, &[], &policy());
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::AttributionOnly));
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::DigestBindingUnavailable)
    );
    assert!(!r.facts[0].evidence.expected_digest_from_disclosed_fact);
}

#[test]
fn malformed_reference_cannot_be_hidden_as_absent() {
    for reference in [
        json!(42),
        json!({"digest":"bad"}),
        json!({"digest":"bad","pointer":"x"}),
    ] {
        let mut f = model("Alpha");
        f["evidence"] = reference;
        let r = evaluate(&[f], None, &[], &policy());
        assert_eq!(r.facts[0].evidence.reference.status, Status::Failed);
        assert_eq!(r.facts[0].provenance, None);
        assert_eq!(r.summary.evidence_failures, 1);
    }
}

#[test]
fn forbidden_attribution_is_visible_despite_good_membership_and_bytes() {
    let digest = sha256_prefixed(b"50");
    let f = fact(
        "limits.rated-force",
        "robot-attributed",
        "measured",
        json!(50),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, b"50")], &policy());
    assert_eq!(r.membership.status, Status::Passed);
    assert_eq!(
        r.facts[0].provenance,
        Some(FactProvenance::AttributionForbidden)
    );
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(r.summary.attribution_forbidden, 1);
}

#[test]
fn implicit_vocabulary_unit_does_not_become_unitless_when_unit_field_is_omitted() {
    let digest = sha256_prefixed(b"50");
    let f = fact(
        "limits.rated-force",
        "manufacturer-declared",
        "declared",
        json!(50),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, b"50")], &policy());
    assert_eq!(
        r.facts[0].constraint.classification,
        ConstraintResult::Permitted
    );
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::EvidenceLinked));
    assert_eq!(
        r.facts[0].evidence.comparison,
        ValueComparison::NotComparable
    );
    assert_eq!(
        r.facts[0].evidence.comparison_reason,
        "unit_binding_not_supported"
    );
}

#[test]
fn malformed_unit_preserves_digest_result_but_cannot_support_comparison() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let mut f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    f["unit"] = json!(42);
    let r = evaluate(&[f], None, &[object(&digest, b"\"Alpha\"")], &policy());
    assert_eq!(r.facts[0].provenance, None);
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(r.facts[0].evidence.comparison, ValueComparison::NotRun);
    assert!(
        r.facts[0]
            .constraint
            .metadata_findings
            .contains(&"unit_mismatch")
    );
}

#[test]
fn comparison_is_opt_in() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let r = evaluate(
        &[f],
        None,
        &[object(&digest, b"\"Alpha\"")],
        &RecipientPolicy::default(),
    );
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(r.facts[0].evidence.comparison, ValueComparison::NotRun);
    assert_eq!(
        r.facts[0].evidence.comparison_reason,
        "comparison_not_requested"
    );
}

#[test]
fn unknown_fact_remains_unsupported_not_evidence_linked() {
    let digest = sha256_prefixed(b"3");
    let f = fact(
        "custom.unknown",
        "site-policy",
        "declared",
        json!(3),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, b"3")], &policy());
    assert_eq!(
        r.facts[0].constraint.classification,
        ConstraintResult::UnknownFact
    );
    assert_eq!(r.facts[0].provenance, None);
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(r.facts[0].evidence.comparison, ValueComparison::NotRun);
}

#[test]
fn null_content_is_distinct_from_no_presentation_for_a_digest() {
    let p = RecipientPolicy {
        require_presented_content: true,
        required_fact_names: &["unit.model"],
        ..policy()
    };
    let null = inspect_proposed_recipient_ed25519(
        &signed(None, "wilder.pser/0.7"),
        &key().verifying_key(),
        None,
        &[],
        &p,
    );
    assert_eq!(null.statement_check.status, Status::Passed);
    assert_eq!(null.presentation_state, PresentationState::NullCommitment);
    assert_eq!(null.disclosure_policy.status, Status::Failed);
    assert_eq!(
        null.requested_facts[0].availability,
        RequestedAvailability::NoBlockCommitted
    );
    let digest = sha256_prefixed(b"not a root proof");
    let missing = inspect_proposed_recipient_ed25519(
        &signed(Some(&digest), "wilder.pser/0.7"),
        &key().verifying_key(),
        None,
        &[],
        &p,
    );
    assert_eq!(missing.presentation_state, PresentationState::NotPresented);
    assert_eq!(missing.disclosure_policy.status, Status::Unestablished);
    assert_eq!(
        missing.requested_facts[0].availability,
        RequestedAvailability::CommittedBlockNotPresented
    );
}

#[test]
fn committed_empty_block_is_not_null_or_proof_of_no_physical_facts() {
    let p = RecipientPolicy {
        require_presented_content: true,
        required_fact_names: &["unit.model"],
        ..policy()
    };
    let r = evaluate(&[], None, &[], &p);
    assert_eq!(r.presentation_state, PresentationState::EmptyCommittedBlock);
    assert!(r.count_bound_to_checked_statement);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::AbsentFromCommittedBlock
    );
    assert!(!r.requested_facts[0].semantic_absence_established);
    assert_eq!(r.disclosure_policy.status, Status::Failed);
}

#[test]
fn nonempty_claim_with_zero_disclosures_does_not_authenticate_count() {
    let r = evaluate(&[model("Alpha")], Some(&[]), &[], &policy());
    assert_eq!(r.presentation_state, PresentationState::NotPresented);
    assert_eq!(r.claimed_fact_count, Some(1));
    assert!(!r.count_bound_to_checked_statement);
    assert_eq!(r.vocabulary.status, Status::NotEvaluated);
}

#[test]
fn selected_disclosure_cannot_prove_a_required_fact_absent() {
    let values = [
        model("Alpha"),
        fact(
            "scene.setting",
            "site-policy",
            "declared",
            json!("indoor"),
            None,
        ),
    ];
    let p = RecipientPolicy {
        required_fact_names: &["unit.model"],
        ..policy()
    };
    let r = evaluate(&values, Some(&["scene.setting"]), &[], &p);
    assert_eq!(r.presentation_state, PresentationState::SelectedSlots);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::NotDisclosedUnproven
    );
    assert_eq!(
        r.requested_facts[0].provenance,
        Some(FactProvenance::FactUnavailable)
    );
    assert_eq!(r.disclosure_policy.status, Status::Unestablished);
}

#[test]
fn full_disclosure_can_establish_only_absence_from_that_block() {
    let p = RecipientPolicy {
        required_fact_names: &["unit.pseudonym"],
        ..policy()
    };
    let r = evaluate(&[model("Alpha")], None, &[], &p);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::AbsentFromCommittedBlock
    );
    assert_eq!(r.disclosure_policy.status, Status::Failed);
    assert_eq!(r.latest_or_complete_history.status, Status::Unestablished);
}

#[test]
fn disclosure_policy_pass_does_not_erase_forbidden_fact_or_imply_acceptance() {
    let f = fact(
        "limits.rated-force",
        "site-policy",
        "declared",
        json!(50),
        None,
    );
    let p = RecipientPolicy {
        require_all_committed_slots: true,
        required_fact_names: &["limits.rated-force"],
        ..policy()
    };
    let r = evaluate(&[f], None, &[], &p);
    assert_eq!(r.disclosure_policy.status, Status::Passed);
    assert_eq!(r.summary.attribution_forbidden, 1);
    assert_eq!(r.application_acceptance.status, Status::Unestablished);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::Disclosed
    );
}

#[test]
fn require_all_slots_fails_to_establish_acceptance_of_a_subset() {
    let values = [
        model("Alpha"),
        fact(
            "unit.deployment-status",
            "site-policy",
            "declared",
            json!("deployed"),
            None,
        ),
    ];
    let p = RecipientPolicy {
        require_all_committed_slots: true,
        ..policy()
    };
    let r = evaluate(&values, Some(&["unit.model"]), &[], &p);
    assert_eq!(r.disclosure_policy.status, Status::Unestablished);
}

#[test]
fn wrong_public_key_stops_content_processing() {
    let signed = signed(None, "wilder.pser/0.7");
    let other = SigningKey::from_bytes(&[92; 32]);
    let r =
        inspect_proposed_recipient_ed25519(&signed, &other.verifying_key(), None, &[], &policy());
    assert_eq!(r.statement_check.code, "supplied_key_signature_failed");
    assert_eq!(r.presentation_state, PresentationState::NotEvaluated);
    assert!(r.facts.is_empty());
    assert!(r.content_digest.is_none());
}

#[test]
fn altered_signature_is_not_hidden_as_missing_content() {
    let signed = alter(&signed(None, "wilder.pser/0.7"), |items| {
        let Cbor::Bytes(bytes) = &mut items[3] else {
            panic!()
        };
        bytes[0] ^= 1;
    });
    let r =
        inspect_proposed_recipient_ed25519(&signed, &key().verifying_key(), None, &[], &policy());
    assert_eq!(r.statement_check.code, "supplied_key_signature_failed");
    assert_eq!(r.presentation_state, PresentationState::NotEvaluated);
}

#[test]
fn root_is_taken_from_checked_payload_not_the_presented_block() {
    let records = [canonical(&model("Alpha"))];
    let b = prepare_content(
        &header(),
        &[SaltedFact {
            record: &records[0],
            salt: [1; 32],
        }],
    )
    .unwrap();
    let d = [b.disclose("unit.model").unwrap()];
    let statement = signed(Some(&sha256_prefixed(b"different root")), "wilder.pser/0.7");
    let r = inspect_proposed_recipient_ed25519(
        &statement,
        &key().verifying_key(),
        Some(ContentPresentation {
            header: header(),
            fact_count: 1,
            disclosures: &d,
        }),
        &[],
        &policy(),
    );
    assert_eq!(r.statement_check.status, Status::Passed);
    assert_eq!(r.presentation_state, PresentationState::Invalid);
    assert_eq!(r.membership.code, "content_root_mismatch");
    assert!(r.facts.is_empty());
}

#[test]
fn null_receipt_does_not_adopt_a_supplied_block_root() {
    let record = canonical(&model("Alpha"));
    let b = prepare_content(
        &header(),
        &[SaltedFact {
            record: &record,
            salt: [1; 32],
        }],
    )
    .unwrap();
    let d = [b.disclose("unit.model").unwrap()];
    let r = inspect_proposed_recipient_ed25519(
        &signed(None, "wilder.pser/0.7"),
        &key().verifying_key(),
        Some(ContentPresentation {
            header: header(),
            fact_count: 1,
            disclosures: &d,
        }),
        &[],
        &policy(),
    );
    assert_eq!(r.presentation_state, PresentationState::NullCommitment);
    assert!(r.ignored_presentation);
    assert!(r.content_digest.is_none());
}

#[test]
fn tampered_fact_fails_membership_before_classification() {
    let record = canonical(&model("Alpha"));
    let altered = canonical(&model("Beta"));
    let b = prepare_content(
        &header(),
        &[SaltedFact {
            record: &record,
            salt: [1; 32],
        }],
    )
    .unwrap();
    let mut d = b.disclose("unit.model").unwrap();
    d.record = &altered;
    let p = RecipientPolicy {
        required_fact_names: &["unit.model"],
        ..policy()
    };
    let r = inspect_proposed_recipient_ed25519(
        &signed(Some(&b.root_digest()), "wilder.pser/0.7"),
        &key().verifying_key(),
        Some(ContentPresentation {
            header: header(),
            fact_count: 1,
            disclosures: &[d],
        }),
        &[],
        &p,
    );
    assert_eq!(r.presentation_state, PresentationState::Invalid);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::NotEvaluated
    );
    assert_eq!(r.requested_facts[0].provenance, None);
    assert!(r.facts.is_empty());
}

#[test]
fn one_invalid_disclosure_stops_batch_no_partial_success_labels() {
    let records = [
        canonical(&model("Alpha")),
        canonical(&fact(
            "scene.setting",
            "site-policy",
            "declared",
            json!("indoor"),
            None,
        )),
    ];
    let b = prepare_content(
        &header(),
        &[
            SaltedFact {
                record: &records[0],
                salt: [1; 32],
            },
            SaltedFact {
                record: &records[1],
                salt: [2; 32],
            },
        ],
    )
    .unwrap();
    let mut disclosures = [
        b.disclose("unit.model").unwrap(),
        b.disclose("scene.setting").unwrap(),
    ];
    disclosures[1].siblings[0][0] ^= 1;
    let r = inspect_proposed_recipient_ed25519(
        &signed(Some(&b.root_digest()), "wilder.pser/0.7"),
        &key().verifying_key(),
        Some(ContentPresentation {
            header: header(),
            fact_count: 2,
            disclosures: &disclosures,
        }),
        &[],
        &policy(),
    );
    assert_eq!(r.presentation_state, PresentationState::Invalid);
    assert!(r.facts.is_empty());
    assert_eq!(r.summary.evidence_linked, 0);
}

#[test]
fn unknown_vocabulary_keeps_proof_success_but_does_not_use_wrong_rule_table() {
    let wrong_vocab = sha256_prefixed(b"different vocabulary");
    let h = ContentHeader {
        vocabulary_digest: &wrong_vocab,
        ..header()
    };
    let record = canonical(&model("Alpha"));
    let b = prepare_content(
        &h,
        &[SaltedFact {
            record: &record,
            salt: [1; 32],
        }],
    )
    .unwrap();
    let d = [b.disclose("unit.model").unwrap()];
    let p = RecipientPolicy {
        required_fact_names: &["unit.model"],
        ..policy()
    };
    let r = inspect_proposed_recipient_ed25519(
        &signed(Some(&b.root_digest()), "wilder.pser/0.7"),
        &key().verifying_key(),
        Some(ContentPresentation {
            header: h,
            fact_count: 1,
            disclosures: &d,
        }),
        &[],
        &p,
    );
    assert_eq!(r.membership.status, Status::Passed);
    assert_eq!(r.vocabulary.status, Status::Unsupported);
    assert!(r.facts.is_empty());
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::NotEvaluated
    );
    assert_eq!(r.disclosure_policy.status, Status::Unestablished);
}

#[test]
fn mismatching_expected_context_stops_downstream_content_processing() {
    let p = RecipientPolicy {
        expected_context: Some(ExpectedContext {
            site_id: "site:wrong",
            engagement_id: "eng:wrong",
        }),
        ..policy()
    };
    let r = evaluate(&[model("Alpha")], None, &[], &p);
    assert_eq!(r.statement_check.status, Status::Passed);
    assert_eq!(r.context_comparison.status, Status::Failed);
    assert!(r.facts.is_empty());
    assert_eq!(r.content_binding.status, Status::NotEvaluated);
}

#[test]
fn matching_expected_context_is_only_a_label_comparison() {
    let value: Value = serde_json::from_str(&pask_wire::canonical_example_06().unwrap()).unwrap();
    let p = RecipientPolicy {
        expected_context: Some(ExpectedContext {
            site_id: value["site"]["id"].as_str().unwrap(),
            engagement_id: value["engagement"]["id"].as_str().unwrap(),
        }),
        ..policy()
    };
    let r = evaluate(&[model("Alpha")], None, &[], &p);
    assert_eq!(r.context_comparison.status, Status::Passed);
    assert_eq!(r.hardware_appraisal.status, Status::NotEvaluated);
    assert_eq!(r.real_world_clock.status, Status::Unestablished);
}

#[test]
fn both_legacy_versions_keep_their_own_statement_check_but_not_new_content_processing() {
    for version in ["wilder.pser/0.5", "wilder.pser/0.6"] {
        let r = inspect_proposed_recipient_ed25519(
            &signed(None, version),
            &key().verifying_key(),
            None,
            &[],
            &policy(),
        );
        assert_eq!(r.statement_check.status, Status::Passed, "{version}");
        assert_eq!(r.profile_support.status, Status::Unsupported);
        assert_eq!(
            r.presentation_state,
            PresentationState::LegacyProfileUnsupported
        );
        assert!(r.facts.is_empty());
    }
}

#[test]
fn identical_duplicate_objects_do_not_create_first_match_policy() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let r = evaluate(
        &[f],
        None,
        &[object(&digest, b"\"Alpha\""), object(&digest, b"\"Alpha\"")],
        &policy(),
    );
    assert_eq!(r.local_object_inventory.status, Status::Failed);
    assert_eq!(r.facts[0].evidence.lookup.status, Status::Failed);
    assert_eq!(r.facts[0].provenance, None);
}

#[test]
fn conflicting_object_order_cannot_select_a_success() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    for objects in [
        [object(&digest, b"\"Alpha\""), object(&digest, b"\"Beta\"")],
        [object(&digest, b"\"Beta\""), object(&digest, b"\"Alpha\"")],
    ] {
        let r = evaluate(std::slice::from_ref(&f), None, &objects, &policy());
        assert_eq!(
            r.local_object_inventory.code,
            "duplicate_local_object_digest"
        );
        assert_eq!(r.facts[0].provenance, None);
    }
}

#[test]
fn unused_valid_object_does_not_change_the_selected_fact_result() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let other = sha256_prefixed(b"unrelated");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let one = evaluate(
        std::slice::from_ref(&f),
        None,
        &[object(&digest, b"\"Alpha\"")],
        &policy(),
    );
    let two = evaluate(
        &[f],
        None,
        &[object(&other, b"unrelated"), object(&digest, b"\"Alpha\"")],
        &policy(),
    );
    assert_eq!(
        serde_json::to_value(&one.facts).unwrap(),
        serde_json::to_value(&two.facts).unwrap()
    );
}

#[test]
fn explicit_not_requested_and_unavailable_are_separate() {
    let digest = sha256_prefixed(b"\"Alpha\"");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    for (availability, expected) in [
        (
            PresentedEvidence::NotRequested,
            EvidenceIntegrity::NotRequested,
        ),
        (
            PresentedEvidence::Unavailable,
            EvidenceIntegrity::BytesUnavailable,
        ),
    ] {
        let r = evaluate(
            std::slice::from_ref(&f),
            None,
            &[LocalEvidenceObject {
                digest: &digest,
                availability,
            }],
            &policy(),
        );
        assert_eq!(r.facts[0].evidence.integrity, Some(expected));
        assert_eq!(r.facts[0].provenance, Some(FactProvenance::AttributionOnly));
    }
}

#[test]
fn empty_evidence_bytes_can_match_integrity_without_becoming_valid_json() {
    let digest = sha256_prefixed(b"");
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, b"")], &policy());
    assert_eq!(
        r.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Matched)
    );
    assert_eq!(r.facts[0].evidence.comparison_reason, "invalid_scalar_json");
}

#[test]
fn object_byte_budget_is_checked_before_hashing() {
    let bytes = vec![0; pask_wire::proposed_evidence::MAX_PRESENTED_EVIDENCE_BYTES + 1];
    let digest = sha256_prefixed(&bytes);
    let f = fact(
        "unit.model",
        "site-policy",
        "declared",
        json!("Alpha"),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, &bytes)], &policy());
    assert_eq!(r.local_object_inventory.code, "local_object_byte_limit");
    assert_eq!(r.facts[0].evidence.checked_bytes, 0);
}

#[test]
fn object_inventory_count_and_digest_failures_are_explicit() {
    let malformed = evaluate(
        &[model("Alpha")],
        None,
        &[object("not-a-digest", b"")],
        &policy(),
    );
    assert_eq!(
        malformed.local_object_inventory.code,
        "local_object_digest_malformed"
    );
    let digest = sha256_prefixed(b"");
    let objects = vec![object(&digest, b""); MAX_LOCAL_OBJECTS + 1];
    let excessive = evaluate(&[model("Alpha")], None, &objects, &policy());
    assert_eq!(
        excessive.local_object_inventory.code,
        "local_object_count_limit"
    );
}

#[test]
fn invalid_policy_does_not_process_inputs() {
    for names in [
        &["unit.model", "unit.model"][..],
        &["not.in.vocabulary"][..],
    ] {
        let p = RecipientPolicy {
            required_fact_names: names,
            ..policy()
        };
        let r = inspect_proposed_recipient_ed25519(
            b"not even cbor",
            &key().verifying_key(),
            None,
            &[],
            &p,
        );
        assert_eq!(r.policy_configuration.status, Status::Failed);
        assert!(r.statement_digest.is_none());
        assert!(r.requested_facts.is_empty());
    }
}

#[test]
fn oversized_statement_rejects_without_digest_or_parser() {
    let r = inspect_proposed_recipient_ed25519(
        &vec![0; MAX_STATEMENT_BYTES + 1],
        &key().verifying_key(),
        None,
        &[],
        &policy(),
    );
    assert_eq!(r.outer_structure.code, "statement_byte_limit");
    assert!(r.statement_digest.is_none());
}

#[test]
fn deeply_nested_payload_stops_before_existing_payload_parser() {
    let mut nested = b"[".repeat(MAX_PAYLOAD_DEPTH + 1);
    nested.extend_from_slice(b"0");
    nested.extend(b"]".repeat(MAX_PAYLOAD_DEPTH + 1));
    let statement = alter(&signed(None, "wilder.pser/0.7"), |items| {
        items[2] = Cbor::Bytes(nested)
    });
    let r = inspect_proposed_recipient_ed25519(
        &statement,
        &key().verifying_key(),
        None,
        &[],
        &policy(),
    );
    assert_eq!(
        r.statement_check.code,
        "payload_json_depth_or_framing_limit"
    );
}

#[test]
fn tag18_statement_wrapper_preserves_processing() {
    let original = signed(None, "wilder.pser/0.7");
    let value: Cbor = coset::cbor::de::from_reader(original.as_slice()).unwrap();
    let tagged = encoding(&Cbor::Tag(18, Box::new(value)));
    let r =
        inspect_proposed_recipient_ed25519(&tagged, &key().verifying_key(), None, &[], &policy());
    assert_eq!(r.statement_check.status, Status::Passed);
    assert_eq!(r.presentation_state, PresentationState::NullCommitment);
}

#[test]
fn unsupported_issuer_algorithm_stays_unsupported() {
    let statement = alter(&signed(None, "wilder.pser/0.7"), |items| {
        let Cbor::Bytes(bytes) = &items[0] else {
            panic!()
        };
        let mut protected: Cbor = coset::cbor::de::from_reader(bytes.as_slice()).unwrap();
        let Cbor::Map(map) = &mut protected else {
            panic!()
        };
        for (k, v) in map {
            if *k == Cbor::Integer(1.into()) {
                *v = Cbor::Integer((-7).into());
            }
        }
        items[0] = Cbor::Bytes(encoding(&protected));
    });
    let r = inspect_proposed_recipient_ed25519(
        &statement,
        &key().verifying_key(),
        None,
        &[],
        &policy(),
    );
    assert_eq!(r.outer_support.status, Status::Unsupported);
    assert_eq!(r.statement_check.status, Status::NotEvaluated);
}

#[test]
fn attached_receipts_are_not_claimed_verified_by_content_success() {
    let statement = alter(&signed(None, "wilder.pser/0.7"), |items| {
        items[1] = Cbor::Map(vec![(
            Cbor::Integer(394.into()),
            Cbor::Array(vec![Cbor::Bytes(b"not a Receipt".to_vec())]),
        )]);
    });
    let r = inspect_proposed_recipient_ed25519(
        &statement,
        &key().verifying_key(),
        None,
        &[],
        &policy(),
    );
    assert_eq!(r.statement_check.status, Status::Passed);
    assert_eq!(r.registration.status, Status::NotEvaluated);
}

#[test]
fn malformed_attachment_container_rejects_without_being_repaired() {
    let statement = alter(&signed(None, "wilder.pser/0.7"), |items| {
        items[1] = Cbor::Map(vec![(Cbor::Integer(394.into()), Cbor::Integer(7.into()))]);
    });
    let r = inspect_proposed_recipient_ed25519(
        &statement,
        &key().verifying_key(),
        None,
        &[],
        &policy(),
    );
    assert_eq!(r.outer_structure.status, Status::Failed);
    assert!(r.content_digest.is_none());
}

#[test]
fn disposition_order_is_canonical_by_slot_not_presentation_order() {
    let values = [
        model("Alpha"),
        fact(
            "scene.setting",
            "site-policy",
            "declared",
            json!("indoor"),
            None,
        ),
    ];
    let a = evaluate(
        &values,
        Some(&["unit.model", "scene.setting"]),
        &[],
        &policy(),
    );
    let b = evaluate(
        &values,
        Some(&["scene.setting", "unit.model"]),
        &[],
        &policy(),
    );
    assert_eq!(
        serde_json::to_value(a).unwrap(),
        serde_json::to_value(b).unwrap()
    );
}

#[test]
fn serialized_report_retains_existing_inspection_and_separate_fact_vocabulary() {
    let r = evaluate(&[model("Alpha")], None, &[], &policy());
    let value = serde_json::to_value(r).unwrap();
    assert_eq!(value["statement_check"]["status"], "passed");
    assert_eq!(value["facts"][0]["provenance"], "ATTRIBUTION_ONLY");
    assert_eq!(value["facts"][0]["evidence"]["comparison"], "NOT_RUN");
    assert!(value.get("accepted").is_none());
    assert!(value.get("valid").is_none());
}

#[test]
fn negative_zero_retains_raw_integrity_semantics_through_composition() {
    let digest = sha256_prefixed(b"-0");
    let f = fact(
        "outcome.severity-grade",
        "operator-entered",
        "declared",
        json!(0),
        Some(&digest),
    );
    let matched = evaluate(
        std::slice::from_ref(&f),
        None,
        &[object(&digest, b"-0")],
        &policy(),
    );
    assert_eq!(matched.facts[0].evidence.comparison, ValueComparison::Match);
    let substituted = evaluate(&[f], None, &[object(&digest, b"0")], &policy());
    assert_eq!(
        substituted.facts[0].evidence.integrity,
        Some(EvidenceIntegrity::Mismatch)
    );
    assert_eq!(
        substituted.facts[0].evidence.comparison,
        ValueComparison::NotRun
    );
}

#[test]
fn numeric_type_coercion_remains_not_comparable() {
    let digest = sha256_prefixed(b"\"0\"");
    let f = fact(
        "outcome.severity-grade",
        "operator-entered",
        "declared",
        json!(0),
        Some(&digest),
    );
    let r = evaluate(&[f], None, &[object(&digest, b"\"0\"")], &policy());
    assert_eq!(
        r.facts[0].evidence.comparison,
        ValueComparison::NotComparable
    );
    assert_eq!(
        r.facts[0].evidence.comparison_reason,
        "scalar_type_mismatch"
    );
}

#[test]
fn requested_fact_requirements_do_not_supply_an_extra_root_or_value() {
    let p = RecipientPolicy {
        required_fact_names: &["unit.model"],
        require_presented_content: true,
        ..policy()
    };
    let r = evaluate(&[model("Alpha")], None, &[], &p);
    assert_eq!(r.disclosure_policy.status, Status::Passed);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::Disclosed
    );
    assert_eq!(r.facts[0].provenance, Some(FactProvenance::AttributionOnly));
    assert_eq!(r.application_acceptance.status, Status::Unestablished);
}

#[test]
fn unsupported_construction_is_not_reported_as_a_bad_proof() {
    let h = ContentHeader {
        construction: "unknown/1",
        ..header()
    };
    let p = RecipientPolicy {
        require_presented_content: true,
        ..policy()
    };
    let r = inspect_proposed_recipient_ed25519(
        &signed(Some(&sha256_prefixed(b"root")), "wilder.pser/0.7"),
        &key().verifying_key(),
        Some(ContentPresentation {
            header: h,
            fact_count: 1,
            disclosures: &[],
        }),
        &[],
        &p,
    );
    assert_eq!(r.presentation_state, PresentationState::Unsupported);
    assert_eq!(r.membership.status, Status::Unsupported);
    assert_eq!(r.disclosure_policy.status, Status::Unestablished);
}

#[test]
fn same_content_can_be_bound_in_two_signed_contexts_without_proving_freshness() {
    let record = canonical(&model("Alpha"));
    let b = prepare_content(
        &header(),
        &[SaltedFact {
            record: &record,
            salt: [1; 32],
        }],
    )
    .unwrap();
    let disclosures = [b.disclose("unit.model").unwrap()];
    let mut reports = Vec::new();
    for site in ["site:one", "site:two"] {
        let mut v: Value =
            serde_json::from_str(&pask_wire::canonical_example_06().unwrap()).unwrap();
        v["spec"] = json!("wilder.pser/0.7");
        v["site"]["id"] = json!(site);
        v["engagement"]["contentDigest"] = json!(b.root_digest());
        let payload = Payload::from_json_for_production(&serde_json::to_vec(&v).unwrap()).unwrap();
        let statement = produce_ed25519(&payload, payload.witness_key(), &key()).unwrap();
        reports.push(inspect_proposed_recipient_ed25519(
            &statement,
            &key().verifying_key(),
            Some(ContentPresentation {
                header: header(),
                fact_count: 1,
                disclosures: &disclosures,
            }),
            &[],
            &policy(),
        ));
    }
    assert_eq!(reports[0].content_digest, reports[1].content_digest);
    assert_ne!(reports[0].site_id, reports[1].site_id);
    for report in reports {
        assert_eq!(report.content_binding.status, Status::Passed);
        assert_eq!(report.context_comparison.status, Status::NotEvaluated);
        assert_eq!(report.real_world_clock.status, Status::Unestablished);
    }
}

#[test]
fn fixed_python_membership_and_explicit_report_expectations() {
    let table: Value = serde_json::from_str(include_str!(
        "fixtures/proposed07/recipient-composition-v1.json"
    ))
    .unwrap();
    assert_eq!(table["cases"].as_array().unwrap().len(), 17);
    for case in table["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let material = &case["material"];
        let rows = material["facts"].as_array().unwrap();
        let records: Vec<Vec<u8>> = rows
            .iter()
            .map(|f| hex::decode(f["canonical_hex"].as_str().unwrap()).unwrap())
            .collect();
        let disclosures: Vec<_> = rows
            .iter()
            .zip(&records)
            .map(|(f, bytes)| DisclosedFact {
                record: bytes,
                salt: hex::decode(f["salt_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                index: f["index"].as_u64().unwrap() as u32,
                siblings: f["proof_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        hex::decode(p.as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap()
                    })
                    .collect(),
            })
            .collect();
        let object_rows = case["objects"].as_array().unwrap();
        let bytes: Vec<Vec<u8>> = object_rows
            .iter()
            .map(|o| hex::decode(o["bytes_hex"].as_str().unwrap()).unwrap())
            .collect();
        let objects: Vec<_> = object_rows
            .iter()
            .zip(&bytes)
            .map(|(o, b)| LocalEvidenceObject {
                digest: o["digest"].as_str().unwrap(),
                availability: match o["state"].as_str().unwrap() {
                    "bytes" => PresentedEvidence::Bytes(b),
                    "not_requested" => PresentedEvidence::NotRequested,
                    "unavailable" => PresentedEvidence::Unavailable,
                    other => panic!("unsupported fixture state {other}"),
                },
            })
            .collect();
        let r = inspect_proposed_recipient_ed25519(
            &signed(material["root_digest"].as_str(), "wilder.pser/0.7"),
            &key().verifying_key(),
            Some(ContentPresentation {
                header: header(),
                fact_count: material["count"].as_u64().unwrap() as u32,
                disclosures: &disclosures,
            }),
            &objects,
            &policy(),
        );
        assert_eq!(r.facts.len(), 1, "{id}");
        let projection = json!({
            "state":r.presentation_state,
            "statement":r.statement_check.status,
            "membership":r.membership.status,
            "binding":r.content_binding.status,
            "vocabulary":r.vocabulary.status,
            "provenance":r.facts[0].provenance,
            "integrity":r.facts[0].evidence.integrity,
            "comparison":r.facts[0].evidence.comparison,
            "invalid_metadata":r.summary.invalid_or_unsupported_metadata,
            "forbidden":r.summary.attribution_forbidden,
            "contradictions":r.summary.value_contradictions,
        });
        assert_eq!(projection, case["expected"], "{id}");
    }
}

#[test]
fn unknown_profile_content_type_is_not_a_failed_signature_or_an_absent_fact() {
    let statement = alter(&signed(None, "wilder.pser/0.7"), |items| {
        let Cbor::Bytes(bytes) = &items[0] else {
            panic!()
        };
        let mut protected: Cbor = coset::cbor::de::from_reader(bytes.as_slice()).unwrap();
        let Cbor::Map(map) = &mut protected else {
            panic!()
        };
        for (k, v) in map {
            if *k == Cbor::Integer(3.into()) {
                *v = Cbor::Text("application/pser+json; profile=wilder.pser/0.999".into());
            }
        }
        items[0] = Cbor::Bytes(encoding(&protected));
    });
    let p = RecipientPolicy {
        required_fact_names: &["unit.model"],
        ..policy()
    };
    let r = inspect_proposed_recipient_ed25519(&statement, &key().verifying_key(), None, &[], &p);
    assert_eq!(r.profile_support.status, Status::Unsupported);
    assert_eq!(r.statement_check.status, Status::NotEvaluated);
    assert_eq!(
        r.requested_facts[0].availability,
        RequestedAvailability::NotEvaluated
    );
    assert_eq!(r.requested_facts[0].provenance, None);
}
