// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.
#![cfg(feature = "alloc")]
use pask_wire::{InspectionPolicy, InspectionStatus as S, Receipt, inspect_scitt_receipt};

fn exercise(id: &str, bytes: &[u8], expected_default: &str, expected_strict: &str) {
    for strict in [false, true] {
        let policy = InspectionPolicy {
            strict_cross_map: strict,
            ..Default::default()
        };
        let r = inspect_scitt_receipt(bytes, &policy);
        let expected = if strict {
            expected_strict
        } else {
            expected_default
        };
        if let Some(dir) = std::env::var_os("PASK71_RESULTS_DIR") {
            let dir = std::path::PathBuf::from(dir);
            std::fs::create_dir_all(&dir).unwrap();
            let record = serde_json::json!({
                "case": id, "strict_cross_map": strict, "input_bytes": bytes.len(),
                "structure": r.structure, "required_claims": r.required_claims,
                "support": r.support, "selected_policy": r.selected_policy,
                "policy": r.policy, "policy_id": r.policy_id,
                "ts_signature": r.ts_signature, "inclusion": r.inclusion,
                "ts_identity_trust": r.ts_identity_trust,
                "subject_policy": r.subject_policy, "application_policy": r.application_policy,
                "cbor_items_inspected": r.cbor_items_inspected,
                "unauthenticated_claims": r.unauthenticated_claims
            });
            std::fs::write(
                dir.join(format!(
                    "{id}-{}.json",
                    if strict { "strict" } else { "default" }
                )),
                serde_json::to_vec_pretty(&record).unwrap(),
            )
            .unwrap();
        }

        assert_eq!(r.encoded_receipt, bytes);
        assert_eq!(r.policy, policy);
        for f in [
            &r.ts_signature,
            &r.inclusion,
            &r.ts_identity_trust,
            &r.subject_policy,
            &r.application_policy,
        ] {
            assert_eq!(f.status, S::NotEvaluated, "{id} / {strict}");
        }
        if expected.starts_with("structure_and_required_claims:passed") {
            assert_eq!(r.structure.status, S::Passed, "{id}: {:?}", r.structure);
            assert_eq!(
                r.required_claims.status,
                S::Passed,
                "{id}: {:?}",
                r.required_claims
            );
            assert_eq!(r.support.status, S::Passed, "{id}: {:?}", r.support);
            assert_eq!(
                r.selected_policy.status,
                S::Passed,
                "{id}: {:?}",
                r.selected_policy
            );
            assert!(!r.unauthenticated_claims.as_ref().unwrap().authenticated);
        } else if expected.starts_with("selected_policy:passed:effective_unknown") {
            assert_eq!(r.structure.status, S::Passed);
            assert_eq!(r.required_claims.status, S::Passed);
            assert_eq!(r.support.status, S::Passed);
            assert_eq!(r.selected_policy.status, S::Passed);
            let key = coset::cbor::Value::Integer(1000.into());
            assert_eq!(
                r.effective_headers
                    .iter()
                    .find(|(k, _)| k == &key)
                    .unwrap()
                    .1,
                coset::cbor::Value::Integer(7.into())
            );
        } else {
            let parts: Vec<_> = expected.split(':').collect();
            let f = match parts[0] {
                "structure" => &r.structure,
                "required_claims" => &r.required_claims,
                "support" => &r.support,
                "selected_policy" => &r.selected_policy,
                _ => panic!("bad expectation"),
            };
            assert_eq!(
                f.status,
                if parts[1] == "failed" {
                    S::Failed
                } else {
                    S::Unsupported
                },
                "{id}/{strict}: {r:?}"
            );
            assert_eq!(f.code, parts[2], "{id}/{strict}: {r:?}");
            if parts[0] == "structure" {
                assert_eq!(r.required_claims.status, S::NotEvaluated);
                assert_eq!(r.support.status, S::NotEvaluated);
            }
        }
    }
}
#[test]
fn text_claims_detached() {
    exercise(
        "text_claims_detached",
        include_bytes!("fixtures/phase1/text_claims_detached.cbor"),
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
    );
}
#[test]
fn text_claims_attached() {
    exercise(
        "text_claims_attached",
        include_bytes!("fixtures/phase1/text_claims_attached.cbor"),
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
    );
}
#[test]
fn duplicate_396_valid_first() {
    exercise(
        "duplicate_396_valid_first",
        include_bytes!("fixtures/phase1/duplicate_396_valid_first.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_396_valid_last() {
    exercise(
        "duplicate_396_valid_last",
        include_bytes!("fixtures/phase1/duplicate_396_valid_last.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_396_equivalent_encoding() {
    exercise(
        "duplicate_396_equivalent_encoding",
        include_bytes!("fixtures/phase1/duplicate_396_equivalent_encoding.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_protected_alg() {
    exercise(
        "duplicate_protected_alg",
        include_bytes!("fixtures/phase1/duplicate_protected_alg.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_protected_unknown() {
    exercise(
        "duplicate_protected_unknown",
        include_bytes!("fixtures/phase1/duplicate_protected_unknown.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_unprotected_unknown() {
    exercise(
        "duplicate_unprotected_unknown",
        include_bytes!("fixtures/phase1/duplicate_unprotected_unknown.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_claim_iss() {
    exercise(
        "duplicate_claim_iss",
        include_bytes!("fixtures/phase1/duplicate_claim_iss.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_claim_equivalent_encoding() {
    exercise(
        "duplicate_claim_equivalent_encoding",
        include_bytes!("fixtures/phase1/duplicate_claim_equivalent_encoding.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_claim_unknown() {
    exercise(
        "duplicate_claim_unknown",
        include_bytes!("fixtures/phase1/duplicate_claim_unknown.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_vdp_inclusion() {
    exercise(
        "duplicate_vdp_inclusion",
        include_bytes!("fixtures/phase1/duplicate_vdp_inclusion.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn duplicate_vdp_unknown() {
    exercise(
        "duplicate_vdp_unknown",
        include_bytes!("fixtures/phase1/duplicate_vdp_unknown.cbor"),
        "structure:failed:duplicate_key",
        "structure:failed:duplicate_key",
    );
}
#[test]
fn signed_protected_trailing_cbor() {
    exercise(
        "signed_protected_trailing_cbor",
        include_bytes!("fixtures/phase1/signed_protected_trailing_cbor.cbor"),
        "structure:failed:protected_trailing_data",
        "structure:failed:protected_trailing_data",
    );
}
#[test]
fn outer_trailing_cbor() {
    exercise(
        "outer_trailing_cbor",
        include_bytes!("fixtures/phase1/outer_trailing_cbor.cbor"),
        "structure:failed:outer_trailing_data",
        "structure:failed:outer_trailing_data",
    );
}
#[test]
fn proof_trailing_cbor() {
    exercise(
        "proof_trailing_cbor",
        include_bytes!("fixtures/phase1/proof_trailing_cbor.cbor"),
        "structure:failed:proof_trailing_data",
        "structure:failed:proof_trailing_data",
    );
}
#[test]
fn untagged_receipt() {
    exercise(
        "untagged_receipt",
        include_bytes!("fixtures/phase1/untagged_receipt.cbor"),
        "structure:failed:missing_receipt_tag",
        "structure:failed:missing_receipt_tag",
    );
}
#[test]
fn wrong_receipt_tag() {
    exercise(
        "wrong_receipt_tag",
        include_bytes!("fixtures/phase1/wrong_receipt_tag.cbor"),
        "structure:failed:wrong_receipt_tag",
        "structure:failed:wrong_receipt_tag",
    );
}
#[test]
fn protected_is_not_map() {
    exercise(
        "protected_is_not_map",
        include_bytes!("fixtures/phase1/protected_is_not_map.cbor"),
        "structure:failed:protected_not_map",
        "structure:failed:protected_not_map",
    );
}
#[test]
fn protected_empty_bstr() {
    exercise(
        "protected_empty_bstr",
        include_bytes!("fixtures/phase1/protected_empty_bstr.cbor"),
        "structure:failed:protected_not_map",
        "structure:failed:protected_not_map",
    );
}
#[test]
fn payload_text() {
    exercise(
        "payload_text",
        include_bytes!("fixtures/phase1/payload_text.cbor"),
        "structure:failed:payload_type",
        "structure:failed:payload_type",
    );
}
#[test]
fn signature_text() {
    exercise(
        "signature_text",
        include_bytes!("fixtures/phase1/signature_text.cbor"),
        "structure:failed:signature_type",
        "structure:failed:signature_type",
    );
}
#[test]
fn wrong_element_count() {
    exercise(
        "wrong_element_count",
        include_bytes!("fixtures/phase1/wrong_element_count.cbor"),
        "structure:failed:element_count",
        "structure:failed:element_count",
    );
}
#[test]
fn unprotected_not_map() {
    exercise(
        "unprotected_not_map",
        include_bytes!("fixtures/phase1/unprotected_not_map.cbor"),
        "structure:failed:unprotected_type",
        "structure:failed:unprotected_type",
    );
}
#[test]
fn protected_not_bstr() {
    exercise(
        "protected_not_bstr",
        include_bytes!("fixtures/phase1/protected_not_bstr.cbor"),
        "structure:failed:protected_type",
        "structure:failed:protected_type",
    );
}
#[test]
fn crossmap_unknown_equal() {
    exercise(
        "crossmap_unknown_equal",
        include_bytes!("fixtures/phase1/crossmap_unknown_equal.cbor"),
        "selected_policy:passed:effective_unknown_1000=7",
        "selected_policy:failed:cross_map_overlap",
    );
}
#[test]
fn crossmap_unknown_conflicting() {
    exercise(
        "crossmap_unknown_conflicting",
        include_bytes!("fixtures/phase1/crossmap_unknown_conflicting.cbor"),
        "selected_policy:passed:effective_unknown_1000=7",
        "selected_policy:failed:cross_map_overlap",
    );
}
#[test]
fn label15_crossmap_equal() {
    exercise(
        "label15_crossmap_equal",
        include_bytes!("fixtures/phase1/label15_crossmap_equal.cbor"),
        "structure:failed:label15_single_occurrence",
        "structure:failed:label15_single_occurrence",
    );
}
#[test]
fn label15_crossmap_conflicting() {
    exercise(
        "label15_crossmap_conflicting",
        include_bytes!("fixtures/phase1/label15_crossmap_conflicting.cbor"),
        "structure:failed:label15_single_occurrence",
        "structure:failed:label15_single_occurrence",
    );
}
#[test]
fn claims_iss_integer() {
    exercise(
        "claims_iss_integer",
        include_bytes!("fixtures/phase1/claims_iss_integer.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_iss_bytes() {
    exercise(
        "claims_iss_bytes",
        include_bytes!("fixtures/phase1/claims_iss_bytes.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_iss_tagged_text() {
    exercise(
        "claims_iss_tagged_text",
        include_bytes!("fixtures/phase1/claims_iss_tagged_text.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_iss_null() {
    exercise(
        "claims_iss_null",
        include_bytes!("fixtures/phase1/claims_iss_null.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_missing_iss() {
    exercise(
        "claims_missing_iss",
        include_bytes!("fixtures/phase1/claims_missing_iss.cbor"),
        "required_claims:failed:missing_claim",
        "required_claims:failed:missing_claim",
    );
}
#[test]
fn claims_sub_integer() {
    exercise(
        "claims_sub_integer",
        include_bytes!("fixtures/phase1/claims_sub_integer.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_sub_bytes() {
    exercise(
        "claims_sub_bytes",
        include_bytes!("fixtures/phase1/claims_sub_bytes.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_sub_tagged_text() {
    exercise(
        "claims_sub_tagged_text",
        include_bytes!("fixtures/phase1/claims_sub_tagged_text.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_sub_null() {
    exercise(
        "claims_sub_null",
        include_bytes!("fixtures/phase1/claims_sub_null.cbor"),
        "required_claims:failed:claim_value_type",
        "required_claims:failed:claim_value_type",
    );
}
#[test]
fn claims_missing_sub() {
    exercise(
        "claims_missing_sub",
        include_bytes!("fixtures/phase1/claims_missing_sub.cbor"),
        "required_claims:failed:missing_claim",
        "required_claims:failed:missing_claim",
    );
}
#[test]
fn claims_text_keys() {
    exercise(
        "claims_text_keys",
        include_bytes!("fixtures/phase1/claims_text_keys.cbor"),
        "required_claims:failed:missing_integer_claims",
        "required_claims:failed:missing_integer_claims",
    );
}
#[test]
fn claims_missing_map() {
    exercise(
        "claims_missing_map",
        include_bytes!("fixtures/phase1/claims_missing_map.cbor"),
        "required_claims:failed:missing_claims",
        "required_claims:failed:missing_claims",
    );
}
#[test]
fn claims_unprotected_only() {
    exercise(
        "claims_unprotected_only",
        include_bytes!("fixtures/phase1/claims_unprotected_only.cbor"),
        "required_claims:failed:claims_location",
        "required_claims:failed:claims_location",
    );
}
#[test]
fn claims_not_map() {
    exercise(
        "claims_not_map",
        include_bytes!("fixtures/phase1/claims_not_map.cbor"),
        "required_claims:failed:claims_map_type",
        "required_claims:failed:claims_map_type",
    );
}
#[test]
fn claims_invalid_uri() {
    exercise(
        "claims_invalid_uri",
        include_bytes!("fixtures/phase1/claims_invalid_uri.cbor"),
        "required_claims:failed:uri_syntax",
        "required_claims:failed:uri_syntax",
    );
}
#[test]
fn claims_case_distinct() {
    exercise(
        "claims_case_distinct",
        include_bytes!("fixtures/phase1/claims_case_distinct.cbor"),
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
    );
}
#[test]
fn alg_unprotected_only() {
    exercise(
        "alg_unprotected_only",
        include_bytes!("fixtures/phase1/alg_unprotected_only.cbor"),
        "required_claims:failed:required_header_location",
        "required_claims:failed:required_header_location",
    );
}
#[test]
fn alg_text_value() {
    exercise(
        "alg_text_value",
        include_bytes!("fixtures/phase1/alg_text_value.cbor"),
        "required_claims:failed:required_header_type",
        "required_claims:failed:required_header_type",
    );
}
#[test]
fn vds_unprotected_only() {
    exercise(
        "vds_unprotected_only",
        include_bytes!("fixtures/phase1/vds_unprotected_only.cbor"),
        "required_claims:failed:required_header_location",
        "required_claims:failed:required_header_location",
    );
}
#[test]
fn vds_text_value() {
    exercise(
        "vds_text_value",
        include_bytes!("fixtures/phase1/vds_text_value.cbor"),
        "required_claims:failed:required_header_type",
        "required_claims:failed:required_header_type",
    );
}
#[test]
fn kid_missing() {
    exercise(
        "kid_missing",
        include_bytes!("fixtures/phase1/kid_missing.cbor"),
        "required_claims:failed:missing_key_identifier",
        "required_claims:failed:missing_key_identifier",
    );
}
#[test]
fn kid_unprotected_only() {
    exercise(
        "kid_unprotected_only",
        include_bytes!("fixtures/phase1/kid_unprotected_only.cbor"),
        "selected_policy:failed:protected_kid_required",
        "selected_policy:failed:protected_kid_required",
    );
}
#[test]
fn kid_text() {
    exercise(
        "kid_text",
        include_bytes!("fixtures/phase1/kid_text.cbor"),
        "required_claims:failed:kid_type",
        "required_claims:failed:kid_type",
    );
}
#[test]
fn x5t_shape_valid() {
    exercise(
        "x5t_shape_valid",
        include_bytes!("fixtures/phase1/x5t_shape_valid.cbor"),
        "support:unsupported:x509_not_implemented",
        "support:unsupported:x509_not_implemented",
    );
}
#[test]
fn x5chain_single_shape_valid() {
    exercise(
        "x5chain_single_shape_valid",
        include_bytes!("fixtures/phase1/x5chain_single_shape_valid.cbor"),
        "support:unsupported:x509_not_implemented",
        "support:unsupported:x509_not_implemented",
    );
}
#[test]
fn x5chain_multi_shape_valid() {
    exercise(
        "x5chain_multi_shape_valid",
        include_bytes!("fixtures/phase1/x5chain_multi_shape_valid.cbor"),
        "support:unsupported:x509_not_implemented",
        "support:unsupported:x509_not_implemented",
    );
}
#[test]
fn x5t_shape_malformed() {
    exercise(
        "x5t_shape_malformed",
        include_bytes!("fixtures/phase1/x5t_shape_malformed.cbor"),
        "required_claims:failed:x5t_shape",
        "required_claims:failed:x5t_shape",
    );
}
#[test]
fn x5chain_one_element_array() {
    exercise(
        "x5chain_one_element_array",
        include_bytes!("fixtures/phase1/x5chain_one_element_array.cbor"),
        "required_claims:failed:x5chain_shape",
        "required_claims:failed:x5chain_shape",
    );
}
#[test]
fn x509_issuer_not_uri() {
    exercise(
        "x509_issuer_not_uri",
        include_bytes!("fixtures/phase1/x509_issuer_not_uri.cbor"),
        "required_claims:failed:x509_issuer_uri",
        "required_claims:failed:x509_issuer_uri",
    );
}
#[test]
fn x509_issuer_too_long() {
    exercise(
        "x509_issuer_too_long",
        include_bytes!("fixtures/phase1/x509_issuer_too_long.cbor"),
        "required_claims:failed:issuer_length",
        "required_claims:failed:issuer_length",
    );
}
#[test]
fn crit_understood() {
    exercise(
        "crit_understood",
        include_bytes!("fixtures/phase1/crit_understood.cbor"),
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
    );
}
#[test]
fn crit_empty() {
    exercise(
        "crit_empty",
        include_bytes!("fixtures/phase1/crit_empty.cbor"),
        "structure:failed:crit_empty",
        "structure:failed:crit_empty",
    );
}
#[test]
fn crit_not_array() {
    exercise(
        "crit_not_array",
        include_bytes!("fixtures/phase1/crit_not_array.cbor"),
        "structure:failed:crit_type",
        "structure:failed:crit_type",
    );
}
#[test]
fn crit_missing_header() {
    exercise(
        "crit_missing_header",
        include_bytes!("fixtures/phase1/crit_missing_header.cbor"),
        "structure:failed:crit_reference_absent",
        "structure:failed:crit_reference_absent",
    );
}
#[test]
fn crit_unknown_semantics() {
    exercise(
        "crit_unknown_semantics",
        include_bytes!("fixtures/phase1/crit_unknown_semantics.cbor"),
        "support:unsupported:critical_semantics",
        "support:unsupported:critical_semantics",
    );
}
#[test]
fn crit_unprotected() {
    exercise(
        "crit_unprotected",
        include_bytes!("fixtures/phase1/crit_unprotected.cbor"),
        "structure:failed:crit_location",
        "structure:failed:crit_location",
    );
}
#[test]
fn vds_reserved_zero() {
    exercise(
        "vds_reserved_zero",
        include_bytes!("fixtures/phase1/vds_reserved_zero.cbor"),
        "support:failed:reserved_vds",
        "support:failed:reserved_vds",
    );
}
#[test]
fn vds_unknown() {
    exercise(
        "vds_unknown",
        include_bytes!("fixtures/phase1/vds_unknown.cbor"),
        "support:unsupported:unknown_vds_registry_review",
        "support:unsupported:unknown_vds_registry_review",
    );
}
#[test]
fn ccf_vds2_opaque_profile() {
    exercise(
        "ccf_vds2_opaque_profile",
        include_bytes!("fixtures/phase1/ccf_vds2_opaque_profile.cbor"),
        "support:unsupported:ccf_profile_not_implemented",
        "support:unsupported:ccf_profile_not_implemented",
    );
}
#[test]
fn ts_es256_not_supported() {
    exercise(
        "ts_es256_not_supported",
        include_bytes!("fixtures/phase1/ts_es256_not_supported.cbor"),
        "support:unsupported:ts_algorithm",
        "support:unsupported:ts_algorithm",
    );
}
#[test]
fn proof_empty_array() {
    exercise(
        "proof_empty_array",
        include_bytes!("fixtures/phase1/proof_empty_array.cbor"),
        "structure:failed:empty_inclusion_array",
        "structure:failed:empty_inclusion_array",
    );
}
#[test]
fn proof_not_bstr() {
    exercise(
        "proof_not_bstr",
        include_bytes!("fixtures/phase1/proof_not_bstr.cbor"),
        "structure:failed:proof_not_bstr",
        "structure:failed:proof_not_bstr",
    );
}
#[test]
fn proof_empty_path() {
    exercise(
        "proof_empty_path",
        include_bytes!("fixtures/phase1/proof_empty_path.cbor"),
        "structure:failed:empty_path",
        "structure:failed:empty_path",
    );
}
#[test]
fn proof_short_node() {
    exercise(
        "proof_short_node",
        include_bytes!("fixtures/phase1/proof_short_node.cbor"),
        "structure:failed:path_node_length",
        "structure:failed:path_node_length",
    );
}
#[test]
fn proof_leaf_outside_tree() {
    exercise(
        "proof_leaf_outside_tree",
        include_bytes!("fixtures/phase1/proof_leaf_outside_tree.cbor"),
        "structure:failed:leaf_bounds",
        "structure:failed:leaf_bounds",
    );
}
#[test]
fn proof_zero_tree() {
    exercise(
        "proof_zero_tree",
        include_bytes!("fixtures/phase1/proof_zero_tree.cbor"),
        "structure:failed:tree_bounds",
        "structure:failed:tree_bounds",
    );
}
#[test]
fn proof_negative_index() {
    exercise(
        "proof_negative_index",
        include_bytes!("fixtures/phase1/proof_negative_index.cbor"),
        "structure:failed:leaf_type",
        "structure:failed:leaf_type",
    );
}
#[test]
fn vdp_protected_only() {
    exercise(
        "vdp_protected_only",
        include_bytes!("fixtures/phase1/vdp_protected_only.cbor"),
        "structure:failed:vdp_location",
        "structure:failed:vdp_location",
    );
}
#[test]
fn vdp_not_map() {
    exercise(
        "vdp_not_map",
        include_bytes!("fixtures/phase1/vdp_not_map.cbor"),
        "structure:failed:vdp_map_type",
        "structure:failed:vdp_map_type",
    );
}
#[test]
fn proofs_unknown_label() {
    exercise(
        "proofs_unknown_label",
        include_bytes!("fixtures/phase1/proofs_unknown_label.cbor"),
        "support:unsupported:proof_type_registry_review",
        "support:unsupported:proof_type_registry_review",
    );
}
#[test]
fn limit_proofs_at_16() {
    exercise(
        "limit_proofs_at_16",
        include_bytes!("fixtures/phase1/limit_proofs_at_16.cbor"),
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
        "structure_and_required_claims:passed; crypto_and_trust:not-evaluated",
    );
}
#[test]
fn limit_proofs_over_17() {
    exercise(
        "limit_proofs_over_17",
        include_bytes!("fixtures/phase1/limit_proofs_over_17.cbor"),
        "selected_policy:failed:proof_limit",
        "selected_policy:failed:proof_limit",
    );
}
#[test]
fn limit_path_nodes_over_65() {
    exercise(
        "limit_path_nodes_over_65",
        include_bytes!("fixtures/phase1/limit_path_nodes_over_65.cbor"),
        "selected_policy:failed:path_limit",
        "selected_policy:failed:path_limit",
    );
}
#[test]
fn limit_receipt_bytes_over() {
    exercise(
        "limit_receipt_bytes_over",
        include_bytes!("fixtures/phase1/limit_receipt_bytes_over.cbor"),
        "selected_policy:failed:receipt_byte_limit",
        "selected_policy:failed:receipt_byte_limit",
    );
}

#[test]
fn generic_duplicate_and_trailing_repairs_before_lookup() {
    let names = [
        "duplicate_396_valid_first",
        "duplicate_396_valid_last",
        "duplicate_396_equivalent_encoding",
        "duplicate_protected_alg",
        "duplicate_protected_unknown",
        "duplicate_unprotected_unknown",
        "duplicate_claim_iss",
        "duplicate_claim_unknown",
        "duplicate_claim_equivalent_encoding",
        "duplicate_vdp_inclusion",
        "duplicate_vdp_unknown",
    ];
    for name in names {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/phase1/{name}.cbor",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let error = Receipt::from_cose_sign1(&bytes).unwrap_err();
        assert!(
            format!("{error:?}").contains("duplicate_key"),
            "{name}: {error:?}"
        );
    }
    let bytes = include_bytes!("fixtures/phase1/signed_protected_trailing_cbor.cbor");
    assert!(
        format!("{:?}", Receipt::from_cose_sign1(bytes).unwrap_err())
            .contains("trailing bytes in receipt protected header")
    );
    // Generic compatibility and old crypto role are retained, not made SCITT claim validators.
    assert!(
        Receipt::from_cose_sign1(include_bytes!("fixtures/phase1/text_claims_detached.cbor"))
            .is_ok()
    );
    assert!(
        Receipt::from_cose_sign1(include_bytes!("fixtures/phase1/untagged_receipt.cbor")).is_ok()
    );
    assert!(
        Receipt::from_cose_sign1(include_bytes!("fixtures/phase1/claims_missing_map.cbor")).is_ok()
    );
}
