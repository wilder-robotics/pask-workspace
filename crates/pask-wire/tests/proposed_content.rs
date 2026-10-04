// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "alloc")]
use ed25519_dalek::SigningKey;
use pask_wire::proposed_content::*;
use pask_wire::{Payload, canonicalize_json, produce_ed25519, verify_ed25519};
use serde_json::{Value, json};

const VOCAB: &str = "sha256:030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d";
fn header() -> ContentHeader<'static> {
    ContentHeader {
        construction: CONSTRUCTION,
        scope: SCOPE,
        vocabulary_digest: VOCAB,
    }
}
fn canonical(v: &Value) -> Vec<u8> {
    canonicalize_json(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn record(name: &str, value: Value) -> Vec<u8> {
    canonical(&json!({"name":name,"assertedBy":"site-policy","basis":"declared","value":value}))
}
fn records(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| record(&format!("sample.fact-{i:03}"), json!(i)))
        .collect()
}
fn facts(records: &[Vec<u8>]) -> Vec<SaltedFact<'_>> {
    records
        .iter()
        .enumerate()
        .map(|(i, r)| SaltedFact {
            record: r,
            salt: [(i + 1) as u8; 32],
        })
        .collect()
}
fn decoded_hash(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn verified(
    root: &str,
    count: u32,
    disclosures: &[DisclosedFact<'_>],
) -> Result<DisclosureReport, ContentError> {
    verify_content_disclosures(root, &header(), count, disclosures)
}

#[test]
fn fixed_independent_roots_leaves_and_paths() {
    let table: Value =
        serde_json::from_str(include_str!("fixtures/proposed07/content-tree-v1.json")).unwrap();
    for group in table["groups"].as_array().unwrap() {
        let rows = group["facts"].as_array().unwrap();
        let bodies: Vec<Vec<u8>> = rows
            .iter()
            .map(|r| hex::decode(r["canonical_hex"].as_str().unwrap()).unwrap())
            .collect();
        let input: Vec<SaltedFact<'_>> = rows
            .iter()
            .zip(&bodies)
            .map(|(r, b)| SaltedFact {
                record: b,
                salt: decoded_hash(r["salt_hex"].as_str().unwrap()),
            })
            .collect();
        let block = prepare_content(&header(), &input).unwrap();
        assert_eq!(block.root_digest(), group["root_digest"].as_str().unwrap());
        assert_eq!(
            u64::from(block.fact_count()),
            group["count"].as_u64().unwrap()
        );
        let mut all = Vec::new();
        for row in rows {
            let name = row["fact"]["name"].as_str().unwrap();
            let d = block.disclose(name).unwrap();
            assert_eq!(d.index as u64, row["index"].as_u64().unwrap());
            let expected: Vec<[u8; 32]> = row["proof_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| decoded_hash(x.as_str().unwrap()))
                .collect();
            assert_eq!(d.siblings, expected);
            let one = verified(
                &block.root_digest(),
                block.fact_count(),
                std::slice::from_ref(&d),
            )
            .unwrap();
            assert_eq!(one.membership, "MATCHED");
            all.push(d);
        }
        let full = verified(&block.root_digest(), block.fact_count(), &all).unwrap();
        assert_eq!(full.disclosure, "ALL_COMMITTED_SLOTS");
        assert!(!full.semantic_absence_established);
    }
}

#[test]
fn all_tree_shapes_through_sixty_five() {
    for n in 1..=65 {
        let r = records(n);
        let b = prepare_content(&header(), &facts(&r)).unwrap();
        for i in 0..n {
            let d = b.disclose(&format!("sample.fact-{i:03}")).unwrap();
            assert!(verified(&b.root_digest(), n as u32, &[d]).is_ok());
        }
    }
}

#[test]
fn maximum_count_and_paths() {
    let r = records(MAX_FACTS);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    for i in [0, 127, 128, 255] {
        let d = b.disclose(&format!("sample.fact-{i:03}")).unwrap();
        assert_eq!(d.siblings.len(), 8);
        assert!(verified(&b.root_digest(), 256, &[d]).is_ok());
    }
}

#[test]
fn input_order_is_not_commitment_order() {
    let r = records(5);
    let mut f = facts(&r);
    let root = prepare_content(&header(), &f).unwrap().root();
    f.reverse();
    assert_eq!(prepare_content(&header(), &f).unwrap().root(), root);
}

#[test]
fn selected_disclosure_keeps_trust_and_absence_unestablished() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let d = b.disclose("sample.fact-001").unwrap();
    let result = verified(&b.root_digest(), 3, &[d]).unwrap();
    assert_eq!(result.disclosure, "SELECTED_SLOTS_ONLY");
    assert_eq!(result.receipt_binding, "NOT_EVALUATED");
    assert_eq!(result.fact_constraints, "NOT_EVALUATED");
    assert_eq!(result.root_origin, "CALLER_SUPPLIED_UNAUTHENTICATED");
    assert!(!result.attributed_party_authenticated);
    assert!(!result.latest_or_complete_history_established);
    assert!(!result.semantic_absence_established);
}

#[test]
fn missing_nonempty_presentation_does_not_authenticate_count() {
    let result = verified(&format!("sha256:{}", "a".repeat(64)), 17, &[]).unwrap();
    assert_eq!(result.membership, "NOT_PRESENTED");
    assert!(!result.count_bound_to_supplied_root);
}

#[test]
fn empty_block_requires_exact_header_root() {
    let b = prepare_content(&header(), &[]).unwrap();
    let result = verified(&b.root_digest(), 0, &[]).unwrap();
    assert_eq!(result.membership, "MATCHED");
    assert!(!result.semantic_absence_established);
    assert_eq!(
        verified(&format!("sha256:{}", "0".repeat(64)), 0, &[]).unwrap_err(),
        ContentError::RootMismatch
    );
}

#[test]
fn malformed_root_is_not_absence() {
    for root in ["", "null", "sha256:bad", "SHA256:bad"] {
        assert_eq!(
            verified(root, 3, &[]).unwrap_err(),
            ContentError::InvalidDigest
        );
    }
}

#[test]
fn scope_and_construction_are_not_silent_aliases() {
    let r = records(1);
    let mut h = header();
    h.scope = "LATEST";
    assert_eq!(
        prepare_content(&h, &facts(&r)).err(),
        Some(ContentError::InvalidScope)
    );
    h = header();
    h.construction = "wilder.pser/0.7";
    assert_eq!(
        prepare_content(&h, &facts(&r)).err(),
        Some(ContentError::UnsupportedConstruction)
    );
}

#[test]
fn vocabulary_digest_is_bound() {
    let r = records(1);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let d = b.disclose("sample.fact-000").unwrap();
    let wrong = format!("sha256:{}", "f".repeat(64));
    let mut h = header();
    h.vocabulary_digest = &wrong;
    assert_eq!(
        verify_content_disclosures(&b.root_digest(), &h, 1, &[d]).unwrap_err(),
        ContentError::RootMismatch
    );
}

#[test]
fn count_and_index_are_bound() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let d = b.disclose("sample.fact-000").unwrap();
    assert!(verified(&b.root_digest(), 4, std::slice::from_ref(&d)).is_err());
    let mut wrong = d;
    wrong.index = 1;
    assert!(verified(&b.root_digest(), 3, &[wrong]).is_err());
}

#[test]
fn out_of_range_index_is_explicit() {
    let r = records(1);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut d = b.disclose("sample.fact-000").unwrap();
    d.index = 1;
    assert_eq!(
        verified(&b.root_digest(), 1, &[d]).unwrap_err(),
        ContentError::InvalidIndex
    );
}

#[test]
fn truncated_and_padded_proofs_reject() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut d = b.disclose("sample.fact-000").unwrap();
    d.siblings.pop();
    assert_eq!(
        verified(&b.root_digest(), 3, &[d]).unwrap_err(),
        ContentError::InvalidProofLength
    );
    let mut d = b.disclose("sample.fact-000").unwrap();
    d.siblings.push([0; 32]);
    assert_eq!(
        verified(&b.root_digest(), 3, &[d]).unwrap_err(),
        ContentError::InvalidProofLength
    );
}

#[test]
fn corrupted_sibling_rejects() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut d = b.disclose("sample.fact-000").unwrap();
    d.siblings[0][0] ^= 1;
    assert_eq!(
        verified(&b.root_digest(), 3, &[d]).unwrap_err(),
        ContentError::RootMismatch
    );
}

#[test]
fn proof_hash_limit_is_checked_before_iteration() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut d = b.disclose("sample.fact-000").unwrap();
    d.siblings = vec![[0; 32]; 9];
    assert_eq!(
        verified(&b.root_digest(), 3, &[d]).unwrap_err(),
        ContentError::InvalidProofLength
    );
}

#[test]
fn all_fact_components_are_bound() {
    let original = json!({"name":"unit.model","assertedBy":"site-policy","basis":"declared",
        "value":"old","unit":null,"evidence":{"digest":format!("sha256:{}","a".repeat(64))},"extra":"old"});
    let r = vec![canonical(&original)];
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    for (field, new) in [
        ("name", json!("unit.other")),
        ("assertedBy", json!("operator-entered")),
        ("basis", json!("measured")),
        ("value", json!("new")),
        ("unit", json!("N")),
        ("evidence", json!({"pointer":"local:new"})),
        ("extra", json!("new")),
    ] {
        let mut changed = original.clone();
        changed[field] = new;
        let bytes = canonical(&changed);
        let mut d = b.disclose("unit.model").unwrap();
        d.record = &bytes;
        assert_eq!(
            verified(&b.root_digest(), 1, &[d]).unwrap_err(),
            ContentError::RootMismatch,
            "{field}"
        );
    }
}

#[test]
fn salt_changes_are_detected() {
    let r = records(1);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut d = b.disclose("sample.fact-000").unwrap();
    d.salt[0] ^= 1;
    assert_eq!(
        verified(&b.root_digest(), 1, &[d]).unwrap_err(),
        ContentError::RootMismatch
    );
}

#[test]
fn equal_values_do_not_allow_proof_substitution() {
    let r = vec![record("sample.a", json!(0)), record("sample.b", json!(0))];
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut d = b.disclose("sample.a").unwrap();
    d.record = &r[1];
    assert_eq!(
        verified(&b.root_digest(), 2, &[d]).unwrap_err(),
        ContentError::RootMismatch
    );
}

#[test]
fn duplicate_names_reject_before_tree_creation() {
    let r = vec![
        record("unit.model", json!(1)),
        record("unit.model", json!(2)),
    ];
    assert_eq!(
        prepare_content(&header(), &facts(&r)).err(),
        Some(ContentError::DuplicateFactName)
    );
}

#[test]
fn repeated_salts_reject_in_complete_block() {
    let r = records(2);
    let mut f = facts(&r);
    f[1].salt = f[0].salt;
    assert_eq!(
        prepare_content(&header(), &f).err(),
        Some(ContentError::ReusedSalt)
    );
}

#[test]
fn duplicate_disclosures_do_not_count_as_completeness() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let d = b.disclose("sample.fact-000").unwrap();
    assert_eq!(
        verified(&b.root_digest(), 3, &[d.clone(), d]).unwrap_err(),
        ContentError::DuplicateDisclosure
    );
}

#[test]
fn complete_disclosure_can_arrive_in_reverse_order() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let all: Vec<_> = (0..3)
        .rev()
        .map(|i| b.disclose(&format!("sample.fact-{i:03}")).unwrap())
        .collect();
    assert_eq!(
        verified(&b.root_digest(), 3, &all).unwrap().disclosure,
        "ALL_COMMITTED_SLOTS"
    );
}

#[test]
fn noncanonical_and_duplicate_json_properties_reject() {
    for bytes in [br#"{ "assertedBy":"site-policy","basis":"declared","name":"unit.model","value":0}"#.as_slice(),
                  br#"{"assertedBy":"site-policy","basis":"declared","name":"unit.model","value":0,"value":1}"#] {
        assert_eq!(prepare_content(&header(),&[SaltedFact{record:bytes,salt:[1;32]}]).err(),Some(ContentError::NonCanonicalFact));
    }
}

#[test]
fn malformed_and_trailing_json_reject() {
    for bytes in [b"{".as_slice(), b"[] garbage", b"null null", b"{\"a\":NaN}"] {
        assert_eq!(
            prepare_content(
                &header(),
                &[SaltedFact {
                    record: bytes,
                    salt: [1; 32]
                }]
            )
            .err(),
            Some(ContentError::InvalidFactJson)
        );
    }
}

#[test]
fn canonical_whole_fact_is_required() {
    for v in [
        json!(null),
        json!([]),
        json!({"name":"unit.model","value":0}),
        json!({"name":"UPPER","assertedBy":"site-policy","basis":"declared","value":0}),
    ] {
        let bytes = canonical(&v);
        assert!(
            prepare_content(
                &header(),
                &[SaltedFact {
                    record: &bytes,
                    salt: [1; 32]
                }]
            )
            .is_err()
        );
    }
}

#[test]
fn exact_safe_integer_domain_does_not_round_big_integer() {
    let good = vec![record("unit.model", json!(9_007_199_254_740_991u64))];
    assert!(prepare_content(&header(), &facts(&good)).is_ok());
    let bad = vec![record("unit.model", json!(9_007_199_254_740_992u64))];
    assert_eq!(
        prepare_content(&header(), &facts(&bad)).err(),
        Some(ContentError::UnsupportedNumber)
    );
}

#[test]
fn forbidden_metadata_is_committed_not_laundered_into_permission() {
    let v = json!({"name":"limits.rated-force","assertedBy":"robot-attributed","basis":"measured","value":50});
    let bytes = vec![canonical(&v)];
    let b = prepare_content(&header(), &facts(&bytes)).unwrap();
    let result = verified(
        &b.root_digest(),
        1,
        &[b.disclose("limits.rated-force").unwrap()],
    )
    .unwrap();
    assert_eq!(result.fact_constraints, "NOT_EVALUATED");
    assert_eq!(
        pask_wire::proposed_constraints::classify(
            "limits.rated-force",
            "robot-attributed",
            "measured"
        ),
        pask_wire::proposed_constraints::ConstraintResult::AttributionForbidden
    );
}

#[test]
fn record_size_limit_accepts_boundary_and_rejects_one_extra_byte() {
    let empty = record("unit.model", json!(""));
    let good = record(
        "unit.model",
        json!("x".repeat(MAX_FACT_BYTES - empty.len())),
    );
    assert_eq!(good.len(), MAX_FACT_BYTES);
    assert!(
        prepare_content(
            &header(),
            &[SaltedFact {
                record: &good,
                salt: [1; 32]
            }]
        )
        .is_ok()
    );
    let bad = record(
        "unit.model",
        json!("x".repeat(MAX_FACT_BYTES - empty.len() + 1)),
    );
    assert_eq!(
        prepare_content(
            &header(),
            &[SaltedFact {
                record: &bad,
                salt: [1; 32]
            }]
        )
        .err(),
        Some(ContentError::FactByteLimit)
    );
}

#[test]
fn total_limit_includes_unknown_metadata() {
    let rs: Vec<_> = (0..65)
        .map(|i| {
            let name = format!("sample.fact-{i:03}");
            let size = record(&name, json!("")).len();
            record(&name, json!("x".repeat(MAX_FACT_BYTES - size)))
        })
        .collect();
    assert!(prepare_content(&header(), &facts(&rs[..64])).is_ok());
    assert_eq!(
        prepare_content(&header(), &facts(&rs)).err(),
        Some(ContentError::TotalByteLimit)
    );
}

#[test]
fn too_many_facts_reject_before_processing() {
    let r = records(257);
    assert_eq!(
        prepare_content(&header(), &facts(&r)).err(),
        Some(ContentError::FactCountLimit)
    );
}

#[test]
fn raw_depth_preflight_handles_extra_fields_and_strings() {
    let deep = format!("{{\"value\":{}0{}}}", "[".repeat(16), "]".repeat(16));
    assert_eq!(
        prepare_content(
            &header(),
            &[SaltedFact {
                record: deep.as_bytes(),
                salt: [1; 32]
            }]
        )
        .err(),
        Some(ContentError::JsonDepthLimit)
    );
    let escaped = record("unit.model", json!("[[[ { \\\" ]]]"));
    assert!(
        prepare_content(
            &header(),
            &[SaltedFact {
                record: &escaped,
                salt: [1; 32]
            }]
        )
        .is_ok()
    );
}

#[test]
fn unknown_fact_lookup_does_not_create_an_absence_proof() {
    let r = records(1);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    assert_eq!(
        b.disclose("unit.model").unwrap_err(),
        ContentError::UnknownFactName
    );
}

#[test]
fn preserved_evidence_digest_uses_original_bytes_not_fact_jcs() {
    let raw = b" 0 ";
    let expected = pask_wire::sha256_prefixed(raw);
    assert_ne!(expected, pask_wire::sha256_prefixed(b"0"));
    let r = vec![canonical(
        &json!({"name":"unit.model","assertedBy":"site-policy","basis":"declared",
        "value":0,"evidence":{"digest":expected}}),
    )];
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    assert!(verified(&b.root_digest(), 1, &[b.disclose("unit.model").unwrap()]).is_ok());
}

#[test]
fn test_only_receipt_roundtrip_uses_verified_payload_root() {
    let r = records(3);
    let b = prepare_content(&header(), &facts(&r)).unwrap();
    let mut v: Value = serde_json::from_str(&pask_wire::canonical_example_06().unwrap()).unwrap();
    v["spec"] = json!("wilder.pser/0.7");
    v["engagement"]["contentDigest"] = json!(b.root_digest());
    let p = Payload::from_json_for_production(&serde_json::to_vec(&v).unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[53; 32]);
    let signed = produce_ed25519(&p, p.witness_key(), &key).unwrap();
    let decoded = verify_ed25519(&signed, &key.verifying_key()).unwrap();
    let root = decoded
        .engagement_content_digest()
        .unwrap()
        .as_str()
        .unwrap();
    let disclosure = b.disclose("sample.fact-001").unwrap();
    assert!(verified(root, 3, &[disclosure]).is_ok());
    let wrong_key = SigningKey::from_bytes(&[54; 32]);
    assert!(verify_ed25519(&signed, &wrong_key.verifying_key()).is_err());
    // Software test keys, not authenticated organizations, TEE evidence or SCITT registration.
}
