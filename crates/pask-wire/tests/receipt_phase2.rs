// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.
#![cfg(feature = "alloc")]

use coset::cbor::Value as V;
use ed25519_dalek::{Signer, SigningKey};
use pask_wire::{
    BindingProvenance, InspectionStatus as S, ReceiptVerificationPolicy as Policy, RotationPolicy,
    TrustInputOrigin as Origin, TsKeyAssociation as Association, TsPublicKey as Key,
    TsTrustContext as Trust, attached_receipts, verify_scitt_receipt,
};

const STATEMENT: &[u8] = include_bytes!("fixtures/phase2/statement.cbor");
const CANDIDATE: &[u8] = include_bytes!("fixtures/phase2/candidate.cbor");
const DETACHED: &[u8] = include_bytes!("fixtures/phase2/tree2-leaf0-detached.cbor");
const ATTACHED: &[u8] = include_bytes!("fixtures/phase2/tree2-leaf0-attached.cbor");
const ROTATED: &[u8] = include_bytes!("fixtures/phase2/rotated-detached.cbor");
const SERVICE: [u8; 32] = *include_bytes!("fixtures/phase2/service-key.bin");
const NEXT: [u8; 32] = *include_bytes!("fixtures/phase2/rotated-key.bin");
const ISS: &str = "https://ts.example.test";

fn association(key: [u8; 32]) -> Association<'static> {
    Association {
        service_identity: ISS,
        public_key: Key::Ed25519(key),
        algorithm: -8,
        provenance: BindingProvenance::CallerAuthenticated {
            authority: "LOCAL TEST provisioning authority (SIMULATED)",
            evidence_ref: "fixtures/phase2/manifest.json; NOT authenticated service evidence",
        },
        kid_hint: Some(b"shared-kid"),
        valid_from: Some(100),
        valid_until: Some(200),
        explicitly_distrusted: false,
    }
}
fn trust<'a>(associations: &'a [Association<'a>]) -> Trust<'a> {
    Trust {
        accepted_ts_identities: &[ISS],
        associations,
        evaluation_time: Some(150),
        rotation_policy: Some(RotationPolicy::ValidAtEvaluationTimeV1),
        provisioned_by: Some("local test harness, simulating provisioning"),
        origin: Origin::LocalSimulation,
    }
}
fn encode(v: &V) -> Vec<u8> {
    let mut b = Vec::new();
    coset::cbor::ser::into_writer(v, &mut b).unwrap();
    b
}
fn decode(b: &[u8]) -> V {
    coset::cbor::de::from_reader(b).unwrap()
}
fn parts(b: &[u8]) -> Vec<V> {
    let v = decode(b);
    let v = if let V::Tag(18, v) = v { *v } else { v };
    let V::Array(v) = v else {
        panic!("fixture shape")
    };
    v
}
fn receipt(v: Vec<V>) -> Vec<u8> {
    encode(&V::Tag(18, Box::new(V::Array(v))))
}
fn mutate_receipt(f: impl FnOnce(&mut Vec<V>)) -> Vec<u8> {
    let mut p = parts(DETACHED);
    f(&mut p);
    receipt(p)
}
fn protected(p: &mut [V], f: impl FnOnce(&mut Vec<(V, V)>)) {
    let V::Bytes(b) = &p[0] else { panic!() };
    let V::Map(mut m) = decode(b) else { panic!() };
    f(&mut m);
    p[0] = V::Bytes(encode(&V::Map(m)));
}
fn resign(p: &mut [V]) {
    let V::Bytes(b) = &p[0] else { panic!() };
    let signed = encode(&V::Array(vec![
        V::Text("Signature1".into()),
        V::Bytes(b.clone()),
        V::Bytes(vec![]),
        V::Bytes(include_bytes!("fixtures/phase2/tree2-leaf0-root.bin").to_vec()),
    ]));
    let seed: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
    p[3] = V::Bytes(
        SigningKey::from_bytes(&seed)
            .sign(&signed)
            .to_bytes()
            .to_vec(),
    );
}
fn passed_local(r: &pask_wire::ReceiptVerificationReport<'_>) {
    assert_eq!(r.candidate_derivation.status, S::Passed, "{r:?}");
    assert_eq!(r.ts_signature.status, S::Passed, "{r:?}");
    assert_eq!(r.inclusion.status, S::Passed, "{r:?}");
    assert_eq!(r.ts_key_association.status, S::Passed, "{r:?}");
    assert_eq!(r.ts_identity_trust.status, S::Passed, "{r:?}");
    assert_eq!(
        r.ts_identity_trust.code,
        "local_simulation_conditional_trust_only"
    );
    assert_eq!(r.acceptable_for_registration.status, S::Unestablished);
    assert_eq!(r.subject_policy.status, S::Unestablished);
    assert_eq!(r.application_policy.status, S::Unestablished);
    assert_eq!(r.issuer_signature.status, S::NotEvaluated);
    assert_eq!(r.hardware_appraisal.status, S::NotEvaluated);
    assert!(
        !r.envelope
            .unauthenticated_claims
            .as_ref()
            .unwrap()
            .authenticated
    );
}

#[test]
fn independent_detached_attached_roots_and_signatures() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    for (n, i) in [(2, 0), (5, 0), (5, 2), (5, 4), (8, 7), (9, 8)] {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase2");
        let root = std::fs::read(base.join(format!("tree{n}-leaf{i}-root.bin"))).unwrap();
        for form in ["attached", "detached"] {
            let b = std::fs::read(base.join(format!("tree{n}-leaf{i}-{form}.cbor"))).unwrap();
            let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
            passed_local(&r);
            assert_eq!(r.proofs[0].reconstructed_root.unwrap().as_slice(), root);
            assert_eq!(r.candidate_entry.as_deref(), Some(CANDIDATE));
            assert_eq!(
                r.candidate_keys[r.proofs[0].verifying_key_indices[0]].public_key,
                SERVICE
            );
        }
    }
}

#[test]
fn exact_noncanonical_signed_contents_preserved() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    passed_local(&r);
    assert_eq!(
        r.envelope.protected_bytes.as_deref(),
        Some(include_bytes!("fixtures/phase2/receipt-protected.bin").as_slice())
    );
    let p = parts(STATEMENT);
    let cp = parts(r.candidate_entry.as_ref().unwrap());
    for i in [0, 2, 3] {
        assert_eq!(p[i], cp[i]);
    }
    assert_eq!(cp[1], V::Map(vec![]));
    assert!(core::ptr::eq(r.statement_bytes, STATEMENT));
    let V::Bytes(p) = &p[0] else { panic!() };
    assert_ne!(encode(&decode(p)), *p);
}

#[test]
fn normalizing_receipt_protected_bytes_breaks_signature() {
    let b = mutate_receipt(|p| protected(p, |_| {}));
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.ts_signature.status, S::Failed);
    assert_eq!(r.inclusion.status, S::Unestablished);
}

#[test]
fn candidate_ignores_mutable_statement_unprotected_and_tag() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let mut p = parts(STATEMENT);
    p[1] = V::Map(vec![
        (700.into(), V::Text("different".into())),
        (394.into(), V::Array(vec![])),
    ]);
    for b in [receipt(p.clone()), encode(&V::Array(p))] {
        let r = verify_scitt_receipt(DETACHED, &b, &c, &Policy::default());
        passed_local(&r);
        assert_eq!(r.candidate_entry.as_deref(), Some(CANDIDATE));
    }
}

#[test]
fn changing_any_signed_statement_content_breaks_inclusion_authentication() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    for i in [0, 2, 3] {
        let mut p = parts(STATEMENT);
        let V::Bytes(b) = &mut p[i] else { panic!() };
        b[0] ^= 1;
        let b = receipt(p);
        let r = verify_scitt_receipt(DETACHED, &b, &c, &Policy::default());
        assert_eq!(r.ts_signature.status, S::Failed);
        assert_ne!(r.inclusion.status, S::Passed);
        assert_ne!(r.ts_identity_trust.status, S::Passed);
    }
}

#[test]
fn attached_wrong_root_is_not_reported_as_signature_failure() {
    let mut p = parts(ATTACHED);
    p[2] = V::Bytes(vec![0; 32]);
    let b = receipt(p);
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(
        r.proofs[0].attached_root_equality.code,
        "attached_root_mismatch"
    );
    assert_eq!(r.proofs[0].ts_signature.status, S::NotEvaluated);
    assert_eq!(r.inclusion.status, S::Failed);
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn wrong_signature_never_authenticates_detached_root() {
    let b = mutate_receipt(|p| {
        let V::Bytes(s) = &mut p[3] else { panic!() };
        s[0] ^= 0x80;
    });
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.proofs[0].root_reconstruction.status, S::Passed);
    assert_eq!(r.ts_signature.status, S::Failed);
    assert_eq!(r.inclusion.status, S::Unestablished);
    assert_eq!(r.ts_identity_trust.status, S::Unestablished);
}

#[test]
fn truncated_signature_is_distinct_from_missing_keys() {
    let b = mutate_receipt(|p| p[3] = V::Bytes(vec![0; 63]));
    let c = trust(&[]);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(
        r.proofs[0].ts_signature.code,
        "invalid_ed25519_signature_length"
    );
    assert_eq!(r.ts_signature.status, S::Failed);
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn no_trust_defaults_unestablished_not_signature_failure() {
    let c = trust(&[]);
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(r.ts_signature.status, S::Unestablished);
    assert_eq!(r.inclusion.status, S::Unestablished);
    assert_eq!(r.ts_identity_trust.status, S::Unestablished);
    assert_eq!(r.acceptable_for_registration.status, S::Unestablished);
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn nonunique_kid_identifies_actual_verifying_key_not_first_row() {
    for rows in [
        [association(NEXT), association(SERVICE)],
        [association(SERVICE), association(NEXT)],
    ] {
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        passed_local(&r);
        assert_eq!(r.signature_attempts, 2);
        assert_eq!(
            r.candidate_keys[r.proofs[0].verifying_key_indices[0]].public_key,
            SERVICE
        );
        assert!(
            r.candidate_keys
                .iter()
                .all(|k| k.kid_hint_match_indices.len() == 1)
        );
    }
}

#[test]
fn missing_or_stale_kid_hint_does_not_override_actual_signature() {
    for kid_hint in [None, Some(b"stale".as_slice())] {
        let mut a = association(SERVICE);
        a.kid_hint = kid_hint;
        let rows = [a];
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        passed_local(&r);
        assert!(r.candidate_keys[0].kid_hint_match_indices.is_empty());
    }
}

#[test]
fn matching_issuer_on_wrong_key_cannot_authorize_actual_signer() {
    let mut signer = association(SERVICE);
    signer.service_identity = "https://other.example.test";
    for rows in [[association(NEXT), signer], [signer, association(NEXT)]] {
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_signature.status, S::Passed);
        assert_eq!(r.inclusion.status, S::Passed);
        assert_eq!(r.ts_key_association.status, S::Failed);
        assert_eq!(r.ts_identity_trust.code, "unauthorized_verifying_key");
    }
}

#[test]
fn authenticated_binding_missing_or_discovered_issuer_key_pair_is_not_trust() {
    for provenance in [
        BindingProvenance::Missing,
        BindingProvenance::Unauthenticated {
            origin: "copied receipt iss + discovery key",
        },
        BindingProvenance::CallerAuthenticated {
            authority: "",
            evidence_ref: "something",
        },
        BindingProvenance::CallerAuthenticated {
            authority: "somebody",
            evidence_ref: "",
        },
    ] {
        let mut a = association(SERVICE);
        a.provenance = provenance;
        let rows = [a];
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_signature.status, S::Passed);
        assert_eq!(r.ts_key_association.status, S::Unestablished);
        assert_eq!(r.ts_identity_trust.status, S::Unestablished);
    }
}

#[test]
fn accepted_identity_is_explicit_and_case_sensitive() {
    let rows = [association(SERVICE)];
    for accepted in [
        &[][..],
        &["https://TS.example.test"][..],
        &["https://ts.example.test/"][..],
    ] {
        let mut c = trust(&rows);
        c.accepted_ts_identities = accepted;
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_key_association.status, S::Passed);
        assert_eq!(r.ts_identity_trust.code, "service_identity_not_accepted");
    }
}

#[test]
fn receipt_signed_issuer_case_is_not_normalized_for_binding() {
    let b = mutate_receipt(|p| {
        protected(p, |m| {
            let (_, V::Map(claims)) = m.iter_mut().find(|(k, _)| *k == 15.into()).unwrap() else {
                panic!()
            };
            claims.iter_mut().find(|(k, _)| *k == 1.into()).unwrap().1 =
                V::Text("https://TS.example.test".into());
        });
        resign(p);
    });
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.ts_signature.status, S::Passed);
    assert_eq!(r.ts_key_association.status, S::Failed);
}

#[test]
fn rotation_overlapping_windows_allow_either_actual_key() {
    let mut next = association(NEXT);
    next.valid_from = Some(150);
    next.valid_until = Some(250);
    let rows = [association(SERVICE), next];
    let c = trust(&rows);
    for b in [DETACHED, ROTATED] {
        passed_local(&verify_scitt_receipt(b, STATEMENT, &c, &Policy::default()));
    }
}

#[test]
fn validity_start_inclusive_end_exclusive_and_no_implicit_clock() {
    let rows = [association(SERVICE)];
    for (now, status) in [
        (None, S::Unestablished),
        (Some(99), S::Failed),
        (Some(100), S::Passed),
        (Some(199), S::Passed),
        (Some(200), S::Failed),
        (Some(i64::MAX), S::Failed),
    ] {
        let mut c = trust(&rows);
        c.evaluation_time = now;
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_signature.status, S::Passed);
        assert_eq!(r.ts_identity_trust.status, status, "{r:?}");
    }
}

#[test]
fn missing_rotation_provisioner_or_validity_never_passes() {
    let mut a = association(SERVICE);
    for mode in 0..5 {
        a.valid_from = if mode == 0 { None } else { Some(100) };
        a.valid_until = if mode == 1 { None } else { Some(200) };
        let rows = [a];
        let mut c = trust(&rows);
        if mode == 2 {
            c.rotation_policy = None;
        }
        if mode == 3 {
            c.provisioned_by = None;
        }
        if mode == 4 {
            c.provisioned_by = Some("");
        }
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(
            r.ts_identity_trust.status,
            S::Unestablished,
            "mode {mode}: {r:?}"
        );
    }
}

#[test]
fn inverted_or_empty_validity_window_fails() {
    for from in [200, 201] {
        let mut a = association(SERVICE);
        a.valid_from = Some(from);
        let rows = [a];
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_identity_trust.status, S::Failed);
    }
}

#[test]
fn rotation_expired_key_does_not_borrow_current_other_key_authority() {
    let mut next = association(NEXT);
    next.valid_until = Some(300);
    let rows = [association(SERVICE), next];
    let mut c = trust(&rows);
    c.evaluation_time = Some(200);
    let old = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(old.ts_identity_trust.status, S::Failed);
    passed_local(&verify_scitt_receipt(
        ROTATED,
        STATEMENT,
        &c,
        &Policy::default(),
    ));
}

#[test]
fn same_key_multiple_associations_use_signed_issuer_and_deduplicate_crypto() {
    let mut other = association(SERVICE);
    other.service_identity = "https://other.example.test";
    let mut old = association(SERVICE);
    old.valid_until = Some(100);
    for rows in [
        [other, old, association(SERVICE)],
        [association(SERVICE), old, other],
    ] {
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        passed_local(&r);
        assert_eq!(r.signature_attempts, 1);
        assert_eq!(r.candidate_keys[0].association_indices.len(), 3);
    }
}

#[test]
fn explicit_distrust_wins_across_same_key_rows_order_issuer_algorithm_and_validity() {
    let mut veto = association(SERVICE);
    veto.explicitly_distrusted = true;
    veto.algorithm = -7;
    veto.service_identity = "other-service";
    veto.valid_until = Some(99);
    veto.provenance = BindingProvenance::Missing;
    for rows in [[association(SERVICE), veto], [veto, association(SERVICE)]] {
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_signature.status, S::Passed);
        assert_eq!(r.ts_identity_trust.code, "actual_key_explicitly_distrusted");
    }
}

#[test]
fn unrelated_key_distrust_does_not_veto_actual_signer() {
    let mut other = association(NEXT);
    other.explicitly_distrusted = true;
    let rows = [other, association(SERVICE)];
    let c = trust(&rows);
    passed_local(&verify_scitt_receipt(
        DETACHED,
        STATEMENT,
        &c,
        &Policy::default(),
    ));
}

#[test]
fn permitted_algorithm_and_key_type_must_match_ed25519() {
    let mut a = association(SERVICE);
    for mode in 0..3 {
        a.algorithm = if mode == 0 { -7 } else { -8 };
        a.public_key = if mode == 1 {
            Key::Unsupported {
                key_type: "P-256",
                bytes: &SERVICE,
            }
        } else if mode == 2 {
            Key::Unsupported {
                key_type: "unrecognized",
                bytes: &SERVICE,
            }
        } else {
            Key::Ed25519(SERVICE)
        };
        let rows = [a];
        let c = trust(&rows);
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
        assert_eq!(
            r.proofs[0].ts_signature.code,
            "no_algorithm_compatible_candidate_key"
        );
        assert_eq!(r.signature_attempts, 0);
        assert_eq!(
            r.key_configuration[0].status,
            if mode == 0 { S::Failed } else { S::Unsupported }
        );
        assert_ne!(r.ts_identity_trust.status, S::Passed);
    }
}

#[test]
fn actual_key_cannot_borrow_same_key_wrong_algorithm_association() {
    let mut wrong_service = association(SERVICE);
    wrong_service.service_identity = "other";
    let mut wrong_alg = association(SERVICE);
    wrong_alg.algorithm = -7;
    let rows = [wrong_service, wrong_alg];
    let c = trust(&rows);
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(r.ts_signature.status, S::Passed);
    assert_eq!(r.ts_key_association.status, S::Failed);
}

#[test]
fn phase1_structure_claims_support_policy_gates_stop_crypto() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    for name in [
        "duplicate_396_valid_first",
        "duplicate_396_valid_last",
        "outer_trailing_cbor",
        "claims_missing_iss",
        "claims_sub_bytes",
        "claims_unprotected_only",
        "ccf_vds2_opaque_profile",
        "ts_es256_not_supported",
        "kid_unprotected_only",
        "x5chain_single_shape_valid",
        "crit_unknown_semantics",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/phase1/{name}.cbor"));
        let b = std::fs::read(path).unwrap();
        let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
        assert!(r.proofs.is_empty(), "{name}: {r:?}");
        assert!(r.candidate_entry.is_none(), "{name}: {r:?}");
        assert_eq!(r.signature_attempts, 0);
        assert_eq!(r.ts_signature.status, S::NotEvaluated);
    }
}

#[test]
fn default_crossmap_off_protected_precedence_strict_rejection() {
    let b = mutate_receipt(|p| {
        let V::Map(u) = &mut p[1] else { panic!() };
        u.push((1.into(), (-7).into()));
        u.push((4.into(), V::Bytes(b"attacker-hint".to_vec())));
        u.push((395.into(), 2.into()));
    });
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let mut policy = Policy::default();
    passed_local(&verify_scitt_receipt(&b, STATEMENT, &c, &policy));
    policy.envelope.strict_cross_map = true;
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &policy);
    assert_eq!(r.envelope.selected_policy.status, S::Failed);
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn label15_crossmap_always_rejected() {
    let b = mutate_receipt(|p| {
        let V::Map(u) = &mut p[1] else { panic!() };
        u.push((15.into(), V::Map(vec![])));
    });
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.envelope.structure.status, S::Failed);
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn phase2_candidate_is_not_outer_validation_and_preserves_70_strict_reader() {
    let mut p = parts(STATEMENT);
    p[1] = V::Map(vec![(1.into(), (-7).into())]);
    let b = receipt(p);
    assert!(attached_receipts(&b).is_err());
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(DETACHED, &b, &c, &Policy::default());
    passed_local(&r);
    assert_eq!(r.issuer_signature.status, S::NotEvaluated);
}

#[test]
fn statement_limits_precede_candidate_allocation() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let mut policy = Policy::default();
    policy.limits.max_statement_bytes = STATEMENT.len() - 1;
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &policy);
    assert_eq!(r.candidate_derivation.code, "statement_byte_limit");
    assert!(r.candidate_entry.is_none());
    policy.limits.max_statement_bytes = STATEMENT.len();
    passed_local(&verify_scitt_receipt(DETACHED, STATEMENT, &c, &policy));
}

#[test]
fn forged_lengths_deep_cbor_and_trailing_statement_rejected_before_candidate() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let mut trailing = STATEMENT.to_vec();
    trailing.push(0);
    let mut deep = vec![0x81; 100];
    deep.push(0);
    for b in [
        trailing,
        deep,
        vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        let r = verify_scitt_receipt(DETACHED, &b, &c, &Policy::default());
        assert_eq!(r.candidate_derivation.code, "statement_cbor_preflight");
        assert!(r.candidate_entry.is_none());
        assert_eq!(r.signature_attempts, 0);
    }
}

#[test]
fn detached_statement_is_not_silently_substituted() {
    let mut p = parts(STATEMENT);
    p[2] = V::Null;
    let b = receipt(p);
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(DETACHED, &b, &c, &Policy::default());
    assert_eq!(r.candidate_derivation.code, "statement_candidate_shape");
}

#[test]
fn phase2_limits_can_only_tighten() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    for value in [0, 257] {
        let mut p = Policy::default();
        p.limits.max_signature_attempts = value;
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &p);
        assert_eq!(r.selected_policy.code, "invalid_phase2_limits");
        assert!(r.candidate_entry.is_none());
    }
}

#[test]
fn trust_rows_identity_fields_and_unique_candidate_limits_are_bounded() {
    let rows = [association(SERVICE), association(NEXT)];
    let c = trust(&rows);
    for mode in 0..3 {
        let mut p = Policy::default();
        if mode == 0 {
            p.limits.max_associations = 1;
        }
        if mode == 1 {
            p.limits.max_candidate_keys = 1;
        }
        if mode == 2 {
            p.limits.max_trust_field_bytes = 1;
        }
        let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &p);
        assert_eq!(r.selected_policy.status, S::Failed);
        assert_eq!(r.signature_attempts, 0);
    }
}

fn duplicate_proof(b: &[u8], damage_first: bool) -> Vec<u8> {
    let mut p = parts(b);
    let V::Map(u) = &mut p[1] else { panic!() };
    let V::Map(vdp) = &mut u.iter_mut().find(|(k, _)| *k == 396.into()).unwrap().1 else {
        panic!()
    };
    let V::Array(proofs) = &mut vdp[0].1 else {
        panic!()
    };
    proofs.push(proofs[0].clone());
    if damage_first {
        let V::Bytes(first) = &mut proofs[0] else {
            panic!()
        };
        *first.last_mut().unwrap() ^= 1;
    }
    receipt(p)
}

#[test]
fn cartesian_attempt_limit_fails_before_any_signature_attempt() {
    let b = duplicate_proof(DETACHED, false);
    let rows = [association(SERVICE), association(NEXT)];
    let c = trust(&rows);
    let mut p = Policy::default();
    p.limits.max_signature_attempts = 3;
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &p);
    assert_eq!(r.selected_policy.code, "signature_attempt_limit");
    assert_eq!(r.signature_attempts, 0);
    assert!(r.proofs.is_empty());
    p.limits.max_signature_attempts = 4;
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &p);
    passed_local(&r);
    assert_eq!(r.signature_attempts, 4);
}

#[test]
fn bad_proof_not_hidden_by_good_proof_in_either_order() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let b = duplicate_proof(DETACHED, true);
    for reverse in [false, true] {
        let mut p = parts(&b);
        if reverse {
            let V::Map(u) = &mut p[1] else { panic!() };
            let V::Map(vdp) = &mut u[0].1 else { panic!() };
            let V::Array(proofs) = &mut vdp[0].1 else {
                panic!()
            };
            proofs.reverse();
        }
        let b = receipt(p);
        let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
        assert_eq!(r.ts_signature.status, S::Failed);
        assert_eq!(
            r.proofs
                .iter()
                .filter(|p| p.inclusion.status == S::Passed)
                .count(),
            1
        );
        assert_ne!(r.inclusion.status, S::Passed);
        assert_ne!(r.ts_identity_trust.status, S::Passed);
    }
}

#[test]
fn caller_authenticated_external_is_an_explicit_assumption_not_observed_authentication() {
    // Exercise the API contract branch by simulation. This test did NOT authenticate a service.
    let rows = [association(SERVICE)];
    let mut c = trust(&rows);
    c.origin = Origin::CallerAuthenticatedExternal;
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(r.acceptable_for_registration.status, S::Passed);
    assert_eq!(r.application_policy.status, S::Unestablished);
    assert_eq!(r.subject_policy.status, S::Unestablished);
    assert_eq!(
        r.ts_identity_trust.code,
        "trusted_under_caller_authenticated_offline_configuration"
    );
}

#[test]
fn small_order_key_and_forged_signature_are_not_accepted() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let rows = [association(identity)];
    let c = trust(&rows);
    let b = mutate_receipt(|p| {
        let mut signature = vec![0; 64];
        signature[0] = 1; // R is the identity and S is zero: rejected by verify_strict.
        p[3] = V::Bytes(signature);
    });
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.ts_signature.status, S::Failed);
    assert_ne!(r.inclusion.status, S::Passed);
}

#[test]
fn valid_shape_but_impossible_merkle_path_is_independent_inclusion_failure() {
    let b = mutate_receipt(|p| {
        let V::Map(u) = &mut p[1] else { panic!() };
        let V::Map(vdp) = &mut u[0].1 else { panic!() };
        let V::Array(proofs) = &mut vdp[0].1 else {
            panic!()
        };
        proofs[0] = V::Bytes(encode(&V::Array(vec![
            4.into(),
            0.into(),
            V::Array(vec![V::Bytes(vec![0; 32])]),
        ]))); // one sibling short
    });
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.envelope.structure.status, S::Passed);
    assert_eq!(r.proofs[0].root_reconstruction.code, "invalid_merkle_path");
    assert_eq!(r.ts_signature.status, S::NotEvaluated);
    assert_eq!(r.inclusion.status, S::Failed);
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn changed_detached_proof_root_is_not_authenticated_by_reconstruction() {
    let b = mutate_receipt(|p| {
        let V::Map(u) = &mut p[1] else { panic!() };
        let V::Map(vdp) = &mut u[0].1 else { panic!() };
        let V::Array(proofs) = &mut vdp[0].1 else {
            panic!()
        };
        let V::Bytes(proof) = &mut proofs[0] else {
            panic!()
        };
        *proof.last_mut().unwrap() ^= 1;
    });
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let r = verify_scitt_receipt(&b, STATEMENT, &c, &Policy::default());
    assert_eq!(r.proofs[0].root_reconstruction.status, S::Passed);
    assert_eq!(r.ts_signature.status, S::Failed);
    assert_eq!(r.inclusion.status, S::Unestablished);
}

#[test]
fn unknown_noncritical_crossmap_equal_and_conflicting_values_are_policy_only() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    for value in [1, 2] {
        let b = mutate_receipt(|p| {
            protected(p, |m| m.push((999.into(), 1.into())));
            let V::Map(u) = &mut p[1] else { panic!() };
            u.push((999.into(), value.into()));
            resign(p);
        });
        let mut policy = Policy::default();
        passed_local(&verify_scitt_receipt(&b, STATEMENT, &c, &policy));
        policy.envelope.strict_cross_map = true;
        let r = verify_scitt_receipt(&b, STATEMENT, &c, &policy);
        assert_eq!(r.envelope.selected_policy.status, S::Failed);
        assert_eq!(r.signature_attempts, 0);
    }
}

#[test]
fn association_and_accepted_identity_hard_ceilings_reject_without_crypto() {
    let rows = vec![association(SERVICE); 64];
    let c = trust(&rows);
    passed_local(&verify_scitt_receipt(
        DETACHED,
        STATEMENT,
        &c,
        &Policy::default(),
    ));
    let too_many = vec![association(SERVICE); 65];
    let c = trust(&too_many);
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(r.selected_policy.code, "trust_context_limit");
    assert_eq!(r.signature_attempts, 0);
    let identities = vec![ISS; 65];
    let mut c = trust(&rows);
    c.accepted_ts_identities = &identities;
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(r.selected_policy.code, "trust_context_limit");
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn unique_candidate_hard_ceiling_is_checked_before_verification() {
    let mut rows = vec![association(SERVICE)];
    for i in 1..=15 {
        let key = SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes();
        rows.push(association(key));
    }
    let c = trust(&rows);
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    passed_local(&r);
    assert_eq!(r.signature_attempts, 16);
    rows.push(association(NEXT));
    let c = trust(&rows);
    let r = verify_scitt_receipt(DETACHED, STATEMENT, &c, &Policy::default());
    assert_eq!(r.selected_policy.code, "candidate_key_limit");
    assert_eq!(r.signature_attempts, 0);
}

#[test]
fn all_statement_preflight_ceilings_are_enforced() {
    let rows = [association(SERVICE)];
    let c = trust(&rows);
    let mut p = parts(STATEMENT);
    p[1] = V::Map(vec![(700.into(), 0.into()), (701.into(), 0.into())]);
    let b = receipt(p);
    for mode in 0..3 {
        let mut policy = Policy::default();
        match mode {
            0 => policy.limits.max_statement_cbor_items = 2,
            1 => policy.limits.max_statement_cbor_nesting = 1,
            _ => policy.limits.max_statement_map_entries = 1,
        }
        let r = verify_scitt_receipt(DETACHED, &b, &c, &policy);
        assert_eq!(r.candidate_derivation.code, "statement_cbor_preflight");
        assert!(r.candidate_entry.is_none());
        assert_eq!(r.signature_attempts, 0);
    }
}
