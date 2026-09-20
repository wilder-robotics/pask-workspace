// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.
#![cfg(feature = "alloc")]
use InspectionStatus as S;
use coset::cbor::Value as V;
use ed25519_dalek::{Signer, SigningKey};
use pask_wire::*;
use sha2::{Digest, Sha256};
const BASE: &[u8] = include_bytes!("fixtures/phase3/statement.cbor");
const TRANSPARENT: &[u8] = include_bytes!("fixtures/phase3/detached-transparent.cbor");
const RECEIPT: &[u8] = include_bytes!("fixtures/phase3/detached-receipt.cbor");
const ISSUER: [u8; 32] = *include_bytes!("fixtures/phase3/issuer-key.bin");
const SERVICE: [u8; 32] = *include_bytes!("fixtures/phase3/service-key.bin");
const TS: &str = "https://ts.example.test";
const ISS: &str = "https://issuer.example.test";
fn auth() -> BindingProvenance<'static> {
    BindingProvenance::CallerAuthenticated {
        authority: "SOFTWARE TEST caller assertion, not live provisioning",
        evidence_ref: "fixtures/phase3/manifest.json",
    }
}
fn encode(v: &V) -> Vec<u8> {
    let mut b = vec![];
    coset::cbor::ser::into_writer(v, &mut b).unwrap();
    b
}
fn decode(b: &[u8]) -> V {
    coset::cbor::de::from_reader(b).unwrap()
}
fn parts(b: &[u8]) -> Vec<V> {
    let v = decode(b);
    let v = if let V::Tag(18, x) = v { *x } else { v };
    let V::Array(a) = v else { panic!() };
    a
}
fn tagged(p: Vec<V>) -> Vec<u8> {
    encode(&V::Tag(18, Box::new(V::Array(p))))
}
fn int(n: i64) -> V {
    V::Integer(n.into())
}
fn protected(p: &mut [V], edit: impl FnOnce(&mut Vec<(V, V)>)) {
    let V::Bytes(b) = &p[0] else { panic!() };
    let V::Map(mut m) = decode(b) else { panic!() };
    edit(&mut m);
    p[0] = V::Bytes(encode(&V::Map(m)));
}
fn resign_issuer(p: &mut [V]) {
    let signed = encode(&V::Array(vec![
        V::Text("Signature1".into()),
        p[0].clone(),
        V::Bytes(vec![]),
        p[2].clone(),
    ]));
    p[3] = V::Bytes(
        SigningKey::from_bytes(&[17; 32])
            .sign(&signed)
            .to_bytes()
            .to_vec(),
    );
}
fn receipt_for(b: &[u8], subject: &str) -> Vec<u8> {
    let p = parts(b);
    let candidate = encode(&V::Array(vec![
        p[0].clone(),
        V::Map(vec![]),
        p[2].clone(),
        p[3].clone(),
    ]));
    let leaf = Sha256::digest([&[0][..], candidate.as_slice()].concat());
    let sibling = Sha256::digest(b"\x00independent other leaf");
    let root = Sha256::digest([&[1][..], &leaf[..], &sibling[..]].concat());
    let h = encode(&V::Map(vec![
        (int(1), int(-8)),
        (int(4), V::Bytes(b"nonunique".to_vec())),
        (
            int(15),
            V::Map(vec![
                (int(1), V::Text(TS.into())),
                (int(2), V::Text(subject.into())),
            ]),
        ),
        (int(395), int(1)),
    ]));
    let sig = SigningKey::from_bytes(&[29; 32]).sign(&encode(&V::Array(vec![
        V::Text("Signature1".into()),
        V::Bytes(h.clone()),
        V::Bytes(vec![]),
        V::Bytes(root.to_vec()),
    ])));
    let proof = encode(&V::Array(vec![
        int(2),
        int(0),
        V::Array(vec![V::Bytes(sibling.to_vec())]),
    ]));
    tagged(vec![
        V::Bytes(h),
        V::Map(vec![(
            int(396),
            V::Map(vec![(int(-1), V::Array(vec![V::Bytes(proof)]))]),
        )]),
        V::Null,
        V::Bytes(sig.to_bytes().to_vec()),
    ])
}
fn attach(b: &[u8], receipts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut p = parts(b);
    let V::Map(u) = &mut p[1] else { panic!() };
    u.retain(|(k, _)| *k != int(394));
    u.push((
        int(394),
        V::Array(receipts.into_iter().map(V::Bytes).collect()),
    ));
    tagged(p)
}
fn modified(edit: impl FnOnce(&mut Vec<V>)) -> Vec<u8> {
    let mut p = parts(BASE);
    edit(&mut p);
    resign_issuer(&mut p);
    let b = tagged(p);
    attach(&b, vec![receipt_for(&b, "site-A")])
}
fn bad_receipt() -> Vec<u8> {
    let mut p = parts(RECEIPT);
    let V::Bytes(s) = &mut p[3] else { panic!() };
    s[0] ^= 1;
    tagged(p)
}
fn unsupported_receipt() -> Vec<u8> {
    let mut p = parts(RECEIPT);
    protected(&mut p, |m| {
        m.iter_mut().find(|(k, _)| *k == int(395)).unwrap().1 = int(2)
    });
    tagged(p)
}
struct TestOptions<'a> {
    issuer: Option<&'a IssuerKeyInput<'a>>,
    expected_digest: Option<&'a ExpectedDigest<'a>>,
    subject: SubjectPolicy<'a>,
    application: StatementApplicationPolicy,
}
struct Harness {
    issuer: IssuerKeyInput<'static>,
    row: TsKeyAssociation<'static>,
    digest: ExpectedDigest<'static>,
    origin: TrustInputOrigin,
}
impl Harness {
    fn new() -> Self {
        Self {
            issuer: IssuerKeyInput {
                public_key: TsPublicKey::Ed25519(ISSUER),
                algorithm: -8,
                issuer: ISS,
                provenance: auth(),
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
                evaluation_time: Some(150),
                valid_from: Some(100),
                valid_until: Some(200),
                explicitly_distrusted: false,
            },
            row: TsKeyAssociation {
                service_identity: TS,
                public_key: TsPublicKey::Ed25519(SERVICE),
                algorithm: -8,
                provenance: auth(),
                kid_hint: Some(b"nonunique"),
                valid_from: Some(100),
                valid_until: Some(200),
                explicitly_distrusted: false,
            },
            digest: ExpectedDigest {
                target: DigestTarget::CandidateEntrySha256,
                sha256: Sha256::digest(include_bytes!("fixtures/phase3/candidate.cbor")).into(),
                provenance: auth(),
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
            },
            origin: TrustInputOrigin::CallerAuthenticatedExternal,
        }
    }
    fn run<'a>(
        &'a self,
        b: &'a [u8],
        p: &TransparentStatementPolicy,
        edit: impl FnOnce(&mut TestOptions<'a>),
        check: impl FnOnce(TransparentStatementReport<'_>),
    ) {
        let rows = [self.row];
        let c = TsTrustContext {
            accepted_ts_identities: &[TS],
            associations: &rows,
            evaluation_time: Some(150),
            rotation_policy: Some(RotationPolicy::ValidAtEvaluationTimeV1),
            provisioned_by: Some("SOFTWARE TEST ASSERTION"),
            origin: self.origin,
        };
        let mut options = TestOptions {
            issuer: Some(&self.issuer),
            expected_digest: Some(&self.digest),
            subject: SubjectPolicy::SharedJsonSiteV1,
            application: StatementApplicationPolicy::SignedJsonSiteV1 {
                require_subject: true,
                require_all_receipts: false,
                require_authenticated_digest: false,
            },
        };
        edit(&mut options);
        let inputs = StatementVerificationInputs {
            issuer: options.issuer,
            services: &c,
            expected_digest: options.expected_digest,
            subject: options.subject,
            application: options.application,
        };
        check(verify_transparent_statement(b, &inputs, p));
    }
    fn normal(&self, b: &[u8], check: impl FnOnce(TransparentStatementReport<'_>)) {
        self.run(b, &TransparentStatementPolicy::default(), |_| {}, check)
    }
}
fn full(r: &TransparentStatementReport<'_>) {
    assert_eq!(r.outer.structure.status, S::Passed, "{r:?}");
    assert_eq!(r.issuer_signature.status, S::Passed);
    assert_eq!(r.registration_evidence.status, S::Passed, "{r:?}");
    assert_eq!(r.subject_policy.status, S::Passed);
    assert_eq!(r.application_policy.status, S::Passed, "{r:?}");
    assert_eq!(r.hardware_appraisal.status, S::NotEvaluated);
    assert_eq!(r.overall_profile.status, S::Unestablished);
}
#[test]
fn independent_attached_detached_exact_bytes() {
    let h = Harness::new();
    for b in [
        TRANSPARENT,
        include_bytes!("fixtures/phase3/attached-transparent.cbor"),
    ] {
        h.normal(b, |r| {
            full(&r);
            assert_eq!(r.actual_issuer_key, Some(ISSUER));
            assert_eq!(
                r.candidate_entry.as_deref(),
                Some(include_bytes!("fixtures/phase3/candidate.cbor").as_slice())
            );
            assert_eq!(
                r.receipts[0].proofs[0].reconstructed_root,
                Some(*include_bytes!("fixtures/phase3/root.bin"))
            );
            assert_eq!(r.digest_equality.status, S::Passed);
            let p = r.outer.protected_bytes.as_ref().unwrap();
            assert_ne!(encode(&decode(p)), *p);
        });
    }
}
#[test]
fn mixed_bad_good_both_orders_does_not_veto() {
    let h = Harness::new();
    for list in [
        vec![bad_receipt(), RECEIPT.to_vec()],
        vec![RECEIPT.to_vec(), bad_receipt()],
    ] {
        let b = attach(BASE, list.clone());
        h.normal(&b, |r| {
            full(&r);
            assert_eq!(r.receipts.len(), 2);
            assert_eq!(r.acceptable_receipt_indices.len(), 1);
            for (i, o) in r.receipts.iter().enumerate() {
                assert_eq!(o.index, i);
                assert_eq!(o.encoded_receipt, list[i]);
            }
            assert!(
                r.receipts
                    .iter()
                    .any(|x| x.ts_signature.status == S::Failed)
            );
        });
    }
}
#[test]
fn unsupported_good_both_orders_does_not_veto() {
    let h = Harness::new();
    for list in [
        vec![unsupported_receipt(), RECEIPT.to_vec()],
        vec![RECEIPT.to_vec(), unsupported_receipt()],
    ] {
        let b = attach(BASE, list);
        h.normal(&b, |r| {
            full(&r);
            assert!(
                r.receipts
                    .iter()
                    .any(|x| x.support.status == S::Unsupported)
            );
        });
    }
}
#[test]
fn explicit_all_receipts_is_stricter_application_only() {
    let h = Harness::new();
    let b = attach(BASE, vec![bad_receipt(), RECEIPT.to_vec()]);
    h.run(
        &b,
        &TransparentStatementPolicy::default(),
        |i| {
            i.application = StatementApplicationPolicy::SignedJsonSiteV1 {
                require_subject: true,
                require_all_receipts: true,
                require_authenticated_digest: false,
            }
        },
        |r| {
            assert_eq!(r.registration_evidence.status, S::Passed);
            assert_eq!(r.application_policy.status, S::Failed);
        },
    );
}
#[test]
fn malformed_encoded_receipt_retained_not_malformed_enclosing() {
    let h = Harness::new();
    for list in [
        vec![vec![0xff], RECEIPT.to_vec()],
        vec![RECEIPT.to_vec(), vec![0xff]],
    ] {
        h.normal(&attach(BASE, list), |r| {
            full(&r);
            assert!(r.receipts.iter().any(|x| x.structure.status == S::Failed));
        });
    }
}
#[test]
fn absence_empty_and_malformed_containers_distinct() {
    let h = Harness::new();
    h.normal(BASE, |r| {
        assert_eq!(r.outer.container, ReceiptContainerState::Absent);
        assert_eq!(r.registration_evidence.status, S::Unestablished);
        assert!(r.receipts.is_empty());
    });
    for value in [
        V::Array(vec![]),
        int(3),
        V::Array(vec![decode(RECEIPT)]),
        V::Array(vec![V::Bytes(RECEIPT.to_vec()), int(2)]),
    ] {
        let mut p = parts(BASE);
        p[1] = V::Map(vec![(int(394), value)]);
        h.normal(&tagged(p), |r| {
            assert_eq!(r.outer.container, ReceiptContainerState::Malformed);
            assert_eq!(r.outer.structure.status, S::Failed);
            assert_eq!(r.issuer_signature.status, S::NotEvaluated);
            assert!(r.receipts.is_empty());
        });
    }
}
#[test]
fn optional_subject_and_application_absence_never_acceptance() {
    let h = Harness::new();
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::None;
            i.application = StatementApplicationPolicy::None;
        },
        |r| {
            assert_eq!(r.registration_evidence.status, S::Passed);
            assert_eq!(r.receipts[0].inclusion.status, S::Passed);
            assert_eq!(r.subject_policy.status, S::Unestablished);
            assert_eq!(r.application_policy.status, S::Unestablished);
        },
    );
}
#[test]
fn case_sensitive_subject_contradiction() {
    let h = Harness::new();
    let b = attach(BASE, vec![receipt_for(BASE, "Site-A")]);
    h.normal(&b, |r| {
        assert_eq!(r.registration_evidence.status, S::Passed);
        assert_eq!(r.subject_policy.status, S::Failed);
        assert_eq!(r.application_policy.status, S::Failed);
    });
}
#[test]
fn mapping_positive_contradiction_missing_and_ambiguous() {
    let h = Harness::new();
    let rows = [SubjectMapping {
        service_identity: TS,
        receipt_subject: "receipt-scope",
        statement_subject: "site-A",
        site_id: "site-A",
    }];
    let b = attach(BASE, vec![receipt_for(BASE, "receipt-scope")]);
    h.run(
        &b,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                rows: &rows,
                provenance: auth(),
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
            }
        },
        |r| full(&r),
    );
    let wrong = [SubjectMapping {
        site_id: "site-B",
        ..rows[0].clone()
    }];
    h.run(
        &b,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                rows: &wrong,
                provenance: auth(),
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
            }
        },
        |r| assert_eq!(r.subject_policy.status, S::Failed),
    );
    h.run(
        &b,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                rows: &rows,
                provenance: BindingProvenance::Missing,
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
            }
        },
        |r| assert_eq!(r.subject_policy.status, S::Unestablished),
    );
    let ambiguous = [rows[0].clone(), wrong[0].clone()];
    h.run(
        &b,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                rows: &ambiguous,
                provenance: auth(),
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
            }
        },
        |r| {
            assert_eq!(
                r.receipts[0].subject_policy.code,
                "ambiguous_subject_mapping"
            )
        },
    );
}
#[test]
fn unrelated_authenticated_mapping_is_missing_evidence_not_contradiction() {
    let h = Harness::new();
    let b = attach(BASE, vec![receipt_for(BASE, "receipt-scope")]);
    let actual = SubjectMapping {
        service_identity: TS,
        receipt_subject: "receipt-scope",
        statement_subject: "site-A",
        site_id: "site-A",
    };
    let unrelated_service = SubjectMapping {
        service_identity: "https://different-ts.example.test",
        ..actual.clone()
    };
    let unrelated_subject = SubjectMapping {
        receipt_subject: "different-receipt-scope",
        ..actual
    };
    for rows in [
        vec![],
        vec![unrelated_service.clone()],
        vec![unrelated_subject.clone()],
        vec![unrelated_service, unrelated_subject],
    ] {
        h.run(
            &b,
            &TransparentStatementPolicy::default(),
            |i| {
                i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                    rows: &rows,
                    provenance: auth(),
                    origin: TrustInputOrigin::CallerAuthenticatedExternal,
                }
            },
            |r| {
                assert_eq!(r.registration_evidence.status, S::Passed);
                assert_eq!(r.receipts[0].subject_policy.status, S::Unestablished);
                assert_eq!(
                    r.receipts[0].subject_policy.code,
                    "authenticated_mapping_missing"
                );
                assert_eq!(r.subject_policy.status, S::Unestablished);
                assert_eq!(r.application_policy.status, S::Unestablished);
            },
        );
    }
}
#[test]
fn unrelated_mapping_rows_do_not_hide_matching_evidence_or_contradictions() {
    let h = Harness::new();
    let b = attach(BASE, vec![receipt_for(BASE, "receipt-scope")]);
    let actual = SubjectMapping {
        service_identity: TS,
        receipt_subject: "receipt-scope",
        statement_subject: "site-A",
        site_id: "site-A",
    };
    let unrelated = SubjectMapping {
        service_identity: "https://different-ts.example.test",
        site_id: "site-B",
        ..actual.clone()
    };
    let contradicting = SubjectMapping {
        site_id: "site-B",
        ..actual.clone()
    };
    for (rows, status, code) in [
        (
            vec![unrelated.clone(), actual.clone()],
            S::Passed,
            "authenticated_mapping_v1_exact_correspondence",
        ),
        (
            vec![unrelated.clone(), contradicting.clone()],
            S::Failed,
            "mapping_contradiction",
        ),
        (
            vec![unrelated, actual, contradicting],
            S::Failed,
            "ambiguous_subject_mapping",
        ),
    ] {
        h.run(
            &b,
            &TransparentStatementPolicy::default(),
            |i| {
                i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                    rows: &rows,
                    provenance: auth(),
                    origin: TrustInputOrigin::CallerAuthenticatedExternal,
                }
            },
            |r| {
                assert_eq!(r.registration_evidence.status, S::Passed);
                assert_eq!(r.receipts[0].subject_policy.status, status);
                assert_eq!(r.receipts[0].subject_policy.code, code);
                assert_eq!(r.subject_policy.status, status);
                assert_eq!(r.application_policy.status, status);
            },
        );
    }
}
#[test]
fn valid_subject_on_invalid_receipt_cannot_lend_binding() {
    let h = Harness::new();
    let b = attach(BASE, vec![bad_receipt(), receipt_for(BASE, "wrong")]);
    h.normal(&b, |r| {
        assert_eq!(r.registration_evidence.status, S::Passed);
        assert_eq!(r.subject_policy.status, S::Failed);
    });
}
#[test]
fn byte_string_subject_is_type_failure_not_repaired() {
    let h = Harness::new();
    let b = modified(|p| {
        protected(p, |m| {
            let V::Map(c) = &mut m.iter_mut().find(|(k, _)| *k == int(15)).unwrap().1 else {
                panic!()
            };
            c.iter_mut().find(|(k, _)| *k == int(2)).unwrap().1 = V::Bytes(b"site-A".to_vec());
        })
    });
    h.normal(&b, |r| {
        assert_eq!(r.outer.required_claims.status, S::Failed);
        assert_eq!(r.issuer_signature.status, S::Passed);
        assert_eq!(r.receipts[0].inclusion.status, S::Passed);
        assert_eq!(r.subject_policy.status, S::Unestablished);
        assert_eq!(r.application_policy.status, S::Failed);
    });
}
#[test]
fn protected_precedence_default_and_optin_strict_no_70_change() {
    let h = Harness::new();
    let b = modified(|p| {
        protected(p, |m| m.push((int(99), int(7))));
        p[1] = V::Map(vec![(int(99), int(8))]);
    });
    assert!(attached_receipts(&b).is_err());
    h.normal(&b, |r| {
        full(&r);
        assert_eq!(
            r.outer
                .effective_headers
                .iter()
                .find(|(k, _)| *k == int(99))
                .unwrap()
                .1,
            int(7)
        );
    });
    let p = TransparentStatementPolicy {
        strict_cross_map: true,
        ..Default::default()
    };
    h.run(
        &b,
        &p,
        |_| {},
        |r| {
            assert_eq!(r.outer.selected_policy.status, S::Failed);
            assert_eq!(r.issuer_signature.status, S::NotEvaluated);
        },
    );
}
#[test]
fn label15_overlap_never_allowed() {
    for strict in [false, true] {
        let mut p = parts(TRANSPARENT);
        let V::Map(u) = &mut p[1] else { panic!() };
        u.push((int(15), V::Map(vec![])));
        Harness::new().run(
            &tagged(p),
            &TransparentStatementPolicy {
                strict_cross_map: strict,
                ..Default::default()
            },
            |_| {},
            |r| {
                assert_eq!(r.outer.structure.code, "label15_single_occurrence");
                assert!(r.candidate_entry.is_none());
            },
        );
    }
}
#[test]
fn duplicate_header_claim_and_trailing_preflight() {
    let h = Harness::new();
    for label in [1, 99, 394] {
        let mut p = parts(TRANSPARENT);
        protected(&mut p, |m| {
            m.push((int(label), int(2)));
            m.push((int(label), int(3)));
        });
        h.normal(&tagged(p), |r| {
            assert_eq!(r.outer.structure.status, S::Failed)
        });
    }
    let mut b = TRANSPARENT.to_vec();
    b.push(0);
    h.normal(&b, |r| {
        assert_eq!(r.outer.structure.status, S::Failed);
        assert!(r.candidate_entry.is_none());
    });
    let mut p = parts(TRANSPARENT);
    let V::Bytes(b) = &mut p[0] else { panic!() };
    b.push(0);
    h.normal(&tagged(p), |r| {
        assert_eq!(r.outer.structure.status, S::Failed)
    });
}
#[test]
fn equivalent_integer_label_duplicate_and_tagged_label_rejected() {
    let mut p = parts(TRANSPARENT);
    p[0] = V::Bytes(vec![0xa2, 0x01, 0x27, 0x18, 0x01, 0x27]);
    Harness::new().normal(&tagged(p.clone()), |r| {
        assert_eq!(r.outer.structure.code, "duplicate_key")
    });
    p[0] = V::Bytes(vec![0xa1, 0xc2, 0x41, 0x01, 0x27]);
    Harness::new().normal(&tagged(p), |r| {
        assert_eq!(r.outer.structure.status, S::Failed)
    });
}
#[test]
fn required_header_location_and_unknown_critical() {
    let h = Harness::new();
    let b = modified(|p| {
        let mut moved = None;
        protected(p, |m| {
            let n = m.iter().position(|(k, _)| *k == int(1)).unwrap();
            moved = Some(m.remove(n));
        });
        p[1] = V::Map(vec![moved.unwrap()]);
    });
    h.normal(&b, |r| {
        assert_eq!(r.outer.required_claims.status, S::Failed);
        assert_ne!(r.issuer_signature.status, S::Passed);
    });
    let b = modified(|p| {
        protected(p, |m| {
            m.push((int(99), int(1)));
            m.push((int(2), V::Array(vec![int(99)])));
        })
    });
    h.normal(&b, |r| {
        assert_eq!(r.outer.support.status, S::Unsupported);
        assert_eq!(r.application_policy.status, S::Unestablished);
    });
}
#[test]
fn invalid_issuer_signature_does_not_hide_valid_ts_inclusion() {
    let mut p = parts(BASE);
    p[3] = V::Bytes(vec![0; 64]);
    let b = tagged(p);
    let b = attach(&b, vec![receipt_for(&b, "site-A")]);
    Harness::new().normal(&b, |r| {
        assert_eq!(r.issuer_signature.status, S::Failed);
        assert_eq!(r.registration_evidence.status, S::Passed);
        assert_eq!(r.receipts[0].inclusion.status, S::Passed);
        assert_eq!(r.application_policy.status, S::Failed);
    });
}
#[test]
fn issuer_wrong_key_algorithm_binding_provenance_and_distrust() {
    for case in 0..6 {
        let mut h = Harness::new();
        match case {
            0 => h.issuer.public_key = TsPublicKey::Ed25519(SERVICE),
            1 => h.issuer.algorithm = -7,
            2 => h.issuer.issuer = TS,
            3 => h.issuer.provenance = BindingProvenance::Missing,
            4 => h.issuer.explicitly_distrusted = true,
            5 => h.issuer.evaluation_time = Some(200),
            _ => unreachable!(),
        };
        h.normal(TRANSPARENT, |r| {
            assert_ne!(r.application_policy.status, S::Passed);
            assert_eq!(r.registration_evidence.status, S::Passed);
            if case >= 2 {
                assert_eq!(r.issuer_signature.status, S::Passed);
            }
        });
    }
}
#[test]
fn no_issuer_input_or_ts_trust_never_application_acceptance() {
    let h = Harness::new();
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| i.issuer = None,
        |r| {
            assert_eq!(r.issuer_signature.status, S::Unestablished);
            assert_eq!(r.application_policy.status, S::Unestablished);
        },
    );
    let mut h = Harness::new();
    h.row.provenance = BindingProvenance::Missing;
    h.normal(TRANSPARENT, |r| {
        assert_eq!(r.receipts[0].inclusion.status, S::Passed);
        assert_eq!(r.registration_evidence.status, S::Unestablished);
        assert_ne!(r.application_policy.status, S::Passed);
    });
}
#[test]
fn all_local_simulation_origins_cannot_accept() {
    let mut h = Harness::new();
    h.origin = TrustInputOrigin::LocalSimulation;
    h.issuer.origin = h.origin;
    h.digest.origin = h.origin;
    h.normal(TRANSPARENT, |r| {
        assert_eq!(r.issuer_signature.status, S::Passed);
        assert_eq!(r.receipts[0].ts_signature.status, S::Passed);
        assert_eq!(r.registration_evidence.status, S::Unestablished);
        assert_eq!(r.application_policy.status, S::Unestablished);
        assert_eq!(r.digest_origin.status, S::Unestablished);
    });
}
#[test]
fn producer_digest_equality_never_independent_origin() {
    let mut h = Harness::new();
    h.digest.provenance = BindingProvenance::Unauthenticated {
        origin: "same producer unsigned manifest",
    };
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| {
            i.application = StatementApplicationPolicy::SignedJsonSiteV1 {
                require_subject: true,
                require_all_receipts: false,
                require_authenticated_digest: true,
            }
        },
        |r| {
            assert_eq!(r.digest_equality.status, S::Passed);
            assert_eq!(r.digest_origin.status, S::Unestablished);
            assert_eq!(r.application_policy.status, S::Unestablished);
        },
    );
    h.digest.sha256[0] ^= 1;
    h.normal(TRANSPARENT, |r| {
        assert_eq!(r.digest_equality.status, S::Failed)
    });
}
#[test]
fn digest_target_missing_and_required_mismatch() {
    let mut h = Harness::new();
    h.digest.target = DigestTarget::PayloadSha256;
    h.digest.sha256 = Sha256::digest(b"{\"site\":{\"id\":\"site-A\"}}").into();
    h.normal(TRANSPARENT, |r| {
        assert_eq!(r.digest_equality.status, S::Passed)
    });
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| i.expected_digest = None,
        |r| assert_eq!(r.digest_equality.status, S::Unestablished),
    );
    h.digest.sha256 = [0; 32];
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| {
            i.application = StatementApplicationPolicy::SignedJsonSiteV1 {
                require_subject: true,
                require_all_receipts: false,
                require_authenticated_digest: true,
            }
        },
        |r| assert_eq!(r.application_policy.status, S::Failed),
    );
}
#[test]
fn no_payload_site_replacement_and_duplicate_json_rejected() {
    for payload in [
        b"{\"site\":{\"id\":\"other\"}}".as_slice(),
        b"{\"site\":{\"id\":\"bad\",\"id\":\"site-A\"}}",
        b"{}",
    ] {
        let b = modified(|p| p[2] = V::Bytes(payload.to_vec()));
        Harness::new().normal(&b, |r| {
            assert_eq!(r.registration_evidence.status, S::Passed);
            assert_ne!(r.application_policy.status, S::Passed);
        });
    }
}
#[test]
fn named_software_profile_not_implicit_pser_acceptance() {
    for ct in [
        CONTENT_TYPE,
        "application/json; profile=pask71-software-site/2",
    ] {
        let b = modified(|p| {
            protected(p, |m| {
                m.iter_mut().find(|(k, _)| *k == int(3)).unwrap().1 = V::Text(ct.into())
            })
        });
        Harness::new().normal(&b, |r| {
            assert_eq!(r.application_profile.status, S::Unsupported);
            assert_eq!(r.overall_profile.status, S::Unestablished);
            assert_ne!(r.application_policy.status, S::Passed);
        });
    }
}
#[test]
fn payload_detachment_tags_and_truncation_stop_work() {
    let h = Harness::new();
    let mut p = parts(TRANSPARENT);
    p[2] = V::Null;
    let b = tagged(p);
    for b in [
        &b[..],
        &TRANSPARENT[..5],
        &encode(&V::Tag(99, Box::new(decode(TRANSPARENT))))[..],
    ] {
        h.normal(b, |r| {
            assert_eq!(r.outer.structure.status, S::Failed);
            assert_eq!(r.issuer_signature.status, S::NotEvaluated);
            assert!(r.receipts.is_empty());
        });
    }
    let b = encode(&V::Array(parts(TRANSPARENT)));
    h.normal(&b, |r| full(&r));
}
#[test]
fn byte_and_attachment_limits_exact_and_over() {
    let h = Harness::new();
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy {
            max_statement_bytes: TRANSPARENT.len(),
            ..Default::default()
        },
        |_| {},
        |r| full(&r),
    );
    h.run(
        TRANSPARENT,
        &TransparentStatementPolicy {
            max_statement_bytes: TRANSPARENT.len() - 1,
            ..Default::default()
        },
        |_| {},
        |r| assert_eq!(r.outer.structure.code, "outer_byte_limit"),
    );
    for count in [8, 9] {
        let b = attach(BASE, vec![RECEIPT.to_vec(); count]);
        h.normal(&b, |r| {
            if count == 8 {
                full(&r);
                assert_eq!(r.receipts.len(), 8);
            } else {
                assert_eq!(r.outer.container, ReceiptContainerState::Malformed);
                assert!(r.receipts.is_empty());
            }
        });
    }
}
#[test]
fn hard_limits_cannot_be_disabled() {
    for p in [
        TransparentStatementPolicy {
            max_receipts: 0,
            ..Default::default()
        },
        TransparentStatementPolicy {
            max_receipts: 9,
            ..Default::default()
        },
        TransparentStatementPolicy {
            max_statement_bytes: 0,
            ..Default::default()
        },
        TransparentStatementPolicy {
            max_statement_bytes: 1_048_577,
            ..Default::default()
        },
    ] {
        Harness::new().run(
            TRANSPARENT,
            &p,
            |_| {},
            |r| {
                assert_eq!(r.outer.selected_policy.status, S::Failed);
                assert!(r.candidate_entry.is_none());
            },
        );
    }
}
#[test]
fn receipt_phase1_failures_do_not_get_converted_to_absence() {
    let mut p = parts(RECEIPT);
    protected(&mut p, |m| {
        let n = m.iter().position(|(k, _)| *k == int(15)).unwrap();
        m.remove(n);
    });
    let b = attach(BASE, vec![tagged(p), RECEIPT.to_vec()]);
    Harness::new().normal(&b, |r| {
        full(&r);
        assert_eq!(r.receipts[0].required_claims.status, S::Failed);
        assert_eq!(r.receipts[0].inclusion.status, S::NotEvaluated);
        assert_eq!(r.receipts.len(), 2);
    });
}

#[test]
fn known_overlap_protected_algorithm_wins_and_receipt_location_is_policy_aware() {
    let b = modified(|p| p[1] = V::Map(vec![(int(1), int(-7))]));
    Harness::new().normal(&b, |r| full(&r));
    let mut p = parts(BASE);
    protected(&mut p, |m| {
        m.push((int(394), V::Array(vec![V::Bytes(RECEIPT.to_vec())])))
    });
    p[1] = V::Map(vec![(int(394), int(7))]);
    let b = tagged(p);
    let r = inspect_transparent_statement(&b, &TransparentStatementPolicy::default());
    assert_eq!(r.structure.status, S::Passed);
    assert_eq!(r.receipts, vec![RECEIPT.to_vec()]);
    let r = inspect_transparent_statement(
        &b,
        &TransparentStatementPolicy {
            strict_cross_map: true,
            ..Default::default()
        },
    );
    assert_eq!(r.selected_policy.status, S::Failed);
}

#[test]
fn subject_absence_does_not_relax_required_type_or_location() {
    for subject in [
        int(17),
        V::Tag(99, Box::new(V::Text("site-A".into()))),
        V::Bytes(b"site-A".to_vec()),
    ] {
        let b = modified(|p| {
            protected(p, |m| {
                let V::Map(c) = &mut m.iter_mut().find(|(k, _)| *k == int(15)).unwrap().1 else {
                    panic!()
                };
                c.iter_mut().find(|(k, _)| *k == int(2)).unwrap().1 = subject;
            })
        });
        Harness::new().run(
            &b,
            &TransparentStatementPolicy::default(),
            |i| i.subject = SubjectPolicy::None,
            |r| {
                assert_eq!(r.outer.required_claims.status, S::Failed);
                assert_eq!(r.subject_policy.status, S::Unestablished);
                assert_eq!(r.receipts[0].inclusion.status, S::Passed);
                assert_eq!(r.application_policy.status, S::Failed);
            },
        );
    }
    let b = modified(|p| {
        let mut moved = None;
        protected(p, |m| {
            let n = m.iter().position(|(k, _)| *k == int(15)).unwrap();
            moved = Some(m.remove(n));
        });
        p[1] = V::Map(vec![moved.unwrap()]);
    });
    Harness::new().normal(&b, |r| {
        assert_eq!(r.outer.required_claims.status, S::Failed)
    });
}

#[test]
fn raw_nesting_count_forged_length_and_protected_size_preflight() {
    let mut p = parts(BASE);
    let mut nested = int(0);
    for _ in 0..20 {
        nested = V::Array(vec![nested]);
    }
    p[1] = V::Map(vec![(int(99), nested)]);
    let deep = tagged(p);
    let mut p = parts(BASE);
    p[1] = V::Map(vec![(int(99), V::Array(vec![int(0); 4096]))]);
    let many = tagged(p);
    let mut p = parts(BASE);
    p[0] = V::Bytes(vec![0; 65_537]);
    let large = tagged(p);
    for b in [
        deep.as_slice(),
        many.as_slice(),
        large.as_slice(),
        &[0xd2, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        Harness::new().normal(b, |r| {
            assert_eq!(r.outer.structure.status, S::Failed);
            assert!(r.candidate_entry.is_none());
            assert!(r.receipts.is_empty());
        });
    }
}

#[test]
fn mutated_signed_components_cannot_borrow_original_receipt() {
    for component in [0, 2, 3] {
        let mut p = parts(TRANSPARENT);
        if component == 0 {
            protected(&mut p, |m| m.push((int(101), int(1))));
        } else {
            let V::Bytes(b) = &mut p[component] else {
                panic!()
            };
            b[0] ^= 1;
        }
        Harness::new().normal(&tagged(p), |r| {
            assert_eq!(r.issuer_signature.status, S::Failed);
            assert_ne!(r.receipts[0].inclusion.status, S::Passed);
            assert_eq!(r.registration_evidence.status, S::Unestablished);
        });
    }
}

#[test]
fn mapped_policy_wrong_service_and_simulated_origin_do_not_bind() {
    let rows = [SubjectMapping {
        service_identity: "https://other.example.test",
        receipt_subject: "site-A",
        statement_subject: "site-A",
        site_id: "site-A",
    }];
    Harness::new().run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                rows: &rows,
                provenance: auth(),
                origin: TrustInputOrigin::CallerAuthenticatedExternal,
            }
        },
        |r| assert_eq!(r.subject_policy.status, S::Unestablished),
    );
    let rows = [SubjectMapping {
        service_identity: TS,
        ..rows[0].clone()
    }];
    Harness::new().run(
        TRANSPARENT,
        &TransparentStatementPolicy::default(),
        |i| {
            i.subject = SubjectPolicy::AuthenticatedMappingV1 {
                rows: &rows,
                provenance: auth(),
                origin: TrustInputOrigin::LocalSimulation,
            }
        },
        |r| assert_eq!(r.subject_policy.status, S::Unestablished),
    );
}

#[test]
fn plain_ros_json_is_not_a_transparent_statement() {
    Harness::new().normal(
        br#"{"schema":"wilder.ros-evidence/dev/2","site":{"id":"site-A"}}"#,
        |r| {
            assert_eq!(r.outer.structure.status, S::Failed);
            assert_eq!(r.overall_profile.status, S::Unestablished);
            assert_eq!(r.hardware_appraisal.status, S::NotEvaluated);
            assert_eq!(r.issuer_signature.status, S::NotEvaluated);
        },
    );
}
