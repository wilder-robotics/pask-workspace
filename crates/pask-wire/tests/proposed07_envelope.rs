// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "alloc")]
use coset::cbor::Value as Cbor;
use ed25519_dalek::{Signer, SigningKey};
use pask_wire::{Payload, canonical_example_06, produce_ed25519, verify_ed25519};
use serde_json::{Value, json};

fn input() -> Value {
    let mut v: Value = serde_json::from_str(&canonical_example_06().unwrap()).unwrap();
    v["spec"] = json!("wilder.pser/0.7");
    v["engagement"]["contentDigest"] = Value::Null;
    v
}
fn payload(v: &Value) -> pask_wire::Result<Payload> {
    Payload::from_json_for_production(&serde_json::to_vec(v).unwrap())
}
fn encoded(v: &Cbor) -> Vec<u8> {
    let mut b = Vec::new();
    coset::cbor::ser::into_writer(v, &mut b).unwrap();
    b
}
// Independent envelope assembly: does not invoke production CwtClaims/header mapping.
fn fixture(p: &Payload, sub: Cbor, ct: &str, key: &SigningKey) -> Vec<u8> {
    let header = Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer((-8).into())),
        (Cbor::Integer(3.into()), Cbor::Text(ct.into())),
        (
            Cbor::Integer(15.into()),
            Cbor::Map(vec![
                (Cbor::Integer(1.into()), Cbor::Text(p.witness_key().into())),
                (Cbor::Integer(2.into()), sub),
            ]),
        ),
    ]);
    let h = encoded(&header);
    let body = p.to_jcs().unwrap();
    let signed = encoded(&Cbor::Array(vec![
        Cbor::Text("Signature1".into()),
        Cbor::Bytes(h.clone()),
        Cbor::Bytes(vec![]),
        Cbor::Bytes(body.clone()),
    ]));
    encoded(&Cbor::Array(vec![
        Cbor::Bytes(h),
        Cbor::Map(vec![]),
        Cbor::Bytes(body),
        Cbor::Bytes(key.sign(&signed).to_bytes().to_vec()),
    ]))
}
#[test]
fn explicit_null_and_digest_required_only_for_07() {
    let mut v = input();
    assert!(payload(&v).is_ok());
    v["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    assert!(payload(&v).is_err());
    for bad in [json!(42), json!("sha256:bad"), json!({})] {
        v["engagement"]["contentDigest"] = bad;
        assert!(payload(&v).is_err());
    }
    v["engagement"]["contentDigest"] = json!(format!("sha256:{}", "a".repeat(64)));
    let p = payload(&v).unwrap();
    assert_eq!(
        p.engagement_content_digest(),
        Some(&v["engagement"]["contentDigest"])
    );
    v["spec"] = json!("wilder.pser/0.6");
    assert!(payload(&v).is_err());
    v["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    assert!(payload(&v).is_ok());
}
#[test]
fn text_subject_roundtrip_and_independent_envelope() {
    let p = payload(&input()).unwrap();
    let k = SigningKey::from_bytes(&[17; 32]);
    let produced = produce_ed25519(&p, p.witness_key(), &k).unwrap();
    let expected = fixture(
        &p,
        Cbor::Text(p.site_id().into()),
        pask_wire::CONTENT_TYPE_07,
        &k,
    );
    assert_eq!(produced, expected);
    assert_eq!(
        verify_ed25519(&expected, &k.verifying_key())
            .unwrap()
            .to_jcs()
            .unwrap(),
        p.to_jcs().unwrap()
    );
    let wrong_type = fixture(
        &p,
        Cbor::Bytes(p.site_id().as_bytes().to_vec()),
        pask_wire::CONTENT_TYPE_07,
        &k,
    );
    assert!(verify_ed25519(&wrong_type, &k.verifying_key()).is_err());
    let wrong_value = fixture(
        &p,
        Cbor::Text("wrong".into()),
        pask_wire::CONTENT_TYPE_07,
        &k,
    );
    assert!(verify_ed25519(&wrong_value, &k.verifying_key()).is_err());
    let wrong_version = fixture(
        &p,
        Cbor::Text(p.site_id().into()),
        pask_wire::CONTENT_TYPE_06,
        &k,
    );
    assert!(verify_ed25519(&wrong_version, &k.verifying_key()).is_err());
}
#[test]
fn legacy_bytes_preserved_and_text_not_silently_accepted() {
    let k = SigningKey::from_bytes(&[17; 32]);
    for s in [
        pask_wire::canonical_example().unwrap(),
        canonical_example_06().unwrap(),
    ] {
        let p = Payload::from_json(s.as_bytes()).unwrap();
        let ct = if p.spec() == pask_wire::SPEC_VERSION {
            pask_wire::CONTENT_TYPE
        } else {
            pask_wire::CONTENT_TYPE_06
        };
        let produced = produce_ed25519(&p, p.witness_key(), &k).unwrap();
        assert_eq!(
            produced,
            fixture(&p, Cbor::Bytes(p.site_id().as_bytes().to_vec()), ct, &k)
        );
        assert!(verify_ed25519(&produced, &k.verifying_key()).is_ok());
        assert!(
            verify_ed25519(
                &fixture(&p, Cbor::Text(p.site_id().into()), ct, &k),
                &k.verifying_key()
            )
            .is_err()
        );
    }
}

#[test]
fn proposed07_retains_inclusive_timestamp_containment() {
    for at in ["2026-10-15T13:00:00Z", "2026-10-15T15:00:00Z"] {
        let mut v = input();
        v["ts"] = json!(at);
        assert!(payload(&v).is_ok());
    }
    for outside in ["2026-10-15T12:59:59Z", "2026-10-15T15:00:01Z"] {
        let mut v = input();
        v["ts"] = json!(outside);
        assert!(matches!(payload(&v), Err(pask_wire::Error::Validation(s))
            if s.contains("validity interval")));
    }
}

#[test]
fn proposed07_direct_identifier_rule_and_delegated_limit() {
    let k = SigningKey::from_bytes(&[17; 32]);
    let mut v = input();
    let p = payload(&v).unwrap();
    let bytes = produce_ed25519(&p, "key:tee:different", &k).unwrap();
    assert!(matches!(verify_ed25519(&bytes, &k.verifying_key()),
        Err(pask_wire::Error::Header(s)) if s.ends_with("wilder.pser/0.7")));
    v["attestation"]["bindingMode"] = json!("DELEGATED_WITNESS");
    let p = payload(&v).unwrap();
    let bytes = produce_ed25519(&p, "key:tee:different", &k).unwrap();
    assert!(verify_ed25519(&bytes, &k.verifying_key()).is_ok());
    // Acceptance here is the existing delegated naming rule, not authenticated
    // issuer/key provisioning, hardware appraisal or service independence.
}

#[cfg(feature = "es256")]
#[test]
fn proposed07_es256_roundtrip_and_wrong_key_rejection() {
    let p = payload(&input()).unwrap();
    let k = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let wrong = p256::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let bytes = pask_wire::produce_es256(&p, p.witness_key(), &k).unwrap();
    assert_eq!(
        pask_wire::verify_es256(&bytes, k.verifying_key()).unwrap(),
        p
    );
    assert!(pask_wire::verify_es256(&bytes, wrong.verifying_key()).is_err());
}
