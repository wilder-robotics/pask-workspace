// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
#![cfg(feature = "alloc")]

use coset::cbor::Value as Cbor;
use ed25519_dalek::SigningKey;
use pask_wire::{
    Error, Payload, canonical_example, canonical_example_06, canonical_example_07, produce_ed25519,
    verify_ed25519,
};
use serde_json::{Value, json};

fn value07() -> Value {
    serde_json::from_str(&canonical_example_07().unwrap()).unwrap()
}

fn production(value: &Value) -> pask_wire::Result<Payload> {
    Payload::from_json_for_production(&serde_json::to_vec(value).unwrap())
}

#[test]
fn dedicated_07_emitter_reproduces_the_original_fixture_payload() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proposed07/replay/single-null.json")).unwrap();
    let bytes = hex::decode(fixture["entries"][0]["statement_hex"].as_str().unwrap()).unwrap();
    let cbor: Cbor = coset::cbor::de::from_reader(bytes.as_slice()).unwrap();
    let inner = match cbor {
        Cbor::Tag(18, value) => *value,
        value => value,
    };
    let Cbor::Array(parts) = inner else {
        panic!("expected statement array")
    };
    let Cbor::Bytes(original_payload) = &parts[2] else {
        panic!("expected attached bytes")
    };
    let payload = Payload::from_json(canonical_example_07().unwrap().as_bytes()).unwrap();
    assert_eq!(
        payload.to_jcs().unwrap().as_slice(),
        original_payload.as_slice()
    );
    let original: Value = serde_json::from_slice(original_payload).unwrap();
    assert_eq!(
        canonical_example_07().unwrap(),
        serde_json::to_string_pretty(&original).unwrap()
    );
}

#[test]
fn new_emitter_changes_only_profile_null_member_and_hash() {
    let mut old: Value = serde_json::from_str(&canonical_example_06().unwrap()).unwrap();
    let mut new = value07();
    assert_eq!(new["spec"], "wilder.pser/0.7");
    assert!(
        new["engagement"]
            .as_object()
            .unwrap()
            .contains_key("contentDigest")
    );
    assert!(new["engagement"]["contentDigest"].is_null());
    new["spec"] = old["spec"].clone();
    new["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    old["chain"].as_object_mut().unwrap().remove("hash");
    new["chain"].as_object_mut().unwrap().remove("hash");
    assert_eq!(new, old);
}

#[test]
fn old_emitters_retain_their_profiles_hashes_and_absent_member() {
    for (text, profile, expected_hash) in [
        (
            canonical_example().unwrap(),
            "wilder.pser/0.5",
            "sha256:6de1b8b2c641536b35fada1a7ee233c68284cf3788408a7160d5f525c309d2b3",
        ),
        (
            canonical_example_06().unwrap(),
            "wilder.pser/0.6",
            "sha256:9c5e4ef37e741d096118adfdb1fe46dcd72dd0f6960a11888d7a1815cf817e1e",
        ),
    ] {
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["spec"], profile);
        assert_eq!(v["chain"]["hash"], expected_hash);
        assert!(
            !v["engagement"]
                .as_object()
                .unwrap()
                .contains_key("contentDigest")
        );
        Payload::from_json(text.as_bytes()).unwrap();
    }
}

#[test]
fn legacy_profiles_reject_present_content_digest_after_rehashing() {
    for original in [
        canonical_example().unwrap(),
        canonical_example_06().unwrap(),
    ] {
        for extra in [Value::Null, json!(format!("sha256:{}", "a".repeat(64)))] {
            let mut v: Value = serde_json::from_str(&original).unwrap();
            v["engagement"]["contentDigest"] = extra;
            assert!(matches!(
                production(&v),
                Err(Error::Validation(
                    "contentDigest is not permitted in legacy profiles"
                ))
            ));
        }
    }
}

#[test]
fn new_profile_requires_the_member_and_rejects_wrong_types() {
    let mut v = value07();
    v["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    assert!(production(&v).is_err());
    for extra in [json!(1), json!(false), json!([]), json!({}), json!("bad")] {
        v["engagement"]["contentDigest"] = extra;
        assert!(production(&v).is_err());
    }
}

#[test]
fn new_example_signed_statement_roundtrip_uses_text_subject() {
    let payload = Payload::from_json(canonical_example_07().unwrap().as_bytes()).unwrap();
    let key = SigningKey::from_bytes(&[17; 32]);
    let statement = produce_ed25519(&payload, payload.witness_key(), &key).unwrap();
    let checked = verify_ed25519(&statement, &key.verifying_key()).unwrap();
    assert_eq!(checked.to_jcs().unwrap(), payload.to_jcs().unwrap());
    let outer: Cbor = coset::cbor::de::from_reader(statement.as_slice()).unwrap();
    let inner = match outer {
        Cbor::Tag(18, value) => *value,
        value => value,
    };
    let Cbor::Array(parts) = inner else {
        panic!("expected statement array")
    };
    let Cbor::Bytes(protected_bytes) = &parts[0] else {
        panic!("expected protected bytes")
    };
    let protected: Cbor = coset::cbor::de::from_reader(protected_bytes.as_slice()).unwrap();
    let Cbor::Map(headers) = protected else {
        panic!("expected protected map")
    };
    let (_, claims) = headers
        .iter()
        .find(|(key, _)| key == &Cbor::Integer(15.into()))
        .unwrap();
    let Cbor::Map(claims) = claims else {
        panic!("expected CWT claims map")
    };
    let (_, subject) = claims
        .iter()
        .find(|(key, _)| key == &Cbor::Integer(2.into()))
        .unwrap();
    assert_eq!(subject, &Cbor::Text(payload.site_id().to_string()));
}

#[test]
fn emitter_is_deterministic_and_does_not_depend_on_wall_clock() {
    let first = canonical_example_07().unwrap();
    for _ in 0..3 {
        assert_eq!(canonical_example_07().unwrap(), first);
    }
    assert_eq!(value07()["ts"], "2026-10-15T14:00:00Z");
}

#[test]
fn digest_content_variant_is_not_substituted_for_null_example() {
    let null = value07();
    let mut digest = null.clone();
    digest["engagement"]["contentDigest"] = json!(format!("sha256:{}", "b".repeat(64)));
    let with_digest = production(&digest).unwrap().to_jcs().unwrap();
    assert_ne!(with_digest, production(&null).unwrap().to_jcs().unwrap());
    assert_eq!(value07(), null);
}
