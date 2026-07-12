// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Negative payload and protected-header tests.

use coset::{AsCborValue, CborSerializable, CoseSign1, Label};
use ed25519_dalek::SigningKey;
use pask_wire::{
    CONTENT_TYPE, Payload, produce_ed25519,
    testvectors::{
        INVALID_ACTOR_CLASS, INVALID_ADAPTER_MODE, INVALID_DIGEST, MINIMAL_VALID_PAYLOAD,
        REVERSED_WINDOW_END, WRONG_CONTENT_TYPE, WRONG_CWT_SUBJECT, WRONG_SPEC,
    },
    verify_ed25519,
};
use serde_json::{Value, json};

const REQUIRED_PATHS: &[&[&str]] = &[
    &["spec"],
    &["id"],
    &["ts"],
    &["site"],
    &["site", "id"],
    &["site", "class"],
    &["site", "envelope"],
    &["site", "envelope", "id"],
    &["site", "envelope", "digest"],
    &["site", "envelope", "geobounds"],
    &["site", "envelope", "temporal"],
    &["site", "envelope", "temporal", "starts"],
    &["site", "envelope", "temporal", "ends"],
    &["actor"],
    &["actor", "id"],
    &["actor", "class"],
    &["actor", "operator"],
    &["engagement"],
    &["engagement", "id"],
    &["engagement", "window"],
    &["engagement", "window", "start"],
    &["engagement", "window", "end"],
    &["engagement", "type"],
    &["engagement", "outcomeClass"],
    &["engagement", "envelopeConformance"],
    &["engagement", "evidenceDigest"],
    &["attestation"],
    &["attestation", "teeClass"],
    &["attestation", "platformEvidence"],
    &["attestation", "measuredBootChain"],
    &["attestation", "sealedEvidence"],
    &["attestation", "sealedEvidence", "digest"],
    &["attestation", "sealedEvidence", "sizeBytes"],
    &["attestation", "sealedEvidence", "encoding"],
    &["attestation", "witnessKey"],
    &["adapter"],
    &["adapter", "system"],
    &["adapter", "endpoint"],
    &["adapter", "postedAt"],
    &["adapter", "ackDigest"],
    &["adapter", "mode"],
    &["chain"],
    &["chain", "seq"],
    &["chain", "prevHash"],
    &["chain", "hash"],
];

fn normalized_value() -> Value {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
    serde_json::from_slice(&payload.to_jcs().unwrap()).unwrap()
}

fn remove_path(value: &mut Value, path: &[&str]) {
    let (leaf, parents) = path.split_last().unwrap();
    let mut parent = value;
    for segment in parents {
        parent = parent.get_mut(*segment).unwrap();
    }
    parent.as_object_mut().unwrap().remove(*leaf);
}

fn assert_payload_rejected(value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(Payload::from_json(&bytes).is_err());
}

fn valid_statement() -> (CoseSign1, SigningKey) {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let bytes = produce_ed25519(&payload, payload.witness_key(), &key).unwrap();
    (parse_with_coset(&bytes), key)
}

fn parse_with_coset(mut encoded: &[u8]) -> CoseSign1 {
    let mut value: coset::cbor::Value = coset::cbor::de::from_reader(&mut encoded).unwrap();
    let coset::cbor::Value::Array(items) = &mut value else {
        panic!("statement must be an array");
    };
    let coset::cbor::Value::Bytes(protected) = &mut items[0] else {
        panic!("protected header must be bytes");
    };
    let original = protected.clone();
    let start = protected
        .windows(CONTENT_TYPE.len())
        .position(|window| window == CONTENT_TYPE.as_bytes())
        .unwrap();
    protected[start + CONTENT_TYPE.rfind('/').unwrap()] = b'-';
    let mut statement = CoseSign1::from_cbor_value(value).unwrap();
    statement.protected.original_data = Some(original);
    statement.protected.header.content_type =
        Some(coset::ContentType::Text(CONTENT_TYPE.to_owned()));
    statement
}

#[test]
fn malformed_json_is_rejected() {
    assert!(Payload::from_json(b"{not-json").is_err());
}

#[test]
fn every_required_field_is_rejected_when_absent() {
    for path in REQUIRED_PATHS {
        let mut value = normalized_value();
        remove_path(&mut value, path);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            Payload::from_json(&bytes).is_err(),
            "missing field was accepted: {path:?}"
        );
    }
}

#[test]
fn package_payload_mutations_are_rejected() {
    let mutations: &[(&[&str], Value)] = &[
        (&["spec"], json!(WRONG_SPEC)),
        (&["actor", "class"], json!(INVALID_ACTOR_CLASS)),
        (&["engagement", "window", "end"], json!(REVERSED_WINDOW_END)),
        (
            &["attestation", "sealedEvidence", "digest"],
            json!(INVALID_DIGEST),
        ),
        (&["adapter", "mode"], json!(INVALID_ADAPTER_MODE)),
    ];
    for (path, replacement) in mutations {
        let mut value = normalized_value();
        let (leaf, parents) = path.split_last().unwrap();
        let mut parent = &mut value;
        for segment in parents {
            parent = parent.get_mut(*segment).unwrap();
        }
        parent[*leaf] = replacement.clone();
        assert_payload_rejected(&value);
    }

    let mut missing_site_id = normalized_value();
    remove_path(&mut missing_site_id, &["site", "id"]);
    assert_payload_rejected(&missing_site_id);
}

#[test]
fn content_type_must_be_present_and_exact() {
    for content_type in [None, Some(WRONG_CONTENT_TYPE)] {
        let (mut statement, key) = valid_statement();
        statement.protected.header.content_type =
            content_type.map(|value| coset::ContentType::Text(value.to_owned()));
        statement.protected.original_data = None;
        let bytes = statement.to_vec().unwrap();
        assert!(verify_ed25519(&bytes, &key.verifying_key()).is_err());
    }
    assert_ne!(WRONG_CONTENT_TYPE, CONTENT_TYPE);
}

#[test]
fn cwt_subject_must_equal_site_id_bytes() {
    let (mut statement, key) = valid_statement();
    let claims = statement
        .protected
        .header
        .rest
        .iter_mut()
        .find(|(label, _)| label == &Label::Int(15))
        .unwrap();
    let coset::cbor::Value::Map(entries) = &mut claims.1 else {
        panic!("claims must be a map");
    };
    let subject = entries
        .iter_mut()
        .find(|(label, _)| label == &coset::cbor::Value::Integer(2_i64.into()))
        .unwrap();
    subject.1 = coset::cbor::Value::Bytes(WRONG_CWT_SUBJECT.to_vec());
    statement.protected.original_data = None;
    let bytes = statement.to_vec().unwrap();
    assert!(verify_ed25519(&bytes, &key.verifying_key()).is_err());
}

#[test]
fn mismatched_chain_hash_is_rejected() {
    let (mut statement, key) = valid_statement();
    let mut value: Value = serde_json::from_slice(statement.payload.as_ref().unwrap()).unwrap();
    value["chain"]["hash"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    statement.payload =
        Some(pask_wire::canonicalize_json(&serde_json::to_vec(&value).unwrap()).unwrap());
    let bytes = statement.to_vec().unwrap();
    assert!(verify_ed25519(&bytes, &key.verifying_key()).is_err());
}

#[test]
fn noncanonical_payload_bytes_are_rejected() {
    let (mut statement, key) = valid_statement();
    let value: Value = serde_json::from_slice(statement.payload.as_ref().unwrap()).unwrap();
    statement.payload = Some(serde_json::to_vec_pretty(&value).unwrap());
    let bytes = statement.to_vec().unwrap();
    assert!(verify_ed25519(&bytes, &key.verifying_key()).is_err());
}

#[test]
fn tampered_signature_is_rejected() {
    let (mut statement, key) = valid_statement();
    // Force coset to reserialize protected header from parsed form rather
    // than the cloned original, so the signature-flip is the only tamper.
    statement.protected.original_data = None;
    assert!(
        !statement.signature.is_empty(),
        "signature must be non-empty"
    );
    statement.signature[0] ^= 0x01;
    let bytes = statement.to_vec().unwrap();
    assert!(verify_ed25519(&bytes, &key.verifying_key()).is_err());
}
