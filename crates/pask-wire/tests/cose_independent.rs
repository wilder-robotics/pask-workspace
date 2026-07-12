// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Independent COSE verification using `coset` directly.

use coset::{Algorithm, AsCborValue, ContentType, CoseSign1, Label, iana};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use pask_wire::{CONTENT_TYPE, Payload, produce_ed25519, testvectors::MINIMAL_VALID_PAYLOAD};

#[test]
fn coset_directly_verifies_ed25519_statement() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let encoded = produce_ed25519(&payload, payload.witness_key(), &key).unwrap();

    let parsed = parse_with_coset(&encoded);
    assert_eq!(
        parsed.protected.header.alg,
        Some(Algorithm::Assigned(iana::Algorithm::EdDSA))
    );
    assert_eq!(
        parsed.protected.header.content_type,
        Some(ContentType::Text(CONTENT_TYPE.to_owned()))
    );
    let claims = parsed
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| label == &Label::Int(15))
        .unwrap();
    let coset::cbor::Value::Map(entries) = &claims.1 else {
        panic!("CWT_Claims must be a map");
    };
    assert!(
        entries
            .iter()
            .any(|(label, _)| { label == &coset::cbor::Value::Integer(1_i64.into()) })
    );
    assert!(entries.iter().any(|(label, value)| {
        label == &coset::cbor::Value::Integer(2_i64.into())
            && value == &coset::cbor::Value::Bytes(payload.site_id().as_bytes().to_vec())
    }));
    assert_eq!(
        parsed.payload.as_deref(),
        Some(payload.to_jcs().unwrap().as_slice())
    );

    parsed
        .verify_signature(&[], |signature, data| {
            let signature = Signature::from_slice(signature).unwrap();
            key.verifying_key().verify(data, &signature)
        })
        .unwrap();
}

fn parse_with_coset(mut encoded: &[u8]) -> CoseSign1 {
    let mut value: coset::cbor::Value = coset::cbor::de::from_reader(&mut encoded).unwrap();
    assert!(encoded.is_empty());
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
    statement.protected.header.content_type = Some(ContentType::Text(CONTENT_TYPE.to_owned()));
    statement
}
