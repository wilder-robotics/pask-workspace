// SPDX-License-Identifier: Apache-2.0
//! P06-CONFORMANCE-01 successor: version-specific supplied-key wire characterization.
//!
//! No production verifier, attestation appraiser, or alternate profile is defined here.
//! The private author package held by the owner was not compiled or executed.
//! This file is a separate identity from that candidate.
//! The fixed seed below is PUBLIC SYNTHETIC TEST MATERIAL, not an issuer or hardware key.
//! Cases use independently assembled COSE envelopes and signature-positive controls.
//! C14-synthetic does not replay the closed audit's exact baseline/test-key pair.
//! That pair is not present in this file.
//! Run with `--features alloc`. A zero-test run is not acceptance.
#![cfg(feature = "alloc")]

use coset::cbor::Value as Cbor;
use ed25519_dalek::{Signature, Signer, SigningKey};
use pask_wire::{
    Error, Payload, canonical_example_06, canonicalize_json, sha256_prefixed, verify_ed25519,
};
use serde_json::{Value, json};

const TEST_SEED: [u8; 32] = [0xc6; 32];
const V05: &str = "wilder.pser/0.5";
const V06: &str = "wilder.pser/0.6";
const V07: &str = "wilder.pser/0.7";

#[derive(Debug)]
enum Expected {
    Accept,
    Header(&'static str),
    Validation(&'static str),
    JsonContains(&'static str),
}

struct Fixture {
    statement: Vec<u8>,
    payload: Vec<u8>,
}

fn base(spec: &str) -> Value {
    let mut value: Value =
        serde_json::from_str(&canonical_example_06().expect("unchanged example"))
            .expect("example JSON");
    value["spec"] = json!(spec);
    if spec == V07 {
        value["engagement"]["contentDigest"] = Value::Null;
    } else {
        value["engagement"]
            .as_object_mut()
            .expect("engagement object")
            .remove("contentDigest");
    }
    value
}

fn encode(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(value, &mut bytes).expect("synthetic CBOR serialization");
    bytes
}

// Use the existing JCS/hash primitives, but DO NOT invoke payload validation here.
// Invalid-profile negative cases need a correctly rehashed and signed raw payload,
// rather than a failed producer call or a stale signature that masks the intended rule.
fn rehash_payload(value: &Value) -> Vec<u8> {
    let mut value = value.clone();
    value["chain"]
        .as_object_mut()
        .expect("chain object")
        .remove("hash");
    let without_hash = canonicalize_json(&serde_json::to_vec(&value).expect("JSON"))
        .expect("JCS without chain.hash");
    value["chain"]["hash"] = json!(sha256_prefixed(&without_hash));
    canonicalize_json(&serde_json::to_vec(&value).expect("JSON")).expect("complete JCS")
}

fn default_subject(value: &Value) -> Cbor {
    let site = value["site"]["id"].as_str().expect("site identifier");
    if value["spec"].as_str() == Some(V07) {
        Cbor::Text(site.into())
    } else {
        Cbor::Bytes(site.as_bytes().to_vec())
    }
}

fn fixture(value: &Value, subject: Cbor, issuer: &str, content_type: Option<&str>) -> Fixture {
    let payload = rehash_payload(value);
    let inferred = format!(
        "application/pser+json; profile={}",
        value["spec"].as_str().expect("spec")
    );
    let protected = encode(&Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer((-8).into())),
        (
            Cbor::Integer(3.into()),
            Cbor::Text(content_type.unwrap_or(&inferred).into()),
        ),
        (
            Cbor::Integer(15.into()),
            Cbor::Map(vec![
                (Cbor::Integer(1.into()), Cbor::Text(issuer.into())),
                (Cbor::Integer(2.into()), subject),
            ]),
        ),
    ]));
    let to_sign = encode(&Cbor::Array(vec![
        Cbor::Text("Signature1".into()),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(vec![]),
        Cbor::Bytes(payload.clone()),
    ]));
    let signature: Signature = SigningKey::from_bytes(&TEST_SEED).sign(&to_sign);
    let statement = encode(&Cbor::Array(vec![
        Cbor::Bytes(protected),
        Cbor::Map(vec![]),
        Cbor::Bytes(payload.clone()),
        Cbor::Bytes(signature.to_bytes().to_vec()),
    ]));
    Fixture { statement, payload }
}

fn ordinary(value: &Value) -> Fixture {
    fixture(
        value,
        default_subject(value),
        value["attestation"]["witnessKey"]
            .as_str()
            .expect("witness identifier"),
        None,
    )
}

// Decode the bytes actually passed to the vendor function, reconstruct Sig_structure,
// and require their signature to verify before asking the profile verifier to accept
// or reject. This is not a hardware or trust-provenance appraisal.
fn signature_control(bytes: &[u8]) {
    let mut remaining = bytes;
    let outer: Cbor = coset::cbor::de::from_reader(&mut remaining).expect("synthetic COSE");
    assert!(
        remaining.is_empty(),
        "no trailing data in these controlled cases"
    );
    let outer = match outer {
        Cbor::Tag(18, inner) => *inner,
        other => other,
    };
    let Cbor::Array(items) = outer else {
        panic!("COSE array required");
    };
    let [
        Cbor::Bytes(protected),
        Cbor::Map(unprotected),
        Cbor::Bytes(payload),
        Cbor::Bytes(signature),
    ] = items.as_slice()
    else {
        panic!("controlled COSE shape required");
    };
    assert!(unprotected.is_empty());
    let signed = encode(&Cbor::Array(vec![
        Cbor::Text("Signature1".into()),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(vec![]),
        Cbor::Bytes(payload.clone()),
    ]));
    SigningKey::from_bytes(&TEST_SEED)
        .verifying_key()
        .verify_strict(
            &signed,
            &Signature::from_slice(signature).expect("Ed25519 signature"),
        )
        .expect("negative profile case must still have a valid test-key signature");
}

fn check(case: &str, variant: &str, f: &Fixture, expected: Expected) -> Option<Payload> {
    signature_control(&f.statement);
    let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
    let result = verify_ed25519(&f.statement, &key);
    let observed = match &result {
        Ok(p) => json!({"wire_result":"ACCEPTED", "spec":p.spec(), "chain_hash":p.chain_hash()}),
        Err(e) => {
            json!({"wire_result":"REJECTED", "error_debug":format!("{e:?}"), "error_display":e.to_string()})
        }
    };
    // When an authorized executor runs with --nocapture, retain this complete line
    // together with the process stdout/stderr, exit, and checked source identity.
    println!(
        "{}",
        json!({
            "schema":"pask.private.conformance-case-observation/1", "case":case, "variant":variant,
            "test_material":"PUBLIC_SYNTHETIC_TEST_KEY_NO_HARDWARE_ASSURANCE",
            "signature_positive_control":true, "verification_key_hex":hex::encode(key.as_bytes()),
            "input_bytes":f.statement.len(), "input_sha256":sha256_prefixed(&f.statement),
            "statement_hex":hex::encode(&f.statement), "payload_sha256":sha256_prefixed(&f.payload),
            "expected":format!("{expected:?}"), "observed":observed,
        })
    );
    match expected {
        Expected::Accept => {
            let p = result.expect("expected supplied-key wire acceptance only");
            assert_eq!(p.to_jcs().expect("verified payload JCS"), f.payload);
            Some(p)
        }
        Expected::Header(message) => {
            assert!(
                matches!(&result, Err(Error::Header(actual)) if *actual == message),
                "{case}/{variant}: {result:?}"
            );
            None
        }
        Expected::Validation(message) => {
            assert!(
                matches!(&result, Err(Error::Validation(actual)) if *actual == message),
                "{case}/{variant}: {result:?}"
            );
            None
        }
        Expected::JsonContains(text) => {
            assert!(
                matches!(&result, Err(Error::Json(actual)) if actual.contains(text)),
                "{case}/{variant}: {result:?}"
            );
            None
        }
    }
}

#[test]
fn c01_explicit_null_07_is_wire_accepted() {
    let _ = check(
        "C01",
        "explicit-null",
        &ordinary(&base(V07)),
        Expected::Accept,
    );
}

#[test]
fn c02_well_formed_content_root_is_not_content_verification() {
    let mut v = base(V07);
    v["engagement"]["contentDigest"] = json!(format!("sha256:{}", "a".repeat(64)));
    let _ = check(
        "C02",
        "syntactic-root-no-content-presented",
        &ordinary(&v),
        Expected::Accept,
    );
}

#[test]
fn c03_omitted_nested_content_digest_is_not_null() {
    let mut v = base(V07);
    v["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    let _ = check(
        "C03",
        "omitted",
        &ordinary(&v),
        Expected::Validation("0.7 requires explicit null or SHA-256 contentDigest"),
    );
}

#[test]
fn c04_top_level_content_digest_is_not_the_nested_member() {
    let mut v = base(V07);
    v["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    v["contentDigest"] = Value::Null;
    let _ = check(
        "C04",
        "top-level-only",
        &ordinary(&v),
        Expected::JsonContains("unknown field `contentDigest`"),
    );
}

#[test]
fn c05_non_string_non_null_content_digests_are_rejected() {
    for (name, bad) in [
        ("boolean", json!(false)),
        ("integer", json!(0)),
        ("array", json!([])),
        ("object", json!({})),
    ] {
        let mut v = base(V07);
        v["engagement"]["contentDigest"] = bad;
        let _ = check(
            "C05",
            name,
            &ordinary(&v),
            Expected::Validation("0.7 requires explicit null or SHA-256 contentDigest"),
        );
    }
}

#[test]
fn c05_malformed_digest_strings_are_rejected() {
    for (name, bad, message) in [
        ("empty", String::new(), "digest prefix must be sha256:"),
        (
            "wrong-prefix",
            format!("sha512:{}", "a".repeat(64)),
            "digest prefix must be sha256:",
        ),
        (
            "uppercase-prefix",
            format!("SHA256:{}", "a".repeat(64)),
            "digest prefix must be sha256:",
        ),
        (
            "uppercase-hex",
            format!("sha256:{}", "A".repeat(64)),
            "digest must contain 64 lowercase hexadecimal digits",
        ),
        (
            "63-hex",
            format!("sha256:{}", "a".repeat(63)),
            "digest must contain 64 lowercase hexadecimal digits",
        ),
        (
            "65-hex",
            format!("sha256:{}", "a".repeat(65)),
            "digest must contain 64 lowercase hexadecimal digits",
        ),
        (
            "nonhex",
            format!("sha256:{}", "g".repeat(64)),
            "digest must contain 64 lowercase hexadecimal digits",
        ),
        (
            "leading-space",
            format!(" sha256:{}", "a".repeat(64)),
            "digest prefix must be sha256:",
        ),
        (
            "trailing-space",
            format!("sha256:{} ", "a".repeat(64)),
            "digest must contain 64 lowercase hexadecimal digits",
        ),
    ] {
        let mut v = base(V07);
        v["engagement"]["contentDigest"] = json!(bad);
        let _ = check("C05", name, &ordinary(&v), Expected::Validation(message));
    }
}

#[test]
fn c06_same_utf8_bytes_in_a_byte_string_do_not_satisfy_07_sub_type() {
    let v = base(V07);
    let f = fixture(
        &v,
        Cbor::Bytes(v["site"]["id"].as_str().unwrap().as_bytes().to_vec()),
        v["attestation"]["witnessKey"].as_str().unwrap(),
        None,
    );
    let _ = check(
        "C06",
        "byte-string",
        &f,
        Expected::Header("0.7 CWT sub must be text"),
    );
}

#[test]
fn c07_text_subject_must_match_site_id_without_case_folding() {
    let v = base(V07);
    for (name, sub) in [
        ("different", "site:other".to_string()),
        (
            "case",
            v["site"]["id"].as_str().unwrap().to_ascii_uppercase(),
        ),
    ] {
        let f = fixture(
            &v,
            Cbor::Text(sub),
            v["attestation"]["witnessKey"].as_str().unwrap(),
            None,
        );
        let _ = check(
            "C07",
            name,
            &f,
            Expected::Header("CWT sub does not match site.id"),
        );
    }
}

#[test]
fn c08_direct_07_name_equality_is_exact() {
    let v = base(V07);
    let name = v["attestation"]["witnessKey"].as_str().unwrap();
    for (variant, issuer) in [
        ("one-extra-character", format!("{name}X")),
        ("case", name.to_ascii_uppercase()),
    ] {
        let f = fixture(&v, default_subject(&v), &issuer, None);
        let _ = check(
            "C08",
            variant,
            &f,
            Expected::Header(
                "DIRECT_WITNESS witnessKey and CWT iss must be textually equal under wilder.pser/0.7",
            ),
        );
    }
}

#[test]
fn c09_legacy_06_byte_subject_and_absent_content_member_are_preserved() {
    let _ = check("C09", "legacy-06", &ordinary(&base(V06)), Expected::Accept);
}

#[test]
fn c10_legacy_06_rejects_added_content_member_or_text_subject() {
    for (name, value) in [
        ("explicit-null", Value::Null),
        ("digest", json!(format!("sha256:{}", "a".repeat(64)))),
    ] {
        let mut v = base(V06);
        v["engagement"]["contentDigest"] = value;
        let _ = check(
            "C10",
            name,
            &ordinary(&v),
            Expected::Validation("contentDigest is not permitted in legacy profiles"),
        );
    }
    let v = base(V06);
    let f = fixture(
        &v,
        Cbor::Text(v["site"]["id"].as_str().unwrap().into()),
        v["attestation"]["witnessKey"].as_str().unwrap(),
        None,
    );
    let _ = check(
        "C10",
        "text-subject",
        &f,
        Expected::Header("CWT sub must be bytes"),
    );
}

#[test]
fn c11_legacy_06_direct_name_mismatch_still_fails() {
    let v = base(V06);
    let f = fixture(&v, default_subject(&v), "key:tee:different", None);
    let _ = check(
        "C11",
        "direct-06",
        &f,
        Expected::Header(
            "DIRECT_WITNESS witnessKey and CWT iss must be textually equal under wilder.pser/0.6",
        ),
    );
}

#[test]
fn c12_delegated_name_inequality_is_not_delegation_authentication() {
    for spec in [V06, V07] {
        let mut v = base(spec);
        v["attestation"]["bindingMode"] = json!("DELEGATED_WITNESS");
        let f = fixture(&v, default_subject(&v), "key:issuer:different", None);
        let _ = check("C12", spec, &f, Expected::Accept);
    }
}

#[test]
fn c13_recorded_ts_containment_uses_inclusive_endpoints() {
    for spec in [V06, V07] {
        for (name, ts, expected) in [
            ("lower", "2026-10-15T13:00:00Z", Expected::Accept),
            ("upper", "2026-10-15T15:00:00Z", Expected::Accept),
            (
                "before",
                "2026-10-15T12:59:59Z",
                Expected::Validation(
                    "receipt-issuance timestamp is outside the attestation validity interval",
                ),
            ),
            (
                "after",
                "2026-10-15T15:00:01Z",
                Expected::Validation(
                    "receipt-issuance timestamp is outside the attestation validity interval",
                ),
            ),
        ] {
            let mut v = base(spec);
            v["attestation"]["validity"]["notBefore"] = json!("2026-10-15T13:00:00Z");
            v["attestation"]["validity"]["notAfter"] = json!("2026-10-15T15:00:00Z");
            v["ts"] = json!(ts);
            let _ = check("C13", &format!("{spec}/{name}"), &ordinary(&v), expected);
        }
    }
}

#[test]
fn c14_synthetic_tag_twin_characterizes_presented_bytes_only() {
    for spec in [V06, V07] {
        let f = ordinary(&base(spec));
        assert_eq!(
            f.statement.first(),
            Some(&0x84),
            "four-element untagged COSE array"
        );
        let mut tagged = vec![0xd2];
        tagged.extend_from_slice(&f.statement);
        let twin = Fixture {
            statement: tagged,
            payload: f.payload.clone(),
        };
        let a = check(
            "C14-SYNTHETIC",
            &format!("{spec}/untagged"),
            &f,
            Expected::Accept,
        )
        .unwrap();
        let b = check(
            "C14-SYNTHETIC",
            &format!("{spec}/tag18"),
            &twin,
            Expected::Accept,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_ne!(
            sha256_prefixed(&f.statement),
            sha256_prefixed(&twin.statement)
        );
        assert_eq!(&twin.statement[1..], f.statement.as_slice());
        // No semantic/canonical statement-identity field or de-duplication rule is allocated.
    }
}

#[test]
fn supplemental_05_checks_are_not_retroactively_strengthened() {
    let mut v = base(V05);
    v["ts"] = json!("2026-10-15T12:59:59Z");
    let f = fixture(&v, default_subject(&v), "key:issuer:different", None);
    let _ = check(
        "LEGACY05",
        "outside-interval-and-name-mismatch",
        &f,
        Expected::Accept,
    );
    v["engagement"]["contentDigest"] = Value::Null;
    let _ = check(
        "LEGACY05",
        "new-member-refused",
        &ordinary(&v),
        Expected::Validation("contentDigest is not permitted in legacy profiles"),
    );
}

#[test]
fn supplemental_envelope_conformance_is_not_inferred_by_wire_acceptance() {
    let mut v = base(V07);
    v["site"]["envelope"]["temporal"]["starts"] = json!("2026-10-16T00:00:00Z");
    v["site"]["envelope"]["temporal"]["ends"] = json!("2026-10-16T01:00:00Z");
    v["engagement"]["envelopeConformance"] = json!("UNKNOWN");
    let p = check(
        "TEMPORAL-BOUNDARY",
        "outside-envelope-remains-unknown",
        &ordinary(&v),
        Expected::Accept,
    )
    .unwrap();
    let parsed: Value = serde_json::from_slice(&p.to_jcs().unwrap()).unwrap();
    assert_eq!(parsed["engagement"]["envelopeConformance"], "UNKNOWN");
}

#[test]
fn supplemental_zero_duration_attestation_interval_is_rejected() {
    for spec in [V06, V07] {
        let mut v = base(spec);
        v["attestation"]["validity"]["notBefore"] = json!("2026-10-15T14:00:00Z");
        v["attestation"]["validity"]["notAfter"] = json!("2026-10-15T14:00:00Z");
        let _ = check(
            "INTERVAL-SHAPE",
            spec,
            &ordinary(&v),
            Expected::Validation(
                "attestation validity notAfter must be strictly later than notBefore",
            ),
        );
    }
}

#[test]
fn supplemental_header_profile_must_match_payload_profile() {
    let v = base(V07);
    let f = fixture(
        &v,
        default_subject(&v),
        v["attestation"]["witnessKey"].as_str().unwrap(),
        Some(pask_wire::CONTENT_TYPE_06),
    );
    let _ = check(
        "PROFILE-AGREEMENT",
        "07-payload-06-header",
        &f,
        Expected::Header("protected content_type does not match payload spec version"),
    );
}
