#![allow(dead_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use pask_attest::clock::Clock;
use pask_attest::{AttestationVerifier, Ed25519RootOfTrust};
use serde_json::{Value, json};

pub const WITNESS_KEY: &str = "key:tee:res-001-witness-01";
pub const NOT_BEFORE_SECS: u64 = 1_792_069_200;
pub const NOT_AFTER_SECS: u64 = 1_792_076_400;
pub const MIDPOINT_SECS: u64 = 1_792_072_800;
pub const FRAME_VERSION: [u8; 8] = [b'a', 0, 0, 0, 0, 0, 0, 1];

#[derive(Clone, Copy, Debug)]
pub struct TestClock(pub SystemTime);

impl Clock for TestClock {
    fn now_rfc3339(&self) -> String {
        let secs = self
            .0
            .duration_since(UNIX_EPOCH)
            .expect("test clock earlier than UNIX epoch")
            .as_secs();
        // Delegate to pask-site's SystemClock formatting via a helper time crate call.
        // Format: YYYY-MM-DDTHH:MM:SSZ
        let dt =
            time::OffsetDateTime::from_unix_timestamp(secs as i64).expect("test clock in-range");
        dt.format(&time::format_description::well_known::Rfc3339)
            .expect("rfc3339 format")
    }
}

pub fn clock_at(unix_seconds: u64) -> TestClock {
    TestClock(UNIX_EPOCH + Duration::from_secs(unix_seconds))
}

pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn root(signing_key: &SigningKey, witness_key: &str) -> Ed25519RootOfTrust {
    Ed25519RootOfTrust::new().with_key(witness_key.to_owned(), signing_key.verifying_key())
}

pub fn sample_claims(witness_key: &str) -> Value {
    let mut claims = json!({
        "spec": "wilder.attest/0.1",
        "teeClass": "arm64.tee-v1",
        "measuredBoot": {
            "chain": "",
            "components": [
                {
                    "name": "bootloader",
                    "digest": format!("sha256:{}", "11".repeat(32))
                },
                {
                    "name": "kernel",
                    "digest": format!("sha256:{}", "22".repeat(32))
                }
            ]
        },
        "platformEvidence": {
            "encoding": "opaque/1",
            "digest": format!("sha256:{}", "33".repeat(32))
        },
        "sealedEvidence": {
            "digest": format!("sha256:{}", "44".repeat(32)),
            "sizeBytes": 4096,
            "encoding": "opaque/1"
        },
        "witnessKey": witness_key,
        "validity": {
            "notBefore": "2026-10-15T13:00:00Z",
            "notAfter": "2026-10-15T15:00:00Z"
        }
    });
    recompute_chain(&mut claims);
    claims
}

pub fn recompute_chain(claims: &mut Value) {
    let components = claims["measuredBoot"]["components"].clone();
    let serialized = serde_json::to_vec(&components).unwrap();
    let canonical = pask_wire::canonicalize_json(&serialized).unwrap();
    claims["measuredBoot"]["chain"] = Value::String(pask_wire::sha256_prefixed(&canonical));
}

pub fn signed_quote(claims: &Value, signing_key: &SigningKey) -> Vec<u8> {
    let serialized = serde_json::to_vec(claims).unwrap();
    let jcs = pask_wire::canonicalize_json(&serialized).unwrap();
    let signature = signing_key.sign(&jcs);
    let mut quote =
        Vec::with_capacity(FRAME_VERSION.len() + jcs.len() + signature.to_bytes().len());
    quote.extend_from_slice(&FRAME_VERSION);
    quote.extend_from_slice(&jcs);
    quote.extend_from_slice(&signature.to_bytes());
    quote
}

pub fn valid_quote(signing_key: &SigningKey, witness_key: &str) -> Vec<u8> {
    signed_quote(&sample_claims(witness_key), signing_key)
}

pub fn verified_attestation() -> pask_attest::Attestation {
    let key = signing_key(7);
    root(&key, WITNESS_KEY)
        .verify(&valid_quote(&key, WITNESS_KEY), &clock_at(MIDPOINT_SECS))
        .unwrap()
}
