// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

#![allow(dead_code)]

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pask_adapter::{
    BuildiumWriteIn, CredentialProvider, Credentials, DedupLog, HttpTransport, RetryPolicy,
    StaticCredentialProvider,
};
use pask_wire::{Payload, produce_ed25519};
use serde_json::json;

pub fn signed_receipt() -> (Vec<u8>, VerifyingKey) {
    signed_receipt_for("buildium", "rental-42")
}

pub fn signed_receipt_for(adapter_system: &str, adapter_endpoint: &str) -> (Vec<u8>, VerifyingKey) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let zero = format!("sha256:{}", "0".repeat(64));
    let one = format!("sha256:{}", "1".repeat(64));
    let two = format!("sha256:{}", "2".repeat(64));
    let three = format!("sha256:{}", "3".repeat(64));
    let four = format!("sha256:{}", "4".repeat(64));

    let input = serde_json::to_vec(&json!({
        "spec": "wilder.pser/0.1",
        "id": "test-receipt-1",
        "ts": "2026-07-12T00:00:00Z",
        "site": {
            "id": "RES-001",
            "class": "residential",
            "envelope": {
                "id": "site-env-1",
                "digest": zero,
                "geobounds": null,
                "temporal": {
                    "starts": null,
                    "ends": null
                }
            }
        },
        "actor": {
            "id": "actor-1",
            "class": "AUTONOMOUS",
            "operator": "site-operator@residential.example"
        },
        "engagement": {
            "id": "eng-1",
            "window": {
                "start": "2026-07-12T00:00:00Z",
                "end": "2026-07-12T00:05:00Z"
            },
            "type": "physical-site/service-visit",
            "outcomeClass": "COMPLETED",
            "envelopeConformance": "WITHIN",
            "evidenceDigest": one
        },
        "attestation": {
            "teeClass": "test-tee",
            "platformEvidence": "test-platform",
            "measuredBootChain": two,
            "sealedEvidence": {
                "digest": three,
                "sizeBytes": 4096,
                "encoding": "cbor"
            },
            "witnessKey": "witness-1"
        },
        "adapter": {
            "system": adapter_system,
            "endpoint": adapter_endpoint,
            "postedAt": "2026-07-12T00:05:01Z",
            "ackDigest": four,
            "mode": "WRITE_ONLY"
        },
        "chain": {
            "seq": 0,
            "prevHash": null,
            "hash": format!("sha256:{}", "0".repeat(64))
        }
    }))
    .expect("fixture JSON must serialize");

    let payload = Payload::from_json_for_production(&input).expect("fixture payload must validate");
    let statement = produce_ed25519(&payload, payload.witness_key(), &signing_key)
        .expect("fixture receipt must be produced");
    (statement, signing_key.verifying_key())
}

pub fn static_credentials() -> impl CredentialProvider {
    StaticCredentialProvider::new(Credentials {
        client_id: "test-id".to_owned(),
        client_secret: "test-secret".to_owned(),
    })
}

pub fn buildium(
    transport: Arc<dyn HttpTransport>,
    dedup: Arc<dyn DedupLog>,
    retry_policy: RetryPolicy,
) -> BuildiumWriteIn {
    BuildiumWriteIn::new(
        "https://example.test",
        transport,
        Arc::new(static_credentials()),
        dedup,
        retry_policy,
    )
    .expect("test base URL must be valid")
}
