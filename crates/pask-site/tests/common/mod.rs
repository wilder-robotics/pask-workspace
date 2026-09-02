// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

#![allow(dead_code)]

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pask_adapter::{
    BuildiumWriteIn, Credentials, DedupLog, HttpResponse, HttpTransport, RetryPolicy,
    StaticCredentialProvider,
};
use pask_site::{Ed25519SiteProducer, EngagementRequest, FixedClock, fixtures::res_001};

/// Returns the RES-001 test keypair, seeded deterministically from the string
/// "pask-site::res-001::v0".
pub fn res_001_keypair() -> (SigningKey, VerifyingKey) {
    use sha2::{Digest, Sha256};

    let seed: [u8; 32] = Sha256::digest(b"pask-site::res-001::v0").into();
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

pub fn producer() -> (Arc<Ed25519SiteProducer>, VerifyingKey) {
    let (signing, verifying) = res_001_keypair();
    let producer = Ed25519SiteProducer::new(
        res_001::site_config(),
        Arc::new(FixedClock::new("2026-10-15T14:00:00Z")),
        signing,
    );
    (Arc::new(producer), verifying)
}

pub fn request() -> EngagementRequest {
    res_001::engagement_request(res_001::evidence_bundle())
}

pub fn success_response() -> Result<HttpResponse, pask_adapter::AdapterError> {
    Ok(HttpResponse {
        status: 201,
        body: br#"{"Id":42}"#.to_vec(),
    })
}

pub fn buildium(
    transport: Arc<dyn HttpTransport>,
    dedup: Arc<dyn DedupLog>,
) -> Arc<BuildiumWriteIn> {
    let credentials = StaticCredentialProvider::new(Credentials {
        client_id: "test-id".to_owned(),
        client_secret: "test-secret".to_owned(),
    });
    let adapter = BuildiumWriteIn::new(
        "https://example.test",
        transport,
        Arc::new(credentials),
        dedup,
        RetryPolicy::default(),
    )
    .expect("test base URL must be valid")
    .with_sleep(Arc::new(|_| {}));
    Arc::new(adapter)
}
