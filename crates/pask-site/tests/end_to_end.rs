// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::{sync::Arc, time::SystemTime};

use pask_adapter::{
    AdapterOutcome, HttpMethod, InMemoryDedupLog, buildium::build_note, mock::MockHttpTransport,
};
use pask_site::{ReferenceSite, SiteProducer};

#[test]
fn end_to_end_produce_verify_push() {
    let (producer, verifying_key) = common::producer();
    let request = common::request();
    let signed = producer.produce(&request).unwrap();
    let payload = pask_wire::verify_ed25519(&signed, &verifying_key).unwrap();
    let (property_id, expected_note) = build_note(&payload, &signed).unwrap();
    let expected_body = serde_json::to_value(expected_note).unwrap();

    let transport = Arc::new(MockHttpTransport::new(vec![common::success_response()]));
    let adapter = common::buildium(transport.clone(), Arc::new(InMemoryDedupLog::new()));
    let site = ReferenceSite::new(producer, adapter);
    let outcome = site.run_engagement(&request).unwrap();

    let pushed_at = match outcome {
        AdapterOutcome::Pushed {
            adapter_name: "buildium",
            adapter_receipt_id,
            pushed_at,
        } if adapter_receipt_id == "buildium-note-42" => pushed_at,
        other => panic!("unexpected adapter outcome: {other:?}"),
    };
    assert!(pushed_at >= SystemTime::UNIX_EPOCH);
    assert!(pushed_at <= SystemTime::now());

    let calls = transport.recorded_calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.method, HttpMethod::Post);
    assert!(call.url.ends_with("/v1/rentals/rental-42/notes"));
    assert_eq!(property_id, "rental-42");
    assert!(
        call.headers
            .iter()
            .any(|(name, value)| { name == "x-buildium-client-id" && value == "test-id" })
    );
    assert!(
        call.headers
            .iter()
            .any(|(name, value)| { name == "x-buildium-client-secret" && value == "test-secret" })
    );
    assert_eq!(call.body.as_ref(), Some(&expected_body));

    let actual_bytes = serde_json::to_vec(call.body.as_ref().unwrap()).unwrap();
    let expected_bytes = serde_json::to_vec(&expected_body).unwrap();
    assert_eq!(actual_bytes, expected_bytes);
    let receipt_digest = pask_adapter::lower_hex(&pask_adapter::receipt_digest(&signed));
    assert!(
        expected_body["Note"]
            .as_str()
            .unwrap()
            .contains(&receipt_digest)
    );
}
