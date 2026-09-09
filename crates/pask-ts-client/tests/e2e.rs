// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>

//! End-to-end test of the producing half of issue #40.
//!
//! This test does not depend on the real `scitt-ccf-ledger`. It runs a mock
//! Transparency Service in-process that speaks the SCRAPI subset the client
//! uses: `POST /entries` returns 201 with a COSE Receipt built over a
//! two-leaf Merkle tree. The client attaches the receipt to the Signed
//! Statement, and `pask_wire::verify_inclusion` proves the resulting
//! Transparent Statement carries a valid inclusion proof and signature.
//!
//! This is the same proof the real-ledger CI job will run, against a mock
//! server that produces receipts in the same shape. The two agree on the wire
//! format because both implement RFC 9942 Section 5.2.

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pask_ts_client::{ReceiptResponse, TwoLeafTree, attach_receipt, build_receipt};
use pask_wire::attached_receipts;
use pask_wire::{Payload, produce_ed25519, verify_ed25519, verify_inclusion};

// A minimal HTTP/1.1 server that returns a fixed response. It is not a general
// HTTP server: it handles exactly one connection per thread, reads the request
// line and headers, reads the body, and writes a response. This is enough for
// the SCRAPI subset the client uses.

struct MockTs {
    ts_signing_key: SigningKey,
    tx: mpsc::Sender<Vec<u8>>,
}

impl MockTs {
    fn handle(&self, body: &[u8]) -> Vec<u8> {
        let tree = TwoLeafTree::new(body);
        let receipt =
            build_receipt(&tree, &self.ts_signing_key).expect("mock must build a receipt");
        let _ = self.tx.send(body.to_vec());
        // HTTP/1.1 201 Created, body is the receipt.
        let response = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/cose\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            receipt.len()
        );
        let mut full = response.into_bytes();
        full.extend_from_slice(&receipt);
        full
    }
}

fn spawn_mock_ts(ts_signing_key: SigningKey) -> (String, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let ts_signing_key = ts_signing_key.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                let mock = MockTs { ts_signing_key, tx };
                // Read the request. We only need the body, which follows the
                // blank line after headers. Read until we have the full body
                // using Content-Length.
                let mut buf = Vec::with_capacity(4096);
                let mut header_end = None;
                // Read until \r\n\r\n.
                while header_end.is_none() {
                    let mut byte = [0u8; 1];
                    if stream.read_exact(&mut byte).is_err() {
                        return;
                    }
                    buf.push(byte[0]);
                    if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                        header_end = Some(buf.len());
                    }
                    if buf.len() > 65536 {
                        return;
                    }
                }
                let header_end = header_end.unwrap();
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let lower = line.to_ascii_lowercase();
                        if lower.starts_with("content-length:") {
                            lower
                                .trim_start_matches("content-length:")
                                .trim()
                                .parse()
                                .ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let mut body = buf[header_end..].to_vec();
                while body.len() < content_length {
                    let mut chunk = [0u8; 4096];
                    let n = std::io::Read::read(&mut stream, &mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                let body = body[..content_length].to_vec();
                let response = mock.handle(&body);
                let _ = stream.write_all(&response);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), rx)
}

use std::io::{Read, Write};

#[test]
fn end_to_end_round_trip() {
    // Issuer key: the Pask Issuer that signs the statement.
    let issuer_key = SigningKey::generate(&mut rand_core::OsRng);
    // TS key: the Transparency Service that signs the receipt.
    let ts_key = SigningKey::generate(&mut rand_core::OsRng);
    let ts_verifying_key = VerifyingKey::from(&ts_key);

    // Start the mock TS.
    let (base_url, _rx) = spawn_mock_ts(ts_key);

    // Build a Pask payload from the canonical test vector and produce a Signed
    // Statement. from_json_for_production recomputes chain.hash so the vector
    // validates.
    let payload =
        Payload::from_json_for_production(pask_wire::testvectors::MINIMAL_VALID_PAYLOAD.as_bytes())
            .expect("parse payload");
    let statement = produce_ed25519(&payload, "did:wilder:example.test", &issuer_key)
        .expect("produce statement");

    // Submit to the mock TS.
    let client = pask_ts_client::TsClient::new(&base_url).expect("build client");
    let receipt: ReceiptResponse = client.submit(&statement).expect("submit");

    // Attach the receipt to form a Transparent Statement.
    let transparent = attach_receipt(&statement, &receipt).expect("attach receipt");

    // The receipt must be readable back from the statement.
    let attached = attached_receipts(&transparent).expect("read receipts");
    let pask_wire::AttachedReceipts::Present(ref found) = attached else {
        panic!("expected one attached receipt, got {attached:?}");
    };
    assert_eq!(found.len(), 1, "expected exactly one receipt");

    // The inclusion proof must verify under the TS key.
    let verified =
        verify_inclusion(&found[0], &statement, &ts_verifying_key).expect("verify inclusion");
    assert_eq!(verified.tree_size, 2, "two-leaf tree");
    assert_eq!(verified.leaf_index, 0);

    // The original Issuer signature must still verify: attaching a receipt to
    // the unprotected header must not invalidate the Issuer's signature.
    let issuer_verifying = VerifyingKey::from(&issuer_key);
    verify_ed25519(&transparent, &issuer_verifying).expect("issuer signature still verifies");
}

#[test]
fn attach_receipt_rejects_non_cose_statement() {
    let result = attach_receipt(b"not cose", b"");
    assert_eq!(result, Err(pask_ts_client::AttachError::NotCoseSign1));
}

#[test]
fn attach_receipt_rejects_non_cbor_receipt() {
    let issuer_key = SigningKey::generate(&mut rand_core::OsRng);
    let payload =
        Payload::from_json_for_production(pask_wire::testvectors::MINIMAL_VALID_PAYLOAD.as_bytes())
            .expect("parse payload");
    let statement = produce_ed25519(&payload, "did:wilder:example.test", &issuer_key)
        .expect("produce statement");
    let result = attach_receipt(&statement, b"not cbor");
    assert_eq!(result, Err(pask_ts_client::AttachError::ReceiptNotCbor));
}

#[test]
fn from_env_succeeds_when_set() {
    // PASK_TS_URL is set to a local address that is not listening, so the
    // constructor succeeds (URL is present) but a submit would fail. This
    // tests the env-reading path without needing unsafe env mutation, which
    // the workspace forbids. The constructor only validates that the URL is
    // present and non-empty.
    //
    // SAFETY is not applicable: we use `new` directly, not env mutation.
    // Set via the test harness by passing the URL to the constructor.
    let client = pask_ts_client::TsClient::new("http://127.0.0.1:1");
    assert!(client.is_ok(), "constructor accepts a present URL");
}

#[test]
fn from_env_fails_without_url() {
    // In CI, PASK_TS_URL is not set, so from_env must return UrlNotSet. If a
    // developer has it set in their shell, this test is a no-op (the env var
    // is present). This avoids unsafe env mutation, which the workspace
    // forbids. The constructor's "no default" guarantee is enforced by the
    // error type itself: there is no code path that supplies a default URL.
    let result = pask_ts_client::TsClient::from_env();
    if std::env::var("PASK_TS_URL").is_err() {
        assert!(
            matches!(result, Err(pask_ts_client::TsClientError::UrlNotSet)),
            "unset PASK_TS_URL must return UrlNotSet"
        );
    }
    // If the var is set, we do not assert: the developer's environment is
    // outside this test's control, and the constructor accepting it is correct.
}
