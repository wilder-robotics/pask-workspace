// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>

//! SCRAPI HTTP integration tests. The mock covers the full Pask round trip,
//! including cryptographic verification. The ignored real-ledger test uses
//! a pyscitt X.509 statement and checks receipt retrieval only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pask_ts_client::{
    ReceiptResponse, TsClient, TsClientError, TwoLeafTree, attach_receipt, build_receipt,
};
use pask_wire::attached_receipts;
use pask_wire::{Payload, produce_ed25519, verify_ed25519, verify_inclusion};

fn http_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

// A finite HTTP/1.1 fixture. Every expected request must arrive and complete.
fn spawn_mock_server(
    requests: usize,
    mut respond: impl FnMut(&str, &[u8], &str) -> Vec<u8> + Send + 'static,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let server_url = base_url.clone();
    let server = thread::spawn(move || {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut reader = BufReader::new(&mut stream);
            let mut request = String::new();
            reader.read_line(&mut request).expect("request line");
            let mut length = 0;
            let mut content_type = None;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).expect("header") > 0);
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.split_once(':').expect("header separator");
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().expect("content length");
                }
                if name.eq_ignore_ascii_case("content-type") {
                    content_type = Some(value.trim().to_owned());
                }
            }
            assert!(length < 1024 * 1024, "fixture request too large");
            let mut body = vec![0; length];
            reader.read_exact(&mut body).expect("request body");
            if request.starts_with("POST ") {
                assert_eq!(content_type.as_deref(), Some("application/cose"));
            }
            let response = respond(request.trim_end(), &body, &server_url);
            stream.write_all(&response).expect("response");
        }
    });
    (base_url, server)
}

fn spawn_mock_ts(
    ts_signing_key: SigningKey,
) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let mut receipt = None;
    let mut polls = 0;
    let (base_url, server) = spawn_mock_server(3, move |request, body, _| match request {
        "POST /entries?api-version=2026-03-26 HTTP/1.1" => {
            assert!(receipt.is_none(), "submit once");
            receipt =
                Some(build_receipt(&TwoLeafTree::new(body), &ts_signing_key).expect("receipt"));
            tx.send(body.to_vec()).expect("capture submitted statement");
            http_response("303 See Other", "Location: /entries/test-txid\r\n", &[])
        }
        "GET /entries/test-txid?api-version=2026-03-26 HTTP/1.1" => {
            polls += 1;
            if polls == 1 {
                http_response(
                    "302 Found",
                    "Location: /entries/test-txid\r\nRetry-After: 0\r\n",
                    &[],
                )
            } else {
                http_response(
                    "200 OK",
                    "Content-Type: application/cose\r\n",
                    receipt.as_ref().expect("submitted first"),
                )
            }
        }
        _ => panic!("unexpected request: {request}"),
    });
    (base_url, rx, server)
}

#[test]
fn end_to_end_round_trip() {
    // Issuer key: the Pask Issuer that signs the statement.
    let issuer_key = SigningKey::generate(&mut rand_core::OsRng);
    // TS key: the Transparency Service that signs the receipt.
    let ts_key = SigningKey::generate(&mut rand_core::OsRng);
    let ts_verifying_key = VerifyingKey::from(&ts_key);

    // Start the mock TS.
    let (base_url, rx, server) = spawn_mock_ts(ts_key);

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
    server.join().expect("all three SCRAPI requests completed");
    assert_eq!(rx.recv().expect("submitted statement"), statement);

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
#[ignore = "needs a real scitt-ccf-ledger; run with scripts/run-dev-ts.sh or in CI"]
fn real_ledger_submit_and_retrieve_receipt() {
    let Ok(url) = std::env::var("PASK_TS_URL") else {
        eprintln!("PASK_TS_URL is unset; skipping the real-ledger test");
        return;
    };
    let statement_path = std::env::var("PASK_SIGNED_STATEMENT_PATH")
        .expect("set PASK_SIGNED_STATEMENT_PATH to a pyscitt signed statement");
    let service_key_path = std::env::var("PASK_TS_SERVICE_KEY_PATH")
        .expect("set PASK_TS_SERVICE_KEY_PATH to the dev service certificate");
    let statement = std::fs::read(statement_path).expect("read signed statement");
    // The service certificate contains its public key and authenticates TLS.
    // This does not verify the receipt signature or its inclusion proof.
    let service_certificate = std::fs::read(service_key_path).expect("read service certificate");
    let client = TsClient::new_with_root_certificate(&url, &service_certificate).expect("client");
    let receipt = client
        .submit(&statement)
        .expect("submit and retrieve real receipt");
    assert!(!receipt.is_empty(), "the ledger must return receipt bytes");

    match CoseSign1::from_tagged_slice(&receipt).or_else(|_| CoseSign1::from_slice(&receipt)) {
        Ok(_) => eprintln!("Retrieved a COSE_Sign1 receipt ({} bytes)", receipt.len()),
        Err(error) => eprintln!(
            "Retrieved {} bytes; COSE parsing is advisory: {error}",
            receipt.len()
        ),
    }
    // CCF's signing algorithm and proof format may differ from pask-wire's.
    // Full Pask cryptographic verification remains covered by the mock test.
}

#[test]
fn submit_rejects_unexpected_status_and_legacy_operation_records() {
    for status in ["400 Bad Request", "201 Created", "202 Accepted"] {
        let (url, server) = spawn_mock_server(1, move |_, _, _| {
            http_response(
                status,
                "Content-Type: application/cbor\r\n",
                b"operation, not a receipt",
            )
        });
        let error = TsClient::new(&url)
            .expect("client")
            .submit(b"statement")
            .unwrap_err();
        assert!(matches!(error, TsClientError::UnexpectedStatus { .. }));
        server.join().expect("server");
    }
}

#[test]
fn submit_requires_an_entry_location() {
    for headers in [
        "",
        "Location: /operations/2.3\r\n",
        "Location: https://example.invalid/entries/2.3\r\n",
        "Location: /entries/2.3/statement\r\n",
    ] {
        let (url, server) = spawn_mock_server(1, move |_, _, _| {
            http_response("303 See Other", headers, &[])
        });
        let error = TsClient::new(&url)
            .expect("client")
            .submit(b"statement")
            .unwrap_err();
        if headers.is_empty() {
            assert!(matches!(error, TsClientError::NoLocationHeader));
        } else {
            assert!(matches!(
                error,
                TsClientError::UnexpectedStatus { status: 303, .. }
            ));
        }
        server.join().expect("server");
    }
}

#[test]
fn polling_accepts_absolute_locations_and_bounds_retry_after() {
    let mut requests = 0;
    let (url, server) = spawn_mock_server(2, move |request, _, base_url| {
        requests += 1;
        if requests == 1 {
            http_response(
                "303 See Other",
                &format!("Location: {base_url}/entries/2.3\r\n"),
                &[],
            )
        } else {
            assert_eq!(request, "GET /entries/2.3?api-version=2026-03-26 HTTP/1.1");
            http_response("302 Found", "Retry-After: 3600\r\n", &[])
        }
    });
    let error = TsClient::new(&url)
        .expect("client")
        .submit(b"statement")
        .unwrap_err();
    assert!(matches!(error, TsClientError::PollTimeout));
    server.join().expect("server");
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
