// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::sync::Arc;

use pask_adapter::{
    AdapterError, BuildiumWriteIn, Credentials, HttpMethod, HttpRequest, HttpResponse,
    HttpTransport, InMemoryDedupLog, RetryPolicy, StaticCredentialProvider,
    mock::MockHttpTransport,
};

const CLIENT_ID: &str = "visible-buildium-client-id";
const SECRET: &str = "do-not-log-7f3c91af-client-secret";

fn credentials() -> Credentials {
    Credentials {
        client_id: CLIENT_ID.to_owned(),
        client_secret: SECRET.to_owned(),
    }
}

fn assert_shows_client_id_and_redacts_secret(rendered: &str) {
    assert!(
        rendered.contains(CLIENT_ID),
        "client id missing from {rendered}"
    );
    assert!(
        rendered.contains("[redacted]"),
        "redaction marker missing from {rendered}"
    );
    assert!(
        !rendered.contains(SECRET),
        "secret leaked into debug output: {rendered}"
    );
}

#[test]
fn credentials_debug_redacts_secret() {
    let credentials = credentials();
    let compact = format!("{credentials:?}");
    let pretty = format!("{credentials:#?}");
    assert!(!compact.contains('\n'));
    assert!(pretty.contains('\n'));
    assert_shows_client_id_and_redacts_secret(&compact);
    assert_shows_client_id_and_redacts_secret(&pretty);

    let provider = StaticCredentialProvider::new(credentials.clone());
    let provider_compact = format!("{provider:?}");
    let provider_pretty = format!("{provider:#?}");
    assert_shows_client_id_and_redacts_secret(&provider_compact);
    assert_shows_client_id_and_redacts_secret(&provider_pretty);

    let different_secret = Credentials {
        client_id: CLIENT_ID.to_owned(),
        client_secret: "different-secret-not-equal".to_owned(),
    };
    assert_ne!(credentials, different_secret);
}

#[test]
fn request_debug_redacts_secret_header() {
    let request = HttpRequest {
        method: HttpMethod::Post,
        url: "https://example.test/v1/rentals/42/notes".to_owned(),
        headers: vec![
            ("x-buildium-client-id".to_owned(), CLIENT_ID.to_owned()),
            ("x-buildium-client-secret".to_owned(), SECRET.to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
        ],
        body: None,
    };
    let compact = format!("{request:?}");
    let pretty = format!("{request:#?}");
    assert_shows_client_id_and_redacts_secret(&compact);
    assert_shows_client_id_and_redacts_secret(&pretty);
    assert!(compact.contains("application/json"));
    assert_eq!(
        request
            .headers
            .iter()
            .find(|(name, _)| name == "x-buildium-client-secret")
            .map(|(_, value)| value.as_str()),
        Some(SECRET)
    );

    let transport = MockHttpTransport::new(vec![Ok(HttpResponse {
        status: 400,
        body: Vec::new(),
    })]);
    let recorded = transport
        .send(request)
        .expect("queued response must be returned");
    assert_eq!(recorded.status, 400);
    assert_shows_client_id_and_redacts_secret(&format!("{transport:?}"));
    assert_shows_client_id_and_redacts_secret(&format!("{transport:#?}"));
    assert_eq!(
        transport.recorded_calls()[0]
            .headers
            .iter()
            .find(|(name, _)| name == "x-buildium-client-secret")
            .map(|(_, value)| value.as_str()),
        Some(SECRET)
    );
}

#[test]
fn error_display_does_not_include_secret() {
    let missing = AdapterError::CredentialMissing {
        adapter: "buildium".to_owned(),
    };
    let missing_display = format!("{missing}");
    assert_eq!(
        missing_display,
        "credentials are missing for adapter buildium"
    );
    assert!(!missing_display.contains(SECRET));

    let transport = Arc::new(MockHttpTransport::new(vec![Ok(HttpResponse {
        status: 400,
        body: SECRET.as_bytes().to_vec(),
    })]));
    let adapter = BuildiumWriteIn::new(
        "https://example.test",
        transport.clone(),
        Arc::new(StaticCredentialProvider::new(credentials())),
        Arc::new(InMemoryDedupLog::new()),
        RetryPolicy::default(),
    )
    .expect("test base URL must be valid");

    let error = adapter
        .healthcheck()
        .expect_err("a rejected health check must fail");
    let displayed = format!("{error}");
    assert!(!displayed.contains(SECRET), "{displayed}");
    assert!(!displayed.contains(CLIENT_ID), "{displayed}");
    assert_shows_client_id_and_redacts_secret(&format!("{transport:?}"));
    assert_shows_client_id_and_redacts_secret(&format!("{transport:#?}"));
}
