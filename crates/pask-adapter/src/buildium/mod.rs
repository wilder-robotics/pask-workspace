// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

pub mod http;
pub mod mapping;

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use url::Url;

use crate::{
    AdapterError, AdapterOutcome, AdapterWriteIn, CredentialProvider, Credentials, DedupLog,
    RetryPolicy, lower_hex, receipt_digest, run_with_retry_and_sleep, verify_before_push,
};

pub use http::{HttpMethod, HttpRequest, HttpResponse, HttpTransport, ReqwestHttpTransport};
pub use mapping::{BuildiumNote, build_note};

/// WRITE_ONLY Buildium note adapter.
pub struct BuildiumWriteIn {
    base_url: Url,
    transport: Arc<dyn HttpTransport>,
    credentials: Arc<dyn CredentialProvider>,
    dedup: Arc<dyn DedupLog>,
    retry_policy: RetryPolicy,
    sleep: Arc<dyn Fn(Duration) + Send + Sync>,
}

impl BuildiumWriteIn {
    /// Creates a Buildium adapter.
    ///
    /// # Errors
    ///
    /// Returns `AdapterError::InvalidBaseUrl` when the URL is invalid or
    /// cannot be used as a hierarchical base URL.
    pub fn new(
        base_url: &str,
        transport: Arc<dyn HttpTransport>,
        credentials: Arc<dyn CredentialProvider>,
        dedup: Arc<dyn DedupLog>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, AdapterError> {
        let base_url = Url::parse(base_url)
            .map_err(|error| AdapterError::InvalidBaseUrl(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.cannot_be_a_base() {
            return Err(AdapterError::InvalidBaseUrl(base_url.to_string()));
        }

        Ok(Self {
            base_url,
            transport,
            credentials,
            dedup,
            retry_policy,
            sleep: Arc::new(std::thread::sleep),
        })
    }

    /// Replaces the delay function, primarily for deterministic tests.
    #[must_use]
    pub fn with_sleep(mut self, sleep: Arc<dyn Fn(Duration) + Send + Sync>) -> Self {
        self.sleep = sleep;
        self
    }

    /// Performs the sole permitted adapter GET against the fixed health endpoint.
    ///
    /// # Errors
    ///
    /// Returns credential, transport, or HTTP status failures.
    pub fn healthcheck(&self) -> Result<(), AdapterError> {
        let credentials = self.credentials.credentials("buildium")?;
        let request = HttpRequest {
            method: HttpMethod::Get,
            url: self.healthcheck_url()?,
            headers: auth_headers(&credentials),
            body: None,
        };
        let response = self.transport.send(request)?;
        match response.status {
            200..=299 => Ok(()),
            429 => Err(AdapterError::RateLimited),
            500..=599 => Err(AdapterError::ServerError(response.status)),
            400..=499 => Err(AdapterError::BadRequest(response.status)),
            status => Err(AdapterError::InvalidResponse(format!(
                "unexpected health-check status {status}"
            ))),
        }
    }

    fn post_once(
        &self,
        property_id: &str,
        credentials: &Credentials,
        body: &serde_json::Value,
    ) -> Result<String, AdapterError> {
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: self.note_url(property_id)?,
            headers: auth_headers(credentials),
            body: Some(body.clone()),
        };
        let response = self.transport.send(request)?;
        match response.status {
            201 => parse_note_id(&response.body),
            429 => Err(AdapterError::RateLimited),
            500..=599 => Err(AdapterError::ServerError(response.status)),
            400..=499 => Err(AdapterError::BadRequest(response.status)),
            status => Err(AdapterError::InvalidResponse(format!(
                "unexpected note status {status}"
            ))),
        }
    }

    fn note_url(&self, property_id: &str) -> Result<String, AdapterError> {
        self.url_with_segments(&["v1", "rentals", property_id, "notes"])
    }

    fn healthcheck_url(&self) -> Result<String, AdapterError> {
        self.url_with_segments(&["v1", "administration", "accountinfo"])
    }

    fn url_with_segments(&self, segments: &[&str]) -> Result<String, AdapterError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| AdapterError::InvalidBaseUrl(self.base_url.to_string()))?;
            path.clear();
            path.extend(segments);
        }
        Ok(url.to_string())
    }
}

impl AdapterWriteIn for BuildiumWriteIn {
    fn push(
        &self,
        signed_receipt: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<AdapterOutcome, AdapterError> {
        let payload = verify_before_push(signed_receipt, verifying_key)?;

        if payload.adapter_system() != "buildium" {
            return Err(AdapterError::AdapterMismatch {
                expected: "buildium",
                actual: payload.adapter_system().to_owned(),
            });
        }

        // This code path is defense-in-depth; the pask-wire validator makes it
        // unreachable through parsing. Preserved for a future protocol revision
        // that adds a non-WRITE_ONLY mode.
        if !payload.adapter_is_write_only() {
            return Err(AdapterError::WriteOnlyRequired {
                actual: "<non-write-only>".to_owned(),
            });
        }

        let digest = receipt_digest(signed_receipt);
        if self.dedup.is_pushed(&digest) {
            let prior = self
                .dedup
                .prior_receipt_id(&digest)
                .unwrap_or_else(|| format!("dedup-{}", lower_hex(&digest)));
            return Ok(AdapterOutcome::AlreadyPushed {
                adapter_name: "buildium",
                prior_receipt_id: prior,
            });
        }

        let credentials = self.credentials.credentials("buildium")?;
        let (property_id, note) = build_note(&payload, signed_receipt)?;
        let body = serde_json::to_value(note)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;

        let result = run_with_retry_and_sleep(
            &self.retry_policy,
            |_| self.post_once(&property_id, &credentials, &body),
            |delay| (self.sleep)(delay),
        );
        let adapter_receipt_id = match result {
            Err(AdapterError::Transport(message)) => {
                return Err(AdapterError::DeadLetter(message));
            }
            result => result?,
        };

        self.dedup.record_pushed(&digest, &adapter_receipt_id);
        Ok(AdapterOutcome::Pushed {
            adapter_name: "buildium",
            adapter_receipt_id,
            pushed_at: SystemTime::now(),
        })
    }

    fn name(&self) -> &'static str {
        "buildium"
    }
}

fn auth_headers(credentials: &Credentials) -> Vec<(String, String)> {
    vec![
        (
            "x-buildium-client-id".to_owned(),
            credentials.client_id.clone(),
        ),
        (
            "x-buildium-client-secret".to_owned(),
            credentials.client_secret.clone(),
        ),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]
}

#[derive(Deserialize)]
struct CreateNoteResponse {
    #[serde(rename = "Id")]
    id: u64,
}

fn parse_note_id(body: &[u8]) -> Result<String, AdapterError> {
    let response: CreateNoteResponse = serde_json::from_slice(body)
        .map_err(|error| AdapterError::InvalidResponse(error.to_string()))?;
    Ok(format!("buildium-note-{}", response.id))
}
