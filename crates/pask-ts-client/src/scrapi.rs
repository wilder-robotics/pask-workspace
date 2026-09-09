// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>

//! SCRAPI client: submits a Signed Statement to a Transparency Service and
//! retrieves the resulting Receipt.
//!
//! Implements the minimal subset of SCRAPI (draft-ietf-scitt-scrapi) needed
//! for issue #40:
//!
//! - `POST /entries` with the Signed Statement as the body, content type
//!   `application/cose`. Returns 201 with the receipt inline, or 202 with a
//!   `Location` header to poll.
//! - `GET {location}` to poll for the receipt when the service returns 202.
//!
//! The receipt returned is a raw COSE Receipt (a `COSE_Sign1`, tag 18 or
//! untagged array) carrying an RFC 9162_SHA256 inclusion proof. It is not
//! parsed or verified here: verification is the reading half, `pask_wire::
//! verify_inclusion`, and the two are deliberately separate so production
//! and verification cannot be mistaken for each other.

use std::time::Duration;

/// A client for a SCITT Transparency Service speaking SCRAPI.
pub struct TsClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

/// The maximum number of polling attempts when the service returns 202.
const MAX_POLLS: u32 = 30;

/// The interval between polling attempts.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The user-agent this client identifies itself with.
const USER_AGENT: &str = "pask-ts-client/0.1";

impl TsClient {
    /// Creates a new client targeting `base_url`.
    ///
    /// `base_url` should not have a trailing slash. If it does, it is
    /// stripped. The client does not add a default port or host: the caller
    /// supplies the full URL, which is the mechanism that prevents a silent
    /// fallback to a production endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error only if the HTTP client cannot be constructed.
    pub fn new(base_url: &str) -> Result<Self, TsClientError> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .map_err(TsClientError::HttpClient)?;
        Ok(Self { base_url, http })
    }

    /// Reads `PASK_TS_URL` from the environment and creates a client from it.
    ///
    /// There is no default. If `PASK_TS_URL` is unset or empty, this returns an
    /// error naming that fact. This is deliberate: the client must never
    /// silently fall back to a production endpoint.
    ///
    /// # Errors
    ///
    /// [`TsClientError::UrlNotSet`] if the variable is absent or empty.
    pub fn from_env() -> Result<Self, TsClientError> {
        let url = std::env::var("PASK_TS_URL").map_err(|_| TsClientError::UrlNotSet)?;
        let url = url.trim();
        if url.is_empty() {
            return Err(TsClientError::UrlNotSet);
        }
        Self::new(url)
    }

    /// Submits a Signed Statement and retrieves the Receipt.
    ///
    /// This is the main entry point. It POSTs the raw COSE_Sign1 bytes to
    /// `/entries`, then either returns the receipt from a 201 response or
    /// polls the `Location` header until a 200 or 201 returns the receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if the service is unreachable, returns a non-2xx
    /// status, or does not return a receipt within the polling window.
    pub fn submit(&self, signed_statement: &[u8]) -> Result<Vec<u8>, TsClientError> {
        let url = format!("{}/entries", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/cose")
            .body(signed_statement.to_vec())
            .send()
            .map_err(TsClientError::RequestFailed)?;

        let status = response.status();
        if status == reqwest::StatusCode::CREATED {
            return response
                .bytes()
                .map(|b| b.to_vec())
                .map_err(TsClientError::ReadBody);
        }
        if status == reqwest::StatusCode::ACCEPTED {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or(TsClientError::NoLocationHeader)?
                .to_str()
                .map_err(|_| TsClientError::LocationNotAscii)?
                .to_owned();
            return self.poll_for_receipt(&location);
        }
        Err(TsClientError::UnexpectedStatus {
            status: status.as_u16(),
            body: response.text().unwrap_or_default(),
        })
    }

    /// Polls `GET {location}` until the receipt is available.
    fn poll_for_receipt(&self, location: &str) -> Result<Vec<u8>, TsClientError> {
        let url = if location.starts_with("http://") || location.starts_with("https://") {
            location.to_owned()
        } else {
            format!("{}{}", self.base_url, location)
        };
        for _ in 0..MAX_POLLS {
            std::thread::sleep(POLL_INTERVAL);
            let response = self
                .http
                .get(&url)
                .send()
                .map_err(TsClientError::RequestFailed)?;
            let status = response.status();
            if status == reqwest::StatusCode::OK || status == reqwest::StatusCode::CREATED {
                return response
                    .bytes()
                    .map(|b| b.to_vec())
                    .map_err(TsClientError::ReadBody);
            }
            if status == reqwest::StatusCode::ACCEPTED {
                continue;
            }
            return Err(TsClientError::UnexpectedStatus {
                status: status.as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }
        Err(TsClientError::PollTimeout)
    }
}

/// The receipt as returned by the service, before attachment.
///
/// This is the raw COSE Receipt bytes. The caller passes them to
/// [`crate::attach_receipt`] to form a Transparent Statement, or to
/// [`pask_wire::verify_inclusion`] to verify them. Both are the caller's
/// responsibility; this client does not verify what it receives.
pub type ReceiptResponse = Vec<u8>;

/// Errors from the SCRAPI client.
#[derive(Debug)]
pub enum TsClientError {
    /// `PASK_TS_URL` was not set or was empty.
    UrlNotSet,
    /// The HTTP client could not be constructed.
    HttpClient(reqwest::Error),
    /// A network request failed.
    RequestFailed(reqwest::Error),
    /// The response body could not be read.
    ReadBody(reqwest::Error),
    /// The service returned 202 but no `Location` header.
    NoLocationHeader,
    /// The `Location` header was not valid ASCII.
    LocationNotAscii,
    /// The service did not return a receipt within the polling window.
    PollTimeout,
    /// The service returned an unexpected status code.
    UnexpectedStatus { status: u16, body: String },
}

impl std::fmt::Display for TsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrlNotSet => write!(
                f,
                "PASK_TS_URL is not set. Set it to the local dev ledger, \
                 http://127.0.0.1:8000, after running scripts/run-dev-ts.sh"
            ),
            Self::HttpClient(e) => write!(f, "could not build HTTP client: {e}"),
            Self::RequestFailed(e) => write!(f, "request to transparency service failed: {e}"),
            Self::ReadBody(e) => write!(f, "could not read response body: {e}"),
            Self::NoLocationHeader => {
                write!(f, "service returned 202 with no Location header")
            }
            Self::LocationNotAscii => write!(f, "Location header was not valid ASCII"),
            Self::PollTimeout => write!(f, "service did not return a receipt in time"),
            Self::UnexpectedStatus { status, body } => {
                write!(f, "service returned status {status}: {body}")
            }
        }
    }
}

impl std::error::Error for TsClientError {}
