// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>

//! SCRAPI client: submits a Signed Statement to a Transparency Service and
//! retrieves the resulting Receipt.
//!
//! Implements the SCRAPI v09 flow exposed by scitt-ccf-ledger:
//!
//! - `POST /entries?api-version=2026-03-26` returns 303 with an entry Location.
//! - `GET /entries/{txid}?api-version=2026-03-26` returns 302 while pending,
//!   then 200 with the receipt. Redirects are handled explicitly.
//!
//! Response bytes are returned without parsing or cryptographic verification.
//! The ledger's receipt proof and signing algorithm may differ from those
//! supported by `pask_wire::verify_inclusion`.
//!
//! Submission is byte-transparent: callers must supply the transmitted tag-18
//! Signed Statement. In particular, current untagged local producer output
//! needs an explicit tag-18 wrapper before submission; `attach_receipt` only
//! constructs the later Transparent Statement. The service must commit to the
//! profile's candidate-entry bytes, not the tagged HTTP request body. Neither
//! adaptation nor service agreement is inferred by this transport.

use std::time::{Duration, Instant};

/// A client for a SCITT Transparency Service speaking SCRAPI.
pub struct TsClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

const API_VERSION: &str = "2026-03-26";
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// The interval between polling attempts.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

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
        Self::build(base_url, reqwest::blocking::Client::builder())
    }

    /// Creates a client trusting an additional PEM-encoded CA certificate.
    ///
    /// The dev ledger's service certificate can be supplied here. TLS
    /// certificate and hostname verification remain enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate or HTTP client cannot be loaded.
    pub fn new_with_root_certificate(
        base_url: &str,
        certificate_pem: &[u8],
    ) -> Result<Self, TsClientError> {
        let certificate =
            reqwest::Certificate::from_pem(certificate_pem).map_err(TsClientError::HttpClient)?;
        Self::build(
            base_url,
            reqwest::blocking::Client::builder().add_root_certificate(certificate),
        )
    }

    fn build(
        base_url: &str,
        builder: reqwest::blocking::ClientBuilder,
    ) -> Result<Self, TsClientError> {
        let http = builder
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .map_err(TsClientError::HttpClient)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
        })
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
    /// `/entries` with the SCRAPI API version, then polls the transaction
    /// identified by a 303 Location until a 200 returns the receipt.
    /// Legacy 202 operation records are not accepted as receipt responses.
    /// The caller must provide the transmitted tag-18 envelope. This method
    /// sends bytes unchanged; current untagged local producer output needs an
    /// explicit tag-18 wrapper before this call, not after registration.
    ///
    /// # Errors
    ///
    /// Returns an error for an unreachable service, an unexpected response,
    /// an invalid entry Location, or an expired polling window.
    pub fn submit(&self, signed_statement: &[u8]) -> Result<Vec<u8>, TsClientError> {
        let url = format!("{}/entries?api-version={API_VERSION}", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/cose")
            .body(signed_statement.to_vec())
            .send()
            .map_err(TsClientError::RequestFailed)?;

        let status = response.status();
        if status == reqwest::StatusCode::SEE_OTHER {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or(TsClientError::NoLocationHeader)?
                .to_str()
                .map_err(|_| TsClientError::LocationNotAscii)?;
            let invalid_location = || TsClientError::UnexpectedStatus {
                status: status.as_u16(),
                body: "expected a same-origin Location identifying one /entries/{txid}".to_owned(),
            };
            let entry = response
                .url()
                .join(location)
                .map_err(|_| invalid_location())?;
            let prefix = format!("{}/", response.url().path());
            let txid = entry
                .path()
                .strip_prefix(&prefix)
                .filter(|id| {
                    !id.is_empty()
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
                })
                .ok_or_else(invalid_location)?;
            if entry.origin() != response.url().origin() || entry.fragment().is_some() {
                return Err(invalid_location());
            }
            return self.poll_for_receipt(txid);
        }
        Err(TsClientError::UnexpectedStatus {
            status: status.as_u16(),
            body: response.text().unwrap_or_default(),
        })
    }

    /// Polls one entry, bounding both requests and sleeps by one deadline.
    fn poll_for_receipt(&self, transaction_id: &str) -> Result<Vec<u8>, TsClientError> {
        let url = format!(
            "{}/entries/{transaction_id}?api-version={API_VERSION}",
            self.base_url
        );
        let deadline = Instant::now() + POLL_TIMEOUT;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
                .ok_or(TsClientError::PollTimeout)?;
            let response = self
                .http
                .get(&url)
                .timeout(remaining)
                .send()
                .map_err(|error| {
                    if error.is_timeout() {
                        TsClientError::PollTimeout
                    } else {
                        TsClientError::RequestFailed(error)
                    }
                })?;
            let status = response.status();
            if status == reqwest::StatusCode::OK {
                return response
                    .bytes()
                    .map(|b| b.to_vec())
                    .map_err(TsClientError::ReadBody);
            }
            if status == reqwest::StatusCode::FOUND {
                let delay = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .map_or(POLL_INTERVAL, Duration::from_secs)
                    .max(Duration::from_millis(10));
                if delay >= deadline.saturating_duration_since(Instant::now()) {
                    return Err(TsClientError::PollTimeout);
                }
                std::thread::sleep(delay);
                continue;
            }
            return Err(TsClientError::UnexpectedStatus {
                status: status.as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }
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
    /// The service returned 303 but no `Location` header.
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
                 https://127.0.0.1:8000, after running scripts/run-dev-ts.sh"
            ),
            Self::HttpClient(e) => write!(f, "could not build HTTP client: {e}"),
            Self::RequestFailed(e) => write!(f, "request to transparency service failed: {e}"),
            Self::ReadBody(e) => write!(f, "could not read response body: {e}"),
            Self::NoLocationHeader => {
                write!(f, "service returned 303 with no Location header")
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
