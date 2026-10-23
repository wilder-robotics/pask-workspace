// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::fmt;

use serde_json::Value;

use crate::AdapterError;

/// Placeholder written in place of a secret header value in `Debug` output.
const REDACTED_SECRET: &str = "[redacted]";

/// HTTP methods permitted by the adapter transport boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET, restricted by the adapter to its fixed health-check path.
    Get,

    /// POST, restricted by the adapter to the note endpoint.
    Post,
}

/// Transport-neutral HTTP request.
///
/// `Debug` redacts header values whose names contain `secret` and leaves other
/// headers, including the client id, visible.
#[derive(Clone, PartialEq)]
pub struct HttpRequest {
    /// Request method.
    pub method: HttpMethod,

    /// Fully resolved URL.
    pub url: String,

    /// Request headers.
    pub headers: Vec<(String, String)>,

    /// Optional JSON request body.
    pub body: Option<Value>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let value = if header_holds_secret(name) {
                    REDACTED_SECRET
                } else {
                    value.as_str()
                };
                (name.as_str(), value)
            })
            .collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body", &self.body)
            .finish()
    }
}

/// Returns whether this header name marks a credential secret.
///
/// The client id header does not match, so it stays visible in `Debug`.
fn header_holds_secret(name: &str) -> bool {
    name.to_ascii_lowercase().contains("secret")
}

/// Transport-neutral HTTP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric HTTP status.
    pub status: u16,

    /// Raw response body.
    pub body: Vec<u8>,
}

/// HTTP transport boundary used by real and mock implementations.
pub trait HttpTransport: Send + Sync {
    /// Sends one request.
    ///
    /// # Errors
    ///
    /// Returns an adapter transport failure if no valid response is received.
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, AdapterError>;
}

/// Blocking reqwest transport using rustls.
#[derive(Debug)]
pub struct ReqwestHttpTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpTransport {
    /// Creates a transport with reqwest defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl Default for ReqwestHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpTransport for ReqwestHttpTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, AdapterError> {
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(&request.url),
            HttpMethod::Post => self.client.post(&request.url),
        };

        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }

        let response = builder
            .send()
            .map_err(|error| AdapterError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|error| AdapterError::Transport(error.to_string()))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}
