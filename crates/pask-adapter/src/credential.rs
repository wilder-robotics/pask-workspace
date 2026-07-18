// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use crate::AdapterError;

/// Credentials required by the Buildium API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    /// Buildium client identifier.
    pub client_id: String,

    /// Buildium client secret.
    pub client_secret: String,
}

/// Resolves credentials at adapter execution time.
pub trait CredentialProvider: Send + Sync {
    /// Returns credentials for the named adapter.
    ///
    /// # Errors
    ///
    /// Returns `AdapterError::CredentialMissing` when credentials are unavailable.
    fn credentials(&self, adapter_name: &str) -> Result<Credentials, AdapterError>;
}

/// Fixed credential provider intended for tests and explicit caller-supplied values.
#[derive(Clone, Debug)]
pub struct StaticCredentialProvider {
    credentials: Credentials,
}

impl StaticCredentialProvider {
    /// Creates a provider from caller-supplied credentials.
    #[must_use]
    pub fn new(credentials: Credentials) -> Self {
        Self { credentials }
    }
}

impl CredentialProvider for StaticCredentialProvider {
    fn credentials(&self, _adapter_name: &str) -> Result<Credentials, AdapterError> {
        Ok(self.credentials.clone())
    }
}

/// Reads Buildium credentials from `PASK_BUILDIUM_CLIENT_ID` and
/// `PASK_BUILDIUM_CLIENT_SECRET` environment variables.
///
/// Returns `AdapterError::CredentialMissing` when either variable is unset.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentCredentials;

impl CredentialProvider for EnvironmentCredentials {
    fn credentials(&self, adapter_name: &str) -> Result<Credentials, AdapterError> {
        let client_id = std::env::var("PASK_BUILDIUM_CLIENT_ID").map_err(|_| {
            AdapterError::CredentialMissing {
                adapter: adapter_name.to_owned(),
            }
        })?;
        let client_secret = std::env::var("PASK_BUILDIUM_CLIENT_SECRET").map_err(|_| {
            AdapterError::CredentialMissing {
                adapter: adapter_name.to_owned(),
            }
        })?;
        Ok(Credentials {
            client_id,
            client_secret,
        })
    }
}
