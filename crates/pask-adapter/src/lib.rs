// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! WRITE_ONLY operations-layer adapters for verified Pask receipts.

#![forbid(unsafe_code)]

pub mod buildium;
pub mod credential;
pub mod dedup;
pub mod error;
pub mod mock;
pub mod outcome;
pub mod propertymeld;
pub mod retry;
pub mod traits;
pub mod verify;

pub use buildium::{
    BuildiumWriteIn, HttpMethod, HttpRequest, HttpResponse, HttpTransport, ReqwestHttpTransport,
};
pub use credential::{
    CredentialProvider, Credentials, EnvironmentCredentials, StaticCredentialProvider,
};
pub use dedup::{DedupLog, InMemoryDedupLog, lower_hex, receipt_digest};
pub use error::AdapterError;
pub use outcome::AdapterOutcome;
pub use propertymeld::PropertyMeldWriteIn;
pub use retry::{RetryPolicy, run_with_retry, run_with_retry_and_sleep};
pub use traits::AdapterWriteIn;
pub use verify::verify_before_push;
