// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Errors from the local operation store.
//!
//! These are local storage failures. They are not wire-profile enums.

use std::fmt;

/// Why a publication or open stopped.
///
/// The class is diagnostic. It is not an application success bit, and it does
/// not authorize a retry that would sign a new statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureClass {
    /// SQLite reported `SQLITE_FULL`.
    DiskFull,
    /// SQLite or an injected hook reported an I/O failure.
    Io,
    /// The path could not be opened or SQLite reported a permission failure.
    Permission,
    /// The schema version is missing, older than this store, or unknown.
    Schema,
    /// Local invariants failed, or SQLite reported a corrupt file.
    Corruption,
    /// A caller-installed [`super::FaultInjector`] stopped the transaction.
    FaultInjected,
}

impl fmt::Display for FailureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DiskFull => "disk-full",
            Self::Io => "io",
            Self::Permission => "permission",
            Self::Schema => "schema",
            Self::Corruption => "corruption",
            Self::FaultInjected => "fault-injected",
        })
    }
}

/// Failure of the durable store.
///
/// A failure leaves committed rows unchanged. This store does not repair a
/// chain, rewrite a sealed statement, or initialize genesis because an open
/// failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Configuration rejected before any write.
    #[error("invalid store configuration: {0}")]
    InvalidConfig(String),

    /// The path has no initialized schema and initialization was not requested.
    #[error("schema is not initialized at {path}")]
    SchemaNotInitialized { path: String },

    /// The on-disk schema is not the one this process can open.
    ///
    /// No in-place migration runs. The stored version is left as it was.
    #[error("schema refused: found {found}, supported version is {supported}: {detail}")]
    SchemaRefused {
        found: String,
        supported: u32,
        detail: String,
    },

    /// Local invariants failed. The file was not rewritten to make them pass.
    #[error("inconsistent local state, not repaired: {detail}")]
    Inconsistent { detail: String },

    /// The operation id exists and the request fingerprint differs.
    #[error("operation {operation_id} already exists with a different request fingerprint")]
    OperationConflict { operation_id: String },

    /// The stable reference was already reserved with different bytes.
    #[error("operation {operation_id} already has a different stable reference")]
    ReferenceConflict { operation_id: String },

    /// A different remote transaction id is already recorded.
    #[error("operation {operation_id} already recorded a different remote transaction id")]
    RemoteIdConflict { operation_id: String },

    /// No operation row exists for this chain and operation id.
    #[error("operation {operation_id} was not found")]
    NotFound { operation_id: String },

    /// No outbox row exists for this id.
    #[error("outbox {outbox_id} was not found")]
    OutboxNotFound { outbox_id: i64 },

    /// The operation has no sealed statement yet.
    #[error("operation {operation_id} is not sealed")]
    NotSealed { operation_id: String },

    /// The operation is in a state that does not accept this transition.
    #[error("operation {operation_id} cannot accept this transition: {detail}")]
    InvalidTransition {
        operation_id: String,
        detail: String,
    },

    /// The statement bytes do not match the position this store assigned.
    ///
    /// The chain head is unchanged. The caller cannot supply `seq` or
    /// `prevHash` as store inputs; a statement that embeds any other position
    /// is rejected.
    #[error("statement does not match the assigned chain position: {detail}")]
    StatementRejected { detail: String },

    /// Publication did not commit. Any earlier committed head is unchanged.
    #[error("publication stopped ({class}): {detail}")]
    PublicationStopped { class: FailureClass, detail: String },

    /// The configured attempt bound has been reached. Submitted bytes are unchanged.
    #[error("outbox {outbox_id} retries are exhausted at {attempts} of {max_attempts}")]
    RetriesExhausted {
        outbox_id: i64,
        attempts: u32,
        max_attempts: u32,
    },

    /// A previous panic held the store lock. The process must stop.
    #[error("the store lock was poisoned; refusing to continue")]
    LockPoisoned,

    /// The statement callback called back into the store.
    #[error("the statement callback re-entered the store")]
    Reentry,

    /// SQLite reported an error that is not one of the publication classes.
    #[error("sqlite error: {detail}")]
    Sqlite { detail: String },
}

pub(super) fn from_sqlite(err: rusqlite::Error) -> StoreError {
    match &err {
        rusqlite::Error::SqliteFailure(ffi, message) => {
            let detail = match message {
                Some(text) => format!("{text} ({:?})", ffi.code),
                None => format!("{:?}", ffi.code),
            };
            let class = match ffi.code {
                rusqlite::ErrorCode::DiskFull => Some(FailureClass::DiskFull),
                rusqlite::ErrorCode::SystemIoFailure => Some(FailureClass::Io),
                rusqlite::ErrorCode::PermissionDenied
                | rusqlite::ErrorCode::ReadOnly
                | rusqlite::ErrorCode::CannotOpen => Some(FailureClass::Permission),
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase => {
                    Some(FailureClass::Corruption)
                }
                _ => None,
            };
            match class {
                Some(class) => StoreError::PublicationStopped { class, detail },
                None => StoreError::Sqlite { detail },
            }
        }
        other => StoreError::Sqlite {
            detail: other.to_string(),
        },
    }
}
