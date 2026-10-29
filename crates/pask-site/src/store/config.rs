// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Explicit configuration for one local operation database.

use std::path::PathBuf;
use std::sync::Arc;

use super::error::StoreError;
use super::types::FaultInjector;
use crate::Clock;

/// Where the store opens its database, and the bounds it enforces.
///
/// `database_path` is the database file itself. The store does not choose a
/// directory, does not consult an environment variable, and does not create a
/// parent directory. Schema creation happens only when [`Self::initialize_schema`]
/// is set. Opening an existing compatible file does not migrate it.
pub struct StoreConfig {
    /// Filesystem path of the SQLite database.
    pub database_path: PathBuf,
    /// Create the versioned schema when the file does not already contain one.
    pub initialize_schema: bool,
    /// Maximum dispatch attempts stored on each new outbox row.
    ///
    /// The bound is copied onto the row at creation and is not rewritten later.
    /// It must be at least 1.
    pub outbox_max_attempts: u32,
    /// Clock used for append-only event timestamps.
    pub clock: Arc<dyn Clock>,
    /// Optional test hook. Production configuration leaves this empty.
    ///
    /// A hook can stop a transaction at a boundary. It cannot rewrite a row
    /// that has already committed.
    pub fault_injector: Option<Arc<dyn FaultInjector>>,
}

impl StoreConfig {
    /// Configuration for an explicit path.
    ///
    /// Schema initialization is off. The outbox bound is 3. The clock is the
    /// system clock. No fault injector is installed.
    #[must_use]
    pub fn new(database_path: impl Into<PathBuf>) -> Self {
        Self {
            database_path: database_path.into(),
            initialize_schema: false,
            outbox_max_attempts: 3,
            clock: Arc::new(crate::SystemClock),
            fault_injector: None,
        }
    }

    pub(super) fn validate(&self) -> Result<(), StoreError> {
        if self.database_path.as_os_str().is_empty() {
            return Err(StoreError::InvalidConfig(
                "database path is empty".to_owned(),
            ));
        }
        if self.database_path.is_dir() {
            return Err(StoreError::InvalidConfig(
                "database path is a directory".to_owned(),
            ));
        }
        if self.outbox_max_attempts == 0 {
            return Err(StoreError::InvalidConfig(
                "outbox max attempts must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}
