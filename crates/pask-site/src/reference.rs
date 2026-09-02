// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Reference-site orchestration.

use std::sync::Arc;

use pask_adapter::{AdapterOutcome, AdapterWriteIn};

use crate::{EngagementRequest, SiteError, SiteProducer};

/// Connects a site producer to a verify-before-push adapter.
pub struct ReferenceSite {
    producer: Arc<dyn SiteProducer>,
    adapter: Arc<dyn AdapterWriteIn>,
}

impl ReferenceSite {
    /// Creates a reference-site orchestrator.
    #[must_use]
    pub fn new(producer: Arc<dyn SiteProducer>, adapter: Arc<dyn AdapterWriteIn>) -> Self {
        Self { producer, adapter }
    }

    /// Produces, verifies, and pushes one engagement receipt.
    ///
    /// # Errors
    ///
    /// Returns a site error when production, verification, or push fails.
    pub fn run_engagement(&self, request: &EngagementRequest) -> Result<AdapterOutcome, SiteError> {
        let signed_bytes = self.producer.produce(request)?;
        let verifying_key = self.producer.verifying_key();
        self.adapter
            .push(&signed_bytes, &verifying_key)
            .map_err(SiteError::from)
    }
}
