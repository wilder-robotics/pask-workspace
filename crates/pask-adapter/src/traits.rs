// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use ed25519_dalek::VerifyingKey;

use crate::{AdapterError, AdapterOutcome};

/// Common interface for WRITE_ONLY operations-layer adapters.
pub trait AdapterWriteIn: Send + Sync {
    /// Verifies the receipt and, if verification passes, pushes it to the
    /// ops-layer system. Verification is enforced INSIDE this method.
    /// Callers cannot bypass it.
    fn push(
        &self,
        signed_receipt: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<AdapterOutcome, AdapterError>;

    /// Human-readable adapter name for logs. Must be a stable identifier.
    fn name(&self) -> &'static str;
}
