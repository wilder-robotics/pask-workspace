// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::time::SystemTime;

/// Successful result of a WRITE_ONLY adapter operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterOutcome {
    /// The receipt was written to the operations-layer system.
    Pushed {
        adapter_name: &'static str,
        adapter_receipt_id: String,
        pushed_at: SystemTime,
    },

    /// A previous write for the same signed receipt was found.
    AlreadyPushed {
        adapter_name: &'static str,
        prior_receipt_id: String,
    },
}
