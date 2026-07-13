// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use pask_wire::Payload;

use crate::{lower_hex, receipt_digest};

/// Deterministic future-facing PropertyMeld comment projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyMeldComment {
    /// Opaque partner endpoint.
    pub endpoint: String,

    /// Receipt summary suitable for a future work-order comment.
    pub body: String,
}

/// Builds the deterministic mapping without issuing any request.
#[must_use]
pub fn build_comment(payload: &Payload, signed_receipt: &[u8]) -> PropertyMeldComment {
    let digest = lower_hex(&receipt_digest(signed_receipt));
    PropertyMeldComment {
        endpoint: payload.adapter_endpoint().to_owned(),
        body: format!(
            "Receipt ID: {digest}\n\
             Site: {}\n\
             Actor: {}\n\
             Engagement: {}\n\
             Window: {} .. {}\n\
             Evidence digest: {}",
            payload.site_id(),
            payload.actor_id(),
            payload.engagement_id(),
            payload.engagement_window_start(),
            payload.engagement_window_end(),
            payload.sealed_evidence_digest(),
        ),
    }
}
