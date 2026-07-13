// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use pask_wire::Payload;
use serde::Serialize;

use crate::{AdapterError, lower_hex, receipt_digest};

/// Buildium note request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct BuildiumNote {
    /// Short receipt-oriented subject.
    pub subject: String,

    /// Deterministic receipt summary.
    pub note: String,

    /// Whether the note is private.
    pub is_private: bool,
}

/// Maps a verified payload and raw signed receipt to a Buildium note.
///
/// # Errors
///
/// The current mapping is deterministic and infallible. A `Result` is retained
/// so future serialization-independent mapping validation can report an
/// adapter error without changing callers.
pub fn build_note(
    payload: &Payload,
    signed_receipt: &[u8],
) -> Result<(String, BuildiumNote), AdapterError> {
    let digest = lower_hex(&receipt_digest(signed_receipt));
    let subject = format!("Pask Receipt {}", &digest[..12]);
    let note = format!(
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
    );

    Ok((
        payload.adapter_endpoint().to_owned(),
        BuildiumNote {
            subject,
            note,
            is_private: false,
        },
    ))
}
