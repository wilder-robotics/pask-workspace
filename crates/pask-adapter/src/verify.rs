// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use ed25519_dalek::VerifyingKey;
use pask_wire::Payload;

use crate::AdapterError;

/// Verifies a signed receipt before adapter processing begins.
///
/// # Errors
///
/// Returns `AdapterError::VerificationFailed` when signature or payload
/// verification fails.
pub fn verify_before_push(
    signed_receipt: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<Payload, AdapterError> {
    pask_wire::verify_ed25519(signed_receipt, verifying_key).map_err(|source| {
        AdapterError::VerificationFailed {
            message: source.to_string(),
        }
    })
}
