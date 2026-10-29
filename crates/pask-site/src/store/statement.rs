// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Read a sealed statement's payload `chain.hash` without treating the COSE
//! transport hash as the chain predecessor.

use pask_wire::{Payload, TransparentStatementPolicy, inspect_transparent_statement};

use super::error::StoreError;

/// Payload carried by an attached statement.
///
/// # Errors
///
/// Returns [`StoreError::StatementRejected`] when the bytes are not an attached
/// statement or the payload fails profile validation, including `chain.hash`.
pub(super) fn read_statement(bytes: &[u8]) -> Result<Payload, StoreError> {
    if bytes.is_empty() {
        return Err(StoreError::StatementRejected {
            detail: "statement is empty".to_owned(),
        });
    }
    let report = inspect_transparent_statement(bytes, &TransparentStatementPolicy::default());
    let Some(payload) = report.payload_bytes else {
        return Err(StoreError::StatementRejected {
            detail: "statement has no attached payload".to_owned(),
        });
    };
    Payload::from_json(&payload).map_err(|error| StoreError::StatementRejected {
        detail: error.to_string(),
    })
}

/// `sha256:` digest of the exact transported statement bytes.
///
/// This is the COSE transport hash. Chain `prevHash` does not use it.
#[must_use]
pub(super) fn transport_hash(statement: &[u8]) -> String {
    pask_wire::sha256_prefixed(statement)
}
