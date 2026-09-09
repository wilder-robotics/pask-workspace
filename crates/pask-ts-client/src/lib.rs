// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-ts-client is licensed AGPL-3.0-only. It is an operational crate. See
// LICENSING.md in the workspace root.

//! SCRAPI client for registering Pask Signed Statements with a Transparency
//! Service.
//!
//! This is the producing half of issue #40. The reading half, offline
//! verification of an attached Receipt, lives in `pask-wire` (PR #57). This
//! crate does the opposite direction: it takes a Signed Statement produced by
//! [`pask_wire::produce_ed25519`], submits it to a Transparency Service
//! speaking SCRAPI, receives a COSE Receipt, and attaches it to the statement
//! to form a Transparent Statement.
//!
//! # Development-only default
//!
//! `PASK_TS_URL` is read from the environment and must be set explicitly. There
//! is no default URL. This is deliberate: a client that silently falls back to
//! a production endpoint is the exact failure Posture 1 (2026-12-31) exists to
//! prevent. The local development ledger is `http://127.0.0.1:8000`, and the
//! caller sets that explicitly via the environment or [`TsClient::new`].
//!
//! The dev script that stands up the local ledger is `scripts/run-dev-ts.sh`.
//! It builds `microsoft/scitt-ccf-ledger` in virtual mode and is the only
//! supported way to run a Transparency Service against this client today.

use coset::cbor::Value;
use pask_wire::RECEIPTS_LABEL;

mod receipt_build;
mod scrapi;

pub use receipt_build::{ReceiptBuildError, TwoLeafTree, build_receipt};
pub use scrapi::{ReceiptResponse, TsClient, TsClientError};

/// Attaches a Receipt to a Signed Statement, producing a Transparent Statement.
///
/// The receipt is placed in the unprotected header under label 394
/// (`receipts`). Placement in the unprotected map is what allows a Receipt to
/// be attached after signing without invalidating the Issuer's signature, per
/// RFC 9942 Section 5.1. The protected header and payload are untouched.
///
/// This is the inverse of [`pask_wire::attached_receipts`]: that function reads
/// the header this one writes.
///
/// # Errors
///
/// Returns an error if the statement is not a valid four-element `COSE_Sign1`
/// array, or if re-encoding fails.
pub fn attach_receipt(statement: &[u8], receipt: &[u8]) -> Result<Vec<u8>, AttachError> {
    let mut cursor = statement;
    let mut value: Value =
        coset::cbor::de::from_reader(&mut cursor).map_err(|_| AttachError::NotCoseSign1)?;
    if !cursor.is_empty() {
        return Err(AttachError::TrailingBytes);
    }
    let Value::Array(items) = &mut value else {
        return Err(AttachError::NotCoseSign1);
    };
    if items.len() != 4 {
        return Err(AttachError::NotFourElements);
    }
    // items[1] is the unprotected header map.
    let unprotected = &mut items[1];
    let Value::Map(map) = unprotected else {
        return Err(AttachError::UnprotectedNotMap);
    };

    // Decode the receipt to confirm it is valid CBOR before attaching, and
    // to obtain the Value to place in the receipts header. The receipts
    // header is an array of COSE_Sign1 values, not an array of bstr-wrapped
    // values. Storing the decoded Value is what lets attached_receipts
    // re-encode it back to the same bytes verify_inclusion expects.
    let receipt_value: Value = {
        let mut probe = receipt;
        let decoded = coset::cbor::de::from_reader::<Value, _>(&mut probe)
            .map_err(|_| AttachError::ReceiptNotCbor)?;
        if !probe.is_empty() {
            return Err(AttachError::ReceiptTrailingBytes);
        }
        decoded
    };

    let key = Value::Integer(RECEIPTS_LABEL.into());
    // If a receipts header already exists, append. Otherwise insert.
    if let Some(existing) = map.iter_mut().find(|(k, _)| *k == key) {
        match &mut existing.1 {
            Value::Array(arr) => arr.push(receipt_value),
            _ => {
                return Err(AttachError::ExistingReceiptsNotArray);
            }
        }
    } else {
        map.push((key, Value::Array(vec![receipt_value])));
    }

    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(&value, &mut encoded).map_err(|_| AttachError::ReencodeFailed)?;
    Ok(encoded)
}

/// Errors from [`attach_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    /// The statement bytes are not a valid `COSE_Sign1`.
    NotCoseSign1,
    /// The statement carried trailing bytes after the `COSE_Sign1`.
    TrailingBytes,
    /// The `COSE_Sign1` did not carry exactly four elements.
    NotFourElements,
    /// The unprotected header element was not a map.
    UnprotectedNotMap,
    /// The receipt bytes are not valid CBOR.
    ReceiptNotCbor,
    /// The receipt carried trailing bytes.
    ReceiptTrailingBytes,
    /// A `receipts` header already existed but was not an array.
    ExistingReceiptsNotArray,
    /// Re-encoding the modified statement failed.
    ReencodeFailed,
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCoseSign1 => write!(f, "statement is not a valid COSE_Sign1"),
            Self::TrailingBytes => write!(f, "trailing bytes after COSE_Sign1"),
            Self::NotFourElements => write!(f, "COSE_Sign1 must carry exactly four elements"),
            Self::UnprotectedNotMap => write!(f, "unprotected header must be a map"),
            Self::ReceiptNotCbor => write!(f, "receipt is not valid CBOR"),
            Self::ReceiptTrailingBytes => write!(f, "trailing bytes after receipt"),
            Self::ExistingReceiptsNotArray => {
                write!(f, "existing receipts header was not an array")
            }
            Self::ReencodeFailed => write!(f, "failed to re-encode the statement"),
        }
    }
}

impl std::error::Error for AttachError {}
