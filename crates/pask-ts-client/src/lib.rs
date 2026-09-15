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
/// RFC 9942 Section 5.1. Each element is a byte string containing the exact
/// supplied tag-18 Receipt encoding (RFC 9942 Section 4.3 / RFC 9943 Section 7).
/// The protected-header, payload, and signature byte-string contents are
/// untouched; outer CBOR framing and the unprotected map may be re-encoded.
///
/// Output is always tag-18 `COSE_Sign1`. An untagged statement is accepted
/// explicitly for compatibility with the current local producers, not as a
/// conforming transmitted envelope. Receipts must already be tagged: this
/// function does not add missing Receipt tags or convert historical decoded
/// attachments. [`pask_wire::attached_receipts`] retains that read-only legacy
/// compatibility separately.
///
/// This checks container structure, not signatures, proofs, SCITT claims,
/// service trust, key association, or hardware evidence. Success is not a
/// conformance or registration-verification result.
///
/// # Errors
///
/// Rejects malformed envelopes, duplicate or overlapping header labels,
/// protected `receipts`, malformed/empty existing attachment arrays, and
/// existing attachments not encoded as byte strings containing tagged Receipts.
/// Invalid inputs are never repaired or silently discarded.
pub fn attach_receipt(statement: &[u8], receipt: &[u8]) -> Result<Vec<u8>, AttachError> {
    let mut cursor = statement;
    let mut value: Value =
        coset::cbor::de::from_reader(&mut cursor).map_err(|_| AttachError::NotCoseSign1)?;
    if !cursor.is_empty() {
        return Err(AttachError::TrailingBytes);
    }
    let array = match &mut value {
        Value::Tag(18, inner) => inner.as_mut(),
        other => other,
    };
    let Value::Array(items) = array else {
        return Err(AttachError::NotCoseSign1);
    };
    if items.len() != 4 {
        return Err(AttachError::NotFourElements);
    }
    let protected = validate_envelope(items, false).map_err(AttachError::InvalidStatement)?;
    if protected
        .iter()
        .any(|(k, _)| *k == Value::Integer(RECEIPTS_LABEL.into()))
    {
        return Err(AttachError::ProtectedReceipts);
    }
    // items[1] is the unprotected header map. Never mutate P, M, or S.
    let unprotected = &mut items[1];
    let Value::Map(map) = unprotected else {
        return Err(AttachError::UnprotectedNotMap);
    };

    // Decode only to validate container shape. Store the original bytes,
    // including any valid noncanonical CBOR framing, never the decoded Value.
    validate_receipt(receipt)?;
    let receipt_value = Value::Bytes(receipt.to_vec());

    let key = Value::Integer(RECEIPTS_LABEL.into());
    // If a receipts header already exists, append. Otherwise insert.
    if let Some(existing) = map.iter_mut().find(|(k, _)| *k == key) {
        match &mut existing.1 {
            Value::Array(arr) => {
                if arr.is_empty() {
                    return Err(AttachError::InvalidExistingReceipt);
                }
                for item in arr.iter() {
                    let Value::Bytes(bytes) = item else {
                        return Err(AttachError::InvalidExistingReceipt);
                    };
                    validate_receipt(bytes).map_err(|_| AttachError::InvalidExistingReceipt)?;
                }
                arr.push(receipt_value);
            }
            _ => {
                return Err(AttachError::ExistingReceiptsNotArray);
            }
        }
    } else {
        map.push((key, Value::Array(vec![receipt_value])));
    }

    // Current local producers emit an untagged array. Adapt that explicit
    // compatibility input to the transmitted form; never strip an input tag.
    if matches!(value, Value::Array(_)) {
        value = Value::Tag(18, Box::new(value));
    }
    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(&value, &mut encoded).map_err(|_| AttachError::ReencodeFailed)?;
    Ok(encoded)
}

fn validate_receipt(receipt: &[u8]) -> Result<(), AttachError> {
    let mut cursor = receipt;
    let value: Value =
        coset::cbor::de::from_reader(&mut cursor).map_err(|_| AttachError::ReceiptNotCbor)?;
    if !cursor.is_empty() {
        return Err(AttachError::ReceiptTrailingBytes);
    }
    let Value::Tag(18, inner) = value else {
        return Err(AttachError::ReceiptNotTaggedSign1);
    };
    let Value::Array(items) = *inner else {
        return Err(AttachError::ReceiptNotTaggedSign1);
    };
    validate_envelope(&items, true).map_err(AttachError::InvalidReceipt)?;
    Ok(())
}

// Only COSE container/header structure is checked here. Header values (e.g.,
// CWT claims and vdp proofs) are not interpreted as claims or verified.
fn validate_envelope(
    items: &[Value],
    allow_detached: bool,
) -> Result<Vec<(Value, Value)>, &'static str> {
    let [
        Value::Bytes(protected),
        Value::Map(unprotected),
        payload,
        Value::Bytes(_),
    ] = items
    else {
        return Err("expected [protected bstr, unprotected map, payload, signature bstr]");
    };
    if !(matches!(payload, Value::Bytes(_)) || allow_detached && *payload == Value::Null) {
        return Err("payload must be a byte string (or null for a Receipt)");
    }
    let protected = if protected.is_empty() {
        Vec::new() // COSE's empty protected-header encoding.
    } else {
        let mut cursor = protected.as_slice();
        let header: Value = coset::cbor::de::from_reader(&mut cursor)
            .map_err(|_| "protected header is not CBOR")?;
        if !cursor.is_empty() {
            return Err("trailing bytes in protected header");
        }
        let Value::Map(entries) = header else {
            return Err("protected header must encode a map");
        };
        entries
    };
    for map in [&protected, unprotected] {
        for (index, (key, _)) in map.iter().enumerate() {
            if !matches!(key, Value::Integer(_) | Value::Text(_)) {
                return Err("COSE header labels must be integers or text");
            }
            if map[..index].iter().any(|(other, _)| key == other) {
                return Err("duplicate COSE header label");
            }
        }
    }
    if protected
        .iter()
        .any(|(key, _)| unprotected.iter().any(|(other, _)| key == other))
    {
        return Err("header label occurs in both protected and unprotected maps");
    }
    Ok(protected)
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
    /// A structural statement check failed.
    InvalidStatement(&'static str),
    /// A Receipt was not a single tag-18 COSE_Sign1 array.
    ReceiptNotTaggedSign1,
    /// A structural Receipt check failed (not a claims/proof check).
    InvalidReceipt(&'static str),
    /// Appending would create protected/unprotected receipts ambiguity.
    ProtectedReceipts,
    /// Existing receipts are empty, malformed, or use decoded legacy values.
    InvalidExistingReceipt,
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
            Self::InvalidStatement(reason) => write!(f, "invalid statement: {reason}"),
            Self::ReceiptNotTaggedSign1 => write!(f, "receipt must be a tag-18 COSE_Sign1"),
            Self::InvalidReceipt(reason) => write!(f, "invalid receipt: {reason}"),
            Self::ProtectedReceipts => write!(f, "cannot append to protected receipts"),
            Self::InvalidExistingReceipt => write!(
                f,
                "existing receipts must be nonempty byte-string-wrapped tagged Receipts"
            ),
            Self::ReencodeFailed => write!(f, "failed to re-encode the statement"),
        }
    }
}

impl std::error::Error for AttachError {}
