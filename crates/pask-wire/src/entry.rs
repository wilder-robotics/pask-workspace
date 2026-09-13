// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Candidate-entry byte encoding for inclusion-proof verification.
//!
//! Derives the candidate entry from a presented Transparent Statement per the
//! -04 candidate-entry design. The candidate entry is the untagged four-element
//! CBOR array `[P, {}, M, S]` where P, M, and S are the original protected
//! header, payload, and signature byte-string contents, and the unprotected
//! header is replaced by an empty map.
//!
//! The derivation preserves P, M, and S by content. It does not parse and
//! reserialize their contents. Only the outer array structure uses
//! deterministic encoding per RFC 8949 Section 4.2.1.
//!
//! See `pask_-04_design_67_v3_consolidated.md` for the full design.

use alloc::{vec, vec::Vec};

use coset::cbor::Value;

use crate::{Error, Result};

/// The CBOR tag for a COSE_Sign1 structure (RFC 9052 Section 4.2).
const COSE_SIGN1_TAG: u64 = 18;

/// Derives the candidate entry from a presented Transparent Statement.
///
/// The input MUST be a COSE_Sign1 with four array elements: protected-header
/// byte string, unprotected-header map, attached-payload byte string, and
/// signature byte string. The payload MUST be present as a byte string; a
/// null payload indicating detached content is not permitted. The input may
/// be an untagged COSE_Sign1 or a COSE_Sign1 wrapped in tag 18.
///
/// The output is the deterministically encoded CBOR array `[P, {}, M, S]`
/// where P, M, and S are the original byte-string contents and the
/// unprotected header is replaced by an empty CBOR map (`0xa0`).
///
/// # Errors
///
/// Returns [`Error::Cose`] if the input is not valid CBOR, is not a
/// four-element COSE_Sign1 array (with or without tag 18), the unprotected
/// header is not a map, contains a null or detached payload, or has
/// trailing bytes after the CBOR object.
///
/// # Derivation rules
///
/// - P, M, and S are preserved by content. Their internal bytes are not
///   parsed or reserialized.
/// - The outer array is definite-length with shortest definite-length
///   byte-string encodings per RFC 8949 Section 4.2.1.
/// - The unprotected header is replaced by an empty map. This means
///   attaching, removing, or modifying receipts does not change the
///   candidate entry.
pub fn derive_candidate_entry(transparent_statement: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = transparent_statement;
    let value: Value = coset::cbor::de::from_reader(&mut cursor)
        .map_err(|_| Error::Cose("failed to parse Transparent Statement CBOR"))?;

    if !cursor.is_empty() {
        return Err(Error::Cose("trailing bytes after Transparent Statement"));
    }

    // Unwrap tag 18 if present; reject other tag wrappers.
    let array_value = match value {
        Value::Tag(tag, inner) => {
            if tag != COSE_SIGN1_TAG {
                return Err(Error::Cose(
                    "unsupported tag wrapper; only tag 18 is accepted",
                ));
            }
            *inner
        }
        Value::Array(_) => value,
        _ => {
            return Err(Error::Cose(
                "Transparent Statement must be a COSE_Sign1 array or tag-18 wrapper",
            ));
        }
    };

    let Value::Array(items) = array_value else {
        return Err(Error::Cose(
            "Transparent Statement must be a COSE_Sign1 array",
        ));
    };

    if items.len() != 4 {
        return Err(Error::Cose("COSE_Sign1 must have exactly 4 elements"));
    }

    // Extract P (protected header bytes)
    let Value::Bytes(protected) = &items[0] else {
        return Err(Error::Cose("protected header must be a byte string"));
    };

    // The unprotected header (items[1]) MUST be a CBOR map. Replacing its
    // contents does not authorize repairing an invalid input type.
    if !matches!(&items[1], Value::Map(_)) {
        return Err(Error::Cose("unprotected header must be a map"));
    }

    // Extract M (payload bytes); reject null (detached payload)
    let payload = match &items[2] {
        Value::Bytes(bytes) => bytes.clone(),
        Value::Null => {
            return Err(Error::Cose(
                "detached payload (null) is not permitted; payload must be present as a byte string",
            ));
        }
        _ => return Err(Error::Cose("payload must be a byte string")),
    };

    // Extract S (signature bytes)
    let Value::Bytes(signature) = &items[3] else {
        return Err(Error::Cose("signature must be a byte string"));
    };

    // Construct candidate entry [P, {}, M, S] with deterministic encoding.
    // The outer array uses RFC 8949 Section 4.2.1 core deterministic encoding.
    // P, M, S are preserved by content — their bytes are not parsed or reserialized.
    let candidate = Value::Array(vec![
        Value::Bytes(protected.clone()),
        Value::Map(vec![]),
        Value::Bytes(payload),
        Value::Bytes(signature.clone()),
    ]);

    let mut output = Vec::new();
    coset::cbor::ser::into_writer(&candidate, &mut output)
        .map_err(|_| Error::Cose("failed to serialize candidate entry"))?;

    Ok(output)
}

/// Computes the leaf hash for a candidate entry using RFC 9162 Section 2.1.1.
///
/// `SHA256(0x00 || candidate_entry)`
///
/// This is a convenience wrapper around [`crate::leaf_hash`] for the
/// candidate-entry derivation path.
#[must_use]
pub fn candidate_leaf_hash(candidate_entry: &[u8]) -> [u8; 32] {
    crate::receipt::leaf_hash(candidate_entry)
}
