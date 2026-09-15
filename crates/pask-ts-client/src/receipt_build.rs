// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>

//! Builds a COSE Receipt carrying an RFC 9162_SHA256 inclusion proof.
//!
//! This module is used by the mock Transparency Service in tests. The real
//! `scitt-ccf-ledger` builds its own receipts internally; this module exists
//! so a test fixture can produce receipts that verify under
//! [`pask_wire::verify_inclusion`] without depending on the real ledger.
//!
//! The receipt is a tag-18 `COSE_Sign1` with:
//!
//! - Protected header: `vds` (395) = `1` (RFC9162_SHA256).
//! - Unprotected header: `vdp` (396) = `{ -1 => [ inclusion_proof ] }`, where
//!   `inclusion_proof` is a bstr wrapping the CBOR array
//!   `[tree_size, leaf_index, [path hashes]]` per RFC 9942 Section 5.2.
//! - Payload: nil (detached). The reconstructed root is the detached payload.
//! - Signature: Ed25519 over the `Sig_structure` of the protected header and
//!   the reconstructed root, matching what `pask_wire::verify_inclusion`
//!   reconstructs.
//!
//! This is a minimal cryptographic test fixture, not a SCITT-conforming
//! claims envelope or an authenticated Transparency Service identity (#71).

use coset::cbor::Value;
use pask_wire::{INCLUSION_PROOF_LABEL, RFC9162_SHA256, VDP_LABEL, VDS_LABEL, leaf_hash};

/// A two-leaf Merkle tree used by the mock service.
///
/// `pask-wire` rejects an empty inclusion path (the CDDL requires `[+ bstr]`)
/// and a single-leaf tree with a non-empty path cannot reconstruct (the loop
/// trips "path is longer than the tree permits" at `tree_size = 1`). The
/// smallest tree that produces a verifiable receipt under the shipped verifier
/// has two leaves, so the mock registers the caller's entry as leaf 0 and a
/// fixed second entry as leaf 1. The root is `HASH(0x01 || left || right)`
/// and the inclusion proof for leaf 0 is `[leaf_hash(entry_1)]` with
/// `tree_size = 2` and `leaf_index = 0`. This is the same algorithm RFC 9162
/// Section 2.1.1 specifies and `InclusionProof::reconstruct_root` implements.
pub struct TwoLeafTree {
    root: [u8; 32],
    sibling: [u8; 32],
}

impl TwoLeafTree {
    /// Builds a tree from the entry bytes the service will register (leaf 0)
    /// and a fixed second entry (leaf 1).
    ///
    /// The leaf hash is `HASH(0x00 || entry)`, matching
    /// [`pask_wire::leaf_hash`]. The root combines the two leaf hashes with
    /// the `0x01` node prefix.
    pub fn new(entry: &[u8]) -> Self {
        use sha2::Digest;
        let left = leaf_hash(entry);
        // A fixed second entry so the tree is deterministic for a given input.
        let right = leaf_hash(b"pask-ts-client mock second leaf");
        let mut hasher = sha2::Sha256::new();
        hasher.update([0x01u8]);
        hasher.update(left);
        hasher.update(right);
        let root: [u8; 32] = hasher.finalize().into();
        Self {
            root,
            sibling: right,
        }
    }

    /// The Merkle root, also the detached payload of the receipt.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The inclusion proof for leaf 0.
    ///
    /// The path holds the sibling hash (leaf 1). With `tree_size = 2` and
    /// `leaf_index = 0`, `reconstruct_root` combines the leaf hash with this
    /// sibling to reconstruct the root.
    pub fn inclusion_proof(&self) -> Vec<[u8; 32]> {
        vec![self.sibling]
    }
}

/// Builds a signed COSE Receipt for a two-leaf tree.
///
/// The receipt is signed by `ts_key` over the reconstructed root. The caller
/// holds the corresponding verifying key and passes it to
/// [`pask_wire::verify_inclusion`].
///
/// # Errors
///
/// Returns an error only if CBOR encoding fails.
pub fn build_receipt(
    tree: &TwoLeafTree,
    ts_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, ReceiptBuildError> {
    use ed25519_dalek::Signer;

    // Protected header: { 395: 1 }
    let protected_map = Value::Map(vec![(
        Value::Integer(VDS_LABEL.into()),
        Value::Integer(RFC9162_SHA256.into()),
    )]);
    let mut protected_raw = Vec::new();
    coset::cbor::ser::into_writer(&protected_map, &mut protected_raw)
        .map_err(|_| ReceiptBuildError::EncodeProtected)?;

    // Inclusion proof: CBOR array [tree_size, leaf_index, [path]] wrapped in bstr.
    let proof_inner = Value::Array(vec![
        Value::Integer(2u64.into()), // tree_size
        Value::Integer(0u64.into()), // leaf_index
        Value::Array(
            tree.inclusion_proof()
                .into_iter()
                .map(|h| Value::Bytes(h.to_vec()))
                .collect(),
        ),
    ]);
    let mut proof_bytes = Vec::new();
    coset::cbor::ser::into_writer(&proof_inner, &mut proof_bytes)
        .map_err(|_| ReceiptBuildError::EncodeProof)?;
    let proof_bstr = Value::Bytes(proof_bytes);

    // Unprotected header: { 396: { -1: [proof_bstr] } }
    let vdp_map = Value::Map(vec![(
        Value::Integer(INCLUSION_PROOF_LABEL.into()),
        Value::Array(vec![proof_bstr]),
    )]);
    let unprotected = Value::Map(vec![(Value::Integer(VDP_LABEL.into()), vdp_map)]);

    // Sig_structure: ["Signature1", protected, h'', root]
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_raw.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(tree.root().to_vec()),
    ]);
    let mut signed_bytes = Vec::new();
    coset::cbor::ser::into_writer(&sig_structure, &mut signed_bytes)
        .map_err(|_| ReceiptBuildError::EncodeSigStructure)?;
    let signature = ts_key.sign(&signed_bytes).to_bytes();

    // COSE_Sign1: [protected, unprotected, payload(nil), signature]
    let receipt = Value::Array(vec![
        Value::Bytes(protected_raw),
        unprotected,
        Value::Null,
        Value::Bytes(signature.to_vec()),
    ]);
    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(&Value::Tag(18, Box::new(receipt)), &mut encoded)
        .map_err(|_| ReceiptBuildError::EncodeReceipt)?;
    Ok(encoded)
}

/// Errors from receipt construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptBuildError {
    EncodeProtected,
    EncodeProof,
    EncodeSigStructure,
    EncodeReceipt,
}

impl std::fmt::Display for ReceiptBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncodeProtected => write!(f, "failed to encode protected header"),
            Self::EncodeProof => write!(f, "failed to encode inclusion proof"),
            Self::EncodeSigStructure => write!(f, "failed to encode Sig_structure"),
            Self::EncodeReceipt => write!(f, "failed to encode the receipt"),
        }
    }
}

impl std::error::Error for ReceiptBuildError {}
