// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Offline verification of a SCITT Receipt attached to a Physical-Site
//! Engagement Receipt Signed Statement.
//!
//! `-02` "SCITT registration and Receipt attachment" makes registration mandatory and places a
//! matching obligation on the reader: a relying party MUST NOT accept a
//! Physical-Site Engagement Receipt as conforming to this profile unless at
//! least one attached Receipt from a Transparency Service that relying party
//! trusts verifies per RFC 9942.
//!
//! Until this module existed, nothing in this repository could evaluate that
//! sentence. [`verify_ed25519`](crate::verify_ed25519) returned `Ok(Payload)`
//! for a statement carrying no attached Receipt at all, so the library's
//! success value said more than the library had checked. That is the narrower
//! and sharper half of the gap recorded in `KNOWN-LIMITATIONS.md` 5.2: the
//! recorded limitation is that no crate *registers* anything, but the
//! consequence a relying party actually meets is that no crate could *check* a
//! registration either. This module closes the checking half. It does not
//! close the producing half, and the limitations file still says so.
//!
//! # What this module will not do
//!
//! It will not tell a caller that a statement is conforming. Conformance under
//! `-02` "SCITT registration and Receipt attachment" turns on a Receipt from a Transparency Service *that
//! relying party trusts*, and trust in a Transparency Service is the relying
//! party's decision, held outside this library. What this module reports is
//! narrower and checkable: this inclusion proof is well formed, it reconstructs
//! this Merkle root over the entry bytes you supplied, and the signature over
//! that root verifies under the key you supplied. Turning that into a
//! conformance decision is the caller's step, and naming the boundary is the
//! point rather than a shortcoming.
//!
//! The same discipline governs [`AttachedReceipts`]. It distinguishes a
//! statement with no `receipts` header from one whose header is present but
//! unreadable, and it does not offer a single boolean over the set. Collapsing
//! "no Receipt was attached" and "a Receipt was attached and did not verify"
//! into one falsey value is the specific error that would let an unregistered
//! statement and a tampered one be reported to a relying party in the same
//! words, which is the mistake [`ChainReport`](crate::ChainReport) exists to
//! avoid one level up.
//!
//! # The entry bytes are a caller input, deliberately
//!
//! RFC 9942 Section 5.2 verification begins "the verifier obtains the bytes of
//! a candidate entry" and applies the inclusion proof to them. It does not say
//! what a SCITT log entry is, and neither does `-02`: the profile requires
//! registration and asserts the result is offline-checkable, but never pins the
//! byte sequence the Merkle leaf covers. Two conforming implementations can
//! therefore disagree about what was logged while both believing they follow
//! the profile, and no proof either produces will verify against the other.
//!
//! This module does not paper over that. [`verify_inclusion`] takes the entry
//! bytes as an explicit argument rather than deriving them from the statement,
//! so the ambiguity stays visible at the call site instead of being silently
//! resolved one way inside a library. Resolving it is document work, not code
//! work, and it belongs in a revision.

use alloc::{vec, vec::Vec};
use coset::cbor::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// COSE header parameter carrying attached Receipts (RFC 9942 Section 5.1).
pub const RECEIPTS_LABEL: i64 = 394;

/// COSE protected header parameter carrying the VDS identifier.
pub const VDS_LABEL: i64 = 395;

/// COSE unprotected header parameter carrying Verifiable Data Structure Proofs.
pub const VDP_LABEL: i64 = 396;

/// Key within the `vdp` map holding inclusion proofs.
pub const INCLUSION_PROOF_LABEL: i64 = -1;

/// The `RFC9162_SHA256` Verifiable Data Structure identifier.
pub const RFC9162_SHA256: i64 = 1;

/// Domain-separation prefix for a Merkle leaf (RFC 9162 Section 2.1.1).
const LEAF_PREFIX: u8 = 0x00;

/// Domain-separation prefix for a Merkle interior node (RFC 9162 Section 2.1.1).
const NODE_PREFIX: u8 = 0x01;

/// `MTH({d})` for a single entry: `HASH(0x00 || d)`.
#[must_use]
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// An interior node: `HASH(0x01 || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// A decoded `RFC9162_SHA256` inclusion proof.
///
/// The wire form is a `bstr` wrapping the CBOR array
/// `[tree_size: uint, leaf_index: uint, inclusion_path: [+ bstr]]`
/// (RFC 9942 Section 5.2). Note the field order: `tree_size` precedes
/// `leaf_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Size of the tree whose root this proof reconstructs.
    pub tree_size: u64,
    /// Index of the proven leaf, relative to `tree_size`.
    pub leaf_index: u64,
    /// Sibling hashes on the path from the leaf to the root.
    pub inclusion_path: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// Decodes one inclusion proof from the CBOR inside its `bstr` wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Receipt`] if the bytes are not the CBOR three-element
    /// array RFC 9942 Section 5.2 specifies, if either count is not an
    /// unsigned integer, if the path is empty, or if any path element is not
    /// exactly 32 bytes. An empty `inclusion_path` is rejected because the
    /// CDDL requires at least one element (`[+ bstr]`); a single-leaf tree
    /// still carries a proof, and a genuinely empty array is a malformed
    /// proof rather than a proof of a one-entry log.
    pub fn from_wrapped_cbor(wrapped: &[u8]) -> Result<Self> {
        let mut cursor = wrapped;
        let value: Value = coset::cbor::de::from_reader(&mut cursor)
            .map_err(|_| Error::Receipt("inclusion proof is not valid CBOR"))?;
        if !cursor.is_empty() {
            return Err(Error::Receipt("trailing bytes after inclusion proof"));
        }
        let Value::Array(items) = value else {
            return Err(Error::Receipt("inclusion proof must be a CBOR array"));
        };
        let [tree_size, leaf_index, path] = items.as_slice() else {
            return Err(Error::Receipt(
                "inclusion proof must carry exactly three elements",
            ));
        };
        let tree_size = unsigned(tree_size)
            .ok_or(Error::Receipt("inclusion proof tree_size must be a uint"))?;
        let leaf_index = unsigned(leaf_index)
            .ok_or(Error::Receipt("inclusion proof leaf_index must be a uint"))?;
        let Value::Array(path) = path else {
            return Err(Error::Receipt(
                "inclusion proof inclusion_path must be an array",
            ));
        };
        if path.is_empty() {
            return Err(Error::Receipt(
                "inclusion proof inclusion_path must not be empty",
            ));
        }
        let mut inclusion_path = Vec::with_capacity(path.len());
        for element in path {
            let Value::Bytes(bytes) = element else {
                return Err(Error::Receipt(
                    "inclusion proof inclusion_path elements must be byte strings",
                ));
            };
            let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                Error::Receipt("inclusion proof inclusion_path elements must be 32 bytes")
            })?;
            inclusion_path.push(hash);
        }
        Ok(Self {
            tree_size,
            leaf_index,
            inclusion_path,
        })
    }

    /// Reconstructs the Merkle root this proof claims, given the proven leaf hash.
    ///
    /// This is RFC 9162 Section 2.1.3.2 verbatim, up to but not including its
    /// final comparison against a known root. The comparison is left to the
    /// caller because in the detached-payload case there is no known root to
    /// compare against: the reconstructed root *becomes* the `COSE_Sign1`
    /// payload, and the signature check is what binds it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Receipt`] when `leaf_index >= tree_size`, when the
    /// path is longer than the tree can justify, or when the path runs out
    /// before the root is reached.
    pub fn reconstruct_root(&self, leaf: [u8; 32]) -> Result<[u8; 32]> {
        // Step 1.
        if self.leaf_index >= self.tree_size {
            return Err(Error::Receipt(
                "inclusion proof leaf_index is not less than tree_size",
            ));
        }
        // Step 2.
        let mut node_index = self.leaf_index;
        let mut last_index = self.tree_size - 1;
        // Step 3.
        let mut root = leaf;
        // Step 4.
        for sibling in &self.inclusion_path {
            // Step 4a.
            if last_index == 0 {
                return Err(Error::Receipt(
                    "inclusion proof path is longer than the tree permits",
                ));
            }
            // Step 4b.
            if node_index & 1 == 1 || node_index == last_index {
                root = node_hash(sibling, &root);
                // Step 4b.ii.
                if node_index & 1 == 0 {
                    loop {
                        node_index >>= 1;
                        last_index >>= 1;
                        if node_index & 1 == 1 || node_index == 0 {
                            break;
                        }
                    }
                }
            } else {
                root = node_hash(&root, sibling);
            }
            // Step 4c.
            node_index >>= 1;
            last_index >>= 1;
        }
        // Step 5.
        if last_index != 0 {
            return Err(Error::Receipt(
                "inclusion proof path ended before the root was reached",
            ));
        }
        Ok(root)
    }
}

/// The `receipts` (394) header of a Signed Statement, as read.
///
/// The two states are kept apart on purpose. A statement that carries no
/// `receipts` header is unregistered as far as the presented bytes can show. A
/// statement whose header is present but unreadable is a different finding,
/// and a relying party that treats the second as the first has been told a
/// tampered or truncated envelope was merely never registered.
///
/// There is deliberately no method returning a single boolean over the set,
/// and no `is_conforming`. Which attached Receipts count is a function of which
/// Transparency Services the relying party trusts, and this type does not know
/// that.
///
/// Both states describe a header that *was read*. This type is only ever
/// produced by [`attached_receipts`], so it cannot represent "the envelope was
/// never examined". A caller that has not called [`attached_receipts`] holds no
/// value of this type at all, which is the distinction giskard09's
/// `negotiation_linkage` invariant draws with an explicit `None`: never report
/// absence you did not look for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachedReceipts {
    /// The statement carried no `receipts` header.
    Absent,
    /// The statement carried a `receipts` header that could not be read as an
    /// array of Receipts. Carries the reason.
    Malformed(&'static str),
    /// One or more attached Receipts, in the priority order presented.
    Present(Vec<Vec<u8>>),
}

impl AttachedReceipts {
    /// The attached Receipts, or an empty slice in the `Absent` and
    /// `Malformed` cases.
    ///
    /// Callers deciding conformance must match on the variant rather than
    /// reach for this, because an empty slice here does not distinguish a
    /// statement that carried nothing from one whose header was unreadable.
    #[must_use]
    pub fn as_slice(&self) -> &[Vec<u8>] {
        match self {
            Self::Present(receipts) => receipts,
            Self::Absent | Self::Malformed(_) => &[],
        }
    }
}

/// Reads the `receipts` (394) header from a `COSE_Sign1` Signed Statement.
///
/// The header may appear in either the protected or the unprotected map per
/// RFC 9942 Section 5.1. This reads the unprotected map, where
/// `-02` "SCITT registration and Receipt attachment" places it, and then the protected map. Placement in
/// the unprotected map is what allows a Receipt to be attached after signing
/// without invalidating the Issuer's signature.
///
/// This parses the envelope structurally and does not verify the Issuer
/// signature. Reading a header is not accepting a statement, and the two steps
/// are kept separate so that neither can be mistaken for the other.
///
/// # Errors
///
/// Returns [`Error::Cose`] if the outer bytes are not a `COSE_Sign1`. A
/// well-formed envelope whose `receipts` header is itself unusable yields
/// `Ok(`[`AttachedReceipts::Malformed`]`)` rather than an error, because that
/// distinction is a finding to report to a relying party rather than a parse
/// failure.
pub fn attached_receipts(statement: &[u8]) -> Result<AttachedReceipts> {
    let mut cursor = statement;
    let value: Value = coset::cbor::de::from_reader(&mut cursor)
        .map_err(|_| Error::Cose("failed to parse COSE_Sign1 CBOR"))?;
    if !cursor.is_empty() {
        return Err(Error::Cose("trailing bytes after COSE_Sign1"));
    }
    let items = cose_sign1_items(&value).ok_or(Error::Cose("COSE_Sign1 must be an array"))?;
    let [protected, unprotected, _payload, _signature] = items else {
        return Err(Error::Cose("COSE_Sign1 must carry exactly four elements"));
    };

    if let Some(found) = map_entry(unprotected, RECEIPTS_LABEL) {
        return Ok(read_receipts_array(found));
    }
    let Value::Bytes(protected) = protected else {
        return Err(Error::Cose("COSE_Sign1 protected header must be bytes"));
    };
    let mut cursor = protected.as_slice();
    if let Ok(header) = coset::cbor::de::from_reader::<Value, _>(&mut cursor)
        && let Some(found) = map_entry(&header, RECEIPTS_LABEL)
    {
        return Ok(read_receipts_array(found));
    }
    Ok(AttachedReceipts::Absent)
}

fn read_receipts_array(value: &Value) -> AttachedReceipts {
    let Value::Array(items) = value else {
        return AttachedReceipts::Malformed("receipts header is not an array");
    };
    if items.is_empty() {
        return AttachedReceipts::Malformed("receipts header is an empty array");
    }
    let mut receipts = Vec::with_capacity(items.len());
    for item in items {
        let mut encoded = Vec::new();
        if coset::cbor::ser::into_writer(item, &mut encoded).is_err() {
            return AttachedReceipts::Malformed("a receipts element could not be re-encoded");
        }
        receipts.push(encoded);
    }
    AttachedReceipts::Present(receipts)
}

/// A decoded attached Receipt, before its signature has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The Verifiable Data Structure identifier from the protected header.
    pub vds: i64,
    /// The inclusion proofs from the `vdp` map, in the order presented.
    pub inclusion_proofs: Vec<InclusionProof>,
    /// The payload, absent when detached.
    pub payload: Option<Vec<u8>>,
    protected_raw: Vec<u8>,
    signature: Vec<u8>,
}

impl Receipt {
    /// Decodes an attached Receipt from its `COSE_Sign1` bytes.
    ///
    /// Accepts both the CBOR-tagged form (`#6.18`, RFC 9942 Section 5.2) and
    /// the untagged array, because a Receipt read out of a `receipts` array has
    /// already been located by position and the tag carries no information the
    /// reader lacks at that point.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Receipt`] if the bytes are not a four-element
    /// `COSE_Sign1`, if the protected header is absent or does not carry an
    /// integer `vds`, or if no inclusion proof can be read from the `vdp` map.
    pub fn from_cose_sign1(receipt: &[u8]) -> Result<Self> {
        let mut cursor = receipt;
        let value: Value = coset::cbor::de::from_reader(&mut cursor)
            .map_err(|_| Error::Receipt("receipt is not valid CBOR"))?;
        if !cursor.is_empty() {
            return Err(Error::Receipt("trailing bytes after receipt"));
        }
        let items =
            cose_sign1_items(&value).ok_or(Error::Receipt("receipt must be a COSE_Sign1 array"))?;
        let [protected, unprotected, payload, signature] = items else {
            return Err(Error::Receipt("receipt must carry exactly four elements"));
        };
        let Value::Bytes(protected_raw) = protected else {
            return Err(Error::Receipt("receipt protected header must be bytes"));
        };
        let Value::Bytes(signature) = signature else {
            return Err(Error::Receipt("receipt signature must be bytes"));
        };

        let mut cursor = protected_raw.as_slice();
        let header: Value = coset::cbor::de::from_reader(&mut cursor)
            .map_err(|_| Error::Receipt("receipt protected header is not valid CBOR"))?;
        let vds = map_entry(&header, VDS_LABEL)
            .and_then(signed)
            .ok_or(Error::Receipt("receipt protected header must carry vds"))?;

        let vdp = map_entry(unprotected, VDP_LABEL)
            .ok_or(Error::Receipt("receipt unprotected header must carry vdp"))?;
        let proofs = map_entry(vdp, INCLUSION_PROOF_LABEL)
            .ok_or(Error::Receipt("vdp map must carry an inclusion proof"))?;
        let Value::Array(proofs) = proofs else {
            return Err(Error::Receipt("inclusion proofs must be an array"));
        };
        if proofs.is_empty() {
            return Err(Error::Receipt("inclusion proofs must not be empty"));
        }
        let mut inclusion_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let Value::Bytes(wrapped) = proof else {
                return Err(Error::Receipt("each inclusion proof must be a byte string"));
            };
            inclusion_proofs.push(InclusionProof::from_wrapped_cbor(wrapped)?);
        }

        let payload = match payload {
            Value::Bytes(bytes) => Some(bytes.clone()),
            Value::Null => None,
            _ => return Err(Error::Receipt("receipt payload must be bytes or null")),
        };

        Ok(Self {
            vds,
            inclusion_proofs,
            payload,
            protected_raw: protected_raw.clone(),
            signature: signature.clone(),
        })
    }

    /// The `Sig_structure` bytes this Receipt's signature covers, for a given root.
    ///
    /// When the payload is attached, `root` must equal it; the caller is
    /// expected to have checked that already. When it is detached, the
    /// reconstructed root supplies the payload, which is the mechanism RFC 9942
    /// Section 5.2 describes.
    fn signed_bytes(&self, root: &[u8]) -> Result<Vec<u8>> {
        let structure = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(self.protected_raw.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(root.to_vec()),
        ]);
        let mut encoded = Vec::new();
        coset::cbor::ser::into_writer(&structure, &mut encoded)
            .map_err(|_| Error::Receipt("failed to encode Sig_structure"))?;
        Ok(encoded)
    }
}

/// What an attached Receipt was found to prove.
///
/// Holding one of these means: an inclusion proof reconstructed
/// [`root`](Self::root) over the entry bytes supplied, and the Receipt's
/// signature over that root verified under the Transparency Service key
/// supplied. It does not mean the statement is conforming, because that turns
/// on whether the relying party trusts the Transparency Service holding that
/// key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInclusion {
    /// The Merkle root the proof reconstructed and the signature covers.
    pub root: [u8; 32],
    /// Size of the tree the proof was taken against.
    pub tree_size: u64,
    /// Index of the proven leaf.
    pub leaf_index: u64,
}

/// Verifies an attached Receipt's inclusion proof and Ed25519 signature, offline.
///
/// This is the two-step algorithm of RFC 9942 Section 5.2, in order:
///
/// 1. Apply the inclusion proof to the leaf hash of `entry` to reconstruct a
///    Merkle root. When the Receipt carries an attached payload, that payload
///    MUST equal the reconstructed root; a mismatch fails here rather than
///    being deferred to the signature check, so the failure names the proof
///    rather than the key.
/// 2. Verify the Receipt's `COSE_Sign1` signature over that root under
///    `transparency_service_key`.
///
/// The first inclusion proof that satisfies both steps is returned. No network
/// access occurs: everything checked is either in `receipt`, in `entry`, or in
/// the key, all of which the caller already holds.
///
/// On `entry`: see the module documentation. The profile does not specify what
/// a SCITT log entry is for a Physical-Site Engagement Receipt, so the caller
/// supplies the bytes rather than this function guessing them.
///
/// # Errors
///
/// Returns [`Error::Receipt`] if the Receipt cannot be decoded, if its `vds`
/// is not [`RFC9162_SHA256`], or if no inclusion proof both reconstructs a
/// root and carries a signature verifying under the supplied key.
pub fn verify_inclusion(
    receipt: &[u8],
    entry: &[u8],
    transparency_service_key: &ed25519_dalek::VerifyingKey,
) -> Result<VerifiedInclusion> {
    use ed25519_dalek::Verifier;

    let receipt = Receipt::from_cose_sign1(receipt)?;
    if receipt.vds != RFC9162_SHA256 {
        return Err(Error::Receipt(
            "unsupported verifiable data structure; only RFC9162_SHA256 is implemented",
        ));
    }
    let signature =
        ed25519_dalek::Signature::from_slice(&receipt.signature).map_err(|_| Error::Signature)?;
    let leaf = leaf_hash(entry);

    let mut last = Error::Receipt("receipt carried no usable inclusion proof");
    for proof in &receipt.inclusion_proofs {
        let root = match proof.reconstruct_root(leaf) {
            Ok(root) => root,
            Err(error) => {
                last = error;
                continue;
            }
        };
        if let Some(attached) = &receipt.payload
            && attached.as_slice() != root.as_slice()
        {
            last =
                Error::Receipt("reconstructed root does not match the receipt's attached payload");
            continue;
        }
        let signed = receipt.signed_bytes(&root)?;
        if transparency_service_key
            .verify(&signed, &signature)
            .is_err()
        {
            last = Error::Signature;
            continue;
        }
        return Ok(VerifiedInclusion {
            root,
            tree_size: proof.tree_size,
            leaf_index: proof.leaf_index,
        });
    }
    Err(last)
}

/// Returns the four `COSE_Sign1` elements, unwrapping a `#6.18` tag if present.
fn cose_sign1_items(value: &Value) -> Option<&[Value]> {
    let value = match value {
        Value::Tag(18, inner) => inner.as_ref(),
        other => other,
    };
    match value {
        Value::Array(items) => Some(items.as_slice()),
        _ => None,
    }
}

/// Looks up an integer-labelled entry in a CBOR map.
fn map_entry(value: &Value, label: i64) -> Option<&Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| signed(key) == Some(label))
        .map(|(_, found)| found)
}

/// Reads a CBOR integer as `i64`.
fn signed(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(integer) => i128::from(*integer).try_into().ok(),
        _ => None,
    }
}

/// Reads a CBOR unsigned integer as `u64`.
fn unsigned(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(integer) => i128::from(*integer).try_into().ok(),
        _ => None,
    }
}
