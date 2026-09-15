// SPDX-License-Identifier: Apache-2.0
//! Issue #67 integration tests: candidate-entry derivation, inclusion verification,
//! receipt reader compatibility, and multi-receipt aggregation.
//!
//! These tests load a JSON file of independently derived expected values
//! (produced by scripts/generate_independent_vectors.py using cbor2) and
//! assert that the Rust implementation produces identical bytes.
//!
//! The expected values were derived in Python from fixture bytes exported by
//! the Rust producer. The Rust tests do NOT call derive_candidate_entry to
//! produce the expected value; they load it from the JSON and compare.
//!
//! ## Test-only aggregation
//!
//! The `verify_from_final_statement` helper and `ReceiptOutcome` enum below
//! are test-only demonstrations of a recipient verification path. They are
//! NOT exported library APIs. Application integration remains open.

#![cfg(feature = "alloc")]

use coset::cbor::Value;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pask_wire::{
    AttachedReceipts, RFC9162_SHA256, VDP_LABEL, VDS_LABEL, attached_receipts,
    derive_candidate_entry, leaf_hash, verify_ed25519, verify_inclusion,
};
use sha2::{Digest, Sha256};

const RECEIPTS_LABEL: i64 = 394;
const COSE_SIGN1_TAG: u64 = 18;

fn cbor_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(value, &mut encoded).expect("encoding to a Vec cannot fail");
    encoded
}

fn merkle_tree_hash(entries: &[Vec<u8>]) -> [u8; 32] {
    match entries {
        [] => Sha256::digest([]).into(),
        [single] => leaf_hash(single),
        _ => {
            let split = largest_power_of_two_below(entries.len());
            let (left, right) = entries.split_at(split);
            let mut hasher = Sha256::new();
            hasher.update([0x01u8]);
            hasher.update(merkle_tree_hash(left));
            hasher.update(merkle_tree_hash(right));
            hasher.finalize().into()
        }
    }
}

fn largest_power_of_two_below(n: usize) -> usize {
    assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn inclusion_path(entries: &[Vec<u8>], index: usize) -> Vec<[u8; 32]> {
    assert!(index < entries.len());
    if entries.len() == 1 {
        return Vec::new();
    }
    let split = largest_power_of_two_below(entries.len());
    let (left, right) = entries.split_at(split);
    if index < split {
        let mut path = inclusion_path(left, index);
        path.push(merkle_tree_hash(right));
        path
    } else {
        let mut path = inclusion_path(right, index - split);
        path.push(merkle_tree_hash(left));
        path
    }
}

fn wrapped_proof(tree_size: u64, leaf_index: u64, path: &[[u8; 32]]) -> Vec<u8> {
    cbor_value(&Value::Array(vec![
        Value::Integer(tree_size.into()),
        Value::Integer(leaf_index.into()),
        Value::Array(path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
    ]))
}

fn ts_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn build_receipt(key: &SigningKey, root: &[u8; 32], proofs: &[Vec<u8>], vds: i64) -> Vec<u8> {
    let protected = cbor_value(&Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer((-8).into())),
        (Value::Integer(VDS_LABEL.into()), Value::Integer(vds.into())),
    ]));
    let unprotected = Value::Map(vec![(
        Value::Integer(VDP_LABEL.into()),
        Value::Map(vec![(
            Value::Integer((-1).into()),
            Value::Array(proofs.iter().cloned().map(Value::Bytes).collect()),
        )]),
    )]);
    let signed = cbor_value(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(root.to_vec()),
    ]));
    let signature = key.sign(&signed).to_bytes().to_vec();
    let receipt_array = Value::Array(vec![
        Value::Bytes(protected),
        unprotected,
        Value::Null,
        Value::Bytes(signature),
    ]);
    cbor_value(&Value::Tag(COSE_SIGN1_TAG, Box::new(receipt_array)))
}

fn attach_receipts_wire(statement: &[u8], receipts: &[Vec<u8>]) -> Vec<u8> {
    let mut cursor = statement;
    let value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(mut items) = value else {
        panic!("must be array");
    };
    let receipt_values: Vec<Value> = receipts.iter().map(|r| Value::Bytes(r.clone())).collect();
    items[1] = Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(receipt_values),
    )]);
    cbor_value(&Value::Array(items))
}

/// Build a statement with receipts as bare COSE_Sign1 Values (legacy form).
fn attach_receipts_legacy(statement: &[u8], receipts: &[Vec<u8>]) -> Vec<u8> {
    let mut cursor = statement;
    let value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(mut items) = value else {
        panic!("must be array");
    };
    let receipt_values: Vec<Value> = receipts
        .iter()
        .map(|r| {
            let v: Value = coset::cbor::de::from_reader(&mut r.as_slice()).unwrap();
            v
        })
        .collect();
    items[1] = Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(receipt_values),
    )]);
    cbor_value(&Value::Array(items))
}

/// Build a statement with no receipts header at all.
fn attach_no_receipts(statement: &[u8]) -> Vec<u8> {
    let mut cursor = statement;
    let value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(mut items) = value else {
        panic!("must be array");
    };
    items[1] = Value::Map(vec![]);
    cbor_value(&Value::Array(items))
}

// ---------------------------------------------------------------------------
// Test-only aggregation helper (NOT an exported library API)
// ---------------------------------------------------------------------------

/// Per-receipt outcome from the test-only recipient verification path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiptOutcome {
    /// The receipt's inclusion proof verified under the supplied TS key.
    Verified,
    /// The receipt was readable but its TS signature did not verify.
    SignatureFailed,
    /// The receipt used a VDS this implementation does not support.
    UnsupportedVds,
    /// The receipt was malformed or its proof did not reconstruct a valid root.
    Malformed,
    /// No receipts were attached to the statement.
    NoReceipts,
}

impl std::fmt::Display for ReceiptOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::SignatureFailed => write!(f, "signature failed"),
            Self::UnsupportedVds => write!(f, "unsupported VDS"),
            Self::Malformed => write!(f, "malformed"),
            Self::NoReceipts => write!(f, "no receipts"),
        }
    }
}

/// Test-only recipient verification path.
///
/// Input: the final Transparent Statement (with receipts attached) and
/// explicit trust inputs (TS public key). No saved entry from the producer.
///
/// Steps:
/// 1. Derive the candidate entry from the final statement.
/// 2. Extract the attached receipts.
/// 3. For each receipt, verify the inclusion proof.
///
/// Returns one outcome per receipt, or a single `NoReceipts` if absent.
///
/// This is a test-only demonstration. It is NOT an exported library API.
fn verify_from_final_statement(
    final_statement: &[u8],
    ts_verifying: &VerifyingKey,
) -> (Vec<ReceiptOutcome>, Vec<Vec<u8>>) {
    let entry = match derive_candidate_entry(final_statement) {
        Ok(entry) => entry,
        Err(_e) => {
            return (vec![ReceiptOutcome::Malformed], Vec::new());
        }
    };

    let attached = match attached_receipts(final_statement) {
        Ok(attached) => attached,
        Err(_) => {
            return (vec![ReceiptOutcome::Malformed], Vec::new());
        }
    };

    let receipts = match &attached {
        AttachedReceipts::Present(receipts) => receipts.clone(),
        AttachedReceipts::Absent => return (vec![ReceiptOutcome::NoReceipts], Vec::new()),
        AttachedReceipts::Malformed(_) => {
            return (vec![ReceiptOutcome::Malformed], Vec::new());
        }
    };

    let mut outcomes = Vec::new();
    for receipt in &receipts {
        let outcome = match verify_inclusion(receipt, &entry, ts_verifying) {
            Ok(_) => ReceiptOutcome::Verified,
            Err(pask_wire::Error::Signature) => ReceiptOutcome::SignatureFailed,
            Err(pask_wire::Error::Receipt(msg)) => {
                if msg.contains("verifiable data structure") || msg.contains("vds") {
                    ReceiptOutcome::UnsupportedVds
                } else {
                    ReceiptOutcome::Malformed
                }
            }
            Err(_) => ReceiptOutcome::Malformed,
        };
        outcomes.push(outcome);
    }

    (outcomes, receipts)
}

/// Expected values loaded from the independent JSON file.
struct ExpectedVectors {
    candidate_entry: Vec<u8>,
    leaf_hash: [u8; 32],
    merkle_root: [u8; 32],
    inclusion_path: Vec<[u8; 32]>,
    raw_statement: Vec<u8>,
    final_statement: Vec<u8>,
    receipt: Vec<u8>,
    issuer_public_key: [u8; 32],
    ts_public_key: [u8; 32],
    tree_size: u64,
    leaf_index: u64,
}

impl ExpectedVectors {
    fn load() -> Self {
        let json_str = include_str!("../pask_67_independent_signed_vectors.json");
        let json: serde_json::Value = serde_json::from_str(json_str).expect("invalid JSON");

        let expected = &json["expected"];
        let fixture = &json["fixture"];

        let candidate_entry =
            hex::decode(expected["candidate_entry_hex"].as_str().unwrap()).unwrap();
        let leaf_hash: [u8; 32] = hex::decode(expected["leaf_hash_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let merkle_root: [u8; 32] = hex::decode(expected["merkle_root_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let inclusion_path: Vec<[u8; 32]> = expected["inclusion_path_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                hex::decode(h.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect();

        let raw_statement = hex::decode(fixture["raw_statement_hex"].as_str().unwrap()).unwrap();
        let final_statement =
            hex::decode(fixture["final_statement_hex"].as_str().unwrap()).unwrap();
        let receipt = hex::decode(fixture["receipt_hex"].as_str().unwrap()).unwrap();
        let issuer_public_key: [u8; 32] =
            hex::decode(fixture["issuer_public_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let ts_public_key: [u8; 32] = hex::decode(fixture["ts_public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let tree_size = fixture["tree_size"].as_u64().unwrap();
        let leaf_index = fixture["leaf_index"].as_u64().unwrap();

        Self {
            candidate_entry,
            leaf_hash,
            merkle_root,
            inclusion_path,
            raw_statement,
            final_statement,
            receipt,
            issuer_public_key,
            ts_public_key,
            tree_size,
            leaf_index,
        }
    }
}

// ===========================================================================
// Independent vector verification (7 tests)
// ===========================================================================

#[test]
fn candidate_entry_from_raw_statement_matches_independent_derivation() {
    let expected = ExpectedVectors::load();
    let derived = derive_candidate_entry(&expected.raw_statement).unwrap();
    assert_eq!(
        derived, expected.candidate_entry,
        "candidate entry from raw statement must match independently derived expected bytes"
    );
}

#[test]
fn candidate_entry_from_final_statement_matches_independent_derivation() {
    let expected = ExpectedVectors::load();
    let derived = derive_candidate_entry(&expected.final_statement).unwrap();
    assert_eq!(
        derived, expected.candidate_entry,
        "candidate entry from final statement must match independently derived expected bytes"
    );
}

#[test]
fn leaf_hash_matches_independent_derivation() {
    let expected = ExpectedVectors::load();
    let leaf = leaf_hash(&expected.candidate_entry);
    assert_eq!(
        leaf, expected.leaf_hash,
        "leaf hash must match independently derived expected value"
    );
}

#[test]
fn merkle_root_matches_independent_derivation() {
    let expected = ExpectedVectors::load();
    let mut log: Vec<Vec<u8>> = (0..expected.tree_size)
        .map(|i| format!("entry-{i}").into_bytes())
        .collect();
    let idx = expected.leaf_index as usize;
    log[idx] = expected.candidate_entry.clone();
    let root = merkle_tree_hash(&log);
    assert_eq!(
        root, expected.merkle_root,
        "Merkle root must match independently derived expected value"
    );
}

#[test]
fn inclusion_path_matches_independent_derivation() {
    let expected = ExpectedVectors::load();
    let mut log: Vec<Vec<u8>> = (0..expected.tree_size)
        .map(|i| format!("entry-{i}").into_bytes())
        .collect();
    let idx = expected.leaf_index as usize;
    log[idx] = expected.candidate_entry.clone();
    let path = inclusion_path(&log, idx);
    assert_eq!(
        path, expected.inclusion_path,
        "inclusion path must match independently derived expected value"
    );
}

#[test]
fn verify_inclusion_with_fixed_fixture() {
    let expected = ExpectedVectors::load();
    let entry = derive_candidate_entry(&expected.final_statement).unwrap();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let result = verify_inclusion(&expected.receipt, &entry, &ts_verifying);
    assert!(
        result.is_ok(),
        "verify_inclusion must succeed with the fixed fixture: {result:?}"
    );
}

#[test]
fn producer_and_recipient_derivation_consistency() {
    let expected = ExpectedVectors::load();
    let producer_entry = derive_candidate_entry(&expected.raw_statement).unwrap();
    let recipient_entry = derive_candidate_entry(&expected.final_statement).unwrap();
    assert_eq!(
        producer_entry, recipient_entry,
        "producer and recipient must derive the same candidate entry"
    );
}

// ===========================================================================
// Receipt reader compatibility (5 tests)
// ===========================================================================

#[test]
fn receipt_reader_accepts_byte_string_rfc_form() {
    // RFC 9942/9943: receipts stored as byte strings containing encoded Receipt objects.
    let expected = ExpectedVectors::load();
    let statement = attach_receipts_wire(
        &expected.raw_statement,
        std::slice::from_ref(&expected.receipt),
    );
    let result = attached_receipts(&statement).unwrap();
    match result {
        AttachedReceipts::Present(receipts) => {
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0], expected.receipt);
        }
        _ => panic!("expected Present, got {result:?}"),
    }
}

#[test]
fn receipt_reader_accepts_bare_array_legacy_form() {
    // Legacy compatibility: receipt stored as a bare COSE_Sign1 array
    // (not wrapped in a byte string). This is what pask-ts-client's
    // attach_receipt produces. See issue #70.
    let expected = ExpectedVectors::load();
    let statement = attach_receipts_legacy(
        &expected.raw_statement,
        std::slice::from_ref(&expected.receipt),
    );
    let result = attached_receipts(&statement).unwrap();
    match result {
        AttachedReceipts::Present(receipts) => {
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0], expected.receipt);
        }
        _ => panic!("expected Present, got {result:?}"),
    }
}

#[test]
fn receipt_reader_rejects_scalar_element() {
    let expected = ExpectedVectors::load();
    let mut cursor = expected.raw_statement.as_slice();
    let mut stmt_value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(ref mut items) = stmt_value else {
        panic!()
    };
    items[1] = Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(vec![Value::Integer(42.into())]),
    )]);
    let statement = cbor_value(&stmt_value);
    let result = attached_receipts(&statement).unwrap();
    match result {
        AttachedReceipts::Malformed(msg) => {
            assert!(
                msg.contains("not a byte string") || msg.contains("not a valid"),
                "expected malformed error about invalid receipt type, got: {msg}"
            );
        }
        _ => panic!("expected Malformed, got {result:?}"),
    }
}

#[test]
fn receipt_reader_rejects_map_element() {
    let expected = ExpectedVectors::load();
    let mut cursor = expected.raw_statement.as_slice();
    let mut stmt_value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(ref mut items) = stmt_value else {
        panic!()
    };
    items[1] = Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(vec![Value::Map(vec![])]),
    )]);
    let statement = cbor_value(&stmt_value);
    let result = attached_receipts(&statement).unwrap();
    match result {
        AttachedReceipts::Malformed(_) => {}
        _ => panic!("expected Malformed for map receipt, got {result:?}"),
    }
}

#[test]
fn receipt_reader_rejects_wrong_tag() {
    let expected = ExpectedVectors::load();
    let receipt_value: Value =
        coset::cbor::de::from_reader(&mut expected.receipt.as_slice()).unwrap();
    let wrong_tag = Value::Tag(99, Box::new(receipt_value));

    let mut cursor = expected.raw_statement.as_slice();
    let mut stmt_value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(ref mut items) = stmt_value else {
        panic!()
    };
    items[1] = Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(vec![wrong_tag]),
    )]);
    let statement = cbor_value(&stmt_value);
    let result = attached_receipts(&statement).unwrap();
    match result {
        AttachedReceipts::Malformed(_) => {}
        _ => panic!("expected Malformed for wrong tag, got {result:?}"),
    }
}

// ===========================================================================
// Recipient-path verification from final statement (6 tests)
// ===========================================================================

#[test]
fn verify_from_final_statement_succeeds() {
    // The recipient path: derive entry from final statement, extract receipts,
    // verify inclusion. This is the core acceptance demonstration.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let (outcomes, _receipts) =
        verify_from_final_statement(&expected.final_statement, &ts_verifying);
    assert_eq!(outcomes.len(), 1, "expected one receipt");
    assert_eq!(
        outcomes[0],
        ReceiptOutcome::Verified,
        "receipt must verify from the final statement"
    );
}

#[test]
fn verify_from_final_statement_no_receipts() {
    // A statement with no receipts header must report NoReceipts.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let statement = attach_no_receipts(&expected.raw_statement);
    let (outcomes, _) = verify_from_final_statement(&statement, &ts_verifying);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0], ReceiptOutcome::NoReceipts);
}

#[test]
fn verify_from_final_statement_only_invalid_proof() {
    // A statement with only an invalid receipt (wrong root) must report
    // SignatureFailed or Malformed, not Verified.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();

    // Build a receipt with a wrong root.
    let ts_key = ts_signing_key();
    let wrong_root = [0xffu8; 32];
    let wrong_receipt = build_receipt(
        &ts_key,
        &wrong_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    let statement = attach_receipts_wire(&expected.raw_statement, &[wrong_receipt]);
    let (outcomes, _) = verify_from_final_statement(&statement, &ts_verifying);
    assert_eq!(outcomes.len(), 1);
    assert_ne!(
        outcomes[0],
        ReceiptOutcome::Verified,
        "invalid receipt must not verify"
    );
}

#[test]
fn verify_from_final_statement_no_verified_proof_under_wrong_key() {
    // A valid receipt must not verify under an untrusted key.
    let expected = ExpectedVectors::load();
    let wrong_signing = SigningKey::from_bytes(&[99u8; 32]);
    let wrong_key = wrong_signing.verifying_key();
    let (outcomes, _) = verify_from_final_statement(&expected.final_statement, &wrong_key);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0],
        ReceiptOutcome::SignatureFailed,
        "valid receipt must fail under wrong key"
    );
}

#[test]
fn verify_from_final_statement_unsupported_vds() {
    // A receipt with an unsupported VDS must report UnsupportedVds.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let ts_key = ts_signing_key();

    let unsupported_receipt = build_receipt(
        &ts_key,
        &expected.merkle_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        999, // unsupported VDS
    );

    let statement = attach_receipts_wire(&expected.raw_statement, &[unsupported_receipt]);
    let (outcomes, _) = verify_from_final_statement(&statement, &ts_verifying);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0], ReceiptOutcome::UnsupportedVds);
}

#[test]
fn round_trip_produce_verify_inclusion() {
    // Full round-trip: produce a statement, derive the candidate entry,
    // build a Merkle tree, create a receipt, attach it, and verify inclusion
    // through the final statement using the recipient path.
    let expected = ExpectedVectors::load();

    let mut log: Vec<Vec<u8>> = (0..expected.tree_size)
        .map(|i| format!("entry-{i}").into_bytes())
        .collect();
    let idx = expected.leaf_index as usize;
    log[idx] = expected.candidate_entry.clone();

    let root = merkle_tree_hash(&log);
    let path = inclusion_path(&log, idx);
    assert_eq!(root, expected.merkle_root);
    assert_eq!(path, expected.inclusion_path);

    let ts_key = ts_signing_key();
    let receipt = build_receipt(
        &ts_key,
        &root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &path,
        )],
        RFC9162_SHA256,
    );

    let final_statement =
        attach_receipts_wire(&expected.raw_statement, std::slice::from_ref(&receipt));

    let ts_verifying = ts_key.verifying_key();
    let (outcomes, _) = verify_from_final_statement(&final_statement, &ts_verifying);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0], ReceiptOutcome::Verified);
}

// ===========================================================================
// Multi-receipt aggregation (3 tests)
// ===========================================================================

#[test]
fn invalid_then_valid_attachment_order() {
    // An invalid receipt followed by a valid receipt. The helper must continue
    // past the first failure and report the valid one.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let ts_key = ts_signing_key();

    // Invalid receipt: wrong root.
    let wrong_root = [0xffu8; 32];
    let invalid_receipt = build_receipt(
        &ts_key,
        &wrong_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    // Valid receipt: correct root and proof.
    let valid_receipt = build_receipt(
        &ts_key,
        &expected.merkle_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    let statement =
        attach_receipts_wire(&expected.raw_statement, &[invalid_receipt, valid_receipt]);
    let (outcomes, _) = verify_from_final_statement(&statement, &ts_verifying);
    assert_eq!(outcomes.len(), 2);
    assert_ne!(
        outcomes[0],
        ReceiptOutcome::Verified,
        "first receipt must not verify"
    );
    assert_eq!(
        outcomes[1],
        ReceiptOutcome::Verified,
        "second receipt must verify"
    );
}

#[test]
fn unsupported_then_valid_attachment_order() {
    // An unsupported-VDS receipt followed by a valid receipt.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let ts_key = ts_signing_key();

    let unsupported_receipt = build_receipt(
        &ts_key,
        &expected.merkle_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        999, // unsupported VDS
    );

    let valid_receipt = build_receipt(
        &ts_key,
        &expected.merkle_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    let statement = attach_receipts_wire(
        &expected.raw_statement,
        &[unsupported_receipt, valid_receipt],
    );
    let (outcomes, _) = verify_from_final_statement(&statement, &ts_verifying);
    assert_eq!(outcomes.len(), 2);
    assert_eq!(
        outcomes[0],
        ReceiptOutcome::UnsupportedVds,
        "first receipt must be unsupported VDS"
    );
    assert_eq!(
        outcomes[1],
        ReceiptOutcome::Verified,
        "second receipt must verify"
    );
}

#[test]
fn valid_then_invalid_attachment_order() {
    // A valid receipt followed by an invalid receipt.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let ts_key = ts_signing_key();

    let valid_receipt = build_receipt(
        &ts_key,
        &expected.merkle_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    let wrong_root = [0xffu8; 32];
    let invalid_receipt = build_receipt(
        &ts_key,
        &wrong_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    let statement =
        attach_receipts_wire(&expected.raw_statement, &[valid_receipt, invalid_receipt]);
    let (outcomes, _) = verify_from_final_statement(&statement, &ts_verifying);
    assert_eq!(outcomes.len(), 2);
    assert_eq!(
        outcomes[0],
        ReceiptOutcome::Verified,
        "first receipt must verify"
    );
    assert_ne!(
        outcomes[1],
        ReceiptOutcome::Verified,
        "second receipt must not verify"
    );
}

// ===========================================================================
// Issuer-signature verification and tampering (4 tests)
// ===========================================================================

#[test]
fn issuer_signature_verifies() {
    let expected = ExpectedVectors::load();
    let issuer_verifying = VerifyingKey::from_bytes(&expected.issuer_public_key).unwrap();
    let result = verify_ed25519(&expected.raw_statement, &issuer_verifying);
    assert!(
        result.is_ok(),
        "issuer signature must verify on the raw statement: {result:?}"
    );
}

#[test]
fn issuer_signature_preserved_after_attachment() {
    // Attaching receipts modifies only the unprotected header (items[1]).
    // The issuer signature covers the protected header and payload, so it
    // must still verify on the final statement.
    let expected = ExpectedVectors::load();
    let issuer_verifying = VerifyingKey::from_bytes(&expected.issuer_public_key).unwrap();

    let result = verify_ed25519(&expected.final_statement, &issuer_verifying);
    assert!(
        result.is_ok(),
        "issuer signature must verify on the final statement after attachment: {result:?}"
    );
}

#[test]
fn issuer_signature_rejects_tampered_protected_header() {
    // Flipping a byte in the protected header must cause rejection. The test
    // demonstrates rejection of the tampered statement; it does not assert
    // which internal stage detected the failure.
    let expected = ExpectedVectors::load();
    let issuer_verifying = VerifyingKey::from_bytes(&expected.issuer_public_key).unwrap();

    let mut tampered = expected.raw_statement.clone();
    // Flip a byte in the protected header area (after the array tag and
    // "Signature1" string, inside the protected header bytes).
    if tampered.len() > 20 {
        tampered[15] ^= 0xff;
    }

    let result = verify_ed25519(&tampered, &issuer_verifying);
    assert!(
        result.is_err(),
        "tampered protected header must fail signature verification"
    );
}

#[test]
fn issuer_signature_rejects_tampered_payload() {
    // Flipping a byte in the payload must cause rejection. The test
    // demonstrates rejection of the tampered statement; it does not assert
    // which internal stage detected the failure.
    let expected = ExpectedVectors::load();
    let issuer_verifying = VerifyingKey::from_bytes(&expected.issuer_public_key).unwrap();

    // Parse the statement, modify the payload, re-serialize.
    let mut cursor = expected.raw_statement.as_slice();
    let mut value: Value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    let Value::Array(ref mut items) = value else {
        panic!("must be array");
    };
    // items[2] is the payload (M). Flip a byte in the payload bytes.
    if let Value::Bytes(ref mut payload) = items[2] {
        if !payload.is_empty() {
            payload[0] ^= 0xff;
        }
    } else {
        panic!("payload must be bytes");
    }
    let tampered = cbor_value(&value);

    let result = verify_ed25519(&tampered, &issuer_verifying);
    assert!(
        result.is_err(),
        "tampered payload must fail signature verification"
    );
}

#[test]
fn issuer_signature_rejects_tampered_signature() {
    // Flipping a byte in the signature must break verification.
    let expected = ExpectedVectors::load();
    let issuer_verifying = VerifyingKey::from_bytes(&expected.issuer_public_key).unwrap();

    let mut tampered = expected.raw_statement.clone();
    // Flip a byte near the end (in the signature area).
    if tampered.len() > 10 {
        let idx = tampered.len() - 5;
        tampered[idx] ^= 0xff;
    }

    let result = verify_ed25519(&tampered, &issuer_verifying);
    assert!(result.is_err(), "tampered signature must fail verification");
}

// ===========================================================================
// Inclusion-proof rejection cases (3 tests)
// ===========================================================================

#[test]
fn verify_inclusion_rejects_wrong_entry() {
    // A receipt valid for the correct entry must fail for a wrong entry.
    let expected = ExpectedVectors::load();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let wrong_entry = b"this-is-not-the-candidate-entry".to_vec();
    let result = verify_inclusion(&expected.receipt, &wrong_entry, &ts_verifying);
    assert!(
        result.is_err(),
        "verify_inclusion must fail with a wrong entry"
    );
}

#[test]
fn verify_inclusion_rejects_tampered_signature() {
    // Flipping a byte in the receipt's signature area must cause failure.
    // This tests signature tampering, not root/proof mismatch.
    let expected = ExpectedVectors::load();
    let entry = derive_candidate_entry(&expected.final_statement).unwrap();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();

    let mut tampered_receipt = expected.receipt.clone();
    // Flip a byte in the signature area (near the end of the tagged receipt).
    if tampered_receipt.len() > 10 {
        let idx = tampered_receipt.len() - 5;
        tampered_receipt[idx] ^= 0xff;
    }

    let result = verify_inclusion(&tampered_receipt, &entry, &ts_verifying);
    assert!(
        result.is_err(),
        "verify_inclusion must fail with a tampered receipt signature"
    );
}

#[test]
fn verify_inclusion_rejects_wrong_root_in_receipt() {
    // The receipt signature is produced over root A (0x42*32), while the
    // supplied inclusion proof for the candidate entry reconstructs root B
    // (the true Merkle root) from the entry's leaf hash. For this
    // detached-payload receipt, signature verification using the
    // reconstructed root fails. This is distinct from altering signature bytes
    // directly and from using a different entry entirely.
    let expected = ExpectedVectors::load();
    let entry = derive_candidate_entry(&expected.final_statement).unwrap();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let ts_key = ts_signing_key();

    // Build a receipt signing root A while the proof path reconstructs root B.
    let wrong_root = [0x42u8; 32];
    let wrong_receipt = build_receipt(
        &ts_key,
        &wrong_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        RFC9162_SHA256,
    );

    let result = verify_inclusion(&wrong_receipt, &entry, &ts_verifying);
    assert!(
        result.is_err(),
        "verify_inclusion must fail when the receipt root does not match the reconstructed root"
    );
}

// ===========================================================================
// Additional coverage (3 tests)
// ===========================================================================

#[test]
fn final_statement_derivation_independent_of_receipts() {
    // Attaching different receipts must not change the candidate entry.
    let expected = ExpectedVectors::load();

    let entry_before = derive_candidate_entry(&expected.raw_statement).unwrap();

    let issuer_key = SigningKey::from_bytes(&[3u8; 32]);
    let dummy_root = [0xabu8; 32];
    let dummy_receipt = build_receipt(
        &issuer_key,
        &dummy_root,
        &[wrapped_proof(1, 0, &[])],
        RFC9162_SHA256,
    );
    let modified = attach_receipts_wire(&expected.raw_statement, &[dummy_receipt]);
    let entry_after = derive_candidate_entry(&modified).unwrap();

    assert_eq!(
        entry_before, entry_after,
        "candidate entry must be invariant under receipt attachment"
    );
}

#[test]
fn byte_string_receipt_round_trip() {
    // Receipts stored as byte strings (RFC 9942/9943 form) must be readable
    // by the receipt reader and verifiable.
    let expected = ExpectedVectors::load();
    let entry = derive_candidate_entry(&expected.final_statement).unwrap();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();
    let result = verify_inclusion(&expected.receipt, &entry, &ts_verifying);
    assert!(result.is_ok(), "byte-string receipt must verify");
}

#[test]
fn unsupported_vds_returns_vds_error() {
    // A receipt with an unsupported VDS must return a VDS error, not a
    // generic malformed error.
    let expected = ExpectedVectors::load();
    let entry = derive_candidate_entry(&expected.final_statement).unwrap();
    let ts_verifying = VerifyingKey::from_bytes(&expected.ts_public_key).unwrap();

    let ts_key = ts_signing_key();
    let receipt = build_receipt(
        &ts_key,
        &expected.merkle_root,
        &[wrapped_proof(
            expected.tree_size,
            expected.leaf_index,
            &expected.inclusion_path,
        )],
        999, // unsupported VDS
    );

    let result = verify_inclusion(&receipt, &entry, &ts_verifying);
    assert!(result.is_err(), "unsupported VDS must return an error");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("vds")
            || err_msg.to_lowercase().contains("verifiable data structure"),
        "error for unsupported VDS should mention VDS or verifiable data structure, got: {err_msg}"
    );
}
