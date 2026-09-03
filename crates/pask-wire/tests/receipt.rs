// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Tests for offline verification of an attached SCITT Receipt.
//!
//! The proofs these tests verify are not produced by the code under test. The
//! tree and the proof paths are built here by the recursive definition in
//! RFC 9162 Section 2.1.1, and the verifier is the iterative algorithm in
//! Section 2.1.3.2. Those are two different algorithms that agree only if both
//! are right, which is the property worth testing. A test that generated
//! proofs with the verifier's own logic would pass while both were wrong in
//! the same direction.
//!
//! Two behaviours here are asserted at the level of what a relying party can
//! observe rather than at the level of "does it parse", for the same reason
//! `ack_provenance.rs` does it:
//!
//! 1. A statement carrying no `receipts` header and a statement whose header
//!    is unreadable are reported as different states. A parse-only test passes
//!    while a verifier collapses them, and collapsing them tells a relying
//!    party that a tampered envelope was merely never registered.
//! 2. A Receipt whose reconstructed root disagrees with its attached payload
//!    fails naming the proof, not the key. Both fail; only one names the cause
//!    the reader can act on.

use ed25519_dalek::{Signer, SigningKey};
use pask_wire::{
    AttachedReceipts, Error, InclusionProof, RECEIPTS_LABEL, RFC9162_SHA256, Receipt, VDP_LABEL,
    VDS_LABEL, attached_receipts, leaf_hash, verify_inclusion,
};
use sha2::{Digest, Sha256};

use coset::cbor::Value;

// ---------------------------------------------------------------------------
// An independent RFC 9162 Section 2.1.1 reference tree.
// ---------------------------------------------------------------------------

/// `MTH(D_n)` by the recursive definition, not by the verifier's iteration.
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

/// The largest power of two strictly smaller than `n`, for `n > 1`.
fn largest_power_of_two_below(n: usize) -> usize {
    assert!(n > 1, "only defined for n > 1");
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The RFC 9162 Section 2.1.3.1 inclusion path for `index` in `entries`.
fn inclusion_path(entries: &[Vec<u8>], index: usize) -> Vec<[u8; 32]> {
    assert!(index < entries.len(), "index must be inside the tree");
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

/// `n` distinct entries, deterministic so failures reproduce.
fn entries(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("entry-{i}").into_bytes()).collect()
}

// ---------------------------------------------------------------------------
// Receipt construction.
// ---------------------------------------------------------------------------

/// Encodes a value as CBOR.
fn cbor(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(value, &mut encoded).expect("encoding to a Vec cannot fail");
    encoded
}

/// The wire form of an inclusion proof: a `bstr` wrapping
/// `[tree_size, leaf_index, inclusion_path]`.
fn wrapped_proof(tree_size: u64, leaf_index: u64, path: &[[u8; 32]]) -> Vec<u8> {
    cbor(&Value::Array(vec![
        Value::Integer(tree_size.into()),
        Value::Integer(leaf_index.into()),
        Value::Array(
            path.iter()
                .map(|hash| Value::Bytes(hash.to_vec()))
                .collect(),
        ),
    ]))
}

/// Builds a signed Receipt over `root`, with `proofs` in the `vdp` map.
///
/// `attach_payload` controls whether the root is carried in the payload slot or
/// detached, which is the case distinction RFC 9942 Section 5.2 draws.
fn build_receipt(
    key: &SigningKey,
    root: &[u8; 32],
    proofs: &[Vec<u8>],
    vds: i64,
    attach_payload: bool,
) -> Vec<u8> {
    let protected = cbor(&Value::Map(vec![
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
    let signed = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(root.to_vec()),
    ]));
    let signature = key.sign(&signed).to_bytes().to_vec();
    cbor(&Value::Array(vec![
        Value::Bytes(protected),
        unprotected,
        if attach_payload {
            Value::Bytes(root.to_vec())
        } else {
            Value::Null
        },
        Value::Bytes(signature),
    ]))
}

/// A Transparency Service signing key, fixed so failures reproduce.
fn ts_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A minimal four-element `COSE_Sign1` carrying `receipts` where given.
fn statement_with_receipts_header(header: Option<Value>) -> Vec<u8> {
    let unprotected = match header {
        Some(value) => Value::Map(vec![(Value::Integer(RECEIPTS_LABEL.into()), value)]),
        None => Value::Map(Vec::new()),
    };
    cbor(&Value::Array(vec![
        Value::Bytes(cbor(&Value::Map(Vec::new()))),
        unprotected,
        Value::Bytes(b"payload".to_vec()),
        Value::Bytes(vec![0u8; 64]),
    ]))
}

// ---------------------------------------------------------------------------
// The inclusion-proof algorithm.
// ---------------------------------------------------------------------------

#[test]
fn a_proof_reconstructs_the_root_for_every_leaf_of_every_tree_size_to_thirty_three() {
    // 33 crosses two powers of two, so it covers both the balanced case and
    // the ragged right-hand subtree where the LSB shifting in step 4b.ii is
    // the only thing keeping the walk aligned.
    for size in 1..=33usize {
        let entries = entries(size);
        let expected = merkle_tree_hash(&entries);
        for index in 0..size {
            let path = inclusion_path(&entries, index);
            let proof = InclusionProof {
                tree_size: size as u64,
                leaf_index: index as u64,
                inclusion_path: path,
            };
            let root = proof
                .reconstruct_root(leaf_hash(&entries[index]))
                .unwrap_or_else(|error| {
                    panic!("tree size {size}, leaf {index} should verify: {error}")
                });
            assert_eq!(
                root, expected,
                "tree size {size}, leaf {index} reconstructed the wrong root"
            );
        }
    }
}

#[test]
fn a_single_entry_tree_has_the_leaf_hash_as_its_root() {
    let entries = entries(1);
    assert_eq!(merkle_tree_hash(&entries), leaf_hash(&entries[0]));
}

#[test]
fn a_leaf_index_at_or_past_the_tree_size_is_refused() {
    let entries = entries(8);
    let path = inclusion_path(&entries, 3);
    for leaf_index in [8u64, 9, u64::MAX] {
        let proof = InclusionProof {
            tree_size: 8,
            leaf_index,
            inclusion_path: path.clone(),
        };
        assert_eq!(
            proof.reconstruct_root(leaf_hash(&entries[3])),
            Err(Error::Receipt(
                "inclusion proof leaf_index is not less than tree_size"
            )),
            "leaf_index {leaf_index} is outside a tree of size 8"
        );
    }
}

#[test]
fn a_proof_for_the_wrong_leaf_reconstructs_a_different_root() {
    let entries = entries(8);
    let expected = merkle_tree_hash(&entries);
    let proof = InclusionProof {
        tree_size: 8,
        leaf_index: 3,
        inclusion_path: inclusion_path(&entries, 3),
    };
    // The path is valid and the walk completes. What fails is the comparison,
    // which is why reconstruct_root returns the root rather than a bool: the
    // caller binds it with the signature.
    let root = proof
        .reconstruct_root(leaf_hash(b"an entry that was never logged"))
        .expect("a structurally valid path still completes");
    assert_ne!(
        root, expected,
        "a proof applied to the wrong entry must not reach the real root"
    );
}

#[test]
fn a_path_longer_than_the_tree_permits_is_refused() {
    let entries = entries(4);
    let mut path = inclusion_path(&entries, 0);
    path.push([0u8; 32]);
    path.push([1u8; 32]);
    let proof = InclusionProof {
        tree_size: 4,
        leaf_index: 0,
        inclusion_path: path,
    };
    assert_eq!(
        proof.reconstruct_root(leaf_hash(&entries[0])),
        Err(Error::Receipt(
            "inclusion proof path is longer than the tree permits"
        ))
    );
}

#[test]
fn a_path_that_ends_before_the_root_is_refused() {
    let entries = entries(8);
    let mut path = inclusion_path(&entries, 0);
    path.truncate(1);
    let proof = InclusionProof {
        tree_size: 8,
        leaf_index: 0,
        inclusion_path: path,
    };
    assert_eq!(
        proof.reconstruct_root(leaf_hash(&entries[0])),
        Err(Error::Receipt(
            "inclusion proof path ended before the root was reached"
        ))
    );
}

// ---------------------------------------------------------------------------
// Proof decoding.
// ---------------------------------------------------------------------------

#[test]
fn a_wire_proof_round_trips_with_tree_size_before_leaf_index() {
    let path = [[3u8; 32], [4u8; 32]];
    let encoded = wrapped_proof(17, 5, &path);
    let decoded = InclusionProof::from_wrapped_cbor(&encoded).expect("a conforming proof decodes");
    // The field order in RFC 9942 Section 5.2 is tree_size then leaf_index.
    // Reversing them yields a proof that decodes and then verifies against
    // nothing, so it is pinned here rather than left to review.
    assert_eq!(decoded.tree_size, 17);
    assert_eq!(decoded.leaf_index, 5);
    assert_eq!(decoded.inclusion_path, path);
}

#[test]
fn a_malformed_wire_proof_is_refused_with_a_reason() {
    let cases: [(Vec<u8>, &str); 5] = [
        (
            cbor(&Value::Array(vec![Value::Integer(1.into())])),
            "inclusion proof must carry exactly three elements",
        ),
        (
            cbor(&Value::Text("not an array".into())),
            "inclusion proof must be a CBOR array",
        ),
        (
            cbor(&Value::Array(vec![
                Value::Integer(4.into()),
                Value::Integer(0.into()),
                Value::Array(Vec::new()),
            ])),
            "inclusion proof inclusion_path must not be empty",
        ),
        (
            cbor(&Value::Array(vec![
                Value::Integer(4.into()),
                Value::Integer(0.into()),
                Value::Array(vec![Value::Bytes(vec![0u8; 31])]),
            ])),
            "inclusion proof inclusion_path elements must be 32 bytes",
        ),
        (
            cbor(&Value::Array(vec![
                Value::Text("four".into()),
                Value::Integer(0.into()),
                Value::Array(vec![Value::Bytes(vec![0u8; 32])]),
            ])),
            "inclusion proof tree_size must be a uint",
        ),
    ];
    for (encoded, expected) in cases {
        assert_eq!(
            InclusionProof::from_wrapped_cbor(&encoded),
            Err(Error::Receipt(expected)),
            "expected {expected}"
        );
    }
}

#[test]
fn a_negative_tree_size_is_not_read_as_a_large_unsigned_one() {
    let encoded = cbor(&Value::Array(vec![
        Value::Integer((-1).into()),
        Value::Integer(0.into()),
        Value::Array(vec![Value::Bytes(vec![0u8; 32])]),
    ]));
    assert_eq!(
        InclusionProof::from_wrapped_cbor(&encoded),
        Err(Error::Receipt("inclusion proof tree_size must be a uint"))
    );
}

// ---------------------------------------------------------------------------
// End to end, offline.
// ---------------------------------------------------------------------------

#[test]
fn a_detached_payload_receipt_verifies_offline() {
    let key = ts_key();
    let entries = entries(9);
    let index = 6;
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(9, index as u64, &inclusion_path(&entries, index));
    let receipt = build_receipt(&key, &root, &[proof], RFC9162_SHA256, false);

    let verified = verify_inclusion(&receipt, &entries[index], &key.verifying_key())
        .expect("a well-formed receipt verifies");
    assert_eq!(verified.root, root);
    assert_eq!(verified.tree_size, 9);
    assert_eq!(verified.leaf_index, 6);
}

#[test]
fn an_attached_payload_receipt_verifies_offline() {
    let key = ts_key();
    let entries = entries(5);
    let index = 4;
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(5, index as u64, &inclusion_path(&entries, index));
    let receipt = build_receipt(&key, &root, &[proof], RFC9162_SHA256, true);

    let verified = verify_inclusion(&receipt, &entries[index], &key.verifying_key())
        .expect("a well-formed receipt verifies");
    assert_eq!(verified.root, root);
}

#[test]
fn a_tagged_receipt_and_an_untagged_receipt_both_decode() {
    let key = ts_key();
    let entries = entries(4);
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(4, 0, &inclusion_path(&entries, 0));
    let untagged = build_receipt(&key, &root, &[proof], RFC9162_SHA256, false);

    let mut cursor = untagged.as_slice();
    let value: Value = coset::cbor::de::from_reader(&mut cursor).expect("the receipt is CBOR");
    let tagged = cbor(&Value::Tag(18, Box::new(value)));

    for (label, bytes) in [("untagged", &untagged), ("tagged", &tagged)] {
        verify_inclusion(bytes, &entries[0], &key.verifying_key())
            .unwrap_or_else(|error| panic!("the {label} receipt should verify: {error}"));
    }
}

#[test]
fn a_receipt_signed_by_a_different_transparency_service_does_not_verify() {
    let key = ts_key();
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let entries = entries(4);
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(4, 1, &inclusion_path(&entries, 1));
    let receipt = build_receipt(&key, &root, &[proof], RFC9162_SHA256, false);

    assert_eq!(
        verify_inclusion(&receipt, &entries[1], &other.verifying_key()),
        Err(Error::Signature),
        "a receipt must not verify under a key that did not sign it"
    );
}

#[test]
fn a_receipt_presented_with_the_wrong_entry_does_not_verify() {
    let key = ts_key();
    let entries = entries(8);
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(8, 2, &inclusion_path(&entries, 2));
    let receipt = build_receipt(&key, &root, &[proof], RFC9162_SHA256, false);

    // The proof, the key and the signature are all genuine. Only the entry is
    // wrong, so the reconstructed root differs and the signature over it fails.
    assert!(
        verify_inclusion(&receipt, b"a different engagement", &key.verifying_key()).is_err(),
        "a receipt must not verify for an entry it does not cover"
    );
}

#[test]
fn a_root_disagreeing_with_the_attached_payload_names_the_proof_not_the_key() {
    let key = ts_key();
    let entries = entries(4);
    let real_root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(4, 0, &inclusion_path(&entries, 0));

    // Sign over a root the proof does not reconstruct, and attach that root.
    // Both the payload comparison and the signature check would fail. The
    // error must name the proof, because "signature error" would send a reader
    // to audit a key that is working correctly.
    let mut wrong_root = real_root;
    wrong_root[0] ^= 0xff;
    let receipt = build_receipt(&key, &wrong_root, &[proof], RFC9162_SHA256, true);

    assert_eq!(
        verify_inclusion(&receipt, &entries[0], &key.verifying_key()),
        Err(Error::Receipt(
            "reconstructed root does not match the receipt's attached payload"
        ))
    );
}

#[test]
fn an_unsupported_verifiable_data_structure_is_refused_rather_than_assumed() {
    let key = ts_key();
    let entries = entries(4);
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(4, 0, &inclusion_path(&entries, 0));
    // vds 0 is Reserved. A verifier that ignored vds and applied the
    // RFC9162_SHA256 walk anyway would accept this and report a proof it had
    // no basis to interpret.
    let receipt = build_receipt(&key, &root, &[proof], 0, false);

    assert_eq!(
        verify_inclusion(&receipt, &entries[0], &key.verifying_key()),
        Err(Error::Receipt(
            "unsupported verifiable data structure; only RFC9162_SHA256 is implemented"
        ))
    );
}

#[test]
fn a_usable_proof_is_found_even_when_an_unusable_one_precedes_it() {
    let key = ts_key();
    let entries = entries(8);
    let index = 5;
    let root = merkle_tree_hash(&entries);
    // RFC 9942 Section 5.1 calls the receipts array priority-ordered, and the
    // vdp map may carry more than one proof. A verifier that read only the
    // first would reject a receipt that does prove inclusion.
    let broken = wrapped_proof(8, 9, &inclusion_path(&entries, index));
    let good = wrapped_proof(8, index as u64, &inclusion_path(&entries, index));
    let receipt = build_receipt(&key, &root, &[broken, good], RFC9162_SHA256, false);

    let verified = verify_inclusion(&receipt, &entries[index], &key.verifying_key())
        .expect("the second proof proves inclusion");
    assert_eq!(verified.leaf_index, 5);
}

#[test]
fn a_receipt_missing_its_vdp_map_is_refused_with_a_reason() {
    let protected = cbor(&Value::Map(vec![(
        Value::Integer(VDS_LABEL.into()),
        Value::Integer(RFC9162_SHA256.into()),
    )]));
    let receipt = cbor(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Null,
        Value::Bytes(vec![0u8; 64]),
    ]));
    assert_eq!(
        Receipt::from_cose_sign1(&receipt),
        Err(Error::Receipt("receipt unprotected header must carry vdp"))
    );
}

#[test]
fn a_receipt_missing_its_vds_is_refused_rather_than_defaulted() {
    let receipt = cbor(&Value::Array(vec![
        Value::Bytes(cbor(&Value::Map(Vec::new()))),
        Value::Map(Vec::new()),
        Value::Null,
        Value::Bytes(vec![0u8; 64]),
    ]));
    assert_eq!(
        Receipt::from_cose_sign1(&receipt),
        Err(Error::Receipt("receipt protected header must carry vds")),
        "vds must not be assumed to be RFC9162_SHA256 when absent"
    );
}

// ---------------------------------------------------------------------------
// Reading the receipts header off a statement.
// ---------------------------------------------------------------------------

#[test]
fn a_statement_with_no_receipts_header_reports_absent() {
    let statement = statement_with_receipts_header(None);
    assert_eq!(
        attached_receipts(&statement).expect("a well-formed envelope reads"),
        AttachedReceipts::Absent
    );
}

#[test]
fn absent_and_malformed_are_reported_as_different_states() {
    // This is the rule the module exists to keep. A verifier that reported
    // both as "no receipt" would tell a relying party that a truncated or
    // tampered envelope had merely never been registered, and no parse-only
    // test catches it because both envelopes parse.
    let absent = attached_receipts(&statement_with_receipts_header(None))
        .expect("a well-formed envelope reads");
    let not_an_array = attached_receipts(&statement_with_receipts_header(Some(Value::Text(
        "nope".into(),
    ))))
    .expect("a well-formed envelope reads");
    let empty_array = attached_receipts(&statement_with_receipts_header(Some(Value::Array(
        Vec::new(),
    ))))
    .expect("a well-formed envelope reads");

    assert_eq!(absent, AttachedReceipts::Absent);
    assert_eq!(
        not_an_array,
        AttachedReceipts::Malformed("receipts header is not an array")
    );
    assert_eq!(
        empty_array,
        AttachedReceipts::Malformed("receipts header is an empty array")
    );
    assert_ne!(absent, not_an_array);
    assert_ne!(absent, empty_array);
    assert_ne!(not_an_array, empty_array);

    // And the convenience accessor is empty for all three, which is precisely
    // why a caller deciding conformance must match on the variant.
    for state in [&absent, &not_an_array, &empty_array] {
        assert!(state.as_slice().is_empty());
    }
}

#[test]
fn attached_receipts_round_trip_through_the_header_and_verify() {
    let key = ts_key();
    let entries = entries(6);
    let index = 2;
    let root = merkle_tree_hash(&entries);
    let proof = wrapped_proof(6, index as u64, &inclusion_path(&entries, index));
    let receipt = build_receipt(&key, &root, &[proof], RFC9162_SHA256, false);

    let mut cursor = receipt.as_slice();
    let receipt_value: Value = coset::cbor::de::from_reader(&mut cursor).expect("receipt is CBOR");
    let statement = statement_with_receipts_header(Some(Value::Array(vec![receipt_value])));

    let AttachedReceipts::Present(found) =
        attached_receipts(&statement).expect("a well-formed envelope reads")
    else {
        panic!("the statement carries one attached receipt");
    };
    assert_eq!(found.len(), 1);
    verify_inclusion(&found[0], &entries[index], &key.verifying_key())
        .expect("the receipt read out of the header verifies unchanged");
}

#[test]
fn a_receipts_header_in_the_protected_map_is_also_found() {
    // RFC 9942 Section 5.1 permits either map. The unprotected map is what
    // `-02` "SCITT registration and Receipt attachment" uses, because it allows attachment after signing,
    // but a reader that only looked there would miss a conforming statement.
    let protected = cbor(&Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(vec![Value::Bytes(b"a receipt".to_vec())]),
    )]));
    let statement = cbor(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(b"payload".to_vec()),
        Value::Bytes(vec![0u8; 64]),
    ]));
    let AttachedReceipts::Present(found) =
        attached_receipts(&statement).expect("a well-formed envelope reads")
    else {
        panic!("the protected map carries the receipts header");
    };
    assert_eq!(found.len(), 1);
}

#[test]
fn bytes_that_are_not_a_cose_sign1_are_refused() {
    for bad in [
        cbor(&Value::Text("not an envelope".into())),
        cbor(&Value::Array(vec![Value::Integer(1.into())])),
    ] {
        assert!(
            attached_receipts(&bad).is_err(),
            "a non-COSE_Sign1 must not read as Absent"
        );
    }
}
