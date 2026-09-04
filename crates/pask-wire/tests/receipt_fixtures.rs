// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Interoperability vectors for attached SCITT Receipt verification.
//!
//! These are the vectors an outside implementer runs against their own
//! verifier. They are described in `fixtures/receipts/README.md` and are
//! generated here rather than hand-written, following the same rule as
//! `fixtures/chains`: a fixture nobody can rebuild becomes a fixture nobody can
//! explain, and hand-editing a signed input silently changes what conformance
//! means.
//!
//! Set `PASK_REGEN_FIXTURES=1` to rewrite them. Review the diff afterwards.
//!
//! Every vector is checked against its own recorded expectation in this file,
//! so a vector cannot claim one outcome in the README and produce another. The
//! Transparency Service key is a fixed all-sevens test key. It is published
//! deliberately and it protects nothing.

use std::{fs, path::PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use pask_wire::{RFC9162_SHA256, VDP_LABEL, VDS_LABEL, leaf_hash, verify_inclusion};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use coset::cbor::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/receipts")
}

/// The Transparency Service test key. Fixed so every vector reproduces.
fn ts_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(value, &mut encoded).expect("encoding to a Vec cannot fail");
    encoded
}

// --- An independent RFC 9162 Section 2.1.1 tree, as in tests/receipt.rs. ---

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
    assert!(n > 1, "only defined for n > 1");
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

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

fn entries(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("entry-{i}").into_bytes()).collect()
}

fn wrapped_proof(tree_size: u64, leaf_index: u64, path: &[[u8; 32]]) -> Vec<u8> {
    cbor(&Value::Array(vec![
        Value::Integer(tree_size.into()),
        Value::Integer(leaf_index.into()),
        Value::Array(path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
    ]))
}

fn build_receipt(key: &SigningKey, root: &[u8; 32], proofs: &[Vec<u8>], vds: i64) -> Vec<u8> {
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
        Value::Null,
        Value::Bytes(signature),
    ]))
}

/// One vector: the file it lives in, and the outcome it pins.
struct Vector {
    name: &'static str,
    json: Json,
    /// `None` means the vector must verify. `Some(reason)` means it must fail,
    /// and the reason is asserted, not merely the failure.
    expect_failure: Option<&'static str>,
}

fn generate() -> Vec<Vector> {
    let key = ts_key();
    let verifying_key = hex(key.verifying_key().as_bytes());
    let log = entries(9);
    let root = merkle_tree_hash(&log);
    let index = 6usize;
    let path = inclusion_path(&log, index);

    let good = build_receipt(&key, &root, &[wrapped_proof(9, 6, &path)], RFC9162_SHA256);
    let wrong_vds = build_receipt(&key, &root, &[wrapped_proof(9, 6, &path)], 0);
    let out_of_range = build_receipt(&key, &root, &[wrapped_proof(9, 9, &path)], RFC9162_SHA256);
    let empty_path = build_receipt(&key, &root, &[wrapped_proof(9, 6, &[])], RFC9162_SHA256);
    let short_element = build_receipt(
        &key,
        &root,
        &[cbor(&Value::Array(vec![
            Value::Integer(9.into()),
            Value::Integer(6.into()),
            Value::Array(vec![Value::Bytes(vec![0u8; 31])]),
        ]))],
        RFC9162_SHA256,
    );
    let foreign = build_receipt(
        &SigningKey::from_bytes(&[9u8; 32]),
        &root,
        &[wrapped_proof(9, 6, &path)],
        RFC9162_SHA256,
    );

    let vector = |receipt: &[u8], expect: &str, purpose: &str| {
        json!({
            "verifiableDataStructure": "RFC9162_SHA256",
            "transparencyServiceVerifyingKey": verifying_key,
            "entry": hex(&log[index]),
            "treeSize": 9,
            "leafIndex": 6,
            "expectedRoot": hex(&root),
            "receipt": hex(receipt),
            "expect": expect,
            "purpose": purpose,
        })
    };

    vec![
        Vector {
            name: "valid-detached-payload.json",
            json: vector(
                &good,
                "verifies",
                "A conforming Receipt over a nine-leaf log, payload detached per RFC 9942 \
                 Section 5.2. The verifier reconstructs the root from the proof and checks \
                 the Transparency Service signature over it. Nothing here touches a network.",
            ),
            expect_failure: None,
        },
        Vector {
            name: "invalid-unsupported-vds.json",
            json: vector(
                &wrong_vds,
                "rejected",
                "Identical to the valid vector but for vds, which carries the Reserved value \
                 0. A verifier that ignores vds and applies the RFC9162_SHA256 walk anyway \
                 accepts this and reports a proof it had no basis to interpret. That is the \
                 failure this vector names, and no parse-only test catches it because the \
                 bytes are well formed.",
            ),
            expect_failure: Some(
                "unsupported verifiable data structure; only RFC9162_SHA256 is implemented",
            ),
        },
        Vector {
            name: "invalid-leaf-index-outside-tree.json",
            json: vector(
                &out_of_range,
                "rejected",
                "leaf_index equals tree_size. RFC 9162 Section 2.1.3.2 step 1 requires this \
                 be refused before any hashing. A verifier that skips the check walks a path \
                 that terminates anyway and reports a root it computed from an entry the log \
                 does not claim to hold.",
            ),
            expect_failure: Some("inclusion proof leaf_index is not less than tree_size"),
        },
        Vector {
            name: "invalid-empty-inclusion-path.json",
            json: vector(
                &empty_path,
                "rejected",
                "An inclusion_path with no elements, which the RFC 9942 CDDL forbids with \
                 `[ + bstr ]`. In a tree of size nine the empty path reconstructs the leaf \
                 hash as the root. A verifier that accepts it treats a single unlogged entry \
                 as an entire log.",
            ),
            expect_failure: Some("inclusion proof inclusion_path must not be empty"),
        },
        Vector {
            name: "invalid-short-path-element.json",
            json: vector(
                &short_element,
                "rejected",
                "A 31-byte path element where SHA-256 requires 32. The vector exists because \
                 a verifier that copies path elements into a buffer without checking the \
                 length is the ordinary way this goes wrong, and the result is a root that \
                 depends on uninitialised bytes.",
            ),
            expect_failure: Some("inclusion proof inclusion_path elements must be 32 bytes"),
        },
        Vector {
            name: "invalid-foreign-signature.json",
            json: vector(
                &foreign,
                "rejected",
                "A structurally perfect Receipt over the correct root, signed by a different \
                 Transparency Service. The proof verifies; the signature does not. A verifier \
                 that checks inclusion and stops accepts a log entry from a service the \
                 relying party never trusted.",
            ),
            expect_failure: Some("signature error"),
        },
    ]
}

fn render(value: &Json) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("fixture serializes");
    text.push('\n');
    text
}

/// Asserts the committed fixtures match the generator, and can rewrite them.
///
/// Set `PASK_REGEN_FIXTURES=1` to write instead of assert. Regeneration is
/// opt-in and never runs in CI, so the guard against silent drift holds.
#[test]
fn committed_fixtures_are_byte_identical_to_the_generator() {
    let regenerate = std::env::var("PASK_REGEN_FIXTURES").is_ok_and(|value| value == "1");
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("fixtures directory is creatable");
    for vector in generate() {
        let expected_text = render(&vector.json);
        let path = dir.join(vector.name);
        if regenerate {
            fs::write(&path, &expected_text)
                .unwrap_or_else(|error| panic!("{} is writable: {error}", path.display()));
            continue;
        }
        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
        assert_eq!(
            committed,
            expected_text,
            "{} has drifted from the generator in this test. Do not hand-edit the \
             fixture; regenerate it with PASK_REGEN_FIXTURES=1.",
            path.display()
        );
    }
}

/// Every vector produces the outcome it advertises.
///
/// A vector whose `expect` field disagrees with what the verifier does is worse
/// than no vector at all, because an outside implementer calibrates against it
/// and inherits the error.
#[test]
fn every_vector_produces_the_outcome_it_advertises() {
    let key = ts_key();
    let log = entries(9);
    for vector in generate() {
        let receipt_hex = vector.json["receipt"]
            .as_str()
            .expect("receipt is a string");
        let receipt: Vec<u8> = (0..receipt_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&receipt_hex[i..i + 2], 16).expect("valid hex"))
            .collect();
        let outcome = verify_inclusion(&receipt, &log[6], &key.verifying_key());
        match vector.expect_failure {
            None => {
                let verified = outcome
                    .unwrap_or_else(|error| panic!("{} should verify: {error}", vector.name));
                assert_eq!(verified.tree_size, 9);
                assert_eq!(verified.leaf_index, 6);
                assert_eq!(vector.json["expect"], "verifies");
            }
            Some(reason) => {
                let error = outcome
                    .expect_err(&format!("{} must not verify", vector.name))
                    .to_string();
                assert!(
                    error.contains(reason),
                    "{} should fail naming {reason:?}, but said {error:?}",
                    vector.name
                );
                assert_eq!(vector.json["expect"], "rejected");
            }
        }
    }
}
