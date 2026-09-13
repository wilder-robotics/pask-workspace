// SPDX-License-Identifier: Apache-2.0
// Export a signed fixture for independent verification in Python.
// This produces deterministic bytes using fixed test keys.

use coset::cbor::Value;
use ed25519_dalek::{Signer, SigningKey};
use pask_wire::{
    Payload, RFC9162_SHA256, VDP_LABEL, VDS_LABEL, derive_candidate_entry, leaf_hash,
    produce_ed25519, testvectors::MINIMAL_VALID_PAYLOAD, verify_ed25519, verify_inclusion,
};
use sha2::{Digest, Sha256};

const RECEIPTS_LABEL: i64 = 394;
const COSE_SIGN1_TAG: u64 = 18;

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

fn cbor_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    coset::cbor::ser::into_writer(value, &mut encoded).expect("encoding to a Vec cannot fail");
    encoded
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
        panic!("must be array")
    };
    let receipt_values: Vec<Value> = receipts.iter().map(|r| Value::Bytes(r.clone())).collect();
    items[1] = Value::Map(vec![(
        Value::Integer(RECEIPTS_LABEL.into()),
        Value::Array(receipt_values),
    )]);
    cbor_value(&Value::Array(items))
}

fn main() {
    // Step 1: Produce a signed Transparent Statement
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
    let issuer_signing = SigningKey::from_bytes(&[3u8; 32]);
    let statement = produce_ed25519(&payload, payload.witness_key(), &issuer_signing).unwrap();
    let issuer_verifying = issuer_signing.verifying_key();
    verify_ed25519(&statement, &issuer_verifying).unwrap();

    // Step 2: Derive the candidate entry
    let candidate_entry = derive_candidate_entry(&statement).unwrap();

    // Step 3: Build a Merkle tree
    let log: Vec<Vec<u8>> = (0..9).map(|i| format!("entry-{i}").into_bytes()).collect();
    let mut log_with_candidate = log.clone();
    log_with_candidate[6] = candidate_entry.clone();
    let root = merkle_tree_hash(&log_with_candidate);
    let path = inclusion_path(&log_with_candidate, 6);
    let tree_size = 9u64;
    let leaf_index = 6u64;

    // Step 4: Build a receipt
    let ts_key = ts_signing_key();
    let ts_verifying = ts_key.verifying_key();
    let receipt = build_receipt(
        &ts_key,
        &root,
        &[wrapped_proof(tree_size, leaf_index, &path)],
        RFC9162_SHA256,
    );

    // Step 5: Attach receipt to produce final statement
    let final_statement = attach_receipts_wire(&statement, std::slice::from_ref(&receipt));

    // Step 6: Verify everything works
    let entry_from_final = derive_candidate_entry(&final_statement).unwrap();
    assert_eq!(entry_from_final, candidate_entry);
    let verify_result = verify_inclusion(&receipt, &entry_from_final, &ts_verifying);
    assert!(verify_result.is_ok());

    // Step 7: Output all bytes as hex
    println!("=== SIGNED FIXTURE EXPORT ===");
    println!("raw_statement_hex: {}", hex::encode(&statement));
    println!("final_statement_hex: {}", hex::encode(&final_statement));
    println!("candidate_entry_hex: {}", hex::encode(&candidate_entry));
    println!("receipt_hex: {}", hex::encode(&receipt));
    println!(
        "issuer_public_key_hex: {}",
        hex::encode(issuer_verifying.to_bytes())
    );
    println!(
        "ts_public_key_hex: {}",
        hex::encode(ts_verifying.to_bytes())
    );
    println!("merkle_root_hex: {}", hex::encode(root));
    println!(
        "inclusion_path_hex: {}",
        path.iter().map(hex::encode).collect::<Vec<_>>().join(",")
    );
    println!("tree_size: {}", tree_size);
    println!("leaf_index: {}", leaf_index);
    println!("=== END EXPORT ===");
}
