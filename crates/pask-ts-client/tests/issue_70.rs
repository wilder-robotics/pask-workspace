// SPDX-License-Identifier: AGPL-3.0-only
//! Actual #70 sender/reader tests. Minimal Receipt fixtures demonstrate
//! container bytes and cryptography only, NOT SCITT claims or service trust.
//! Expected output is hand-framed or loaded from unchanged independent vectors;
//! no test attachment helper substitutes for pask_ts_client::attach_receipt.

use coset::cbor::Value;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pask_ts_client::{TwoLeafTree, attach_receipt, build_receipt};
use pask_wire::{
    AttachedReceipts, Payload, attached_receipts, derive_candidate_entry, produce_ed25519,
    verify_ed25519, verify_inclusion,
};

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn decode(bytes: &[u8]) -> Value {
    let mut cursor = bytes;
    let value = coset::cbor::de::from_reader(&mut cursor).unwrap();
    assert!(cursor.is_empty());
    value
}

fn items(bytes: &[u8]) -> Vec<Value> {
    let value = match decode(bytes) {
        Value::Tag(18, inner) => *inner,
        other => other,
    };
    let Value::Array(items) = value else {
        panic!("array")
    };
    items
}

fn tagged(items: Vec<Value>) -> Vec<u8> {
    encode(&Value::Tag(18, Box::new(Value::Array(items))))
}

fn key(n: i64) -> Value {
    Value::Integer(n.into())
}
fn empty_map() -> Value {
    Value::Map(vec![])
}
fn receipt() -> Vec<u8> {
    hex("d28440a0f640")
}
fn statement() -> Vec<u8> {
    hex("d28443a10127a042787940")
}

// Handwritten CBOR framing, not coset or a production transformation.
fn bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        0..=23 => out.push(0x40 | bytes.len() as u8),
        24..=255 => out.extend([0x58, bytes.len() as u8]),
        256..=65535 => {
            out.push(0x59);
            out.extend((bytes.len() as u16).to_be_bytes());
        }
        _ => panic!("fixture too large"),
    }
    out.extend_from_slice(bytes);
}

fn signed_contents(bytes: &[u8]) -> [Vec<u8>; 3] {
    let a = items(bytes);
    [0, 2, 3].map(|i| {
        let Value::Bytes(b) = &a[i] else {
            panic!("bstr")
        };
        b.clone()
    })
}

fn expected_candidate(pms: &[Vec<u8>; 3]) -> Vec<u8> {
    let mut out = vec![0x84];
    bstr(&mut out, &pms[0]);
    out.push(0xa0);
    bstr(&mut out, &pms[1]);
    bstr(&mut out, &pms[2]);
    out
}

fn expected_wire(pms: &[Vec<u8>; 3], receipts: &[Vec<u8>]) -> Vec<u8> {
    assert!(receipts.len() < 24);
    let mut out = vec![0xd2, 0x84];
    bstr(&mut out, &pms[0]);
    out.extend([0xa1, 0x19, 0x01, 0x8a, 0x80 | receipts.len() as u8]);
    for r in receipts {
        bstr(&mut out, r);
    }
    bstr(&mut out, &pms[1]);
    bstr(&mut out, &pms[2]);
    out
}

#[test]
fn exact_wire_matches_handwritten_noncanonical_receipt_bytes() {
    // Non-shortest tag, array, bstr, and map framing is valid CBOR.
    let r = hex("d81298045800b800f65800");
    // Noncanonical P bstr framing, indefinite payload bstr; P/M/S contents
    // survive while the sender re-frames the surrounding statement.
    let s = hex("d81298045803a10127b8005f41784179ff5800");
    let expected = hex("d28443a10127a119018a814bd81298045800b800f6580042787940");
    let out = attach_receipt(&s, &r).unwrap();
    assert_eq!(out, expected);
    assert_eq!(signed_contents(&out), signed_contents(&s));
    assert_eq!(
        attached_receipts(&out).unwrap(),
        AttachedReceipts::Present(vec![r])
    );
    assert_eq!(
        derive_candidate_entry(&out).unwrap(),
        derive_candidate_entry(&s).unwrap()
    );
}

#[test]
fn multiple_attachments_preserve_every_prior_encoded_byte_and_order() {
    let r1 = hex("d81298045800b800f65800");
    let r2 = receipt();
    let first = attach_receipt(&statement(), &r1).unwrap();
    let second = attach_receipt(&first, &r2).unwrap();
    let third = attach_receipt(&second, &r1).unwrap();
    let expected = vec![r1.clone(), r2, r1];
    assert_eq!(
        third,
        expected_wire(&signed_contents(&statement()), &expected)
    );
    assert_eq!(
        attached_receipts(&third).unwrap(),
        AttachedReceipts::Present(expected)
    );
}

#[test]
fn noncanonical_signed_receipt_survives_repeated_attachment_and_inclusion_verification() {
    let p = payload("wilder.pser/0.6");
    let issuer = SigningKey::from_bytes(&[49; 32]);
    let ts = SigningKey::from_bytes(&[50; 32]);
    let local = produce_ed25519(&p, p.witness_key(), &issuer).unwrap();
    let entry = expected_candidate(&signed_contents(&local));
    let r = build_receipt(&TwoLeafTree::new(&entry), &ts).unwrap();
    assert_eq!(&r[..2], &[0xd2, 0x84]);
    // Preserve a non-shortest tag and an indefinite array around a genuinely
    // signed Receipt; they do not participate in its Sig_structure.
    let mut noncanonical = vec![0xd8, 0x12, 0x9f];
    noncanonical.extend_from_slice(&r[2..]);
    noncanonical.push(0xff);
    verify_inclusion(&noncanonical, &entry, &ts.verifying_key()).unwrap();
    let first = attach_receipt(&local, &noncanonical).unwrap();
    let out = attach_receipt(&first, &r).unwrap();
    let expected = vec![noncanonical, r];
    assert_eq!(out, expected_wire(&signed_contents(&local), &expected));
    let AttachedReceipts::Present(found) = attached_receipts(&out).unwrap() else {
        panic!("present")
    };
    assert_eq!(found, expected);
    for r in found {
        verify_inclusion(&r, &entry, &ts.verifying_key()).unwrap();
    }
    assert_eq!(derive_candidate_entry(&out).unwrap(), entry);
    verify_ed25519(&out, &issuer.verifying_key()).unwrap();
}

#[test]
fn bad_additional_signature_is_preserved_and_does_not_replace_good_receipt() {
    for version in ["wilder.pser/0.5", "wilder.pser/0.6"] {
        let p = payload(version);
        let issuer = SigningKey::from_bytes(&[51; 32]);
        let ts = SigningKey::from_bytes(&[52; 32]);
        let local = produce_ed25519(&p, p.witness_key(), &issuer).unwrap();
        let entry = expected_candidate(&signed_contents(&local));
        let good = build_receipt(&TwoLeafTree::new(&entry), &ts).unwrap();
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        for (receipts, expected_valid) in [
            (vec![bad.clone(), good.clone()], vec![false, true]),
            (vec![good.clone(), bad.clone()], vec![true, false]),
            (vec![bad.clone(), bad.clone()], vec![false, false]),
        ] {
            let first = attach_receipt(&local, &receipts[0]).unwrap();
            let out = attach_receipt(&first, &receipts[1]).unwrap();
            let AttachedReceipts::Present(found) = attached_receipts(&out).unwrap() else {
                panic!("present")
            };
            assert_eq!(found, receipts);
            let actual_valid: Vec<bool> = found
                .iter()
                .map(|r| verify_inclusion(r, &entry, &ts.verifying_key()).is_ok())
                .collect();
            assert_eq!(actual_valid, expected_valid);
            assert_eq!(derive_candidate_entry(&out).unwrap(), entry);
            assert_eq!(signed_contents(&out), signed_contents(&local));
            verify_ed25519(&out, &issuer.verifying_key()).unwrap();
        }
    }
}

#[test]
fn existing_unprotected_evidence_is_not_discarded() {
    let mut s = items(&statement());
    s[1] = Value::Map(vec![(
        Value::Text("evidence".into()),
        Value::Bytes(vec![1, 2, 3]),
    )]);
    let out = attach_receipt(&tagged(s.clone()), &receipt()).unwrap();
    let Value::Map(after) = &items(&out)[1] else {
        panic!("map")
    };
    let Value::Map(before) = &s[1] else {
        panic!("map")
    };
    assert_eq!(&after[..1], before);
}

#[test]
fn independent_signed_vector_matches_actual_sender_and_verifiers() {
    // This existing file and its generators are deliberately unchanged.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../pask-wire/pask_67_independent_signed_vectors.json"
    ))
    .unwrap();
    let f = &fixture["fixture"];
    let bytes = |field: &str| hex(f[field].as_str().unwrap());
    let raw = bytes("raw_statement_hex");
    let r = bytes("receipt_hex");
    let mut transmitted = vec![0xd2];
    transmitted.extend_from_slice(&raw);
    let mut expected = vec![0xd2];
    expected.extend(bytes("final_statement_hex"));
    let out = attach_receipt(&transmitted, &r).unwrap();
    assert_eq!(
        out, expected,
        "source-derived complete wire regression; independent signature and candidate fixtures"
    );
    let entry = hex(fixture["expected"]["candidate_entry_hex"].as_str().unwrap());
    assert_eq!(derive_candidate_entry(&out).unwrap(), entry);
    assert_eq!(
        attached_receipts(&out).unwrap(),
        AttachedReceipts::Present(vec![r.clone()])
    );
    let issuer =
        VerifyingKey::from_bytes(&bytes("issuer_public_key_hex").try_into().unwrap()).unwrap();
    let ts = VerifyingKey::from_bytes(&bytes("ts_public_key_hex").try_into().unwrap()).unwrap();
    verify_ed25519(&out, &issuer).unwrap();
    let verified = verify_inclusion(&r, &entry, &ts).unwrap();
    assert_eq!(verified.tree_size, f["tree_size"].as_u64().unwrap());
    assert_eq!(verified.leaf_index, f["leaf_index"].as_u64().unwrap());
}

fn payload(version: &str) -> Payload {
    let json = pask_wire::testvectors::MINIMAL_VALID_PAYLOAD.replace("wilder.pser/0.5", version);
    Payload::from_json_for_production(json.as_bytes()).unwrap()
}

fn roundtrip(version: &str) {
    let p = payload(version);
    let issuer = SigningKey::from_bytes(&[41; 32]);
    let ts = SigningKey::from_bytes(&[42; 32]);
    let local = produce_ed25519(&p, p.witness_key(), &issuer).unwrap();
    let mut transmitted = vec![0xd2];
    transmitted.extend_from_slice(&local);
    let pms = signed_contents(&transmitted);
    let entry = expected_candidate(&pms);
    let r = build_receipt(&TwoLeafTree::new(&entry), &ts).unwrap();
    let out = attach_receipt(&transmitted, &r).unwrap();
    assert_eq!(out, expected_wire(&pms, std::slice::from_ref(&r)));
    assert_eq!(signed_contents(&out), pms);
    assert_eq!(derive_candidate_entry(&transmitted).unwrap(), entry);
    assert_eq!(derive_candidate_entry(&out).unwrap(), entry);
    assert_eq!(
        verify_ed25519(&transmitted, &issuer.verifying_key()).unwrap(),
        p
    );
    assert_eq!(verify_ed25519(&out, &issuer.verifying_key()).unwrap(), p);
    let AttachedReceipts::Present(found) = attached_receipts(&out).unwrap() else {
        panic!("present")
    };
    assert_eq!(found, vec![r]);
    assert_eq!(
        verify_inclusion(&found[0], &entry, &ts.verifying_key())
            .unwrap()
            .tree_size,
        2
    );
    assert!(
        verify_inclusion(&found[0], &out, &ts.verifying_key()).is_err(),
        "final wire bytes are not the logged candidate"
    );
    assert!(verify_inclusion(&found[0], &entry, &issuer.verifying_key()).is_err());
}

#[test]
fn tagged_ed25519_v05_actual_sender_reader_signature_and_inclusion() {
    roundtrip("wilder.pser/0.5");
}
#[test]
fn tagged_ed25519_v06_actual_sender_reader_signature_and_inclusion() {
    roundtrip("wilder.pser/0.6");
}

#[cfg(feature = "es256")]
fn es256_roundtrip(version: &str) {
    let p = payload(version);
    // Type inferred through the public producer, avoiding a new dependency.
    let key = (&[43u8; 32][..]).try_into().unwrap();
    let local = pask_wire::produce_es256(&p, p.witness_key(), &key).unwrap();
    let ts = SigningKey::from_bytes(&[44; 32]);
    let entry = expected_candidate(&signed_contents(&local));
    let r = build_receipt(&TwoLeafTree::new(&entry), &ts).unwrap();
    let mut transmitted = vec![0xd2];
    transmitted.extend(local);
    let out = attach_receipt(&transmitted, &r).unwrap();
    assert_eq!(out, expected_wire(&signed_contents(&transmitted), &[r]));
    assert_eq!(derive_candidate_entry(&out).unwrap(), entry);
    assert_eq!(
        pask_wire::verify_es256(&out, key.verifying_key()).unwrap(),
        p
    );
    let AttachedReceipts::Present(found) = attached_receipts(&out).unwrap() else {
        panic!("present")
    };
    verify_inclusion(&found[0], &entry, &ts.verifying_key()).unwrap();
}

#[cfg(feature = "es256")]
#[test]
fn tagged_es256_v05_issuer_with_ed25519_ts_roundtrip() {
    es256_roundtrip("wilder.pser/0.5");
}
#[cfg(feature = "es256")]
#[test]
fn tagged_es256_v06_issuer_with_ed25519_ts_roundtrip() {
    es256_roundtrip("wilder.pser/0.6");
}

#[test]
fn noncanonical_signed_protected_contents_are_not_reserialized() {
    let p = payload("wilder.pser/0.6");
    let issuer = SigningKey::from_bytes(&[45; 32]);
    let ts = SigningKey::from_bytes(&[46; 32]);
    let mut s = items(&produce_ed25519(&p, p.witness_key(), &issuer).unwrap());
    let Value::Bytes(protected) = &s[0] else {
        panic!("protected")
    };
    assert_eq!(protected[0], 0xa3);
    let mut noncanonical = vec![0xbf]; // valid indefinite protected map
    noncanonical.extend_from_slice(&protected[1..]);
    noncanonical.push(0xff);
    s[0] = Value::Bytes(noncanonical);
    let to_sign = encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        s[0].clone(),
        Value::Bytes(vec![]),
        s[2].clone(),
    ]));
    s[3] = Value::Bytes(issuer.sign(&to_sign).to_bytes().to_vec());
    let before = tagged(s);
    verify_ed25519(&before, &issuer.verifying_key()).unwrap();
    let entry = expected_candidate(&signed_contents(&before));
    let r = build_receipt(&TwoLeafTree::new(&entry), &ts).unwrap();
    let out = attach_receipt(&before, &r).unwrap();
    assert_eq!(signed_contents(&before), signed_contents(&out));
    assert_eq!(derive_candidate_entry(&out).unwrap(), entry);
    verify_ed25519(&out, &issuer.verifying_key()).unwrap();
    verify_inclusion(&r, &entry, &ts.verifying_key()).unwrap();
}

#[test]
fn legacy_untagged_statement_input_is_explicitly_emitted_tagged() {
    let s = statement();
    assert_eq!(
        attach_receipt(&s[1..], &receipt()).unwrap(),
        attach_receipt(&s, &receipt()).unwrap()
    );
    assert_eq!(attach_receipt(&s[1..], &receipt()).unwrap()[0], 0xd2);
}

#[test]
fn legacy_decoded_attachments_remain_readable_but_are_not_upgraded_by_sender() {
    for r in [decode(&receipt()), decode(&receipt()[1..])] {
        let mut s = items(&statement());
        s[1] = Value::Map(vec![(key(394), Value::Array(vec![r]))]);
        let s = tagged(s);
        assert!(matches!(
            attached_receipts(&s).unwrap(),
            AttachedReceipts::Present(_)
        ));
        assert!(attach_receipt(&s, &receipt()).is_err());
    }
    assert!(
        attach_receipt(&statement(), &receipt()[1..]).is_err(),
        "untagged Receipt is not transmitted form"
    );
}

fn reject_envelope(s: &[u8]) {
    assert!(
        attach_receipt(s, &receipt()).is_err(),
        "sender accepted {s:02x?}"
    );
    assert!(attached_receipts(s).is_err(), "reader accepted {s:02x?}");
}

#[test]
fn rejects_unsupported_nested_wrappers_and_trailing_statement_data() {
    let a = Value::Array(items(&statement()));
    for s in [
        vec![],
        hex("ff"),
        encode(&key(1)),
        encode(&Value::Bytes(statement())),
        encode(&Value::Tag(17, Box::new(a.clone()))),
        encode(&Value::Tag(24, Box::new(a.clone()))),
        encode(&Value::Tag(18, Box::new(decode(&statement())))),
        encode(&Value::Tag(18, Box::new(empty_map()))),
        [statement(), vec![0x00]].concat(),
    ] {
        reject_envelope(&s);
    }
    let p = payload("wilder.pser/0.5");
    let issuer = SigningKey::from_bytes(&[47; 32]);
    let local = produce_ed25519(&p, p.witness_key(), &issuer).unwrap();
    for s in [
        encode(&Value::Tag(17, Box::new(decode(&local)))),
        encode(&Value::Tag(
            18,
            Box::new(Value::Tag(18, Box::new(decode(&local)))),
        )),
        [vec![0xd2], local, vec![0x00]].concat(),
    ] {
        assert!(verify_ed25519(&s, &issuer.verifying_key()).is_err());
    }
}

#[test]
fn rejects_wrong_arity_and_non_bstr_signed_elements() {
    for n in [0, 1, 3, 5] {
        let mut s = items(&statement());
        s.resize(n, Value::Null);
        reject_envelope(&tagged(s));
    }
    for position in [0, 2, 3] {
        for bad in [Value::Null, empty_map(), key(1), Value::Text("bad".into())] {
            let mut s = items(&statement());
            s[position] = bad;
            reject_envelope(&tagged(s));
        }
    }
    let mut s = items(&statement());
    s[1] = Value::Array(vec![]);
    reject_envelope(&tagged(s));
}

#[test]
fn rejects_malformed_protected_headers_even_when_unprotected_receipts_exist() {
    for bad in [hex("ff"), hex("00"), hex("a000"), hex("d2a0")] {
        let mut s = items(&statement());
        s[0] = Value::Bytes(bad);
        s[1] = Value::Map(vec![(
            key(394),
            Value::Array(vec![Value::Bytes(receipt())]),
        )]);
        reject_envelope(&tagged(s));
    }
}

#[test]
fn rejects_duplicate_integer_text_and_receipts_header_keys() {
    for label in [key(394), key(4), Value::Text("extension".into())] {
        for protected in [false, true] {
            let mut s = items(&statement());
            let map = Value::Map(vec![(label.clone(), key(1)), (label.clone(), key(2))]);
            if protected {
                s[0] = Value::Bytes(encode(&map));
            } else {
                s[1] = map;
            }
            reject_envelope(&tagged(s));
        }
    }
    // Same integer label encoded with two different CBOR integer widths.
    let mut s = items(&statement());
    s[0] = Value::Bytes(hex("a20127180127"));
    reject_envelope(&tagged(s));
}

#[test]
fn duplicate_valid_receipts_arrays_are_not_resolved_by_first_match() {
    for protected in [false, true] {
        let mut s = items(&statement());
        let arr = Value::Array(vec![Value::Bytes(receipt())]);
        let map = Value::Map(vec![(key(394), arr.clone()), (key(394), arr)]);
        if protected {
            s[0] = Value::Bytes(encode(&map));
        } else {
            s[1] = map;
        }
        reject_envelope(&tagged(s));
    }
}

#[test]
fn rejects_header_label_overlap_including_protected_unprotected_receipts() {
    for label in [key(394), key(4), Value::Text("extension".into())] {
        let mut s = items(&statement());
        let map = Value::Map(vec![(label, Value::Array(vec![Value::Bytes(receipt())]))]);
        s[0] = Value::Bytes(encode(&map));
        s[1] = map;
        reject_envelope(&tagged(s));
    }
}

#[test]
fn protected_only_receipts_are_read_but_sender_refuses_to_create_ambiguity() {
    let mut s = items(&statement());
    s[0] = Value::Bytes(encode(&Value::Map(vec![(
        key(394),
        Value::Array(vec![Value::Bytes(receipt())]),
    )])));
    let s = tagged(s);
    assert_eq!(
        attached_receipts(&s).unwrap(),
        AttachedReceipts::Present(vec![receipt()])
    );
    assert!(attach_receipt(&s, &receipt()).is_err());
}

#[test]
fn rejects_non_label_header_map_keys() {
    for k in [
        Value::Null,
        Value::Bytes(vec![1]),
        Value::Array(vec![]),
        Value::Bool(true),
    ] {
        for protected in [false, true] {
            let mut s = items(&statement());
            let map = Value::Map(vec![(k.clone(), key(1))]);
            if protected {
                s[0] = Value::Bytes(encode(&map));
            } else {
                s[1] = map;
            }
            reject_envelope(&tagged(s));
        }
    }
}

#[test]
fn rejects_empty_nonarray_and_mixed_existing_attachment_containers() {
    for bad in [
        Value::Array(vec![]),
        key(1),
        empty_map(),
        Value::Array(vec![Value::Bytes(receipt()), key(3)]),
        Value::Array(vec![Value::Tag(24, Box::new(empty_map()))]),
        Value::Array(vec![Value::Tag(18, Box::new(empty_map()))]),
        Value::Array(vec![Value::Tag(18, Box::new(decode(&receipt())))]),
        Value::Array(vec![Value::Array(vec![])]),
    ] {
        let mut s = items(&statement());
        s[1] = Value::Map(vec![(key(394), bad)]);
        let s = tagged(s);
        assert!(attach_receipt(&s, &receipt()).is_err());
        assert!(matches!(
            attached_receipts(&s).unwrap(),
            AttachedReceipts::Malformed(_)
        ));
    }
}

#[test]
fn rejects_malformed_new_and_existing_encoded_receipts_without_repair() {
    let mut invalid = vec![
        vec![],
        hex("ff"),
        hex("00"),
        receipt()[1..].to_vec(),
        [receipt(), vec![0x00]].concat(),
        encode(&Value::Bytes(receipt())),
        encode(&Value::Tag(24, Box::new(decode(&receipt())))),
        encode(&Value::Tag(18, Box::new(decode(&receipt())))),
        hex("d280"),
        hex("d2a0"),
    ];
    for (index, bad) in [
        (0, Value::Null),
        (0, Value::Bytes(hex("a000"))),
        (0, Value::Bytes(hex("00"))),
        (1, Value::Array(vec![])),
        (2, key(1)),
        (3, Value::Null),
    ] {
        let mut r = items(&receipt());
        r[index] = bad;
        invalid.push(tagged(r));
    }
    for r in invalid {
        assert!(attach_receipt(&statement(), &r).is_err(), "new {r:02x?}");
        let mut s = items(&statement());
        s[1] = Value::Map(vec![(key(394), Value::Array(vec![Value::Bytes(r)]))]);
        assert!(attach_receipt(&tagged(s), &receipt()).is_err(), "existing");
    }
}

#[test]
fn rejects_duplicate_and_overlapping_receipt_headers() {
    for label in [key(394), key(395), Value::Text("extension".into())] {
        for position in [0, 1, 2] {
            let mut r = items(&receipt());
            let map = Value::Map(vec![(label.clone(), key(1)), (label.clone(), key(2))]);
            match position {
                0 => r[0] = Value::Bytes(encode(&map)),
                1 => r[1] = map,
                _ => {
                    let one = Value::Map(vec![(label.clone(), key(1))]);
                    r[0] = Value::Bytes(encode(&one));
                    r[1] = one;
                }
            }
            assert!(attach_receipt(&statement(), &tagged(r)).is_err());
        }
    }
}

#[test]
fn attachment_success_does_not_validate_signatures_proofs_or_claims() {
    let out = attach_receipt(&statement(), &receipt()).unwrap();
    let AttachedReceipts::Present(found) = attached_receipts(&out).unwrap() else {
        panic!("present")
    };
    let key = SigningKey::from_bytes(&[48; 32]).verifying_key();
    assert!(verify_ed25519(&out, &key).is_err());
    assert!(verify_inclusion(&found[0], &derive_candidate_entry(&out).unwrap(), &key).is_err());
}
