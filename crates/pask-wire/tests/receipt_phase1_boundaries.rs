// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.
#![cfg(feature = "alloc")]
use coset::cbor::Value as V;
use pask_wire::{InspectionLimits, InspectionPolicy, InspectionStatus as S, inspect_scitt_receipt};

fn i(n: i64) -> V {
    V::Integer(n.into())
}
fn bytes(n: usize) -> V {
    V::Bytes(vec![0x11; n])
}
fn encode(v: &V) -> Vec<u8> {
    let mut b = Vec::new();
    coset::cbor::ser::into_writer(v, &mut b).unwrap();
    b
}
fn base() -> V {
    coset::cbor::de::from_reader(
        include_bytes!("fixtures/phase1/text_claims_detached.cbor").as_slice(),
    )
    .unwrap()
}
fn parts(v: &mut V) -> &mut Vec<V> {
    let V::Tag(18, t) = v else { panic!() };
    let V::Array(a) = t.as_mut() else { panic!() };
    a
}
fn protected(v: &mut V, f: impl FnOnce(&mut Vec<(V, V)>)) {
    let V::Bytes(b) = &mut parts(v)[0] else {
        panic!()
    };
    let mut p: V = coset::cbor::de::from_reader(b.as_slice()).unwrap();
    let V::Map(m) = &mut p else { panic!() };
    f(m);
    *b = encode(&p);
}
fn unprotected(v: &mut V) -> &mut Vec<(V, V)> {
    let V::Map(m) = &mut parts(v)[1] else {
        panic!()
    };
    m
}
fn set(m: &mut Vec<(V, V)>, k: i64, v: V) {
    if let Some((_, x)) = m.iter_mut().find(|(key, _)| key == &i(k)) {
        *x = v;
    } else {
        m.push((i(k), v));
    }
}
fn claim(v: &mut V, k: i64, value: V) {
    protected(v, |p| {
        let (_, V::Map(c)) = p.iter_mut().find(|(key, _)| key == &i(15)).unwrap() else {
            panic!()
        };
        set(c, k, value);
    });
}
fn proof(v: &mut V, tree: V, leaf: V, nodes: usize) {
    set(
        unprotected(v),
        396,
        V::Map(vec![(
            i(-1),
            V::Array(vec![V::Bytes(encode(&V::Array(vec![
                tree,
                leaf,
                V::Array(vec![bytes(32); nodes]),
            ])))]),
        )]),
    );
}
fn acceptable(v: &V, p: &InspectionPolicy) {
    let b = encode(v);
    let r = inspect_scitt_receipt(&b, p);
    assert_eq!(r.structure.status, S::Passed, "{r:?}");
    assert_eq!(r.required_claims.status, S::Passed, "{r:?}");
    assert_eq!(r.selected_policy.status, S::Passed, "{r:?}");
    assert_eq!(r.ts_signature.status, S::NotEvaluated);
    assert_eq!(r.inclusion.status, S::NotEvaluated);
}
fn rejected(v: &V, p: &InspectionPolicy, code: &str) {
    let b = encode(v);
    let r = inspect_scitt_receipt(&b, p);
    assert!(
        [
            &r.structure,
            &r.required_claims,
            &r.selected_policy,
            &r.support
        ]
        .iter()
        .any(|f| f.status == S::Failed && f.code == code),
        "expected {code}: {r:?}"
    );
}
fn policy(f: impl FnOnce(&mut InspectionLimits)) -> InspectionPolicy {
    let mut p = InspectionPolicy::default();
    f(&mut p.limits);
    p
}

#[test]
fn receipt_bytes_default_at_and_over_before_parse() {
    let mut v = base();
    parts(&mut v)[2] = bytes(1_048_000);
    let overhead = encode(&v).len() - 1_048_000;
    parts(&mut v)[2] = bytes(1_048_576 - overhead);
    assert_eq!(encode(&v).len(), 1_048_576);
    acceptable(&v, &Default::default());
    parts(&mut v)[2] = bytes(1_048_577 - overhead);
    rejected(&v, &Default::default(), "receipt_byte_limit");
    let b = vec![0xff; 1_048_577];
    let r = inspect_scitt_receipt(&b, &Default::default());
    assert_eq!(r.cbor_items_inspected, 0);
    assert_eq!(r.encoded_receipt.as_ptr(), b.as_ptr());
}
#[test]
fn protected_bytes_default_at_and_over() {
    let mut v = base();
    protected(&mut v, |p| set(p, 1000, bytes(65_000)));
    let V::Bytes(b) = &parts(&mut v)[0] else {
        panic!()
    };
    let overhead = b.len() - 65_000;
    protected(&mut v, |p| set(p, 1000, bytes(65_536 - overhead)));
    let V::Bytes(b) = &parts(&mut v)[0] else {
        panic!()
    };
    assert_eq!(b.len(), 65_536);
    acceptable(&v, &Default::default());
    protected(&mut v, |p| set(p, 1000, bytes(65_537 - overhead)));
    rejected(&v, &Default::default(), "protected_byte_limit");
}
#[test]
fn signature_bytes_default_at_and_over() {
    let mut v = base();
    parts(&mut v)[3] = bytes(1024);
    acceptable(&v, &Default::default());
    parts(&mut v)[3] = bytes(1025);
    rejected(&v, &Default::default(), "signature_byte_limit");
}
#[test]
fn nesting_across_protected_and_proof_boundaries() {
    let mut v = base();
    let mut nested = i(0);
    for _ in 0..13 {
        nested = V::Array(vec![nested]);
    }
    protected(&mut v, |p| set(p, 1000, nested.clone()));
    acceptable(&v, &Default::default());
    protected(&mut v, |p| set(p, 1000, V::Array(vec![nested])));
    rejected(&v, &Default::default(), "cbor_nesting_limit");
    acceptable(&base(), &policy(|p| p.max_cbor_nesting = 7));
    rejected(
        &base(),
        &policy(|p| p.max_cbor_nesting = 6),
        "cbor_nesting_limit",
    );
}
#[test]
fn cumulative_items_default_at_and_over_including_embedded_proofs() {
    let mut v = base();
    protected(&mut v, |p| set(p, 1000, V::Array(vec![])));
    let b = encode(&v);
    let n = inspect_scitt_receipt(&b, &Default::default()).cbor_items_inspected;
    protected(&mut v, |p| set(p, 1000, V::Array(vec![i(0); 4096 - n])));
    let b = encode(&v);
    let r = inspect_scitt_receipt(&b, &Default::default());
    assert_eq!(r.cbor_items_inspected, 4096);
    acceptable(&v, &Default::default());
    protected(&mut v, |p| set(p, 1000, V::Array(vec![i(0); 4097 - n])));
    rejected(&v, &Default::default(), "cbor_item_limit");
    let b = encode(&base());
    let n = inspect_scitt_receipt(&b, &Default::default()).cbor_items_inspected;
    acceptable(&base(), &policy(|p| p.max_cbor_items = n));
    rejected(
        &base(),
        &policy(|p| p.max_cbor_items = n - 1),
        "cbor_item_limit",
    );
}
#[test]
fn map_entries_default_at_and_over_before_lookup() {
    let mut v = base();
    protected(&mut v, |p| {
        for n in 1000..1060 {
            set(p, n, i(0));
        }
    });
    acceptable(&v, &Default::default());
    protected(&mut v, |p| set(p, 1060, i(0)));
    rejected(&v, &Default::default(), "map_entry_limit");
}
#[test]
fn proof_count_default_at_and_over_and_path_nodes_default_at_and_over() {
    let mut v = base();
    let (_, V::Map(m)) = &mut unprotected(&mut v)[0] else {
        panic!()
    };
    let (_, V::Array(a)) = &mut m[0] else {
        panic!()
    };
    *a = vec![a[0].clone(); 16];
    acceptable(&v, &Default::default());
    let (_, V::Map(m)) = &mut unprotected(&mut v)[0] else {
        panic!()
    };
    let (_, V::Array(a)) = &mut m[0] else {
        panic!()
    };
    a.push(a[0].clone());
    rejected(&v, &Default::default(), "proof_limit");
    proof(&mut v, V::Integer(u64::MAX.into()), i(0), 64);
    acceptable(&v, &Default::default());
    proof(&mut v, V::Integer(u64::MAX.into()), i(0), 65);
    rejected(&v, &Default::default(), "path_limit");
}
#[test]
fn certificate_chain_count_and_bytes_before_certificate_decode() {
    let mut v = base();
    claim(&mut v, 1, V::Text("https://ts.example".into()));
    protected(&mut v, |p| set(p, 33, V::Array(vec![bytes(4); 8])));
    acceptable(&v, &Default::default());
    protected(&mut v, |p| set(p, 33, V::Array(vec![bytes(4); 9])));
    rejected(&v, &Default::default(), "certificate_count_limit");
    // Default certificate-byte ceiling equals the entire protected-byte ceiling:
    // a 65536-byte protected cert cannot fit with header overhead. Tighten to
    // isolate the certificate-byte boundary; no DER/chain/trust claim is made.
    protected(&mut v, |p| set(p, 33, bytes(128)));
    let p = policy(|p| p.max_certificate_bytes = 128);
    acceptable(&v, &p);
    protected(&mut v, |p| set(p, 33, bytes(129)));
    rejected(&v, &p, "certificate_byte_limit");
}
#[test]
fn claim_text_characters_not_utf8_bytes_at_and_over() {
    let mut v = base();
    claim(&mut v, 2, V::Text("é".repeat(8192)));
    acceptable(&v, &Default::default());
    claim(&mut v, 2, V::Text("é".repeat(8193)));
    rejected(&v, &Default::default(), "claim_text_limit");
    claim(&mut v, 2, V::Text("abc".into()));
    acceptable(&v, &policy(|p| p.max_claim_text_characters = 3));
    rejected(
        &v,
        &policy(|p| p.max_claim_text_characters = 2),
        "claim_text_limit",
    );
}
#[test]
fn tree_size_uint_max_and_tightened_boundary() {
    let mut v = base();
    proof(
        &mut v,
        V::Integer(u64::MAX.into()),
        V::Integer((u64::MAX - 1).into()),
        1,
    );
    acceptable(&v, &Default::default());
    proof(
        &mut v,
        V::Tag(2, Box::new(V::Bytes(vec![1, 0, 0, 0, 0, 0, 0, 0, 0]))),
        i(0),
        1,
    );
    rejected(&v, &Default::default(), "tree_type");
    proof(&mut v, i(2), i(0), 1);
    acceptable(&v, &policy(|p| p.max_tree_size = 2));
    proof(&mut v, i(3), i(0), 1);
    rejected(&v, &policy(|p| p.max_tree_size = 2), "tree_size_limit");
}
#[test]
fn invalid_limit_configuration_never_disables_hard_ceilings() {
    let p = policy(|p| p.max_cbor_nesting = usize::MAX);
    rejected(&base(), &p, "invalid_policy_limits");
    let p = policy(|p| p.max_cbor_items = 0);
    rejected(&base(), &p, "invalid_policy_limits");
}
#[test]
fn declared_huge_lengths_counts_and_truncation_no_allocation() {
    for b in [
        vec![0xd2, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![
            0xd2, 0x84, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ] {
        let r = inspect_scitt_receipt(&b, &Default::default());
        assert_eq!(r.selected_policy.status, S::Failed);
        assert!(r.protected_bytes.is_none());
    }
    let b = encode(&base());
    for n in 0..b.len() {
        let r = inspect_scitt_receipt(&b[..n], &Default::default());
        assert_ne!(r.structure.status, S::Passed, "prefix {n}");
    }
}
#[test]
fn string_or_uri_exact_text_and_syntax_not_normalization() {
    let valid = [
        "",
        "ts",
        "https://EXAMPLE.test/a%2fb",
        "urn:example:ABC",
        "did:example:AbC",
        "https://[2001:db8::1]/x",
        "a:b",
    ];
    for text in valid {
        let mut v = base();
        claim(&mut v, 2, V::Text(text.into()));
        let b = encode(&v);
        let r = inspect_scitt_receipt(&b, &Default::default());
        assert_eq!(r.required_claims.status, S::Passed, "{text}: {r:?}");
        assert_eq!(r.unauthenticated_claims.unwrap().subject, text);
    }
    for text in [
        "1bad:scheme",
        "https://a b",
        "https://a/%xz",
        "https://[xyz]/",
        "https://a/é",
        ":",
    ] {
        let mut v = base();
        claim(&mut v, 2, V::Text(text.into()));
        rejected(&v, &Default::default(), "uri_syntax");
    }
}
#[test]
fn protected_precedence_only_for_permitted_overlaps() {
    let mut v = base();
    set(unprotected(&mut v), 1, V::Text("ignored shadow".into()));
    set(unprotected(&mut v), 4, V::Text("ignored shadow".into()));
    acceptable(&v, &Default::default());
    let p = InspectionPolicy {
        strict_cross_map: true,
        ..Default::default()
    };
    rejected(&v, &p, "cross_map_overlap");
    let mut v = base();
    set(unprotected(&mut v), 2, V::Array(vec![i(1)]));
    rejected(&v, &Default::default(), "crit_location");
    let mut v = base();
    protected(&mut v, |p| set(p, 396, V::Map(vec![])));
    rejected(&v, &Default::default(), "vdp_location");
}
#[test]
fn critical_rules_presence_valid_labels_and_understood_semantics() {
    for (crit, code) in [
        (V::Array(vec![i(1), i(1)]), "crit_duplicate_label"),
        (V::Array(vec![i(2)]), "crit_self_reference"),
        (V::Array(vec![bytes(1)]), "crit_label_type"),
    ] {
        let mut v = base();
        protected(&mut v, |p| set(p, 2, crit));
        rejected(&v, &Default::default(), code);
    }
    let mut v = base();
    set(unprotected(&mut v), 1000, i(1));
    protected(&mut v, |p| set(p, 2, V::Array(vec![i(1000)])));
    rejected(&v, &Default::default(), "crit_reference_absent");
    let mut v = base();
    protected(&mut v, |p| {
        set(p, 2, V::Array(vec![V::Text("future".into())]));
        p.push((V::Text("future".into()), i(0)));
    });
    let b = encode(&v);
    let r = inspect_scitt_receipt(&b, &Default::default());
    assert_eq!(r.structure.status, S::Passed);
    assert_eq!(r.support.code, "critical_semantics");
}
#[test]
fn unsupported_vds_never_interprets_opaque_proof_bytes_as_rfc9162() {
    for vds in [2, 777] {
        let mut v = base();
        protected(&mut v, |p| set(p, 395, i(vds)));
        set(
            unprotected(&mut v),
            396,
            V::Map(vec![(i(-1), V::Array(vec![V::Bytes(vec![0xff, 0xff])]))]),
        );
        let b = encode(&v);
        let r = inspect_scitt_receipt(&b, &Default::default());
        assert_eq!(r.structure.status, S::Passed);
        assert_eq!(r.support.status, S::Unsupported);
    }
    let mut v = base();
    set(
        unprotected(&mut v),
        396,
        V::Map(vec![(i(-1), V::Array(vec![V::Bytes(vec![0xff])]))]),
    );
    rejected(&v, &Default::default(), "invalid_cbor");
}
#[test]
fn duplicate_unknown_nested_map_and_semantically_equal_encoded_keys() {
    let mut v = base();
    protected(&mut v, |p| {
        set(p, 1000, V::Map(vec![(i(999), i(1)), (i(999), i(2))]))
    });
    rejected(&v, &Default::default(), "duplicate_key");
    let mut v = base();
    let key1 = V::Map(vec![(i(1), i(2)), (i(3), i(4))]);
    let key2 = V::Map(vec![(i(3), i(4)), (i(1), i(2))]);
    protected(&mut v, |p| {
        set(p, 1000, V::Map(vec![(key1, i(1)), (key2, i(2))]))
    });
    rejected(&v, &Default::default(), "duplicate_key");
}
#[test]
fn exact_signed_bytes_and_nonminimal_encoding_preserved() {
    let mut v = base();
    let V::Bytes(p) = &mut parts(&mut v)[0] else {
        panic!()
    };
    // alg -8 encoded non-minimally: 0x27 => 0x38 0x07.
    let pos = p.iter().position(|x| *x == 0x27).unwrap();
    p.splice(pos..pos + 1, [0x38, 0x07]);
    let expected = p.clone();
    let b = encode(&v);
    let r = inspect_scitt_receipt(&b, &Default::default());
    assert_eq!(r.structure.status, S::Passed);
    assert_eq!(r.protected_bytes.unwrap(), expected);
    assert_eq!(r.encoded_receipt, b);
}
#[test]
fn indefinite_maps_arrays_and_byte_strings_consumed_exactly() {
    let mut v = base();
    let V::Bytes(p) = &mut parts(&mut v)[0] else {
        panic!()
    };
    p[0] = 0xbf;
    p.push(0xff);
    let expected = p.clone();
    let mut b = encode(&v);
    assert_eq!(b[1], 0x84);
    b[1] = 0x9f;
    b.push(0xff);
    let r = inspect_scitt_receipt(&b, &Default::default());
    assert_eq!(r.structure.status, S::Passed, "{r:?}");
    assert_eq!(r.protected_bytes.unwrap(), expected);
    // Outer protected bstr can itself use chunked representation.
    let mut v = base();
    let V::Bytes(p) = &parts(&mut v)[0] else {
        panic!()
    };
    let p = p.clone();
    let a = parts(&mut v);
    let mut b = vec![0xd2, 0x84, 0x5f];
    b.extend(encode(&V::Bytes(p[..8].to_vec())));
    b.extend(encode(&V::Bytes(p[8..].to_vec())));
    b.push(0xff);
    for item in &a[1..] {
        b.extend(encode(item));
    }
    let r = inspect_scitt_receipt(&b, &Default::default());
    assert_eq!(r.structure.status, S::Passed, "{r:?}");
    assert_eq!(r.protected_bytes.unwrap(), p);
    b.push(0x00);
    assert_eq!(
        inspect_scitt_receipt(&b, &Default::default())
            .structure
            .code,
        "outer_trailing_data"
    );
}
#[test]
fn serialization_spells_not_evaluated_and_never_authenticates_claims() {
    let b = encode(&base());
    let r = inspect_scitt_receipt(&b, &Default::default());
    let j = serde_json::to_value(&r.ts_signature).unwrap();
    assert_eq!(j["status"], "not-evaluated");
    assert_eq!(
        serde_json::to_value(r.unauthenticated_claims.unwrap()).unwrap()["authenticated"],
        false
    );
}

#[test]
fn unprotected_x509_shape_does_not_replace_protected_kid_or_provision_trust() {
    let mut v = base();
    set(unprotected(&mut v), 33, i(7));
    rejected(&v, &Default::default(), "x5chain_shape");
    set(unprotected(&mut v), 33, bytes(8));
    acceptable(&v, &Default::default());
    protected(&mut v, |p| p.retain(|(key, _)| key != &i(4)));
    rejected(&v, &Default::default(), "missing_key_identifier");
    let mut v = base();
    claim(&mut v, 1, V::Text("https://ts.example".into()));
    protected(&mut v, |p| set(p, 33, bytes(8)));
    set(unprotected(&mut v), 33, i(7));
    acceptable(&v, &Default::default());
}

#[test]
fn historical_generic_crypto_fixture_still_verifies_without_claim_conformance() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/receipts/valid-detached-payload.json"
    ))
    .unwrap();
    let receipt = hex::decode(v["receipt"].as_str().unwrap()).unwrap();
    let entry = hex::decode(v["entry"].as_str().unwrap()).unwrap();
    let key: [u8; 32] = hex::decode(v["transparencyServiceVerifyingKey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
    assert!(pask_wire::verify_inclusion(&receipt, &entry, &key).is_ok());
    // A new tag does not rewrite signed fields, but also cannot supply claims.
    let mut tagged = vec![0xd2];
    tagged.extend(receipt);
    let r = inspect_scitt_receipt(&tagged, &Default::default());
    assert_eq!(r.structure.status, S::Passed);
    assert_eq!(r.required_claims.code, "missing_claims");
    assert_eq!(r.ts_signature.status, S::NotEvaluated);
}

fn small_bignum(tag: u64, magnitude: &[u8]) -> V {
    V::Tag(tag, Box::new(V::Bytes(magnitude.to_vec())))
}

#[test]
fn raw_bignum_required_integer_and_uint_boundaries() {
    // Both positive and negative tagged bignums must remain distinct from
    // CBOR major-type 0/1 values, even when their magnitude fits in a u64.
    for tag in [2, 3] {
        for label in [1, 395] {
            let mut v = base();
            protected(&mut v, |p| set(p, label, small_bignum(tag, &[1])));
            rejected(&v, &Default::default(), "required_header_type");
        }
        let mut v = base();
        proof(&mut v, small_bignum(tag, &[2]), i(0), 1);
        rejected(&v, &Default::default(), "tree_type");
        proof(&mut v, i(2), small_bignum(tag, &[0]), 1);
        rejected(&v, &Default::default(), "leaf_type");
    }
}

#[test]
fn raw_bignum_labels_at_all_interpreted_map_boundaries() {
    for tag in [2, 3] {
        let mut v = base();
        protected(&mut v, |p| p.push((small_bignum(tag, &[3, 231]), i(0))));
        rejected(&v, &Default::default(), "header_label_type");
        let mut v = base();
        unprotected(&mut v).push((small_bignum(tag, &[3, 231]), i(0)));
        rejected(&v, &Default::default(), "header_label_type");
        let mut v = base();
        // Replace, rather than duplicate, the required integer claim name.
        protected(&mut v, |p| {
            let (_, V::Map(c)) = p.iter_mut().find(|(key, _)| key == &i(15)).unwrap() else {
                panic!()
            };
            c[0].0 = small_bignum(tag, &[1]);
        });
        rejected(&v, &Default::default(), "claim_label_type");
        let mut v = base();
        let (_, V::Map(m)) = &mut unprotected(&mut v)[0] else {
            panic!()
        };
        m[0].0 = small_bignum(tag, &[0]);
        rejected(&v, &Default::default(), "header_label_type");
    }
}

#[test]
fn raw_bignum_critical_and_thumbprint_identifiers() {
    for tag in [2, 3] {
        let mut v = base();
        protected(&mut v, |p| {
            set(p, 2, V::Array(vec![small_bignum(tag, &[1])]))
        });
        rejected(&v, &Default::default(), "crit_label_type");
        let mut v = base();
        claim(&mut v, 1, V::Text("urn:test:issuer".into()));
        protected(&mut v, |p| {
            set(p, 34, V::Array(vec![small_bignum(tag, &[1]), bytes(32)]))
        });
        rejected(&v, &Default::default(), "x5t_shape");
    }
}

#[test]
fn tagged_certificate_label_rejected_before_protected_map_decode() {
    let mut v = base();
    protected(&mut v, |p| p.push((small_bignum(2, &[33]), bytes(2000))));
    let p = policy(|p| p.max_certificate_bytes = 100);
    let b = encode(&v);
    let r = inspect_scitt_receipt(&b, &p);
    assert_eq!(r.structure.code, "header_label_type");
    // No effective-header clones or semantic claims exist on this early path.
    assert!(r.effective_headers.is_empty());
    assert!(r.unauthenticated_claims.is_none());
    assert_eq!(r.required_claims.status, S::NotEvaluated);
    // Valid numeric label33 still takes its explicit preallocation-limit path.
    let mut v = base();
    protected(&mut v, |p| set(p, 33, bytes(2000)));
    rejected(&v, &p, "certificate_byte_limit");
}

#[test]
fn opaque_unknown_extension_tags_are_not_blanket_rejected() {
    for tag in [2, 3, 1000] {
        let mut v = base();
        protected(&mut v, |p| set(p, 1000, small_bignum(tag, &[1])));
        acceptable(&v, &Default::default());
        let mut v = base();
        set(unprotected(&mut v), 1000, small_bignum(tag, &[1]));
        acceptable(&v, &Default::default());
    }
}

#[test]
fn raw_unprotected_thumbprint_type_checked_only_when_effective() {
    let mut v = base();
    set(
        unprotected(&mut v),
        34,
        V::Array(vec![small_bignum(2, &[1]), bytes(32)]),
    );
    rejected(&v, &Default::default(), "x5t_shape");
    claim(&mut v, 1, V::Text("urn:test:issuer".into()));
    protected(&mut v, |p| set(p, 34, V::Array(vec![i(1), bytes(32)])));
    acceptable(&v, &Default::default());
    let strict = InspectionPolicy {
        strict_cross_map: true,
        ..Default::default()
    };
    rejected(&v, &strict, "cross_map_overlap");
}
