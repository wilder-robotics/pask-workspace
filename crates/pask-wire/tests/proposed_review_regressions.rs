// SPDX-License-Identifier: Apache-2.0
//! Native regressions derived from the supplied September 22 review.
//! Its referenced companion regression file was not attached; these exercise
//! the reported cases through the actual public implementation.
#![cfg(feature = "alloc")]
use pask_wire::proposed_constraints::{ConstraintResult, EvidenceState, inspect_fact};
use serde_json::{Value, json};

fn model() -> Value {
    json!({"name":"unit.model","assertedBy":"site-policy","basis":"declared","value":"Example model"})
}
fn event(value: &str) -> Value {
    json!({"name":"scene.event-instant","assertedBy":"appliance-measured","basis":"measured",
        "value":value,"evidence":{"digest":format!("sha256:{}", "a".repeat(64))}})
}
fn findings(f: &Value) -> Vec<&'static str> {
    inspect_fact(f, EvidenceState::NotResolved).metadata_findings
}

#[test]
fn date_positive_uses_real_inspection_path_and_only_checks_form() {
    for text in ["2026-09-22T12:34:56.789Z", "0000-99-99T99:99:99.000Z"] {
        let r = inspect_fact(&event(text), EvidenceState::NotResolved);
        assert_eq!(r.classification, ConstraintResult::Permitted);
        assert!(
            r.metadata_findings.is_empty(),
            "{text}: {:?}",
            r.metadata_findings
        );
        assert_eq!(r.evidence, "NOT_RESOLVED");
        assert_eq!(r.receipt_binding, "NOT_EVALUATED");
        assert!(!r.attributed_party_authenticated);
    }
}

#[test]
fn date_negative_forms_are_not_rewritten_or_widened() {
    for text in [
        r"2026-09-22T12:34:56\.789Z",
        r"2026-09-22T12:34:56\X789Z",
        "2026-09-22T12:34:56X789Z",
        "2026-09-22T12:34:56.78Z",
        "2026-09-22T12:34:56.7890Z",
        "2026-09-22t12:34:56.789Z",
        "2026-09-22T12:34:56.789z",
        "2026-09-22T12:34:56.789Z\n",
        "２０２６-09-22T12:34:56.789Z",
        "",
    ] {
        assert!(
            findings(&event(text)).contains(&"invalid_typed_value"),
            "{text}"
        );
    }
}

#[test]
fn malformed_present_unit_types_never_equal_a_unitless_rule() {
    for unit in [json!(42), json!(true), json!([]), json!({}), json!(1.5)] {
        let mut f = model();
        f["unit"] = unit;
        assert!(findings(&f).contains(&"unit_mismatch"), "{f}");
    }
}

#[test]
fn unit_omission_null_and_text_keep_existing_policy() {
    let mut f = model();
    assert!(findings(&f).is_empty());
    f["unit"] = Value::Null;
    assert!(findings(&f).is_empty());
    f["unit"] = json!("N");
    assert!(findings(&f).contains(&"unit_mismatch"));
    let mut rated = json!({"name":"limits.rated-force","assertedBy":"manufacturer-declared",
        "basis":"declared","value":10});
    assert!(findings(&rated).is_empty());
    rated["unit"] = json!("N");
    assert!(findings(&rated).is_empty());
    for bad in [Value::Null, json!("mm/s"), json!(42), json!({})] {
        rated["unit"] = bad;
        assert!(findings(&rated).contains(&"unit_mismatch"));
    }
}

#[test]
fn shallow_oversize_and_escape_expansion_are_bounded() {
    let mut f = model();
    f["extra"] = json!("x".repeat(65_536));
    assert!(findings(&f).contains(&"input_byte_limit"));
    f["extra"] = json!("\u{0001}".repeat(11_000));
    assert!(findings(&f).contains(&"input_byte_limit"));
    f["extra"] = json!("safe");
    assert!(findings(&f).is_empty()); // Resource bounds do not ban unknown fields.
}

#[test]
fn unrecognized_nested_fields_are_preflighted() {
    let mut f = model();
    let mut extra = Value::Null;
    for _ in 0..20 {
        extra = Value::Array(vec![extra]);
    }
    f["extra"] = extra;
    assert!(findings(&f).contains(&"input_depth_limit"));
}

#[test]
fn broad_small_values_have_a_separate_node_budget() {
    let mut f = model();
    f["extra"] = Value::Array(vec![Value::Null; 5_000]);
    assert!(findings(&f).contains(&"input_node_limit"));
}

#[test]
fn oversized_unknown_keys_are_bounded_too() {
    let mut f = model();
    f.as_object_mut()
        .unwrap()
        .insert("k".repeat(65_536), Value::Null);
    assert!(findings(&f).contains(&"input_byte_limit"));
}

#[test]
fn exact_byte_boundary_counts_json_escaping_and_utf8() {
    use pask_wire::proposed_constraints::MAX_FACT_JSON_BYTES;
    let mut f = model();
    f["extra"] = json!("");
    let overhead = serde_json::to_vec(&f).unwrap().len();
    f["extra"] = json!("x".repeat(MAX_FACT_JSON_BYTES - overhead));
    assert_eq!(serde_json::to_vec(&f).unwrap().len(), MAX_FACT_JSON_BYTES);
    assert!(findings(&f).is_empty());
    f["extra"] = json!("x".repeat(MAX_FACT_JSON_BYTES - overhead + 1));
    assert!(findings(&f).contains(&"input_byte_limit"));
    for text in ["é中🙂", "\"\\\n\r\t\u{0008}\u{000c}\u{0000}"] {
        let mut s = text.repeat(100);
        f["extra"] = json!(s);
        let remaining = MAX_FACT_JSON_BYTES - serde_json::to_vec(&f).unwrap().len();
        s.push_str(&"x".repeat(remaining));
        f["extra"] = json!(s);
        assert_eq!(serde_json::to_vec(&f).unwrap().len(), MAX_FACT_JSON_BYTES);
        assert!(findings(&f).is_empty());
        s.push('x');
        f["extra"] = json!(s);
        assert!(findings(&f).contains(&"input_byte_limit"));
    }
}

#[test]
fn exact_depth_and_node_boundaries_include_extra_values() {
    use pask_wire::proposed_constraints::{MAX_FACT_DEPTH, MAX_FACT_NODES};
    let mut f = model();
    let mut extra = Value::Null;
    for _ in 1..MAX_FACT_DEPTH {
        extra = Value::Array(vec![extra]);
    }
    f["extra"] = extra.clone();
    assert!(findings(&f).is_empty());
    f["extra"] = Value::Array(vec![extra]);
    assert!(findings(&f).contains(&"input_depth_limit"));
    f["extra"] = Value::Array(vec![Value::Null; MAX_FACT_NODES - 6]);
    assert!(findings(&f).is_empty());
    f["extra"] = Value::Array(vec![Value::Null; MAX_FACT_NODES - 5]);
    assert!(findings(&f).contains(&"input_node_limit"));
}

#[test]
fn numeric_extra_values_do_not_require_whole_value_serialization() {
    let mut f = model();
    f["extra"] = json!([i64::MIN, u64::MAX, 1.25, 1e308, -1e-308, true, false, null]);
    assert!(findings(&f).is_empty());
}
