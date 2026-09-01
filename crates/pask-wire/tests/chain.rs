// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Chain-Verifier tests, and the fixture-generation guard described in
//! `fixtures/chains/README.md`.
//!
//! The four fixture files under `fixtures/chains/` are not hand-written.
//! This file regenerates their expected content from
//! `pask_wire::canonical_example()` on every run and asserts each committed
//! file is byte-identical to what the generator produces, following the
//! pattern in `crates/pask-wire-cli/tests/draft_example_is_generated.rs`. If
//! this fails, do not hand-edit the fixture: the failure message says how to
//! regenerate it.

use std::{fs, path::PathBuf};

use pask_wire::{Payload, verify_chain};
use serde_json::{Value, json};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/chains")
}

fn placeholder_digest(nibble: char) -> String {
    format!("sha256:{}", nibble.to_string().repeat(64))
}

/// Builds one receipt JSON value from the canonical example, overriding
/// `id`, `chain.seq`, and `chain.prevHash`, then rebuilding through
/// `Payload::from_json_for_production`, which recomputes `chain.hash`
/// correctly for the result. Returns the receipt as a JCS-ordered `Value`.
fn build_receipt(base: &Value, id: &str, seq: u64, prev_hash: Option<&str>) -> Value {
    let mut receipt = base.clone();
    receipt["id"] = json!(id);
    receipt["chain"]["seq"] = json!(seq);
    receipt["chain"]["prevHash"] = match prev_hash {
        Some(hash) => json!(hash),
        None => Value::Null,
    };
    // Overwritten by from_json_for_production; the value here never matters.
    receipt["chain"]["hash"] = json!(placeholder_digest('0'));

    let bytes = serde_json::to_vec(&receipt).expect("receipt serializes");
    let payload =
        Payload::from_json_for_production(&bytes).expect("receipt is otherwise conforming");
    let jcs = payload.to_jcs().expect("payload serializes to JCS");
    serde_json::from_slice(&jcs).expect("JCS bytes are valid JSON")
}

fn chain_hash_of(receipt: &Value) -> String {
    receipt["chain"]["hash"]
        .as_str()
        .expect("receipt carries a chain.hash string")
        .to_owned()
}

fn wrap(description: &str, expect: &str, receipts: Vec<Value>) -> Value {
    json!({
        "description": description,
        "expect": expect,
        "receipts": receipts,
    })
}

fn render(value: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).expect("value serializes")
    )
}

/// Regenerates the four fixtures' expected content, keyed by filename.
///
/// The base receipt is `pask_wire::canonical_example()`: a real nine-member
/// receipt that already validates. Each fixture's receipts are derived from
/// it with only `id`, `chain.seq`, and `chain.prevHash` overridden, so that a
/// change to the wire format that the fixtures should track is caught here
/// rather than drifting silently, as the original hand-written fixtures did.
fn generate_expected() -> Vec<(&'static str, Value)> {
    let example = pask_wire::canonical_example().expect("the canonical example emits");
    let base: Value = serde_json::from_str(&example).expect("the canonical example is JSON");

    // valid-3.json: 3 receipts, seq 0,1,2, links correct -- verifies.
    let r0 = build_receipt(&base, "uuid:00000000-0000-4000-8000-0000000000a0", 0, None);
    let r0_hash = chain_hash_of(&r0);
    let r1 = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000a1",
        1,
        Some(&r0_hash),
    );
    let r1_hash = chain_hash_of(&r1);
    let r2 = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000a2",
        2,
        Some(&r1_hash),
    );
    let valid_3 = wrap(
        "Conforming three-receipt chain. Both Section 4.1 Chain-Verifier checks MUST pass.",
        "verifies",
        vec![r0, r1, r2],
    );

    // invalid-seq-gap.json: seq 0 then seq 2 -- rejected. The link from the
    // seq-0 receipt is otherwise correct, so this isolates the seq-contiguity
    // rule from the prevHash-link rule.
    let g0 = build_receipt(&base, "uuid:00000000-0000-4000-8000-0000000000b0", 0, None);
    let g0_hash = chain_hash_of(&g0);
    let g2 = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000b2",
        2,
        Some(&g0_hash),
    );
    let invalid_seq_gap = wrap(
        "Two-receipt presentation whose second member is seq 2 rather than seq 1. \
         The Chain-Verifier's seq-contiguity check MUST reject it.",
        "rejected",
        vec![g0, g2],
    );

    // invalid-broken-link.json: 3 receipts, receipt[1].prevHash altered after
    // sealing -- rejected. Altering prevHash post-hoc also makes that
    // receipt's own chain.hash stale relative to its content, which is the
    // realistic shape of in-band tampering; both checks catch it, but this
    // fixture exists to exercise the chain-level prevHash-link check.
    let b0 = build_receipt(&base, "uuid:00000000-0000-4000-8000-0000000000c0", 0, None);
    let b0_hash = chain_hash_of(&b0);
    let mut b1 = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000c1",
        1,
        Some(&b0_hash),
    );
    b1["chain"]["prevHash"] = json!(placeholder_digest('d'));
    let b1_hash = chain_hash_of(&b1);
    let b2 = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000c2",
        2,
        Some(&b1_hash),
    );
    let invalid_broken_link = wrap(
        "Three-receipt presentation whose middle receipt's prevHash was altered after \
         sealing, so it no longer matches the preceding receipt's chain.hash. Altering \
         prevHash after chain.hash was computed also makes that receipt's chain.hash stale \
         relative to its own content -- the realistic shape of in-band tampering -- so the \
         per-receipt parser rejects it (chain.hash does not match payload) before the \
         chain-level link check ever runs. Both checks catch it; this fixture exercises the \
         per-receipt one, which fires first.",
        "rejected",
        vec![b0, b1, b2],
    );

    // invalid-head-not-zero.json: head at seq 1 -- rejected. A lone receipt
    // at seq 1 with a non-null prevHash passes per-receipt validation
    // (nonzero seq requires a prevHash, which it has); the chain-level head
    // rule is the one this fixture exercises.
    let head_prev = placeholder_digest('e');
    let h0 = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000d0",
        1,
        Some(&head_prev),
    );
    let invalid_head_not_zero = wrap(
        "Single-receipt presentation whose only member carries seq 1 instead of seq 0. \
         The Chain-Verifier's head rule MUST reject it: the head of a presentation must \
         be sequence zero.",
        "rejected",
        vec![h0],
    );

    vec![
        ("valid-3.json", valid_3),
        ("invalid-seq-gap.json", invalid_seq_gap),
        ("invalid-broken-link.json", invalid_broken_link),
        ("invalid-head-not-zero.json", invalid_head_not_zero),
    ]
}

/// Asserts the committed fixtures match the generator, and can rewrite them.
///
/// Set `PASK_REGEN_FIXTURES=1` to write the generated content to disk instead of
/// asserting against it. This exists because the assertion message told the
/// reader to "regenerate it from this test's expected content" without providing
/// any way to do so, which left hand-editing as the only available route -- the
/// precise thing the message forbids. Regeneration is opt-in and never runs in
/// CI, so the guard against silent drift is unaffected.
///
/// Review the diff after regenerating. These fixtures are signed-payload inputs
/// and a change to any of them changes what conformance means.
#[test]
fn committed_fixtures_are_byte_identical_to_the_generator() {
    let regenerate = std::env::var("PASK_REGEN_FIXTURES").is_ok_and(|value| value == "1");
    let dir = fixtures_dir();
    for (name, expected) in generate_expected() {
        let expected_text = render(&expected);
        let path = dir.join(name);
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
             fixture -- regenerate it from this test's expected content.",
            path.display()
        );
    }
}

fn load_receipts(name: &str) -> Vec<Payload> {
    let path = fixtures_dir().join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    let value: Value = serde_json::from_str(&text).expect("fixture is valid JSON");
    value["receipts"]
        .as_array()
        .expect("fixture carries a receipts array")
        .iter()
        .map(|receipt| {
            let bytes = serde_json::to_vec(receipt).expect("receipt serializes");
            Payload::from_json(&bytes).expect("fixture receipt parses and validates on its own")
        })
        .collect()
}

/// Like [`load_receipts`], but returns the first per-receipt parse error
/// instead of panicking on it. Used by `invalid-broken-link.json`, whose
/// tampered receipt fails per-receipt validation before it could ever reach
/// [`verify_chain`].
fn try_load_receipts(name: &str) -> Result<Vec<Payload>, pask_wire::Error> {
    let path = fixtures_dir().join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    let value: Value = serde_json::from_str(&text).expect("fixture is valid JSON");
    value["receipts"]
        .as_array()
        .expect("fixture carries a receipts array")
        .iter()
        .map(|receipt| {
            let bytes = serde_json::to_vec(receipt).expect("receipt serializes");
            Payload::from_json(&bytes)
        })
        .collect()
}

#[test]
fn valid_three_receipt_chain_verifies() {
    let receipts = load_receipts("valid-3.json");
    assert_eq!(verify_chain(&receipts), Ok(()));
}

#[test]
fn seq_gap_is_rejected_with_the_specific_error() {
    let receipts = load_receipts("invalid-seq-gap.json");
    assert_eq!(
        verify_chain(&receipts),
        Err(pask_wire::Error::Validation("chain.seq is not contiguous"))
    );
}

/// `invalid-broken-link.json`'s tampered receipt has a `chain.hash` that is
/// stale relative to its own (altered) content -- altering `prevHash` after
/// `chain.hash` was computed does that, and is the realistic shape of
/// in-band tampering. `Payload::from_json` therefore rejects it at parse
/// time, before a caller could ever assemble a slice to hand to
/// `verify_chain`. This is not a gap in the Chain-Verifier: it is
/// per-receipt validation (already exercised by `payload.rs`'s own tests)
/// catching the defect first. Asserted here as the specific error actually
/// produced, not the chain-level error the README's older draft assumed.
#[test]
fn broken_link_fixture_is_rejected_by_per_receipt_validation_before_verify_chain_runs() {
    let result = try_load_receipts("invalid-broken-link.json");
    assert_eq!(
        result,
        Err(pask_wire::Error::Validation(
            "chain.hash does not match payload"
        ))
    );
}

/// The chain-level link check in isolation: two receipts, each individually
/// conforming (so they parse), where the second's `prevHash` was set to a
/// value that is not the first's `chain.hash`. This exercises
/// `verify_chain`'s own link check directly, without the per-receipt
/// `chain.hash` check intervening first.
#[test]
fn chain_level_link_check_rejects_a_mismatched_prev_hash_that_still_parses() {
    let receipts = load_receipts("valid-3.json");
    let example = pask_wire::canonical_example().expect("the canonical example emits");
    let base: Value = serde_json::from_str(&example).expect("the canonical example is JSON");
    let wrong_prev = placeholder_digest('f');
    let tampered_second = build_receipt(
        &base,
        "uuid:00000000-0000-4000-8000-0000000000a9",
        1,
        Some(&wrong_prev),
    );
    let bytes = serde_json::to_vec(&tampered_second).expect("receipt serializes");
    let tampered_second =
        Payload::from_json(&bytes).expect("a receipt with a self-consistent chain.hash parses");

    let presentation = [receipts[0].clone(), tampered_second];
    assert_eq!(
        verify_chain(&presentation),
        Err(pask_wire::Error::Validation(
            "chain.prevHash does not match the preceding receipt"
        ))
    );
}

#[test]
fn head_not_zero_is_rejected_with_the_specific_error() {
    let receipts = load_receipts("invalid-head-not-zero.json");
    assert_eq!(
        verify_chain(&receipts),
        Err(pask_wire::Error::Validation(
            "chain head must have seq 0 and a null prevHash"
        ))
    );
}

#[test]
fn single_receipt_chain_at_seq_zero_verifies() {
    let receipts = load_receipts("valid-3.json");
    assert_eq!(verify_chain(&receipts[..1]), Ok(()));
}

#[test]
fn empty_slice_is_rejected() {
    let receipts: Vec<Payload> = Vec::new();
    assert_eq!(
        verify_chain(&receipts),
        Err(pask_wire::Error::Validation(
            "chain must carry at least one receipt"
        ))
    );
}
