// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Tests for the top-level `issuerAffiliation` member and the three rules that
//! govern it.
//!
//! The three rules are separate requirements and are tested separately:
//!
//! 1. The three named values stay distinguishable from each other, and in
//!    particular `NOT_DISCLOSED` is never read as `INDEPENDENT`.
//! 2. An unrecognised value is surfaced as unrecognised. It is not read as
//!    `AFFILIATED` and it is not normalised to `NOT_DISCLOSED`.
//! 3. Receipts presented as one chain MUST agree about the value. Where they
//!    disagree the presentation is refused, and the disagreement is named.
//!
//! Rule 1 carries the whole point of the member. A relying party reading a
//! receipt wants to know whether the party that signed it has an interest in
//! what it says. Three answers are possible: they are related, they are not
//! related, and nobody has said. Folding the third into the second turns
//! silence into a denial, which is a claim nobody made and which flatters the
//! Issuer. That is the one collapse this member exists to prevent, so it is
//! asserted directly against a committed vector rather than inferred from a
//! round trip.
//!
//! Rule 2 is tested at the level of what a caller can observe rather than at
//! the level of "does it parse", for the same reason as `ackProvenance`: a
//! lenient parser that quietly mapped an unknown string onto `NOT_DISCLOSED`
//! also parses, and would pass a parse-only test while the promise was broken.
//!
//! Rule 2 is not fail-closed and rule 3 is. That is not an inconsistency. An
//! unrecognised value appears on a single receipt read after the fact, often by
//! somebody reconstructing an event months later, and refusing the record there
//! destroys the reconstruction the record exists to serve. A disagreement
//! inside a chain is different in kind: it is not a value the reader cannot
//! interpret, it is two values that cannot both be true, and the tempting
//! resolution (take the newer one) is exactly how a chain gets relabelled after
//! the fact by appending one receipt. Refusing costs a verifier one
//! presentation and leaves every individual receipt intact and readable.

use std::{fs, path::PathBuf};

use pask_wire::{Error, IssuerAffiliation, Payload, testvectors::MINIMAL_VALID_JCS};

/// Returns the canonical JCS vector with `issuerAffiliation` set to `value`.
fn with_affiliation(value: &str) -> String {
    let from = r#""issuerAffiliation":"NOT_DISCLOSED""#;
    assert!(
        MINIMAL_VALID_JCS.contains(from),
        "the canonical vector carries issuerAffiliation"
    );
    MINIMAL_VALID_JCS.replace(from, &format!(r#""issuerAffiliation":"{value}""#))
}

/// Parses a vector whose `chain.hash` is stale because a member was replaced.
///
/// Production normalization recomputes `chain.hash` over the modified content,
/// so these tests exercise the deserializer and `validate` rather than tripping
/// over a digest that no longer matches. That is a property of the test
/// construction, not a relaxation of any rule.
fn parse_mutated(json: &str) -> pask_wire::Result<Payload> {
    Payload::from_json_for_production(json.as_bytes())
}

fn load_vector(name: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/issuer-affiliation")
        .join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&text).expect("the vector is JSON")
}

fn parse_receipts(vector: &serde_json::Value, expected_len: usize, why: &str) -> Vec<Payload> {
    let receipts = vector["receipts"]
        .as_array()
        .expect("the vector carries a receipts array");
    assert_eq!(receipts.len(), expected_len, "{why}");
    receipts
        .iter()
        .map(|receipt| {
            let bytes = serde_json::to_vec(receipt).expect("receipt re-serializes");
            Payload::from_json(&bytes)
                .expect("every receipt in this vector is well-formed and must be accepted")
        })
        .collect()
}

#[test]
fn the_three_named_values_each_round_trip_to_their_exact_wire_string() {
    for (wire, expected) in [
        ("AFFILIATED", IssuerAffiliation::Affiliated),
        ("INDEPENDENT", IssuerAffiliation::Independent),
        ("NOT_DISCLOSED", IssuerAffiliation::NotDisclosed),
    ] {
        let payload = parse_mutated(&with_affiliation(wire))
            .unwrap_or_else(|error| panic!("{wire} is a conforming value: {error}"));
        assert_eq!(payload.issuer_affiliation(), &expected);
        assert!(!payload.issuer_affiliation().is_unrecognized());
        assert_eq!(payload.issuer_affiliation().as_wire_str(), wire);

        let reserialized = String::from_utf8(payload.to_jcs().expect("payload serializes"))
            .expect("JCS output is UTF-8");
        assert!(
            reserialized.contains(&format!(r#""issuerAffiliation":"{wire}""#)),
            "{wire} must survive a round trip as itself"
        );
    }
}

#[test]
fn the_three_named_values_are_distinguishable_from_each_other() {
    let affiliated = parse_mutated(&with_affiliation("AFFILIATED")).expect("parses");
    let independent = parse_mutated(&with_affiliation("INDEPENDENT")).expect("parses");
    let not_disclosed = parse_mutated(&with_affiliation("NOT_DISCLOSED")).expect("parses");

    assert_ne!(
        affiliated.issuer_affiliation(),
        independent.issuer_affiliation()
    );
    assert_ne!(
        independent.issuer_affiliation(),
        not_disclosed.issuer_affiliation(),
        "silence about a relationship is not a claim of independence"
    );
    assert_ne!(
        affiliated.issuer_affiliation(),
        not_disclosed.issuer_affiliation()
    );
}

#[test]
fn not_disclosed_is_reported_as_undisclosed_and_never_as_independent() {
    let payload = parse_mutated(&with_affiliation("NOT_DISCLOSED")).expect("parses");
    assert!(payload.issuer_affiliation().is_not_disclosed());
    assert_ne!(
        payload.issuer_affiliation(),
        &IssuerAffiliation::Independent,
        "reading NOT_DISCLOSED as INDEPENDENT states something nobody said"
    );
    assert!(
        !payload.issuer_affiliation().is_unrecognized(),
        "NOT_DISCLOSED is a named member of the closed set, not an unknown value"
    );
}

#[test]
fn an_unrecognized_value_is_surfaced_as_unrecognized_and_keeps_its_string() {
    for wire in ["SAME_GROUP", "affiliated", "AFFILIATED_PARENT", ""] {
        let payload = parse_mutated(&with_affiliation(wire))
            .unwrap_or_else(|error| panic!("{wire:?} must be accepted, not refused: {error}"));
        let value = payload.issuer_affiliation();

        assert!(
            value.is_unrecognized(),
            "{wire:?} is outside the closed set and must be surfaced as such"
        );
        assert_eq!(
            value.as_wire_str(),
            wire,
            "the original string must be preserved for the reader"
        );
        assert_ne!(value, &IssuerAffiliation::Affiliated);
        assert_ne!(value, &IssuerAffiliation::Independent);
        assert_ne!(
            value,
            &IssuerAffiliation::NotDisclosed,
            "normalising an unknown value onto NOT_DISCLOSED hides that a \
             producer wrote something the profile does not define"
        );
        assert!(
            !value.is_not_disclosed(),
            "an unknown value is not the same as a declared refusal to state"
        );
    }
}

#[test]
fn a_missing_member_is_refused_rather_than_defaulted() {
    // The member is REQUIRED. A payload that omits it is not a payload with an
    // undisclosed affiliation, it is a payload that does not conform, and
    // defaulting it would let a producer ship silence while the record showed a
    // deliberate declaration.
    let without = MINIMAL_VALID_JCS.replace(r#""issuerAffiliation":"NOT_DISCLOSED","#, "");
    assert!(
        !without.contains("issuerAffiliation"),
        "the member was actually removed"
    );
    let error = parse_mutated(&without).expect_err("a missing REQUIRED member is refused");
    assert!(matches!(error, Error::Json(_)), "got {error:?}");
}

/// First negative conformance vector: the collapse the member exists to stop.
#[test]
fn not_disclosed_is_not_independent_vector_is_committed_and_holds() {
    let vector = load_vector("not-disclosed-is-not-independent.json");
    assert_eq!(
        vector["expect"], "distinguishable",
        "this vector asserts a distinction, not an acceptance or a rejection"
    );

    let parsed = parse_receipts(
        &vector,
        2,
        "one NOT_DISCLOSED receipt and one INDEPENDENT receipt",
    );
    let not_disclosed = parsed[0].issuer_affiliation();
    let independent = parsed[1].issuer_affiliation();

    assert_eq!(not_disclosed, &IssuerAffiliation::NotDisclosed);
    assert_eq!(independent, &IssuerAffiliation::Independent);
    assert_ne!(
        not_disclosed, independent,
        "reporting an undisclosed relationship as independence is the failure \
         this vector names"
    );
}

/// Second negative conformance vector: the chain-consistency rule.
#[test]
fn changed_within_a_chain_vector_is_committed_and_is_refused() {
    let vector = load_vector("changed-within-a-chain.json");
    assert_eq!(
        vector["expect"], "rejected",
        "this vector asserts a rejection at the chain level"
    );

    let parsed = parse_receipts(
        &vector,
        2,
        "one INDEPENDENT receipt at seq 0 and one AFFILIATED receipt at seq 1",
    );
    assert_eq!(
        parsed[0].issuer_affiliation(),
        &IssuerAffiliation::Independent
    );
    assert_eq!(
        parsed[1].issuer_affiliation(),
        &IssuerAffiliation::Affiliated
    );

    // Every other chain-level check passes, so the rejection can only be the
    // consistency rule. Asserting this is what makes the vector a test of the
    // new rule rather than an accidental retest of seq contiguity.
    assert_eq!(parsed[1].chain_seq(), parsed[0].chain_seq() + 1);
    assert_eq!(parsed[1].chain_prev_hash(), Some(parsed[0].chain_hash()));

    let error = pask_wire::verify_chain(&parsed)
        .expect_err("a chain whose members disagree about issuerAffiliation is refused");
    assert!(
        matches!(
            error,
            Error::Validation("issuerAffiliation changed within a chain")
        ),
        "the error must name the disagreement rather than any other rule: got {error:?}"
    );
}

#[test]
fn a_chain_that_agrees_about_affiliation_still_verifies() {
    // The consistency rule must not make chains harder to build. This is the
    // control for the vector above.
    let vector = load_vector("changed-within-a-chain.json");
    let receipts = vector["receipts"]
        .as_array()
        .expect("the vector carries a receipts array");

    let mut head = receipts[0].clone();
    head["issuerAffiliation"] = serde_json::json!("AFFILIATED");
    let head_bytes = serde_json::to_vec(&head).expect("receipt re-serializes");
    let head = Payload::from_json_for_production(&head_bytes).expect("head parses");

    let mut second = receipts[1].clone();
    second["chain"]["prevHash"] = serde_json::json!(head.chain_hash());
    let second_bytes = serde_json::to_vec(&second).expect("receipt re-serializes");
    let second = Payload::from_json_for_production(&second_bytes).expect("second parses");

    assert_eq!(head.issuer_affiliation(), second.issuer_affiliation());
    pask_wire::verify_chain(&[head, second]).expect("an agreeing chain verifies");
}
