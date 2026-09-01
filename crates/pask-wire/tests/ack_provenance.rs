// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Tests for `adapter.ackProvenance` and the two rules that govern it.
//!
//! The two rules are separate requirements and are tested separately, because
//! folding them together is the specific mistake this member exists to avoid:
//!
//! 1. The three named values stay distinguishable from each other.
//! 2. An unrecognised value is surfaced as unrecognised. It is not read as
//!    `THIRD_PARTY` and it is not normalised to `NONE`.
//!
//! Rule 2 is deliberately tested at the level of what a caller can observe,
//! not at the level of "does it parse". A parse-only test would pass while the
//! promise was broken, because a lenient parser that quietly mapped an unknown
//! string onto `NONE` also parses.
//!
//! The reason rule 2 is not fail-closed: this member is a descriptive property
//! of a record read after the engagement has already happened, frequently by
//! somebody reconstructing an event months later. Refusing the record there
//! destroys the reconstruction the record exists to serve. That is the opposite
//! of the cost function under an enumeration feeding a pre-action gate, where
//! refusing costs only availability.

use std::{fs, path::PathBuf};

use pask_wire::{AckProvenance, Error, Payload, SPEC_VERSION, testvectors::MINIMAL_VALID_JCS};

/// Returns the canonical JCS vector with `ackProvenance` set to `value`.
fn with_provenance(value: &str) -> String {
    let from = r#""ackProvenance":"THIRD_PARTY""#;
    assert!(
        MINIMAL_VALID_JCS.contains(from),
        "the canonical vector carries ackProvenance"
    );
    MINIMAL_VALID_JCS.replace(from, &format!(r#""ackProvenance":"{value}""#))
}

/// Parses a vector whose `chain.hash` is stale because a member was replaced.
///
/// `from_json_for_production` recomputes `chain.hash` over the modified content,
/// so these tests exercise the deserializer and `validate` rather than tripping
/// over a digest that no longer matches. Production normalization is the only
/// entry point that can accept a vector built this way; that is a property of
/// the test construction, not a relaxation of any rule.
fn parse_mutated(json: &str) -> pask_wire::Result<Payload> {
    Payload::from_json_for_production(json.as_bytes())
}

#[test]
fn the_three_named_values_each_round_trip_to_their_exact_wire_string() {
    for (wire, expected) in [
        ("THIRD_PARTY", AckProvenance::ThirdParty),
        ("ISSUER_ASSERTED", AckProvenance::IssuerAsserted),
        ("NONE", AckProvenance::NoAcknowledgement),
    ] {
        let payload = parse_mutated(&with_provenance(wire))
            .unwrap_or_else(|error| panic!("{wire} is a conforming value: {error}"));
        assert_eq!(payload.adapter_ack_provenance(), &expected);
        assert!(!payload.adapter_ack_provenance().is_unrecognized());
        assert_eq!(payload.adapter_ack_provenance().as_wire_str(), wire);

        let reserialized = String::from_utf8(payload.to_jcs().expect("payload serializes"))
            .expect("JCS output is UTF-8");
        assert!(
            reserialized.contains(&format!(r#""ackProvenance":"{wire}""#)),
            "{wire} must survive a round trip as itself"
        );
    }
}

#[test]
fn the_three_named_values_are_distinguishable_from_each_other() {
    let third_party = parse_mutated(&with_provenance("THIRD_PARTY")).expect("parses");
    let issuer = parse_mutated(&with_provenance("ISSUER_ASSERTED")).expect("parses");
    let none = parse_mutated(&with_provenance("NONE")).expect("parses");

    assert_ne!(
        third_party.adapter_ack_provenance(),
        issuer.adapter_ack_provenance(),
        "an Issuer-authored acknowledgement must not read as a third-party one"
    );
    assert_ne!(
        issuer.adapter_ack_provenance(),
        none.adapter_ack_provenance()
    );
    assert_ne!(
        third_party.adapter_ack_provenance(),
        none.adapter_ack_provenance()
    );
}

#[test]
fn an_unrecognized_value_is_accepted_and_reported_as_unrecognized() {
    let payload = parse_mutated(&with_provenance("READ_BACK_CONFIRMED"))
        .expect("an unrecognised value must not cause the record to be refused");

    assert!(
        payload.adapter_ack_provenance().is_unrecognized(),
        "the reader must be told the value is outside the closed set"
    );
    assert_eq!(
        payload.adapter_ack_provenance(),
        &AckProvenance::Unrecognized("READ_BACK_CONFIRMED".to_owned()),
        "the original string must be preserved, not merely flagged"
    );
}

#[test]
fn an_unrecognized_value_is_not_read_as_third_party_and_not_normalized_to_none() {
    // This is rule 2 stated as a test, in the same words the rule uses.
    for value in [
        "READ_BACK_CONFIRMED",
        "CONFIRMED",
        "third_party",
        "",
        "NONE ",
        "UNKNOWN",
    ] {
        let payload = parse_mutated(&with_provenance(value))
            .unwrap_or_else(|error| panic!("{value:?} must still parse: {error}"));
        let observed = payload.adapter_ack_provenance();

        assert_ne!(
            observed,
            &AckProvenance::ThirdParty,
            "{value:?} was read as THIRD_PARTY, which claims an independent party \
             acknowledged the write-in when nothing in the record says so"
        );
        assert_ne!(
            observed,
            &AckProvenance::NoAcknowledgement,
            "{value:?} was normalised to NONE, which manufactures a positive claim \
             that the operations layer returned nothing"
        );
        assert!(
            observed.is_unrecognized(),
            "{value:?} must surface as unrecognised"
        );
    }
}

#[test]
fn lowercase_and_whitespace_variants_are_unrecognized_rather_than_repaired() {
    // No case folding and no trimming. A near-miss is a different value, and
    // repairing it silently would put a value in the record that the producer
    // never emitted.
    for value in ["third_party", "ThirdParty", " THIRD_PARTY", "THIRD_PARTY "] {
        let payload = parse_mutated(&with_provenance(value)).expect("parses");
        assert!(
            payload.adapter_ack_provenance().is_unrecognized(),
            "{value:?} must not be repaired into THIRD_PARTY"
        );
        assert_eq!(payload.adapter_ack_provenance().as_wire_str(), value);
    }
}

#[test]
fn an_unrecognized_value_round_trips_byte_identically() {
    // The payload is signed over its JCS serialization. A fallback that
    // discarded the string, or re-serialised it as anything else, would
    // invalidate the signature on every receipt carrying one. This is why
    // `#[serde(other)]` is not used.
    let value = "READ_BACK_CONFIRMED";
    let payload = parse_mutated(&with_provenance(value)).expect("parses");
    let jcs = String::from_utf8(payload.to_jcs().expect("serializes")).expect("UTF-8");

    assert!(jcs.contains(&format!(r#""ackProvenance":"{value}""#)));

    let reparsed = Payload::from_json(jcs.as_bytes())
        .expect("the re-serialized form is itself a valid receipt");
    assert_eq!(
        reparsed.adapter_ack_provenance(),
        payload.adapter_ack_provenance()
    );
    assert_eq!(
        String::from_utf8(reparsed.to_jcs().expect("serializes")).expect("UTF-8"),
        jcs,
        "a second round trip must be a fixed point"
    );
}

#[test]
fn the_member_is_required() {
    let without = MINIMAL_VALID_JCS.replace(r#""ackProvenance":"THIRD_PARTY","#, "");
    assert!(!without.contains("ackProvenance"));
    let error = parse_mutated(&without).expect_err("ackProvenance is REQUIRED at 0.4");
    assert!(
        matches!(error, Error::Json(_)),
        "a missing required member is a parse failure, got {error:?}"
    );
}

#[test]
fn a_null_value_is_rejected_rather_than_treated_as_an_absence() {
    // `null` is not a member of the value space and is not a synonym for NONE.
    // Reading it as NONE would be the same manufactured-absence collapse that
    // rule 2 prohibits, arriving by a different route.
    let nulled = MINIMAL_VALID_JCS.replace(
        r#""ackProvenance":"THIRD_PARTY""#,
        r#""ackProvenance":null"#,
    );
    let error = parse_mutated(&nulled).expect_err("null is not a value in the closed set");
    assert!(matches!(error, Error::Json(_)), "got {error:?}");
}

#[test]
fn a_receipt_from_an_unimplemented_revision_reports_the_version_not_a_missing_member() {
    // The two-stage parse. A 0.3 receipt carries no ackProvenance, so a
    // one-stage parse would report a missing member and send an operator
    // looking for a malformed producer. The useful answer is that the receipt
    // is from a revision this build does not implement.
    let older = MINIMAL_VALID_JCS
        .replace(SPEC_VERSION, "wilder.pser/0.3")
        .replace(r#""ackProvenance":"THIRD_PARTY","#, "");

    let error = parse_mutated(&older).expect_err("0.3 is not implemented by this build");
    assert_eq!(
        error,
        Error::Validation("unsupported spec version"),
        "the version must be diagnosed before the member shape"
    );
    let rendered = format!("{error}");
    assert!(
        !rendered.contains("ackProvenance"),
        "the diagnosis must not blame the member: {rendered}"
    );
}

#[test]
fn a_future_revision_is_also_reported_as_a_version_problem() {
    let newer = MINIMAL_VALID_JCS.replace(SPEC_VERSION, "wilder.pser/0.5");
    let error = parse_mutated(&newer).expect_err("0.5 is not implemented by this build");
    assert_eq!(error, Error::Validation("unsupported spec version"));
}

#[test]
fn a_document_too_malformed_to_carry_a_version_still_gets_its_real_diagnosis() {
    // The version probe must not swallow unrelated failures. A document with no
    // usable `spec` member is not a version problem and the caller should see
    // whatever is actually wrong with it.
    let error = Payload::from_json(b"{").expect_err("not JSON");
    assert!(matches!(error, Error::Json(_)), "got {error:?}");
}

/// The negative conformance vector, named to mirror the convention in
/// `verify-failure-mode-ref-v1`'s `collapsed-unreachable-and-invalid`.
///
/// The failure it pins is a collapse, not a rejection: a verifier that reported
/// an unrecognised value and an explicit `NONE` as the same state would pass a
/// parse-only test and still be wrong. The vector holds both receipts so the
/// distinction is asserted directly rather than inferred.
#[test]
fn collapsed_unrecognized_and_none_vector_is_committed_and_holds() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/ack-provenance/collapsed-unrecognized-and-NONE.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    let vector: serde_json::Value = serde_json::from_str(&text).expect("the vector is JSON");

    assert_eq!(
        vector["expect"], "distinguishable",
        "this vector asserts a distinction, not an acceptance or a rejection"
    );

    let receipts = vector["receipts"]
        .as_array()
        .expect("the vector carries a receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "one unrecognised receipt and one NONE receipt"
    );

    let mut parsed = Vec::new();
    for receipt in receipts {
        let bytes = serde_json::to_vec(receipt).expect("receipt re-serializes");
        parsed.push(
            Payload::from_json(&bytes)
                .expect("both receipts in this vector are well-formed and must be accepted"),
        );
    }

    let unrecognized = parsed[0].adapter_ack_provenance();
    let none = parsed[1].adapter_ack_provenance();

    assert!(unrecognized.is_unrecognized());
    assert_eq!(none, &AckProvenance::NoAcknowledgement);
    assert_ne!(
        unrecognized, none,
        "collapsing an unrecognised value into NONE is the failure this vector names"
    );
    assert_ne!(unrecognized, &AckProvenance::ThirdParty);
}
