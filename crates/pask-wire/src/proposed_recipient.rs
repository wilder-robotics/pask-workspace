// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! LOCAL PROPOSAL: compose a supplied-key statement check, retained-content
//! membership, vocabulary constraints and caller-presented evidence. No I/O,
//! provisioning, SCITT Receipt verification, hardware appraisal or final PSER
//! conformance is supplied. This is a single-statement, typed-presentation API.
//!
//! The expected content root is obtained ONLY from the checked 0.7 payload.
//! Evidence digests and recorded values are obtained ONLY from verified fact
//! disclosures. A caller cannot substitute a second expected root/value. The
//! caller's key, local objects and policy remain unauthenticated inputs.

use alloc::{string::String, vec::Vec};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use serde_json::Value;

use crate::proposed_constraints::{
    ConstraintReport, ConstraintResult, EvidenceState, Vocabulary, inspect_fact_with_vocabulary,
    vocabulary_for_digest,
};
use crate::proposed_content::{
    ContentError, ContentHeader, DisclosedFact, MAX_FACTS, verify_content_disclosures,
};
use crate::proposed_evidence::{
    EvidenceIntegrity, EvidenceReference, MAX_PRESENTED_EVIDENCE_BYTES, PresentedEvidence,
    ScalarComparison, ValueComparison, inspect_presented_evidence,
};
use crate::{
    CONTENT_TYPE, CONTENT_TYPE_06, CONTENT_TYPE_07, Error, InspectionFinding, InspectionStatus,
    SPEC_VERSION_07, TransparentStatementPolicy, inspect_transparent_statement, sha256_prefixed,
    verify_ed25519,
};

pub const REPORT_SCHEMA: &str = "pask-local-recipient-report/1";
pub const POLICY_ID: &str = "pask-local-content-disclosure-policy/1";
pub const MAX_STATEMENT_BYTES: usize = 1_048_576;
pub const MAX_PAYLOAD_DEPTH: usize = 32;
pub const MAX_LOCAL_OBJECTS: usize = 256;
pub const MAX_TOTAL_LOCAL_OBJECT_BYTES: usize = 1_048_576;
pub const MAX_CONTEXT_BYTES: usize = 8_192;

/// These are borrowed typed inputs, not a transport-format definition. The
/// original canonical record bytes remain intact; callers bound their own
/// wrapper parsing/allocation before making this call.
#[derive(Clone, Copy)]
pub struct ContentPresentation<'a> {
    pub header: ContentHeader<'a>,
    pub fact_count: u32,
    pub disclosures: &'a [DisclosedFact<'a>],
}

/// Index a locally supplied object by a claimed digest. Every selected object
/// is still hashed against the digest inside the verified fact. No pointer is
/// fetched and no digest is derived from the object's bytes to invent a binding.
#[derive(Clone, Copy)]
pub struct LocalEvidenceObject<'a> {
    pub digest: &'a str,
    pub availability: PresentedEvidence<'a>,
}

/// Exact comparison with labels inside the verified statement, not evidence
/// that these physical site/engagement identities are independently authentic.
#[derive(Clone, Copy)]
pub struct ExpectedContext<'a> {
    pub site_id: &'a str,
    pub engagement_id: &'a str,
}

/// A deliberately narrow disclosure policy, NOT full application acceptance.
/// Comparison is an explicit caller-selected interpretation, not a standardized
/// binding from every vocabulary fact to the unitless-scalar evidence format.
#[derive(Default)]
pub struct RecipientPolicy<'a> {
    pub expected_context: Option<ExpectedContext<'a>>,
    pub require_presented_content: bool,
    pub require_all_committed_slots: bool,
    pub required_fact_names: &'a [&'a str],
    pub compare_unitless_scalars: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PresentationState {
    NotEvaluated,
    LegacyProfileUnsupported,
    NullCommitment,
    NotPresented,
    Invalid,
    Unsupported,
    EmptyCommittedBlock,
    SelectedSlots,
    AllCommittedSlots,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactProvenance {
    EvidenceLinked,
    AttributionOnly,
    AttributionForbidden,
    FactUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedAvailability {
    Disclosed,
    NotDisclosedUnproven,
    AbsentFromCommittedBlock,
    NoBlockCommitted,
    CommittedBlockNotPresented,
    /// Name is known to this build, but absent from this block's vocabulary.
    UnsupportedByVocabulary,
    NotEvaluated,
}

#[derive(Debug, Serialize)]
pub struct FactEvidenceReport {
    pub reference: InspectionFinding,
    pub lookup: InspectionFinding,
    pub integrity: Option<EvidenceIntegrity>,
    pub checked_bytes: usize,
    pub comparison: ValueComparison,
    pub comparison_reason: &'static str,
    pub comparator: Option<&'static str>,
    pub expected_digest_from_disclosed_fact: bool,
    pub object_origin: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FactConstraintReport {
    pub classification: ConstraintResult,
    pub metadata_findings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct DisclosedFactReport {
    pub index: u32,
    pub name: String,
    pub asserted_by: String,
    pub basis: String,
    pub constraint: FactConstraintReport,
    pub evidence: FactEvidenceReport,
    /// None for malformed/unsupported metadata or failed evidence integrity.
    /// Such failures MUST NOT be silently relabeled ATTRIBUTION_ONLY or ABSENT.
    pub provenance: Option<FactProvenance>,
    pub provenance_reason: &'static str,
    pub attribution_bound_to_checked_statement: bool,
    pub attributed_party_authenticated: bool,
}

#[derive(Debug, Serialize)]
pub struct RequestedFactReport {
    pub name: String,
    pub availability: RequestedAvailability,
    pub provenance: Option<FactProvenance>,
    pub reason: &'static str,
    pub semantic_absence_established: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct FindingCounts {
    pub evidence_linked: usize,
    pub attribution_only: usize,
    pub attribution_forbidden: usize,
    pub invalid_or_unsupported_metadata: usize,
    pub evidence_failures: usize,
    pub value_contradictions: usize,
    pub values_not_comparable: usize,
}

/// No global `valid`/`accepted` Boolean is exported. A passed disclosure policy
/// does not override a forbidden attribution, evidence failure or contradiction.
#[derive(Debug, Serialize)]
pub struct RecipientReport {
    pub schema: &'static str,
    pub policy_id: &'static str,
    pub policy_configuration: InspectionFinding,
    pub outer_structure: InspectionFinding,
    pub outer_required_claims: InspectionFinding,
    pub outer_support: InspectionFinding,
    /// Combined existing payload/header validation and supplied-key signature
    /// check. Failure need not mean a signature comparison was actually reached.
    pub statement_check: InspectionFinding,
    pub statement_digest: Option<String>,
    pub actual_verification_key: Option<[u8; 32]>,
    pub verification_key_origin: &'static str,
    pub profile: Option<String>,
    pub profile_support: InspectionFinding,
    pub site_id: Option<String>,
    pub engagement_id: Option<String>,
    pub context_comparison: InspectionFinding,
    pub content_digest: Option<String>,
    pub content_digest_source: &'static str,
    pub presentation_state: PresentationState,
    pub membership: InspectionFinding,
    pub vocabulary: InspectionFinding,
    pub content_binding: InspectionFinding,
    pub claimed_fact_count: Option<u32>,
    pub count_bound_to_checked_statement: bool,
    pub ignored_presentation: bool,
    pub local_object_inventory: InspectionFinding,
    pub facts: Vec<DisclosedFactReport>,
    pub requested_facts: Vec<RequestedFactReport>,
    pub disclosure_policy: InspectionFinding,
    pub summary: FindingCounts,
    pub issuer_identity_trust: InspectionFinding,
    pub registration: InspectionFinding,
    pub chain_contiguity: InspectionFinding,
    pub latest_or_complete_history: InspectionFinding,
    pub hardware_appraisal: InspectionFinding,
    pub real_world_clock: InspectionFinding,
    pub application_acceptance: InspectionFinding,
    pub full_profile: InspectionFinding,
}

fn finding(status: InspectionStatus, code: &'static str) -> InspectionFinding {
    InspectionFinding {
        status,
        code,
        detail: "Only the named local check and supplied inputs; not a global acceptance verdict.",
        evidence_refs: alloc::vec!["exact_statement_disclosures_and_local_inputs"],
    }
}
fn passed(code: &'static str) -> InspectionFinding {
    finding(InspectionStatus::Passed, code)
}
fn failed(code: &'static str) -> InspectionFinding {
    finding(InspectionStatus::Failed, code)
}
fn unestablished(code: &'static str) -> InspectionFinding {
    finding(InspectionStatus::Unestablished, code)
}
fn skipped(code: &'static str) -> InspectionFinding {
    finding(InspectionStatus::NotEvaluated, code)
}
fn unsupported(code: &'static str) -> InspectionFinding {
    finding(InspectionStatus::Unsupported, code)
}
fn is_passed(f: &InspectionFinding) -> bool {
    f.status == InspectionStatus::Passed
}

fn empty_report() -> RecipientReport {
    RecipientReport {
        schema: REPORT_SCHEMA,
        policy_id: POLICY_ID,
        policy_configuration: skipped("not_started"),
        outer_structure: skipped("not_started"),
        outer_required_claims: skipped("not_started"),
        outer_support: skipped("not_started"),
        statement_check: skipped("statement_prerequisites_not_established"),
        statement_digest: None,
        actual_verification_key: None,
        verification_key_origin: "CALLER_SUPPLIED_UNAUTHENTICATED",
        profile: None,
        profile_support: skipped("statement_not_checked"),
        site_id: None,
        engagement_id: None,
        context_comparison: skipped("statement_not_checked"),
        content_digest: None,
        content_digest_source: "NOT_EVALUATED",
        presentation_state: PresentationState::NotEvaluated,
        membership: skipped("content_not_evaluated"),
        vocabulary: skipped("content_not_evaluated"),
        content_binding: skipped("membership_not_established"),
        claimed_fact_count: None,
        count_bound_to_checked_statement: false,
        ignored_presentation: false,
        local_object_inventory: skipped("not_started"),
        facts: Vec::new(),
        requested_facts: Vec::new(),
        disclosure_policy: skipped("no_disclosure_policy_selected"),
        summary: FindingCounts::default(),
        issuer_identity_trust: unestablished("key_to_identity_authentication_not_supplied"),
        registration: skipped("scitt_receipts_not_verified_here"),
        chain_contiguity: skipped("single_statement_no_contiguity_check"),
        latest_or_complete_history: unestablished("presenter_may_withhold_history"),
        hardware_appraisal: skipped("hardware_evidence_not_appraised"),
        real_world_clock: unestablished("recorded_time_is_not_independently_authenticated_time"),
        application_acceptance: unestablished("disclosure_policy_is_not_full_application_policy"),
        full_profile: unestablished("full_pser_conformance_not_established"),
    }
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 71
        && digest.starts_with("sha256:")
        && digest.as_bytes()[7..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn policy_configuration(policy: &RecipientPolicy<'_>) -> InspectionFinding {
    if policy.required_fact_names.len() > MAX_FACTS {
        return failed("required_fact_limit");
    }
    for (i, name) in policy.required_fact_names.iter().enumerate() {
        // Configuration accepts names known to either supported table. Actual
        // availability is assessed per block after its committed table is known.
        if name.len() > 128
            || ![Vocabulary::V1, Vocabulary::V2]
                .iter()
                .any(|vocabulary| vocabulary.fact(name).is_some())
        {
            return failed("required_fact_name_not_supported");
        }
        if policy.required_fact_names[..i].contains(name) {
            return failed("duplicate_required_fact");
        }
    }
    if let Some(context) = policy.expected_context {
        for text in [context.site_id, context.engagement_id] {
            if text.is_empty() || text.len() > MAX_CONTEXT_BYTES {
                return failed("expected_context_limit_or_empty");
            }
        }
    }
    passed("bounded_local_policy")
}

fn object_inventory(objects: &[LocalEvidenceObject<'_>]) -> InspectionFinding {
    if objects.len() > MAX_LOCAL_OBJECTS {
        return failed("local_object_count_limit");
    }
    let mut total = 0;
    for (index, object) in objects.iter().enumerate() {
        if !valid_digest(object.digest) {
            return failed("local_object_digest_malformed");
        }
        if objects[..index]
            .iter()
            .any(|other| other.digest == object.digest)
        {
            return failed("duplicate_local_object_digest");
        }
        if let PresentedEvidence::Bytes(bytes) = object.availability {
            if bytes.len() > MAX_PRESENTED_EVIDENCE_BYTES
                || bytes.len() > MAX_TOTAL_LOCAL_OBJECT_BYTES - total
            {
                return failed("local_object_byte_limit");
            }
            total += bytes.len();
        }
    }
    passed("local_inventory_framing_not_byte_integrity")
}

// The existing outer inspector bounds CBOR structure and embedded protected
// headers. This additional pass bounds payload JSON nesting BEFORE Payload's
// parser allocates a tree. It is not a second JSON syntax validator.
fn payload_depth_within_limit(bytes: &[u8]) -> bool {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_PAYLOAD_DEPTH {
                        return false;
                    }
                }
                b'}' | b']' => {
                    let Some(next) = depth.checked_sub(1) else {
                        return false;
                    };
                    depth = next;
                }
                _ => {}
            }
        }
    }
    depth == 0 && !quoted && !escaped
}

fn statement_error(error: Error) -> InspectionFinding {
    match error {
        Error::Signature => failed("supplied_key_signature_failed"),
        Error::Header(_) => failed("implemented_protected_header_check_failed"),
        Error::NonCanonicalPayload => failed("payload_not_canonical"),
        Error::Validation(_) => failed("implemented_payload_check_failed"),
        Error::Json(_) | Error::Jcs(_) => failed("payload_json_or_canonicalization_failed"),
        Error::Cose(_) | Error::Receipt(_) => failed("statement_or_receipt_container_failed"),
    }
}

fn content_error(error: ContentError) -> InspectionFinding {
    match error {
        ContentError::UnsupportedConstruction => unsupported("content_construction"),
        ContentError::UnsupportedNumber => unsupported("content_numeric_domain"),
        ContentError::InvalidScope => failed("content_scope"),
        ContentError::InvalidDigest => failed("content_digest_spelling"),
        ContentError::FactCountLimit => failed("content_count_limit"),
        ContentError::FactByteLimit => failed("content_fact_byte_limit"),
        ContentError::TotalByteLimit => failed("content_total_byte_limit"),
        ContentError::JsonDepthLimit => failed("content_json_depth_limit"),
        ContentError::InvalidFactJson => failed("content_fact_json"),
        ContentError::NonCanonicalFact => failed("content_fact_not_canonical"),
        ContentError::InvalidFactShape => failed("content_fact_shape"),
        ContentError::InvalidFactName => failed("content_fact_name"),
        ContentError::DuplicateFactName => failed("content_duplicate_name"),
        ContentError::ReusedSalt => failed("content_reused_visible_salt"),
        ContentError::UnknownFactName => failed("content_unknown_disclosure_name"),
        ContentError::InvalidIndex => failed("content_invalid_index"),
        ContentError::InvalidProofLength => failed("content_invalid_proof_length"),
        ContentError::RootMismatch => failed("content_root_mismatch"),
        ContentError::DuplicateDisclosure => failed("content_duplicate_disclosure"),
        ContentError::UnorderedNames => failed("content_unordered_names"),
    }
}

fn reference_from_fact(fact: &Value) -> Result<EvidenceReference<'_>, ()> {
    match fact.get("evidence") {
        None | Some(Value::Null) => Ok(EvidenceReference::Absent),
        Some(Value::Object(map)) if map.len() == 1 => {
            if let Some(Value::String(digest)) = map.get("digest") {
                return Ok(EvidenceReference::Sha256(digest));
            }
            if let Some(Value::String(pointer)) = map.get("pointer")
                && !pointer.is_empty()
                && pointer.len() <= 2048
            {
                return Ok(EvidenceReference::PointerOnly);
            }
            Err(())
        }
        _ => Err(()),
    }
}

fn evidence_for_fact(
    vocabulary: Vocabulary,
    fact: &Value,
    constraint: &ConstraintReport,
    objects: &[LocalEvidenceObject<'_>],
    inventory_ok: bool,
    compare: bool,
) -> FactEvidenceReport {
    let mut out = FactEvidenceReport {
        reference: skipped("reference_not_inspected"),
        lookup: skipped("no_bound_digest_to_look_up"),
        integrity: None,
        checked_bytes: 0,
        comparison: ValueComparison::NotRun,
        comparison_reason: "prerequisite_not_established",
        comparator: None,
        expected_digest_from_disclosed_fact: false,
        object_origin: "CALLER_PRESENTED_UNAUTHENTICATED",
    };
    let Ok(reference) = reference_from_fact(fact) else {
        out.reference = failed("malformed_fact_evidence_reference");
        return out;
    };
    let presentation = match reference {
        EvidenceReference::Absent => {
            out.reference = unestablished("no_evidence_reference");
            PresentedEvidence::NotRequested
        }
        EvidenceReference::PointerOnly => {
            out.reference = unsupported("pointer_has_no_immutable_evidence_binding");
            PresentedEvidence::NotRequested
        }
        EvidenceReference::Sha256(digest) => {
            if !valid_digest(digest) {
                out.reference = failed("malformed_fact_evidence_digest");
                return out;
            }
            out.reference = passed("digest_inside_verified_fact_disclosure");
            out.expected_digest_from_disclosed_fact = true;
            if !inventory_ok {
                out.lookup = failed("local_object_inventory_invalid");
                return out;
            }
            match objects.iter().find(|object| object.digest == digest) {
                Some(object) => {
                    out.lookup = passed("exact_digest_key_selected_not_yet_hashed");
                    object.availability
                }
                None => {
                    out.lookup = unestablished("digest_object_not_presented");
                    PresentedEvidence::Unavailable
                }
            }
        }
    };
    let name = fact.get("name").and_then(Value::as_str).unwrap_or("");
    let rule = vocabulary.fact(name);
    // The vocabulary supplies semantic units even if an optional unit member is
    // omitted. Never treat an omitted unit on a unit-bearing fact as unitless.
    let effective_unit = rule.and_then(|rule| rule.unit);
    let comparison = if compare && rule.is_some() && constraint.metadata_findings.is_empty() {
        fact.get("value").map(|value| ScalarComparison {
            recorded_value: value,
            declared_unit: effective_unit,
        })
    } else {
        None
    };
    let checked = inspect_presented_evidence(reference, presentation, comparison);
    out.integrity = Some(checked.integrity);
    out.checked_bytes = checked.checked_bytes;
    out.comparison = checked.comparison;
    out.comparison_reason = if compare && comparison.is_none() {
        "comparison_requires_supported_well_formed_fact"
    } else {
        checked.comparison_reason
    };
    out.comparator = checked.comparator;
    out
}

fn fact_provenance(
    constraint: &ConstraintReport,
    evidence: &FactEvidenceReport,
) -> (Option<FactProvenance>, &'static str) {
    match constraint.classification {
        ConstraintResult::AttributionForbidden => {
            return (
                Some(FactProvenance::AttributionForbidden),
                "fact_party_basis_combination_forbidden",
            );
        }
        ConstraintResult::Permitted => {}
        _ => return (None, "fact_party_or_basis_not_supported"),
    }
    if !constraint.metadata_findings.is_empty() {
        return (None, "fact_metadata_failed");
    }
    match evidence.integrity {
        Some(EvidenceIntegrity::Matched) => (
            Some(FactProvenance::EvidenceLinked),
            "permitted_committed_fact_with_checked_evidence_bytes_not_party_authentication",
        ),
        Some(
            EvidenceIntegrity::NoReference
            | EvidenceIntegrity::DigestBindingUnavailable
            | EvidenceIntegrity::NotRequested
            | EvidenceIntegrity::BytesUnavailable,
        ) => (
            Some(FactProvenance::AttributionOnly),
            "permitted_committed_attribution_without_checked_evidence_bytes",
        ),
        _ => (None, "evidence_integrity_or_inventory_failed"),
    }
}

fn count_findings(report: &mut RecipientReport) {
    for fact in &report.facts {
        match fact.provenance {
            Some(FactProvenance::EvidenceLinked) => report.summary.evidence_linked += 1,
            Some(FactProvenance::AttributionOnly) => report.summary.attribution_only += 1,
            Some(FactProvenance::AttributionForbidden) => report.summary.attribution_forbidden += 1,
            _ => {}
        }
        if !fact.constraint.metadata_findings.is_empty()
            || matches!(
                fact.constraint.classification,
                ConstraintResult::UnknownFact
                    | ConstraintResult::UnknownParty
                    | ConstraintResult::UnknownBasis
            )
        {
            report.summary.invalid_or_unsupported_metadata += 1;
        }
        if fact.evidence.reference.status == InspectionStatus::Failed
            || fact.evidence.lookup.status == InspectionStatus::Failed
            || matches!(
                fact.evidence.integrity,
                Some(
                    EvidenceIntegrity::Mismatch
                        | EvidenceIntegrity::MalformedDigest
                        | EvidenceIntegrity::InputLimitExceeded
                )
            )
        {
            report.summary.evidence_failures += 1;
        }
        match fact.evidence.comparison {
            ValueComparison::Contradiction => report.summary.value_contradictions += 1,
            ValueComparison::NotComparable => report.summary.values_not_comparable += 1,
            _ => {}
        }
    }
}

fn required_fact_reports(
    report: &mut RecipientReport,
    policy: &RecipientPolicy<'_>,
    vocabulary: Option<Vocabulary>,
) {
    for name in policy.required_fact_names {
        let (availability, reason) = if vocabulary.is_some_and(|v| v.fact(name).is_none()) {
            (
                RequestedAvailability::UnsupportedByVocabulary,
                "required_fact_not_supported_by_committed_vocabulary",
            )
        } else if report.facts.iter().any(|fact| fact.name == *name) {
            (
                RequestedAvailability::Disclosed,
                "fact_was_disclosed_constraints_remain_separate",
            )
        } else {
            match report.presentation_state {
                PresentationState::NullCommitment => (
                    RequestedAvailability::NoBlockCommitted,
                    "receipt_declares_no_content_not_physical_absence",
                ),
                PresentationState::NotPresented => (
                    RequestedAvailability::CommittedBlockNotPresented,
                    "committed_content_not_presented",
                ),
                PresentationState::EmptyCommittedBlock | PresentationState::AllCommittedSlots
                    if is_passed(&report.vocabulary) =>
                {
                    (
                        RequestedAvailability::AbsentFromCommittedBlock,
                        "absent_from_presented_committed_block_not_semantic_absence",
                    )
                }
                PresentationState::SelectedSlots if is_passed(&report.vocabulary) => (
                    RequestedAvailability::NotDisclosedUnproven,
                    "subset_does_not_prove_absence",
                ),
                _ => (
                    RequestedAvailability::NotEvaluated,
                    "prerequisite_failed_or_unsupported",
                ),
            }
        };
        let provenance = match availability {
            RequestedAvailability::Disclosed
            | RequestedAvailability::UnsupportedByVocabulary
            | RequestedAvailability::NotEvaluated => None,
            _ => Some(FactProvenance::FactUnavailable),
        };
        report.requested_facts.push(RequestedFactReport {
            name: String::from(*name),
            availability,
            provenance,
            reason,
            semantic_absence_established: false,
        });
    }
}

fn disclosure_policy(report: &RecipientReport, policy: &RecipientPolicy<'_>) -> InspectionFinding {
    if !policy.require_presented_content
        && !policy.require_all_committed_slots
        && policy.required_fact_names.is_empty()
    {
        return skipped("no_disclosure_policy_selected");
    }
    if !is_passed(&report.statement_check)
        || !is_passed(&report.profile_support)
        || (policy.expected_context.is_some() && !is_passed(&report.context_comparison))
    {
        return unestablished("disclosure_prerequisites_not_established");
    }
    match report.presentation_state {
        PresentationState::NullCommitment => {
            return failed("policy_requires_content_but_null_declared");
        }
        PresentationState::Invalid => return failed("invalid_presentation_cannot_satisfy_policy"),
        PresentationState::Unsupported => return unestablished("unsupported_content_mechanism"),
        PresentationState::NotEvaluated | PresentationState::LegacyProfileUnsupported => {
            return unestablished("presentation_not_evaluated");
        }
        PresentationState::NotPresented => return unestablished("committed_content_not_presented"),
        _ => {}
    }
    if !is_passed(&report.vocabulary) {
        return unestablished("vocabulary_not_supported");
    }
    if report
        .requested_facts
        .iter()
        .any(|fact| fact.availability == RequestedAvailability::UnsupportedByVocabulary)
    {
        return unestablished("required_fact_not_supported_by_committed_vocabulary");
    }
    if report
        .requested_facts
        .iter()
        .any(|fact| fact.availability == RequestedAvailability::AbsentFromCommittedBlock)
    {
        return failed("required_fact_not_in_committed_block");
    }
    if (policy.require_all_committed_slots
        && report.presentation_state == PresentationState::SelectedSlots)
        || report
            .requested_facts
            .iter()
            .any(|fact| fact.availability != RequestedAvailability::Disclosed)
    {
        return unestablished("required_disclosure_not_established");
    }
    passed("disclosure_requirements_only_not_fact_truth_or_application_acceptance")
}

fn finish(report: RecipientReport, policy: &RecipientPolicy<'_>) -> RecipientReport {
    finish_with_vocabulary(report, policy, None)
}

fn finish_with_vocabulary(
    mut report: RecipientReport,
    policy: &RecipientPolicy<'_>,
    vocabulary: Option<Vocabulary>,
) -> RecipientReport {
    if is_passed(&report.policy_configuration) {
        required_fact_reports(&mut report, policy, vocabulary);
        report.disclosure_policy = disclosure_policy(&report, policy);
    }
    count_findings(&mut report);
    report
}

/// Compose reviewed helpers on one original Signed/Transparent Statement.
///
/// No second expected content root, fact value or evidence digest is accepted:
/// each comes from successfully checked preceding bytes. Only the Ed25519 path
/// is supplied here. Legacy statements may pass their existing signature/parser
/// path but are explicitly unsupported for this proposed 0.7 content operation.
///
/// Bounds: statement <=1 MiB, inherited outer CBOR preflight and payload JSON
/// depth <=32; inherited content limits; at most 256 evidence objects, <=64 KiB
/// each and <=1 MiB total; at most 256 unique required names known to this build.
/// Each block must support its required names under its own committed vocabulary.
/// These bound this operation, not caller input acquisition/allocation/disposal. Batch proof
/// failure stops fact evaluation rather than returning misleading bound labels.
///
/// The existing outer inspector's local header/container policy is retained.
/// Encoded SCITT Receipts are structurally inspected there, NOT verified here.
/// Single-statement chain seq/hash fields are validated by the existing payload
/// path, but predecessor contiguity and latest/complete history are not checked.
#[must_use]
pub fn inspect_proposed_recipient_ed25519(
    statement: &[u8],
    key: &VerifyingKey,
    presentation: Option<ContentPresentation<'_>>,
    objects: &[LocalEvidenceObject<'_>],
    policy: &RecipientPolicy<'_>,
) -> RecipientReport {
    let mut r = empty_report();
    r.policy_configuration = policy_configuration(policy);
    if !is_passed(&r.policy_configuration) {
        return r;
    }
    r.local_object_inventory = object_inventory(objects);
    if statement.len() > MAX_STATEMENT_BYTES {
        r.outer_structure = failed("statement_byte_limit");
        return finish(r, policy);
    }
    r.statement_digest = Some(sha256_prefixed(statement));
    let outer = inspect_transparent_statement(statement, &TransparentStatementPolicy::default());
    r.outer_structure = outer.structure.clone();
    r.outer_required_claims = outer.required_claims.clone();
    r.outer_support = outer.support.clone();
    if !is_passed(&outer.structure)
        || !is_passed(&outer.selected_policy)
        || !is_passed(&outer.support)
    {
        return finish(r, policy);
    }
    match outer.protected_content_type.as_deref() {
        Some(value) if [CONTENT_TYPE, CONTENT_TYPE_06, CONTENT_TYPE_07].contains(&value) => {}
        Some(_) => {
            r.profile_support = unsupported("protected_content_type_not_supported");
            return finish(r, policy);
        }
        None => {
            r.statement_check = failed("protected_content_type_required");
            return finish(r, policy);
        }
    }
    if !outer
        .payload_bytes
        .as_deref()
        .is_some_and(payload_depth_within_limit)
    {
        r.statement_check = failed("payload_json_depth_or_framing_limit");
        return finish(r, policy);
    }
    let payload = match verify_ed25519(statement, key) {
        Ok(payload) => payload,
        Err(error) => {
            r.statement_check = statement_error(error);
            return finish(r, policy);
        }
    };
    r.statement_check = passed("implemented_statement_checks_under_supplied_key");
    r.actual_verification_key = Some(key.to_bytes());
    r.profile = Some(String::from(payload.spec()));
    r.site_id = Some(String::from(payload.site_id()));
    r.engagement_id = Some(String::from(payload.engagement_id()));
    if payload.spec() != SPEC_VERSION_07 {
        r.profile_support = unsupported("content_operation_requires_proposed_0_7");
        r.presentation_state = PresentationState::LegacyProfileUnsupported;
        r.ignored_presentation = presentation.is_some();
        return finish(r, policy);
    }
    r.profile_support = passed("proposed_0_7_content_path");
    if !is_passed(&outer.required_claims) {
        return finish(r, policy);
    }
    r.context_comparison = match policy.expected_context {
        Some(expected)
            if expected.site_id == payload.site_id()
                && expected.engagement_id == payload.engagement_id() =>
        {
            passed("exact_caller_expected_context_matches_recorded_labels")
        }
        Some(_) => failed("caller_expected_context_mismatch"),
        None => skipped("no_expected_context_supplied"),
    };
    if policy.expected_context.is_some() && !is_passed(&r.context_comparison) {
        return finish(r, policy);
    }
    let root = match payload.engagement_content_digest() {
        Some(Value::Null) => {
            r.presentation_state = PresentationState::NullCommitment;
            r.content_digest_source = "EXPLICIT_NULL_IN_CHECKED_STATEMENT";
            r.membership = skipped("no_content_root_declared");
            r.content_binding = skipped("null_does_not_prove_absence_of_facts");
            r.ignored_presentation = presentation.is_some();
            return finish(r, policy);
        }
        Some(Value::String(root)) => root,
        _ => {
            r.presentation_state = PresentationState::Invalid;
            r.content_binding = failed("checked_payload_content_member_invalid");
            return finish(r, policy);
        }
    };
    r.content_digest = Some(root.clone());
    r.content_digest_source = "CHECKED_STATEMENT_UNDER_SUPPLIED_KEY";
    let Some(presentation) = presentation else {
        r.presentation_state = PresentationState::NotPresented;
        r.membership = unestablished("committed_content_not_presented");
        return finish(r, policy);
    };
    r.claimed_fact_count = Some(presentation.fact_count);
    let membership = match verify_content_disclosures(
        root,
        &presentation.header,
        presentation.fact_count,
        presentation.disclosures,
    ) {
        Ok(report) => report,
        Err(error) => {
            r.membership = content_error(error);
            r.presentation_state = if r.membership.status == InspectionStatus::Unsupported {
                PresentationState::Unsupported
            } else {
                PresentationState::Invalid
            };
            r.content_binding = unestablished("presented_content_not_bound");
            return finish(r, policy);
        }
    };
    if membership.membership != "MATCHED" {
        r.presentation_state = PresentationState::NotPresented;
        r.membership = unestablished("no_disclosure_to_authenticate_claimed_header_or_count");
        return finish(r, policy);
    }
    r.membership = passed("disclosed_membership_matches_statement_root");
    r.content_binding = passed("disclosure_bound_to_statement_under_supplied_key");
    r.count_bound_to_checked_statement = true;
    r.presentation_state = if presentation.fact_count == 0 {
        PresentationState::EmptyCommittedBlock
    } else if presentation.disclosures.len() == presentation.fact_count as usize {
        PresentationState::AllCommittedSlots
    } else {
        PresentationState::SelectedSlots
    };
    let digest = presentation.header.vocabulary_digest;
    let Some(vocabulary) = vocabulary_for_digest(digest) else {
        r.vocabulary = unsupported("committed_vocabulary_digest_not_implemented");
        return finish(r, policy);
    };
    r.vocabulary = passed(match vocabulary {
        Vocabulary::V1 => "committed_vocabulary_matches_compiled_rule_source",
        Vocabulary::V2 => "committed_vocabulary_v2_matches_compiled_rule_source",
    });
    for disclosed in presentation.disclosures {
        // Membership already bounded and checked canonical JSON. No replacement
        // encoding is used in the proof or raw-evidence check.
        let Ok(fact) = serde_json::from_slice::<Value>(disclosed.record) else {
            r.facts.clear();
            r.presentation_state = PresentationState::Invalid;
            r.membership = failed("verified_fact_parse_inconsistency");
            r.content_binding = unestablished("fact_processing_not_established");
            return finish(r, policy);
        };
        let constraint =
            inspect_fact_with_vocabulary(vocabulary, &fact, EvidenceState::NotResolved);
        let evidence = evidence_for_fact(
            vocabulary,
            &fact,
            &constraint,
            objects,
            is_passed(&r.local_object_inventory),
            policy.compare_unitless_scalars,
        );
        let (provenance, provenance_reason) = fact_provenance(&constraint, &evidence);
        r.facts.push(DisclosedFactReport {
            index: disclosed.index,
            name: String::from(fact["name"].as_str().unwrap_or("")),
            asserted_by: String::from(fact["assertedBy"].as_str().unwrap_or("")),
            basis: String::from(fact["basis"].as_str().unwrap_or("")),
            constraint: FactConstraintReport {
                classification: constraint.classification,
                metadata_findings: constraint.metadata_findings,
            },
            evidence,
            provenance,
            provenance_reason,
            attribution_bound_to_checked_statement: true,
            attributed_party_authenticated: false,
        });
    }
    r.facts.sort_by_key(|fact| fact.index);
    finish_with_vocabulary(r, policy, Some(vocabulary))
}
