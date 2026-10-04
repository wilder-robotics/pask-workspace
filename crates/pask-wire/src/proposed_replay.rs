// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! Local, bounded, self-contained JSON replay envelope for RECIPIENT-01.
//! This is not the PSER or content-proof wire format. Hex fields preserve the
//! original statement/fact/evidence bytes. The explicit key is outside the
//! document. The document's policy and context are unauthenticated local inputs.
//! No retrieval, discovery, service verification, or application decision occurs.

use crate::proposed_content::{
    ContentHeader, DisclosedFact, MAX_FACT_BYTES, MAX_FACTS, MAX_PROOF_HASHES,
};
use crate::proposed_evidence::{MAX_PRESENTED_EVIDENCE_BYTES, PresentedEvidence};
use crate::proposed_recipient::{
    ContentPresentation, ExpectedContext, LocalEvidenceObject, MAX_CONTEXT_BYTES,
    MAX_LOCAL_OBJECTS, MAX_STATEMENT_BYTES, RecipientPolicy, RecipientReport,
    inspect_proposed_recipient_ed25519,
};
use crate::{
    InspectionFinding, InspectionStatus, IssuerAffiliation, sha256_prefixed, verify_chain,
    verify_ed25519,
};
use alloc::{string::String, vec::Vec};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize};

pub const DOCUMENT_SCHEMA: &str = "pask-local-recipient-replay/1";
pub const REPORT_SCHEMA: &str = "pask-local-recipient-replay-report/1";
pub const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DOCUMENT_DEPTH: usize = 32;
pub const MAX_ENTRIES: usize = 16;
pub const MAX_TOTAL_DECODED_BYTES: usize = 3 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayMode {
    Single,
    Chain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    DocumentBytes,
    DocumentDepth,
    DocumentJson,
    Schema,
    EntryCount,
    ModeCardinality,
    FieldBound,
    InvalidHex,
    DecodedBudget,
    ObjectState,
    InvalidKey,
}
impl ReplayError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DocumentBytes => "document_byte_limit",
            Self::DocumentDepth => "document_depth_limit",
            Self::DocumentJson => "invalid_closed_replay_document",
            Self::Schema => "unsupported_replay_schema",
            Self::EntryCount => "entry_count_limit",
            Self::ModeCardinality => "single_mode_requires_one_entry",
            Self::FieldBound => "transport_field_limit",
            Self::InvalidHex => "invalid_lowercase_hex",
            Self::DecodedBudget => "aggregate_decoded_byte_limit",
            Self::ObjectState => "bytes_disagree_with_availability_state",
            Self::InvalidKey => "invalid_explicit_ed25519_key",
        }
    }
}

// deserialize_with (without default) requires the member even when its value
// may be null. Plain Option<T> would silently treat a missing member as None.
fn required_nullable<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(de)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    entries: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    statement_hex: String,
    #[serde(deserialize_with = "required_nullable")]
    presentation: Option<Presentation>,
    objects: Vec<Object>,
    policy: Policy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Presentation {
    construction: String,
    scope: String,
    vocabulary_digest: String,
    fact_count: u32,
    disclosures: Vec<Disclosure>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Disclosure {
    record_hex: String,
    salt_hex: String,
    index: u32,
    siblings_hex: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Availability {
    Bytes,
    Unavailable,
    NotRequested,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    digest: String,
    state: Availability,
    #[serde(deserialize_with = "required_nullable")]
    bytes_hex: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    site_id: String,
    engagement_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    #[serde(deserialize_with = "required_nullable")]
    expected_context: Option<Context>,
    require_presented_content: bool,
    require_all_committed_slots: bool,
    required_fact_names: Vec<String>,
    compare_unitless_scalars: bool,
}

struct OwnedDisclosure {
    record: Vec<u8>,
    salt: [u8; 32],
    index: u32,
    siblings: Vec<[u8; 32]>,
}
struct DecodedEntry {
    source: Entry,
    statement: Vec<u8>,
    disclosures: Vec<OwnedDisclosure>,
    objects: Vec<Option<Vec<u8>>>,
}

#[derive(Debug, Default, Serialize)]
pub struct ReplayMeasurements {
    pub document_bytes: usize,
    pub entry_count: usize,
    pub decoded_statement_bytes: usize,
    pub decoded_fact_bytes: usize,
    pub decoded_evidence_bytes: usize,
    pub decoded_salt_and_proof_bytes: usize,
    pub decoded_total_bytes: usize,
    pub note: &'static str,
}
#[derive(Debug, Serialize)]
pub struct ChainTransition {
    pub at_seq: u64,
    pub from: IssuerAffiliation,
    pub to: IssuerAffiliation,
}
#[derive(Debug, Serialize)]
pub struct ReplayChainReport {
    pub check: InspectionFinding,
    pub verified_payloads: usize,
    pub starts_at_genesis_required: bool,
    pub affiliation_changes: Vec<ChainTransition>,
    pub limitation: &'static str,
}
#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub schema: &'static str,
    pub mode: ReplayMode,
    pub input_document_digest: String,
    pub explicit_key_digest: String,
    pub key_origin: &'static str,
    pub policy_origin: &'static str,
    pub measurements: ReplayMeasurements,
    pub records: Vec<RecipientReport>,
    pub chain: ReplayChainReport,
    pub latest_or_complete_history: InspectionFinding,
    pub registration: InspectionFinding,
    pub application_acceptance: InspectionFinding,
    pub full_profile: InspectionFinding,
    pub note: &'static str,
}
fn finding(status: InspectionStatus, code: &'static str) -> InspectionFinding {
    InspectionFinding {
        status,
        code,
        detail: "Only the named local check; the supplied key and local policy are not authenticated origins.",
        evidence_refs: alloc::vec!["ordered_replay_entries"],
    }
}

fn raw_preflight(bytes: &[u8]) -> Result<(), ReplayError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ReplayError::DocumentBytes);
    }
    let (mut depth, mut in_string, mut escape) = (0usize, false, false);
    for &byte in bytes {
        if in_string {
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DOCUMENT_DEPTH {
                        return Err(ReplayError::DocumentDepth);
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(ReplayError::DocumentJson)?;
                }
                _ => {}
            }
        }
    }
    // Complete syntax, duplicate/unknown fields and trailing input are checked
    // by the subsequent closed derived deserializer, not by this lexical scan.
    Ok(())
}
fn decode_hex(text: &str, maximum: usize, total: &mut usize) -> Result<Vec<u8>, ReplayError> {
    if text.len() > maximum.saturating_mul(2) || !text.len().is_multiple_of(2) {
        return Err(ReplayError::InvalidHex);
    }
    let length = text.len() / 2;
    let updated = total
        .checked_add(length)
        .ok_or(ReplayError::DecodedBudget)?;
    if updated > MAX_TOTAL_DECODED_BYTES {
        return Err(ReplayError::DecodedBudget);
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    // Validate the complete string before allocating its decoded representation.
    if !text.bytes().all(|byte| nibble(byte).is_some()) {
        return Err(ReplayError::InvalidHex);
    }
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return Err(ReplayError::InvalidHex);
    };
    let mut output = Vec::with_capacity(length);
    for pair in pairs {
        output.push(
            (nibble(pair[0]).ok_or(ReplayError::InvalidHex)? << 4)
                | nibble(pair[1]).ok_or(ReplayError::InvalidHex)?,
        );
    }
    *total = updated;
    Ok(output)
}
fn decode_hash(text: &str, total: &mut usize) -> Result<[u8; 32], ReplayError> {
    if text.len() != 64 {
        return Err(ReplayError::InvalidHex);
    }
    decode_hex(text, 32, total)?
        .try_into()
        .map_err(|_| ReplayError::InvalidHex)
}
/// Decode one explicit lowercase 64-hex-character public verification key.
/// It is not an authenticated identity or a secret/private key.
/// # Errors
/// Returns an error for any other representation or invalid key encoding.
pub fn replay_key_from_hex(text: &str) -> Result<VerifyingKey, ReplayError> {
    let mut used = 0;
    let bytes = decode_hash(text, &mut used).map_err(|_| ReplayError::InvalidKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ReplayError::InvalidKey)
}
fn bounded_text(text: &str, maximum: usize) -> Result<(), ReplayError> {
    if text.len() > maximum {
        Err(ReplayError::FieldBound)
    } else {
        Ok(())
    }
}
fn decode_entry(source: Entry, m: &mut ReplayMeasurements) -> Result<DecodedEntry, ReplayError> {
    if source.objects.len() > MAX_LOCAL_OBJECTS
        || source.policy.required_fact_names.len() > MAX_FACTS
    {
        return Err(ReplayError::FieldBound);
    }
    for name in &source.policy.required_fact_names {
        bounded_text(name, 128)?;
    }
    if let Some(context) = &source.policy.expected_context {
        bounded_text(&context.site_id, MAX_CONTEXT_BYTES)?;
        bounded_text(&context.engagement_id, MAX_CONTEXT_BYTES)?;
    }
    let statement = decode_hex(
        &source.statement_hex,
        MAX_STATEMENT_BYTES,
        &mut m.decoded_total_bytes,
    )?;
    m.decoded_statement_bytes += statement.len();
    let mut disclosures = Vec::new();
    if let Some(p) = &source.presentation {
        bounded_text(&p.construction, 128)?;
        bounded_text(&p.scope, 128)?;
        bounded_text(&p.vocabulary_digest, 71)?;
        if p.disclosures.len() > MAX_FACTS || p.fact_count as usize > MAX_FACTS {
            return Err(ReplayError::FieldBound);
        }
        for fact in &p.disclosures {
            if fact.siblings_hex.len() > MAX_PROOF_HASHES {
                return Err(ReplayError::FieldBound);
            }
            let record = decode_hex(&fact.record_hex, MAX_FACT_BYTES, &mut m.decoded_total_bytes)?;
            m.decoded_fact_bytes += record.len();
            let salt = decode_hash(&fact.salt_hex, &mut m.decoded_total_bytes)?;
            let mut siblings = Vec::with_capacity(fact.siblings_hex.len());
            for hash in &fact.siblings_hex {
                siblings.push(decode_hash(hash, &mut m.decoded_total_bytes)?);
            }
            m.decoded_salt_and_proof_bytes += 32 * (1 + siblings.len());
            disclosures.push(OwnedDisclosure {
                record,
                salt,
                index: fact.index,
                siblings,
            });
        }
    }
    let mut objects = Vec::with_capacity(source.objects.len());
    for object in &source.objects {
        bounded_text(&object.digest, 71)?;
        let bytes = match (&object.state, &object.bytes_hex) {
            (Availability::Bytes, Some(text)) => {
                let data = decode_hex(
                    text,
                    MAX_PRESENTED_EVIDENCE_BYTES,
                    &mut m.decoded_total_bytes,
                )?;
                m.decoded_evidence_bytes += data.len();
                Some(data)
            }
            (Availability::Unavailable | Availability::NotRequested, None) => None,
            _ => return Err(ReplayError::ObjectState),
        };
        objects.push(bytes);
    }
    Ok(DecodedEntry {
        source,
        statement,
        disclosures,
        objects,
    })
}
fn inspect_entry(entry: &DecodedEntry, key: &VerifyingKey) -> RecipientReport {
    let records: Vec<_> = entry
        .disclosures
        .iter()
        .map(|f| DisclosedFact {
            record: &f.record,
            salt: f.salt,
            index: f.index,
            siblings: f.siblings.clone(),
        })
        .collect();
    let presentation = entry
        .source
        .presentation
        .as_ref()
        .map(|p| ContentPresentation {
            header: ContentHeader {
                construction: &p.construction,
                scope: &p.scope,
                vocabulary_digest: &p.vocabulary_digest,
            },
            fact_count: p.fact_count,
            disclosures: &records,
        });
    let objects: Vec<_> = entry
        .source
        .objects
        .iter()
        .zip(&entry.objects)
        .map(|(input, bytes)| {
            let availability = match &input.state {
                Availability::Bytes => PresentedEvidence::Bytes(bytes.as_deref().unwrap_or(&[])),
                Availability::Unavailable => PresentedEvidence::Unavailable,
                Availability::NotRequested => PresentedEvidence::NotRequested,
            };
            LocalEvidenceObject {
                digest: &input.digest,
                availability,
            }
        })
        .collect();
    let p = &entry.source.policy;
    let names: Vec<_> = p.required_fact_names.iter().map(String::as_str).collect();
    let policy = RecipientPolicy {
        expected_context: p.expected_context.as_ref().map(|c| ExpectedContext {
            site_id: &c.site_id,
            engagement_id: &c.engagement_id,
        }),
        require_presented_content: p.require_presented_content,
        require_all_committed_slots: p.require_all_committed_slots,
        required_fact_names: &names,
        compare_unitless_scalars: p.compare_unitless_scalars,
    };
    inspect_proposed_recipient_ed25519(&entry.statement, key, presentation, &objects, &policy)
}

/// Parse a bounded local replay envelope and evaluate its entries with the
/// unchanged RECIPIENT-01 path. Chain mode additionally invokes verify_chain
/// only on individually checked Payloads. No input is sorted or gap-filled.
/// # Errors
/// Returns a framing/resource error for malformed closed-schema JSON, bad hex,
/// or finite transport limits. Semantic verification failures are report fields,
/// not transport errors. Reports are not application acceptance decisions.
pub fn inspect_replay_document(
    bytes: &[u8],
    key: &VerifyingKey,
    mode: ReplayMode,
) -> Result<ReplayReport, ReplayError> {
    raw_preflight(bytes)?;
    let document: Document =
        serde_json::from_slice(bytes).map_err(|_| ReplayError::DocumentJson)?;
    if document.schema != DOCUMENT_SCHEMA {
        return Err(ReplayError::Schema);
    }
    if document.entries.is_empty() || document.entries.len() > MAX_ENTRIES {
        return Err(ReplayError::EntryCount);
    }
    if mode == ReplayMode::Single && document.entries.len() != 1 {
        return Err(ReplayError::ModeCardinality);
    }
    let mut measurements = ReplayMeasurements {
        document_bytes: bytes.len(),
        entry_count: document.entries.len(),
        note: "Input sizes only, not CPU, peak memory or an overall hashing-work bound; policy/header JSON is not decoded binary.",
        ..ReplayMeasurements::default()
    };
    // Parse/decode every entry before evaluating any. An invalid late envelope
    // cannot yield a successful partial batch. No external path is dereferenced.
    let mut entries = Vec::with_capacity(document.entries.len());
    for entry in document.entries {
        entries.push(decode_entry(entry, &mut measurements)?);
    }
    let reports: Vec<_> = entries
        .iter()
        .map(|entry| inspect_entry(entry, key))
        .collect();
    let mut chain = ReplayChainReport {
        check: finding(
            InspectionStatus::NotEvaluated,
            "single_mode_does_not_check_chain",
        ),
        verified_payloads: 0,
        starts_at_genesis_required: mode == ReplayMode::Chain,
        affiliation_changes: Vec::new(),
        limitation: "Checks presented sequence/hash links from genesis only; no discovery, identity continuity, same-site guarantee, latest-history or semantic completeness. Single-record findings stay scoped to their original calls.",
    };
    if mode == ReplayMode::Chain {
        if reports
            .iter()
            .any(|r| r.statement_check.status != InspectionStatus::Passed)
        {
            chain.check = finding(
                InspectionStatus::Unestablished,
                "all_statements_must_pass_before_chain_check",
            );
        } else {
            // Reuse the existing verifier to obtain its invariant-preserving
            // Payload type. This intentionally rechecks signatures; it does not
            // trust payload fields deserialized from an unsigned transport copy.
            let payloads: Result<Vec<_>, _> = entries
                .iter()
                .map(|entry| verify_ed25519(&entry.statement, key))
                .collect();
            match payloads {
                Err(_) => {
                    chain.check = finding(
                        InspectionStatus::Unestablished,
                        "payload_reverification_failed",
                    )
                }
                Ok(payloads) => {
                    chain.verified_payloads = payloads.len();
                    // Defensive ceiling before the inherited unchecked seq+1.
                    if payloads
                        .windows(2)
                        .any(|pair| pair[0].chain_seq().checked_add(1).is_none())
                    {
                        chain.check = finding(InspectionStatus::Failed, "chain_sequence_overflow");
                    } else {
                        match verify_chain(&payloads) {
                            Ok(result) => {
                                chain.check = finding(
                                    InspectionStatus::Passed,
                                    "presented_genesis_sequence_and_predecessor_hashes_checked",
                                );
                                chain.affiliation_changes = result
                                    .affiliation_changes()
                                    .iter()
                                    .map(|c| ChainTransition {
                                        at_seq: c.at_seq,
                                        from: c.from.clone(),
                                        to: c.to.clone(),
                                    })
                                    .collect();
                            }
                            Err(_) => {
                                chain.check = finding(
                                    InspectionStatus::Failed,
                                    "presented_chain_relation_failed",
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(ReplayReport {
        schema: REPORT_SCHEMA,
        mode,
        input_document_digest: sha256_prefixed(bytes),
        explicit_key_digest: sha256_prefixed(key.as_bytes()),
        key_origin: "EXPLICIT_CALLER_KEY_UNAUTHENTICATED_ORIGIN",
        policy_origin: "LOCAL_DOCUMENT_NOT_AUTHENTICATED_POLICY",
        measurements,
        records: reports,
        chain,
        latest_or_complete_history: finding(
            InspectionStatus::Unestablished,
            "valid_prefix_does_not_exclude_withheld_suffix",
        ),
        registration: finding(
            InspectionStatus::NotEvaluated,
            "no_service_receipt_verification_in_this_runner",
        ),
        application_acceptance: finding(
            InspectionStatus::Unestablished,
            "reports_are_not_acceptance",
        ),
        full_profile: finding(
            InspectionStatus::Unestablished,
            "local_proposal_not_full_conformance",
        ),
        note: "One explicit Ed25519 key for all entries; no rotation lookup. Unchanged single-record reports and an additional batch chain finding, not a global pass/fail verdict.",
    })
}
