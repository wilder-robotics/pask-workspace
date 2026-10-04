// SPDX-License-Identifier: Apache-2.0
//! Local proposed evidence primitive, not a retained-content proof verifier.
//!
//! Hashes caller-presented ORIGINAL bytes against a caller-supplied SHA-256
//! reference. Optional comparison is deliberately limited to a unitless JSON
//! root scalar (Boolean, text or exact integer). No selector, unit conversion,
//! remote retrieval, evidence attestation or party authentication is provided.
//! A matching digest may coexist with a contradictory value. This report must
//! not be promoted to a bound/proven fact without the separate checks.
//!
//! The API borrows already-acquired bytes/Values. Limits protect this operation,
//! not a caller's preceding retrieval, allocation, parsing or eventual disposal.
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Local processing budget, not a new public profile-wide size rule.
pub const MAX_PRESENTED_EVIDENCE_BYTES: usize = 65_536;
/// The only comparison contract implemented here; not a vendor evidence format.
pub const SCALAR_COMPARATOR: &str = "json-root-unitless-scalar-exact/1";

/// The caller must first inspect the fact/reference declaration separately.
#[derive(Clone, Copy)]
pub enum EvidenceReference<'a> {
    Absent,
    Sha256(&'a str),
    /// A locator without an expected digest cannot establish byte integrity.
    PointerOnly,
}

/// Acquisition state is supplied by the caller, not inferred from empty bytes.
#[derive(Clone, Copy)]
pub enum PresentedEvidence<'a> {
    NotRequested,
    Unavailable,
    Bytes(&'a [u8]),
}

/// Explicit opt-in to this local comparator. `recorded_value` is NOT thereby
/// established as a value from a valid signed receipt or committed content block.
/// Any declared unit is outside this comparator: no unit binding is invented.
#[derive(Clone, Copy)]
pub struct ScalarComparison<'a> {
    pub recorded_value: &'a Value,
    pub declared_unit: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceIntegrity {
    NoReference,
    DigestBindingUnavailable,
    MalformedDigest,
    NotRequested,
    BytesUnavailable,
    InputLimitExceeded,
    Matched,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueComparison {
    Match,
    Contradiction,
    NotComparable,
    NotRun,
}

/// A scoped finding, not an overall acceptance verdict. No inspection enum,
/// legacy ConstraintReport, payload or signed input is changed by this module.
#[derive(Debug, Serialize)]
pub struct EvidenceReport {
    pub schema: &'static str,
    pub integrity: EvidenceIntegrity,
    pub checked_bytes: usize,
    pub comparison: ValueComparison,
    pub comparison_reason: &'static str,
    pub comparator: Option<&'static str>,
    pub digest_origin: &'static str,
    pub receipt_binding: &'static str,
    pub fact_constraints: &'static str,
    pub attributed_party_authenticated: bool,
}

fn decode_digest(text: &str) -> Option<[u8; 32]> {
    // Check total length before inspecting an arbitrarily long caller string.
    if text.len() != 71 || !text.starts_with("sha256:") {
        return None;
    }
    // Safe fixed-width chunks are available at the workspace's Rust 1.88 floor.
    let (pairs, []) = text.as_bytes()[7..].as_chunks::<2>() else {
        return None;
    };
    let mut digest = [0_u8; 32];
    for (output, pair) in digest.iter_mut().zip(pairs) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *output = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(digest)
}

#[derive(Clone, Copy)]
enum Scalar<'a> {
    Boolean(bool),
    Integer(i128),
    Text(&'a str),
}

fn scalar(value: &Value) -> Option<Scalar<'_>> {
    match value {
        Value::Bool(value) => Some(Scalar::Boolean(*value)),
        Value::String(value) => Some(Scalar::Text(value)),
        Value::Number(value) if value.is_i64() => value
            .as_i64()
            .map(|value| Scalar::Integer(i128::from(value))),
        Value::Number(value) if value.is_u64() => value
            .as_u64()
            .map(|value| Scalar::Integer(i128::from(value))),
        // No lossy float conversion, null inference or nested value selection.
        _ => None,
    }
}

fn compare_scalar(bytes: &[u8], request: ScalarComparison<'_>) -> (ValueComparison, &'static str) {
    if request.declared_unit.is_some() {
        return (ValueComparison::NotComparable, "unit_binding_not_supported");
    }
    if request
        .recorded_value
        .as_str()
        .is_some_and(|value| value.len() > MAX_PRESENTED_EVIDENCE_BYTES)
    {
        return (ValueComparison::NotComparable, "recorded_scalar_limit");
    }
    let Some(recorded) = scalar(request.recorded_value) else {
        return (
            ValueComparison::NotComparable,
            "recorded_scalar_not_supported",
        );
    };
    // Refuse compound roots BEFORE decoding them. Their JSON syntax, duplicate
    // keys and any hidden descendants are not validated by this scalar helper.
    let first = bytes
        .iter()
        .copied()
        .find(|byte| !matches!(*byte, b' ' | b'\n' | b'\r' | b'\t'));
    if matches!(first, Some(b'{' | b'[')) {
        return (
            ValueComparison::NotComparable,
            "compound_evidence_not_supported",
        );
    }
    let evidence: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return (ValueComparison::NotComparable, "invalid_scalar_json"),
    };
    // JSON syntax (including permitted whitespace and absence of trailing data)
    // has already been validated. serde_json represents the integer token -0
    // as a floating-point Number. Recognize only that exact original token for
    // this integer comparison; do not promote -0.0, -0e0 or other float forms.
    // This borrowed comparison view never replaces the bytes hashed above.
    let evidence = if bytes.trim_ascii() == b"-0" {
        Scalar::Integer(0)
    } else {
        let Some(value) = scalar(&evidence) else {
            return (
                ValueComparison::NotComparable,
                "evidence_scalar_not_supported",
            );
        };
        value
    };
    let equal = match (recorded, evidence) {
        (Scalar::Boolean(left), Scalar::Boolean(right)) => left == right,
        (Scalar::Integer(left), Scalar::Integer(right)) => left == right,
        (Scalar::Text(left), Scalar::Text(right)) => left == right,
        _ => return (ValueComparison::NotComparable, "scalar_type_mismatch"),
    };
    if equal {
        (ValueComparison::Match, "exact_scalar_agreement")
    } else {
        (ValueComparison::Contradiction, "exact_scalar_disagreement")
    }
}

/// Evaluate one explicit reference and one caller-presented byte object.
///
/// The raw SHA-256 check precedes any value comparison. Hash mismatch, missing
/// bytes/reference and resource failure leave comparison NOT_RUN. Unsupported
/// comparison leaves an independently successful hash check visible. Pointer-
/// only inputs cannot manufacture a digest from the same presented object.
///
/// This function never fetches a URI, dereferences a path, calls an external
/// resolver, alters a Value, validates a receipt signature, or verifies a content
/// proof. It also does not claim that selected bytes are relevant or truthful.
/// `Sha256` is a claimed reference until the caller separately verifies binding.
pub fn inspect_presented_evidence(
    reference: EvidenceReference<'_>,
    presented: PresentedEvidence<'_>,
    comparison: Option<ScalarComparison<'_>>,
) -> EvidenceReport {
    let mut report = EvidenceReport {
        schema: "pask-local-presented-evidence-report/1",
        integrity: EvidenceIntegrity::NoReference,
        checked_bytes: 0,
        comparison: ValueComparison::NotRun,
        comparison_reason: if comparison.is_some() {
            "integrity_not_established"
        } else {
            "comparison_not_requested"
        },
        comparator: comparison.map(|_| SCALAR_COMPARATOR),
        digest_origin: "CALLER_SUPPLIED_UNAUTHENTICATED",
        receipt_binding: "NOT_EVALUATED",
        fact_constraints: "NOT_EVALUATED",
        attributed_party_authenticated: false,
    };
    let expected = match reference {
        EvidenceReference::Absent => return report,
        EvidenceReference::PointerOnly => {
            report.integrity = EvidenceIntegrity::DigestBindingUnavailable;
            return report;
        }
        EvidenceReference::Sha256(text) => match decode_digest(text) {
            Some(digest) => digest,
            None => {
                report.integrity = EvidenceIntegrity::MalformedDigest;
                return report;
            }
        },
    };
    let bytes = match presented {
        PresentedEvidence::NotRequested => {
            report.integrity = EvidenceIntegrity::NotRequested;
            return report;
        }
        PresentedEvidence::Unavailable => {
            report.integrity = EvidenceIntegrity::BytesUnavailable;
            return report;
        }
        PresentedEvidence::Bytes(bytes) => bytes,
    };
    if bytes.len() > MAX_PRESENTED_EVIDENCE_BYTES {
        report.integrity = EvidenceIntegrity::InputLimitExceeded;
        return report;
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    report.checked_bytes = bytes.len();
    if actual != expected {
        report.integrity = EvidenceIntegrity::Mismatch;
        return report;
    }
    report.integrity = EvidenceIntegrity::Matched;
    if let Some(request) = comparison {
        (report.comparison, report.comparison_reason) = compare_scalar(bytes, request);
    }
    report
}
