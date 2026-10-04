// SPDX-License-Identifier: Apache-2.0
//! Proposed local constraints only. Not a content-proof or Receipt verifier.
//! Generated technical table has separately recorded origin; not release material.
use alloc::{string::String, vec::Vec};
use core::fmt::{self, Write};
use serde::Serialize;
use serde_json::Value;

pub struct FactRule {
    pub name: &'static str,
    pub parties: &'static [&'static str],
    pub bases: &'static [&'static str],
    pub forbidden: &'static [(&'static str, &'static str)],
    pub unit: Option<&'static str>,
    pub evidence_required: bool,
    pub remote_required: bool,
    pub value_json: &'static str,
}
include!("proposed_vocabulary_generated.rs");

mod vocabulary_v2 {
    use super::FactRule;
    include!("proposed_vocabulary_v2_generated.rs");
}

/// Local candidate vocabulary identity. This is independent of the PSER profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vocabulary {
    V1,
    V2,
}

impl Vocabulary {
    #[must_use]
    pub const fn version(self) -> &'static str {
        match self {
            Self::V1 => "wilder.pser-content-vocab/1",
            Self::V2 => "wilder.pser-content-vocab/2",
        }
    }

    /// SHA-256 of the exact retained vocabulary file, without a prefix.
    #[must_use]
    pub const fn sha256(self) -> &'static str {
        match self {
            Self::V1 => VOCAB_SHA256,
            Self::V2 => vocabulary_v2::VOCAB_SHA256,
        }
    }

    #[must_use]
    pub fn facts(self) -> &'static [FactRule] {
        match self {
            Self::V1 => FACTS,
            Self::V2 => vocabulary_v2::FACTS,
        }
    }

    #[must_use]
    pub fn fact(self, name: &str) -> Option<&'static FactRule> {
        self.facts().iter().find(|rule| rule.name == name)
    }

    #[must_use]
    pub const fn parties(self) -> &'static [&'static str] {
        match self {
            Self::V1 => PARTIES,
            Self::V2 => vocabulary_v2::PARTIES,
        }
    }

    #[must_use]
    pub const fn bases(self) -> &'static [&'static str] {
        match self {
            Self::V1 => BASES,
            Self::V2 => vocabulary_v2::BASES,
        }
    }

    const fn party_bases(self) -> &'static [(&'static str, &'static [&'static str])] {
        match self {
            Self::V1 => PARTY_BASES,
            Self::V2 => vocabulary_v2::PARTY_BASES,
        }
    }

    const fn evidence_required(self) -> &'static [&'static str] {
        match self {
            Self::V1 => EVIDENCE_REQUIRED,
            Self::V2 => vocabulary_v2::EVIDENCE_REQUIRED,
        }
    }
}

/// Select only by the exact full digest from the verified content header.
/// Unknown, unprefixed or differently cased values never fall back to v1.
#[must_use]
pub fn vocabulary_for_digest(digest: &str) -> Option<Vocabulary> {
    let hash = digest.strip_prefix("sha256:")?;
    [Vocabulary::V1, Vocabulary::V2]
        .into_iter()
        .find(|vocabulary| vocabulary.sha256() == hash)
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConstraintResult {
    Permitted,
    AttributionForbidden,
    UnknownFact,
    UnknownParty,
    UnknownBasis,
}

/// Legacy entry point: its table and behavior remain v1.
pub fn classify(name: &str, party: &str, basis: &str) -> ConstraintResult {
    classify_with_vocabulary(Vocabulary::V1, name, party, basis)
}

pub fn classify_with_vocabulary(
    vocabulary: Vocabulary,
    name: &str,
    party: &str,
    basis: &str,
) -> ConstraintResult {
    let Some(f) = vocabulary.fact(name) else {
        return ConstraintResult::UnknownFact;
    };
    if !vocabulary.parties().contains(&party) {
        return ConstraintResult::UnknownParty;
    }
    if !vocabulary.bases().contains(&basis) {
        return ConstraintResult::UnknownBasis;
    }
    let global = vocabulary
        .party_bases()
        .iter()
        .find(|(p, _)| *p == party)
        .is_some_and(|(_, bs)| bs.contains(&basis));
    if f.parties.contains(&party)
        && f.bases.contains(&basis)
        && global
        && !f.forbidden.contains(&(party, basis))
    {
        ConstraintResult::Permitted
    } else {
        ConstraintResult::AttributionForbidden
    }
}

/// Separate caller-supplied evidence-processing state, never inferred from a label.
#[derive(Clone, Copy)]
pub enum EvidenceState {
    NotResolved,
    Unavailable,
    IntegrityMatched,
    IntegrityFailed,
}

#[derive(Debug, Serialize)]
pub struct ConstraintReport {
    pub schema: &'static str,
    pub classification: ConstraintResult,
    pub metadata_findings: Vec<&'static str>,
    pub evidence: &'static str,
    pub comparison: &'static str,
    pub receipt_binding: &'static str,
    pub attributed_party_authenticated: bool,
}

/// Maximum compact JSON size accepted by this local helper.
pub const MAX_FACT_JSON_BYTES: usize = 65_536;
/// All Value nodes count, including unrecognized extra fields; keys count as bytes.
pub const MAX_FACT_NODES: usize = 4_096;
/// Root is depth zero. Children of both objects and arrays increase depth.
pub const MAX_FACT_DEPTH: usize = 16;

// Preflight counts compact JSON bytes without constructing a serialized copy.
// Recursion is capped before descending and iteration stops at the first budget
// violation. Number Display writes to this bounded counter, not a new String.
#[derive(Default)]
struct Budget {
    bytes: usize,
    nodes: usize,
}
impl Budget {
    fn bytes(&mut self, n: usize) -> Result<(), &'static str> {
        if n > MAX_FACT_JSON_BYTES - self.bytes {
            return Err("input_byte_limit");
        }
        self.bytes += n;
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<(), &'static str> {
        if s.len() > MAX_FACT_JSON_BYTES - self.bytes {
            return Err("input_byte_limit");
        }
        self.bytes(2)?;
        for b in s.bytes() {
            self.bytes(match b {
                b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
                0..=31 => 6,
                _ => 1,
            })?;
        }
        Ok(())
    }
    fn value(&mut self, v: &Value, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_FACT_DEPTH {
            return Err("input_depth_limit");
        }
        if self.nodes == MAX_FACT_NODES {
            return Err("input_node_limit");
        }
        self.nodes += 1;
        match v {
            Value::Null => self.bytes(4),
            Value::Bool(b) => self.bytes(if *b { 4 } else { 5 }),
            Value::Number(n) => write!(self, "{n}").map_err(|_| "input_byte_limit"),
            Value::String(s) => self.string(s),
            Value::Array(a) => {
                self.bytes(2)?;
                for (i, child) in a.iter().enumerate() {
                    self.bytes(usize::from(i != 0))?;
                    self.value(child, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(m) => {
                self.bytes(2)?;
                for (i, (key, child)) in m.iter().enumerate() {
                    self.bytes(usize::from(i != 0))?;
                    self.string(key)?;
                    self.bytes(1)?;
                    self.value(child, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}
impl Write for Budget {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.bytes(s.len()).map_err(|_| fmt::Error)
    }
}

/// Validates local fact metadata after bounded preflight of the supplied Value.
///
/// Limits: 65,536 compact JSON bytes, 4,096 Value nodes and depth 16 (root zero),
/// including unknown fields. No whole-input serialization/allocation is performed.
/// Early rejection may report the first exceeded bound, not every exceeded bound.
/// This API does NOT bound the caller's prior parsing, allocation or later drop
/// of a Value. Callers accepting raw untrusted bytes must separately bound their
/// input and parser. Unknown properties within the budgets remain permitted.
///
/// Classification describes only the name/party/basis relation; a permitted
/// classification does not override metadata/resource findings. No key, receipt,
/// salt proof, byte resolver or party authentication is invoked.
pub fn inspect_fact(fact: &Value, evidence: EvidenceState) -> ConstraintReport {
    inspect_fact_with_vocabulary(Vocabulary::V1, fact, evidence)
}

/// Explicit-table variant. The caller must authenticate the content-header digest
/// before using its selected vocabulary; this helper does not verify a proof.
/// V2 recognizes opt-in closed objects. V1 schemas and open behavior are unchanged.
pub fn inspect_fact_with_vocabulary(
    vocabulary: Vocabulary,
    fact: &Value,
    evidence: EvidenceState,
) -> ConstraintReport {
    let name = fact["name"].as_str().unwrap_or("");
    let party = fact["assertedBy"].as_str().unwrap_or("");
    let basis = fact["basis"].as_str().unwrap_or("");
    let mut r = ConstraintReport {
        schema: "pask-local-constraint-report/0",
        classification: classify_with_vocabulary(vocabulary, name, party, basis),
        metadata_findings: Vec::new(),
        evidence: "NOT_EVALUATED",
        comparison: "NOT_RUN",
        receipt_binding: "NOT_EVALUATED",
        attributed_party_authenticated: false,
    };
    if !fact.is_object() {
        r.metadata_findings.push("malformed_fact");
        return r;
    }
    if let Err(finding) = Budget::default().value(fact, 0) {
        r.metadata_findings.push(finding);
        return r;
    }
    let Some(rule) = vocabulary.fact(name) else {
        return r;
    };
    let schema: Value = serde_json::from_str(rule.value_json).expect("generated schema");
    if !fact
        .get("value")
        .is_some_and(|v| value_matches(&schema, v, 0, vocabulary == Vocabulary::V2))
    {
        r.metadata_findings.push("invalid_typed_value");
    }
    match fact.get("unit") {
        None => {}
        Some(Value::Null) if rule.unit.is_none() => {}
        Some(Value::String(s)) if rule.unit == Some(s.as_str()) => {}
        _ => r.metadata_findings.push("unit_mismatch"),
    }
    match fact.get("remoteOrigin") {
        Some(v)
            if rule.remote_required
                && v.as_str()
                    .is_some_and(|s| ["on-site", "off-site", "undetermined"].contains(&s)) => {}
        None if !rule.remote_required => {}
        _ => r.metadata_findings.push("remote_origin_constraint"),
    }
    let required = rule.evidence_required || vocabulary.evidence_required().contains(&party);
    let reference = fact.get("evidence").filter(|v| !v.is_null());
    let declared = match reference {
        Some(Value::Object(m)) if m.len() == 1 => {
            m.get("digest")
                .and_then(Value::as_str)
                .is_some_and(is_digest)
                || m.get("pointer")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty() && s.len() <= 2048)
        }
        _ => false,
    };
    if required && reference.is_none() {
        r.metadata_findings
            .push("required_evidence_reference_missing");
    } else if reference.is_some() && !declared {
        r.metadata_findings.push("malformed_evidence_reference");
    }
    r.evidence = if !declared {
        "NO_VALID_REFERENCE"
    } else {
        match evidence {
            EvidenceState::NotResolved => "NOT_RESOLVED",
            EvidenceState::Unavailable => "REFERENCED_BYTES_UNAVAILABLE",
            EvidenceState::IntegrityMatched => "CALLER_REPORTED_INTEGRITY_MATCH",
            EvidenceState::IntegrityFailed => "INTEGRITY_FAILURE",
        }
    };
    r
}

fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn value_matches(s: &Value, v: &Value, depth: usize, closed_objects: bool) -> bool {
    if depth > 8 {
        return false;
    }
    if v.is_null() {
        return s["nullable"] == true;
    }
    match s["type"].as_str() {
        Some("boolean") => v.is_boolean(),
        Some("integer") => {
            let Some(n) = v.as_i64() else {
                return false;
            };
            !v.is_f64()
                && s["minimum"].as_i64().is_none_or(|x| n >= x)
                && s["maximum"].as_i64().is_none_or(|x| n <= x)
        }
        Some("string") => {
            let Some(t) = v.as_str() else {
                return false;
            };
            s["maxLength"]
                .as_u64()
                .is_none_or(|n| t.chars().count() as u64 <= n)
                && s["enum"]
                    .as_array()
                    .is_none_or(|a| a.iter().any(|x| x == t))
                && s["pattern"].as_str().is_none_or(|p| pattern_matches(p, t))
        }
        Some("map-of-integer") => v.as_object().is_some_and(|m| {
            m.len() <= 256 && m.values().all(|x| x.as_i64().is_some() && !x.is_f64())
        }),
        Some("object") => {
            let Some(m) = v.as_object() else {
                return false;
            };
            if m.len() > 256 {
                return false;
            }
            let Some(props) = s["properties"].as_object() else {
                return false;
            };
            // Only the new dialect interprets an explicit closed-object rule.
            // Never delete an unknown member before validation or commitment.
            if closed_objects
                && s.get("additionalProperties") == Some(&Value::Bool(false))
                && m.keys().any(|key| !props.contains_key(key))
            {
                return false;
            }
            s["required"].as_array().is_none_or(|a| {
                a.iter()
                    .all(|k| k.as_str().is_some_and(|key| m.contains_key(key)))
            }) && props.iter().all(|(k, spec)| {
                m.get(k)
                    .is_none_or(|x| value_matches(spec, x, depth + 1, closed_objects))
            })
        }
        _ => false,
    }
}

fn pattern_matches(p: &str, t: &str) -> bool {
    if p == "^[A-Za-z0-9:_.-]+$" {
        return !t.is_empty()
            && t.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b":_.-".contains(&c));
    }
    if p == "^sha256:[0-9a-f]{64}$" {
        return is_digest(t);
    }
    // JSON-decoded regex contains one backslash: the decimal point is literal.
    // Match its ASCII form only, not calendar validity or real event time.
    if p == r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$" {
        let a = t.as_bytes();
        if a.len() != 24 {
            return false;
        }
        return a.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            23 => *c == b'Z',
            _ => c.is_ascii_digit(),
        });
    }
    false
}

pub fn report_json(fact: &Value, evidence: EvidenceState) -> String {
    serde_json::to_string(&inspect_fact(fact, evidence)).expect("report serializes")
}

/// Explicit table selected by the caller; legacy report_json stays v1.
pub fn report_json_with_vocabulary(
    vocabulary: Vocabulary,
    fact: &Value,
    evidence: EvidenceState,
) -> String {
    serde_json::to_string(&inspect_fact_with_vocabulary(vocabulary, fact, evidence))
        .expect("report serializes")
}
