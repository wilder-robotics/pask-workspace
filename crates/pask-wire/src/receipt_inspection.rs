// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.

//! Key-free, offline Phase 1 inspection, not signature/inclusion/trust verification.
//! RFC 9942/9943 envelope and text-claim checks are separate from local support
//! and policy. This module does not coordinate attachments or change the #70 reader.
use alloc::{string::String, vec::Vec};
use coset::cbor::Value;
use serde::Serialize;

use crate::receipt_cbor::{Budget, Role};

/// Finding vocabulary shared with the proposed recipient report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionStatus {
    Passed,
    Failed,
    Unsupported,
    Unestablished,
    NotEvaluated,
}

/// One independently scoped finding. Codes are machine-readable, not acceptance badges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectionFinding {
    pub status: InspectionStatus,
    pub code: &'static str,
    pub detail: &'static str,
    pub evidence_refs: Vec<&'static str>,
}
impl InspectionFinding {
    fn new(status: InspectionStatus, code: &'static str, detail: &'static str) -> Self {
        Self {
            status,
            code,
            detail,
            evidence_refs: alloc::vec!["encoded_receipt"],
        }
    }
    fn passed() -> Self {
        Self::new(
            InspectionStatus::Passed,
            "checked",
            "Passed only this inspection dimension; unauthenticated.",
        )
    }
    fn skipped() -> Self {
        Self::new(
            InspectionStatus::NotEvaluated,
            "dependent_check_not_run",
            "A prerequisite was not established; this is not a pass.",
        )
    }
    fn later() -> Self {
        Self::new(
            InspectionStatus::NotEvaluated,
            "outside_phase1",
            "Phase 1 does not evaluate cryptography, trust, subject correspondence or application acceptance.",
        )
    }
}

/// Finite local resource ceilings, not universal RFC limits. Only Phase 1 budgets
/// live here: attachment/statement/key-attempt limits belong to later APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectionLimits {
    pub max_receipt_bytes: usize,
    pub max_protected_bytes: usize,
    pub max_signature_bytes: usize,
    pub max_cbor_nesting: usize,
    pub max_cbor_items: usize,
    pub max_map_entries: usize,
    pub max_proofs_per_receipt: usize,
    pub max_path_nodes_per_proof: usize,
    pub max_certificate_chain_length: usize,
    pub max_certificate_bytes: usize,
    pub max_claim_text_characters: usize,
    pub max_tree_size: u64,
}
impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_receipt_bytes: 1_048_576,
            max_protected_bytes: 65_536,
            max_signature_bytes: 1_024,
            max_cbor_nesting: 16,
            max_cbor_items: 4_096,
            max_map_entries: 64,
            max_proofs_per_receipt: 16,
            max_path_nodes_per_proof: 64,
            max_certificate_chain_length: 8,
            max_certificate_bytes: 65_536,
            max_claim_text_characters: 8_192,
            max_tree_size: u64::MAX,
        }
    }
}

/// Selected local policy. Support, protected kid and empty external AAD are fixed
/// to the accepted initial profile; callers cannot declare new supported semantics.
/// Limits may be tightened, never raised above the default hard ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct InspectionPolicy {
    pub strict_cross_map: bool,
    pub limits: InspectionLimits,
}
impl InspectionPolicy {
    pub const ID: &'static str = "pask71-local-ed25519-rfc9162/1";
    pub const UNDERSTOOD_CRITICAL_LABELS: &'static [i128] = &[1, 2, 4, 15, 395];
    pub const EXTERNAL_AAD: &'static [u8] = &[];
    fn valid(&self) -> bool {
        let d = InspectionLimits::default();
        let l = &self.limits;
        macro_rules! bounded { ($($f:ident),+) => { true $(&& l.$f > 0 && l.$f <= d.$f)+ }; }
        bounded!(
            max_receipt_bytes,
            max_protected_bytes,
            max_signature_bytes,
            max_cbor_nesting,
            max_cbor_items,
            max_map_entries,
            max_proofs_per_receipt,
            max_path_nodes_per_proof,
            max_certificate_chain_length,
            max_certificate_bytes,
            max_claim_text_characters,
            max_tree_size
        )
    }
}

/// Receipt-controlled text, explicitly unauthenticated. Subject TYPE is checked;
/// subject semantic correspondence is not. No URI normalization is performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnauthenticatedReceiptClaims {
    pub issuer: String,
    pub subject: String,
    pub authenticated: bool,
}

/// Exact original input is borrowed even on oversized/malformed inputs (no copy).
/// Protected/payload/signature contents are exact, never re-encoded for signing.
/// Effective headers are decoded conveniences, NOT replacement signed bytes.
/// No field asserts registration, application acceptance, crypto or TS identity.
#[derive(Debug, Clone)]
pub struct EnvelopeReport<'a> {
    pub encoded_receipt: &'a [u8],
    pub protected_bytes: Option<Vec<u8>>,
    pub payload_bytes: Option<Vec<u8>>,
    pub signature_bytes: Option<Vec<u8>>,
    pub unauthenticated_claims: Option<UnauthenticatedReceiptClaims>,
    pub effective_headers: Vec<(Value, Value)>,
    pub structure: InspectionFinding,
    pub required_claims: InspectionFinding,
    pub support: InspectionFinding,
    pub selected_policy: InspectionFinding,
    pub policy_id: &'static str,
    pub policy: InspectionPolicy,
    pub cbor_items_inspected: usize,
    pub ts_signature: InspectionFinding,
    pub inclusion: InspectionFinding,
    pub ts_identity_trust: InspectionFinding,
    pub subject_policy: InspectionFinding,
    pub application_policy: InspectionFinding,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Dimension {
    Structure,
    Claims,
    Policy,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Problem {
    dimension: Dimension,
    code: &'static str,
}
impl Problem {
    pub(crate) fn structure(code: &'static str) -> Self {
        Self {
            dimension: Dimension::Structure,
            code,
        }
    }
    pub(crate) fn policy(code: &'static str) -> Self {
        Self {
            dimension: Dimension::Policy,
            code,
        }
    }
    pub(crate) fn claims(code: &'static str) -> Self {
        Self {
            dimension: Dimension::Claims,
            code,
        }
    }
}

/// Inspect a single encoded tagged Receipt under explicit local policy, with no
/// keys, I/O, network, crypto, subject binding or attachment acceptance decision.
/// A passed structure/claims finding does NOT establish a valid signature.
#[must_use]
pub fn inspect_scitt_receipt<'a>(
    receipt_bytes: &'a [u8],
    policy: &InspectionPolicy,
) -> EnvelopeReport<'a> {
    let mut report = EnvelopeReport {
        encoded_receipt: receipt_bytes,
        protected_bytes: None,
        payload_bytes: None,
        signature_bytes: None,
        unauthenticated_claims: None,
        effective_headers: Vec::new(),
        structure: InspectionFinding::skipped(),
        required_claims: InspectionFinding::skipped(),
        support: InspectionFinding::skipped(),
        selected_policy: InspectionFinding::passed(),
        policy_id: InspectionPolicy::ID,
        policy: policy.clone(),
        cbor_items_inspected: 0,
        ts_signature: InspectionFinding::later(),
        inclusion: InspectionFinding::later(),
        ts_identity_trust: InspectionFinding::later(),
        subject_policy: InspectionFinding::later(),
        application_policy: InspectionFinding::later(),
    };
    let mut budget = Budget {
        limits: &policy.limits,
        items: 0,
        unprotected_x5t_invalid: false,
    };
    if let Err(problem) = inspect(&mut report, &mut budget) {
        apply_problem(&mut report, problem);
    }
    report.cbor_items_inspected = budget.items;
    report
}
fn apply_problem(report: &mut EnvelopeReport<'_>, problem: Problem) {
    let finding = InspectionFinding::new(
        InspectionStatus::Failed,
        problem.code,
        "Rejected in the named dimension; consult policy and exact input bytes.",
    );
    match problem.dimension {
        Dimension::Structure => {
            report.structure = finding;
            report.required_claims = InspectionFinding::skipped();
            report.support = InspectionFinding::skipped();
        }
        Dimension::Claims => report.required_claims = finding,
        Dimension::Policy => report.selected_policy = finding,
    }
}

fn decode(bytes: &[u8]) -> Result<Value, Problem> {
    let mut cursor = bytes;
    let value = coset::cbor::de::from_reader(&mut cursor)
        .map_err(|_| Problem::structure("invalid_cbor"))?;
    if !cursor.is_empty() {
        return Err(Problem::structure("trailing_cbor"));
    }
    Ok(value)
}

/// Called before any semantic lookup, including generic receipt parsing.
/// All nested maps are visited; integer equality is decoded-value equality,
/// so alternate-width integer encodings cannot bypass duplicate rejection.
pub(crate) fn check_unique_maps(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::Map(entries) => {
            for (i, (key, val)) in entries.iter().enumerate() {
                if entries[..i].iter().any(|(other, _)| equal_key(key, other)) {
                    return Err("duplicate_key");
                }
                check_unique_maps(key)?;
                check_unique_maps(val)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                check_unique_maps(item)?;
            }
        }
        Value::Tag(_, value) => check_unique_maps(value)?,
        _ => (),
    }
    Ok(())
}
fn equal_key(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Map(a), Value::Map(b)) => {
            a.len() == b.len()
                && a.iter().all(|(ak, av)| {
                    b.iter()
                        .any(|(bk, bv)| equal_key(ak, bk) && equal_key(av, bv))
                })
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal_key(a, b))
        }
        (Value::Tag(a, av), Value::Tag(b, bv)) => a == b && equal_key(av, bv),
        (Value::Float(a), Value::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
        _ => a == b,
    }
}
fn integer(value: &Value) -> Option<i128> {
    if let Value::Integer(n) = value {
        Some((*n).into())
    } else {
        None
    }
}
fn get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| integer(k) == Some(key))
        .map(|(_, v)| v)
}
fn labels(map: &[(Value, Value)]) -> Result<(), Problem> {
    if map
        .iter()
        .any(|(key, _)| !matches!(key, Value::Integer(_) | Value::Text(_)))
    {
        return Err(Problem::structure("header_label_type"));
    }
    Ok(())
}

fn inspect(report: &mut EnvelopeReport<'_>, budget: &mut Budget<'_>) -> Result<(), Problem> {
    if !report.policy.valid() {
        return Err(Problem::policy("invalid_policy_limits"));
    }
    if report.encoded_receipt.len() > budget.limits.max_receipt_bytes {
        return Err(Problem::policy("receipt_byte_limit"));
    }
    budget.scan(
        report.encoded_receipt,
        0,
        Role::Envelope,
        "outer_trailing_data",
    )?;
    let value = decode(report.encoded_receipt)?;
    check_unique_maps(&value).map_err(Problem::structure)?;
    let inner = match &value {
        Value::Tag(18, inner) => inner,
        Value::Tag(_, _) => return Err(Problem::structure("wrong_receipt_tag")),
        _ => return Err(Problem::structure("missing_receipt_tag")),
    };
    let Value::Array(items) = inner.as_ref() else {
        return Err(Problem::structure("element_count"));
    };
    let [p, u, m, s] = items.as_slice() else {
        return Err(Problem::structure("element_count"));
    };
    let Value::Bytes(p) = p else {
        return Err(Problem::structure("protected_type"));
    };
    let Value::Map(u) = u else {
        return Err(Problem::structure("unprotected_type"));
    };
    if !matches!(m, Value::Bytes(_) | Value::Null) {
        return Err(Problem::structure("payload_type"));
    }
    let Value::Bytes(s) = s else {
        return Err(Problem::structure("signature_type"));
    };
    report.protected_bytes = Some(p.clone());
    report.signature_bytes = Some(s.clone());
    if let Value::Bytes(m) = m {
        report.payload_bytes = Some(m.clone());
    }
    if p.is_empty() {
        return Err(Problem::structure("protected_not_map"));
    }
    // The protected map is at container depth 3 (tag=1, Sign1 array=2).
    budget.scan(p, 2, Role::ProtectedMap, "protected_trailing_data")?;
    let protected = decode(p)?;
    check_unique_maps(&protected).map_err(Problem::structure)?;
    let Value::Map(p) = &protected else {
        return Err(Problem::structure("protected_not_map"));
    };
    labels(p)?;
    labels(u)?;
    if get(p, 15).is_some() && get(u, 15).is_some() {
        return Err(Problem::structure("label15_single_occurrence"));
    }
    if get(u, 2).is_some() {
        return Err(Problem::structure("crit_location"));
    }
    if get(p, 396).is_some() {
        return Err(Problem::structure("vdp_location"));
    }
    let overlaps = p
        .iter()
        .any(|(key, _)| u.iter().any(|(other, _)| key == other));
    if report.policy.strict_cross_map && overlaps {
        apply_problem(report, Problem::policy("cross_map_overlap"));
    }
    // Only otherwise permitted overlaps reach this point; protected wins.
    report.effective_headers = p.clone();
    report.effective_headers.extend(
        u.iter()
            .filter(|(key, _)| !p.iter().any(|(other, _)| key == other))
            .cloned(),
    );
    let mut critical_unknown = false;
    if let Some(crit) = get(p, 2) {
        let Value::Array(crit) = crit else {
            return Err(Problem::structure("crit_type"));
        };
        if crit.is_empty() {
            return Err(Problem::structure("crit_empty"));
        }
        for (i, label) in crit.iter().enumerate() {
            if !matches!(label, Value::Integer(_) | Value::Text(_)) {
                return Err(Problem::structure("crit_label_type"));
            }
            if crit[..i].contains(label) {
                return Err(Problem::structure("crit_duplicate_label"));
            }
            if integer(label) == Some(2) {
                return Err(Problem::structure("crit_self_reference"));
            }
            if !p.iter().any(|(key, _)| key == label) {
                return Err(Problem::structure("crit_reference_absent"));
            }
            if !integer(label)
                .is_some_and(|n| InspectionPolicy::UNDERSTOOD_CRITICAL_LABELS.contains(&n))
            {
                critical_unknown = true;
            }
        }
    }
    // Validate profile-independent VDP container before profile dispatch. Opaque
    // unknown-profile proof bytes are never reinterpreted as RFC9162 CBOR.
    let vdp = get(u, 396).ok_or(Problem::structure("vdp_location"))?;
    let Value::Map(vdp) = vdp else {
        return Err(Problem::structure("vdp_map_type"));
    };
    labels(vdp)?;
    let alg = get(p, 1).and_then(integer);
    let vds = get(p, 395).and_then(integer);
    let mut proof_unknown = false;
    if vds == Some(1) {
        if let Some(proofs) = get(vdp, -1) {
            let Value::Array(proofs) = proofs else {
                return Err(Problem::structure("inclusion_array_type"));
            };
            if proofs.is_empty() {
                return Err(Problem::structure("empty_inclusion_array"));
            }
            if proofs.len() > budget.limits.max_proofs_per_receipt {
                return Err(Problem::policy("proof_limit"));
            }
            for proof in proofs {
                let Value::Bytes(bytes) = proof else {
                    return Err(Problem::structure("proof_not_bstr"));
                };
                // Embedded proof array is depth 6, path array depth 7.
                budget.scan(bytes, 5, Role::Proof, "proof_trailing_data")?;
                let proof = decode(bytes)?;
                check_unique_maps(&proof).map_err(Problem::structure)?;
                inspect_proof(&proof, budget.limits)?;
            }
        } else if vdp.is_empty() {
            return Err(Problem::structure("missing_inclusion"));
        }
        // Unknown extra proof types also remain visible as unsupported.
        proof_unknown = vdp.iter().any(|(key, _)| integer(key) != Some(-1));
    }
    report.structure = InspectionFinding::passed();
    let raw_x5t_invalid = budget.unprotected_x5t_invalid && get(p, 34).is_none();
    let claims_result = if raw_x5t_invalid {
        Err(Problem::claims("x5t_shape"))
    } else {
        inspect_claims(p, u, budget.limits)
    };
    match claims_result {
        Ok(claims) => {
            report.unauthenticated_claims = Some(claims);
            report.required_claims = InspectionFinding::passed();
        }
        Err(problem) => apply_problem(report, problem),
    }
    // Support is independent of claim validity, but only typed identifiers can
    // establish algorithm/profile support. Invalid shapes are never unsupported.
    if alg.is_none() || vds.is_none() {
        return Ok(());
    }
    let unsupported = if vds == Some(0) {
        report.support = InspectionFinding::new(
            InspectionStatus::Failed,
            "reserved_vds",
            "VDS zero is reserved, not an unsupported registration.",
        );
        return Ok(());
    } else if vds == Some(2) {
        Some("ccf_profile_not_implemented")
    } else if vds != Some(1) {
        Some("unknown_vds_registry_review")
    } else if alg != Some(-8) {
        Some("ts_algorithm")
    } else if critical_unknown {
        Some("critical_semantics")
    } else if proof_unknown {
        Some("proof_type_registry_review")
    } else if get(p, 33).is_some() || get(p, 34).is_some() {
        // Only valid X.509 syntax earns an unsupported-support finding.
        if raw_x5t_invalid || x509_shape(p, u, budget.limits).is_err() {
            return Ok(());
        }
        Some("x509_not_implemented")
    } else {
        None
    };
    report.support = match unsupported {
        Some(code) => InspectionFinding::new(
            InspectionStatus::Unsupported,
            code,
            "Not implemented by the initial Ed25519/RFC9162 policy; no crypto or trust finding follows.",
        ),
        None => InspectionFinding::passed(),
    };
    Ok(())
}

fn inspect_proof(value: &Value, limits: &InspectionLimits) -> Result<(), Problem> {
    let Value::Array(items) = value else {
        return Err(Problem::structure("proof_array_type"));
    };
    let [tree, leaf, path] = items.as_slice() else {
        return Err(Problem::structure("proof_element_count"));
    };
    let tree: u64 = integer(tree)
        .and_then(|n| n.try_into().ok())
        .ok_or(Problem::structure("tree_type"))?;
    let leaf: u64 = integer(leaf)
        .and_then(|n| n.try_into().ok())
        .ok_or(Problem::structure("leaf_type"))?;
    if tree == 0 {
        return Err(Problem::structure("tree_bounds"));
    }
    if tree > limits.max_tree_size {
        return Err(Problem::policy("tree_size_limit"));
    }
    if leaf >= tree {
        return Err(Problem::structure("leaf_bounds"));
    }
    let Value::Array(path) = path else {
        return Err(Problem::structure("path_type"));
    };
    if path.is_empty() {
        return Err(Problem::structure("empty_path"));
    }
    for node in path {
        let Value::Bytes(node) = node else {
            return Err(Problem::structure("path_node_type"));
        };
        if node.len() != 32 {
            return Err(Problem::structure("path_node_length"));
        }
    }
    Ok(())
}
fn uri(text: &str) -> bool {
    fluent_uri::Uri::parse(text).is_ok()
}
fn x509_shape(
    p: &[(Value, Value)],
    u: &[(Value, Value)],
    limits: &InspectionLimits,
) -> Result<(), Problem> {
    if let Some(x5t) = get(p, 34).or_else(|| get(u, 34))
        && !matches!(x5t, Value::Array(a) if matches!(a.as_slice(), [Value::Integer(_) | Value::Text(_), Value::Bytes(_)]))
    {
        return Err(Problem::claims("x5t_shape"));
    }
    if let Some(chain) = get(p, 33).or_else(|| get(u, 33)) {
        let certs: &[Value] = match chain {
            Value::Bytes(_) => core::slice::from_ref(chain),
            Value::Array(certs) if certs.len() >= 2 => certs,
            _ => return Err(Problem::claims("x5chain_shape")),
        };
        if certs.len() > limits.max_certificate_chain_length {
            return Err(Problem::policy("certificate_count_limit"));
        }
        for cert in certs {
            let Value::Bytes(cert) = cert else {
                return Err(Problem::claims("x5chain_shape"));
            };
            if cert.len() > limits.max_certificate_bytes {
                return Err(Problem::policy("certificate_byte_limit"));
            }
        }
    }
    Ok(())
}
fn inspect_claims(
    p: &[(Value, Value)],
    u: &[(Value, Value)],
    limits: &InspectionLimits,
) -> Result<UnauthenticatedReceiptClaims, Problem> {
    for key in [1, 395] {
        let value = get(p, key).ok_or(Problem::claims(if get(u, key).is_some() {
            "required_header_location"
        } else {
            "missing_required_header"
        }))?;
        if integer(value).is_none() {
            return Err(Problem::claims("required_header_type"));
        }
    }
    let claims = get(p, 15).ok_or(Problem::claims(if get(u, 15).is_some() {
        "claims_location"
    } else {
        "missing_claims"
    }))?;
    let Value::Map(claims) = claims else {
        return Err(Problem::claims("claims_map_type"));
    };
    if claims
        .iter()
        .any(|(key, _)| !matches!(key, Value::Integer(_) | Value::Text(_)))
    {
        return Err(Problem::claims("claim_label_type"));
    }
    let text = |label| -> Result<&str, Problem> {
        let value = get(claims, label).ok_or(Problem::claims(
            if get(claims, 1).is_none() && get(claims, 2).is_none() {
                "missing_integer_claims"
            } else {
                "missing_claim"
            },
        ))?;
        let Value::Text(text) = value else {
            return Err(Problem::claims("claim_value_type"));
        };
        Ok(text)
    };
    let iss = text(1)?;
    let sub = text(2)?;
    let x509 = get(p, 33).is_some() || get(p, 34).is_some();
    if x509 && (iss.is_empty() || iss.chars().count() > 8192) {
        return Err(Problem::claims("issuer_length"));
    }
    for value in [iss, sub] {
        if value.chars().count() > limits.max_claim_text_characters {
            return Err(Problem::policy("claim_text_limit"));
        }
    }
    if x509 && !uri(iss) {
        return Err(Problem::claims("x509_issuer_uri"));
    }
    for value in [iss, sub] {
        if value.contains(':') && !uri(value) {
            return Err(Problem::claims("uri_syntax"));
        }
    }
    x509_shape(p, u, limits)?;
    // Any supplied kid must have the right shape, even alongside an alternative.
    if let Some(kid) = get(p, 4).or_else(|| get(u, 4))
        && !matches!(kid, Value::Bytes(_))
    {
        return Err(Problem::claims("kid_type"));
    }
    if !x509 && get(p, 4).is_none() {
        return Err(if get(u, 4).is_some() {
            Problem::policy("protected_kid_required")
        } else {
            Problem::claims("missing_key_identifier")
        });
    }
    Ok(UnauthenticatedReceiptClaims {
        issuer: iss.into(),
        subject: sub.into(),
        authenticated: false,
    })
}
