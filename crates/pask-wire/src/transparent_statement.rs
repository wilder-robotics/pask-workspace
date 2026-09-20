// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.

//! Bounded offline recipient coordination. No I/O, live clock or authenticated
//! provisioning transport. Software-only application policies are not PSER,
//! hardware appraisal or physical-event truth. Existing #70 helpers are unchanged.
use alloc::{string::String, vec, vec::Vec};
use coset::cbor::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    BindingProvenance, InspectionFinding as Finding, InspectionLimits, InspectionStatus as Status,
    ProofVerification, ReceiptVerificationPolicy, TrustInputOrigin, TsPublicKey, TsTrustContext,
    UnauthenticatedReceiptClaims, VerifyingKeyEvidence, canonicalize_json, derive_candidate_entry,
    receipt_cbor::{Budget, Role},
    receipt_inspection::check_unique_maps,
    verify_scitt_receipt,
};

/// Private software-fixture application convention, not a core PSER version.
pub const SOFTWARE_SITE_CONTENT_TYPE: &str = "application/json; profile=pask71-software-site/1";

fn f(status: Status, code: &'static str) -> Finding {
    Finding {
        status,
        code,
        detail: "Only the named dimension under the recorded local policy; not a general acceptance claim.",
        evidence_refs: vec!["exact_statement_and_explicit_caller_inputs"],
    }
}
fn pass(code: &'static str) -> Finding {
    f(Status::Passed, code)
}
fn fail(code: &'static str) -> Finding {
    f(Status::Failed, code)
}
fn unset(code: &'static str) -> Finding {
    f(Status::Unestablished, code)
}
fn skip() -> Finding {
    f(Status::NotEvaluated, "prerequisite_not_established")
}
fn ok(x: &Finding) -> bool {
    x.status == Status::Passed
}
fn integer(v: &Value) -> Option<i128> {
    if let Value::Integer(i) = v {
        Some((*i).into())
    } else {
        None
    }
}
fn get(m: &[(Value, Value)], key: i128) -> Option<&Value> {
    m.iter()
        .find(|(k, _)| integer(k) == Some(key))
        .map(|(_, v)| v)
}
fn text(v: Option<&Value>) -> Option<&str> {
    if let Some(Value::Text(s)) = v {
        Some(s)
    } else {
        None
    }
}
fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing into Vec is infallible for the supported CBOR values.
    coset::cbor::ser::into_writer(v, &mut out).expect("CBOR Vec writer");
    out
}
fn decode(bytes: &[u8]) -> Option<Value> {
    let mut b = bytes;
    let v = coset::cbor::de::from_reader(&mut b).ok()?;
    b.is_empty().then_some(v)
}
fn bounded_text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 8192
}
fn string_or_uri(s: &str) -> bool {
    bounded_text(s) && (!s.contains(':') || fluent_uri::Uri::parse(s).is_ok())
}
fn authenticated(p: BindingProvenance<'_>) -> bool {
    matches!(p, BindingProvenance::CallerAuthenticated { authority, evidence_ref }
        if bounded_text(authority) && bounded_text(evidence_ref))
}
fn bounded_provenance(p: BindingProvenance<'_>) -> bool {
    match p {
        BindingProvenance::Missing => true,
        BindingProvenance::Unauthenticated { origin } => origin.len() <= 8192,
        BindingProvenance::CallerAuthenticated {
            authority,
            evidence_ref,
        } => authority.len() <= 8192 && evidence_ref.len() <= 8192,
    }
}

/// Tightenable local ceilings. Aggregate receipt work is at most eight times
/// the unchanged Phase 2 hard ceiling (256 signature attempts per Receipt).
#[derive(Debug, Clone)]
pub struct TransparentStatementPolicy {
    pub strict_cross_map: bool,
    pub max_statement_bytes: usize,
    pub max_receipts: usize,
    pub receipt: ReceiptVerificationPolicy,
}
impl Default for TransparentStatementPolicy {
    fn default() -> Self {
        Self {
            strict_cross_map: false,
            max_statement_bytes: 1_048_576,
            max_receipts: 8,
            receipt: ReceiptVerificationPolicy::default(),
        }
    }
}
impl TransparentStatementPolicy {
    pub const ID: &'static str = "pask71-recipient-offline/1";
}

/// Absence, malformed enclosing container and malformed encoded Receipt differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptContainerState {
    NotExamined,
    Absent,
    Malformed,
    Present,
}

/// Exact signed byte contents plus unauthenticated decoded conveniences.
#[derive(Debug, Clone)]
pub struct OuterStatementReport<'a> {
    pub encoded_statement: &'a [u8],
    pub policy: TransparentStatementPolicy,
    pub protected_bytes: Option<Vec<u8>>,
    pub payload_bytes: Option<Vec<u8>>,
    pub signature_bytes: Option<Vec<u8>>,
    pub effective_headers: Vec<(Value, Value)>,
    pub claims: Option<UnauthenticatedReceiptClaims>,
    pub algorithm: Option<i128>,
    pub protected_content_type: Option<String>,
    pub structure: Finding,
    pub required_claims: Finding,
    pub support: Finding,
    pub selected_policy: Finding,
    pub container: ReceiptContainerState,
    pub receipts: Vec<Vec<u8>>,
}

/// Inspect the transmitted object before deriving a candidate or doing crypto.
/// Accepts one tag-18 wrapper or legacy untagged local producer form. Payload
/// must be attached. Receipts must be byte strings, never repaired legacy arrays.
#[must_use]
pub fn inspect_transparent_statement<'a>(
    bytes: &'a [u8],
    policy: &TransparentStatementPolicy,
) -> OuterStatementReport<'a> {
    let mut r = OuterStatementReport {
        encoded_statement: bytes,
        policy: policy.clone(),
        protected_bytes: None,
        payload_bytes: None,
        signature_bytes: None,
        effective_headers: Vec::new(),
        claims: None,
        algorithm: None,
        protected_content_type: None,
        structure: skip(),
        required_claims: skip(),
        support: skip(),
        selected_policy: pass("bounded_outer_policy"),
        container: ReceiptContainerState::NotExamined,
        receipts: Vec::new(),
    };
    if let Err(code) = inspect_outer(&mut r) {
        r.structure = fail(code);
    }
    r
}
fn inspect_outer(r: &mut OuterStatementReport<'_>) -> Result<(), &'static str> {
    let p = &r.policy;
    if p.max_statement_bytes == 0
        || p.max_statement_bytes > 1_048_576
        || p.max_receipts == 0
        || p.max_receipts > 8
    {
        r.selected_policy = fail("invalid_outer_limits");
        return Err("outer_policy_limit");
    }
    if r.encoded_statement.len() > p.max_statement_bytes {
        return Err("outer_byte_limit");
    }
    let limits = InspectionLimits {
        max_receipt_bytes: p.max_statement_bytes,
        ..InspectionLimits::default()
    };
    let mut budget = Budget {
        limits: &limits,
        items: 0,
        unprotected_x5t_invalid: false,
    };
    let role = if r.encoded_statement.first().is_some_and(|b| b >> 5 == 6) {
        Role::Envelope
    } else {
        Role::Sign1
    };
    budget
        .scan(r.encoded_statement, 0, role, "outer_trailing")
        .map_err(|_| "outer_cbor_preflight")?;
    let value = decode(r.encoded_statement).ok_or("outer_cbor")?;
    check_unique_maps(&value)?;
    let value = match value {
        Value::Tag(18, inner) => *inner,
        v => v,
    };
    let Value::Array(items) = value else {
        return Err("outer_shape");
    };
    let [
        Value::Bytes(protected),
        Value::Map(u),
        Value::Bytes(payload),
        Value::Bytes(signature),
    ] = items.as_slice()
    else {
        return Err("outer_shape");
    };
    budget
        .scan(protected, 2, Role::ProtectedMap, "protected_trailing")
        .map_err(|_| "protected_cbor_preflight")?;
    let protected_map = decode(protected).ok_or("protected_cbor")?;
    check_unique_maps(&protected_map)?;
    let Value::Map(p) = &protected_map else {
        return Err("protected_not_map");
    };
    for m in [p, u] {
        if m.iter()
            .any(|(k, _)| !matches!(k, Value::Integer(_) | Value::Text(_)))
        {
            return Err("header_label_type");
        }
    }
    if get(p, 15).is_some() && get(u, 15).is_some() {
        return Err("label15_single_occurrence");
    }
    if get(u, 2).is_some() {
        return Err("crit_location");
    }
    if r.policy.strict_cross_map && p.iter().any(|(k, _)| u.iter().any(|(q, _)| q == k)) {
        r.selected_policy = fail("cross_map_overlap");
    }
    r.protected_bytes = Some(protected.clone());
    r.payload_bytes = Some(payload.clone());
    r.signature_bytes = Some(signature.clone());
    r.effective_headers = p.clone();
    r.effective_headers.extend(
        u.iter()
            .filter(|(k, _)| !p.iter().any(|(q, _)| q == k))
            .cloned(),
    );
    r.algorithm = get(p, 1).and_then(integer);
    r.protected_content_type = text(get(p, 3)).map(String::from);
    r.support = match r.algorithm {
        Some(-8) => pass("ed25519_issuer_supported"),
        Some(_) => f(Status::Unsupported, "issuer_algorithm"),
        None => fail("protected_algorithm_required"),
    };
    if let Some(crit) = get(p, 2) {
        let Value::Array(labels) = crit else {
            return Err("crit_type");
        };
        if labels.is_empty() {
            return Err("crit_empty");
        }
        for (i, label) in labels.iter().enumerate() {
            if !matches!(label, Value::Integer(_) | Value::Text(_))
                || labels[..i].contains(label)
                || integer(label) == Some(2)
            {
                return Err("crit_label");
            }
            if !p.iter().any(|(k, _)| k == label) {
                return Err("crit_reference_absent");
            }
            // Only implemented semantics; content-type and key discovery are not understood critical extensions here.
            if !matches!(integer(label), Some(1 | 15 | 394)) {
                r.support = f(Status::Unsupported, "outer_critical_semantics");
            }
        }
    }
    r.required_claims = fail("protected_text_claims_required");
    if let Some(Value::Map(c)) = get(p, 15)
        && let (Some(iss), Some(sub)) = (text(get(c, 1)), text(get(c, 2)))
        && string_or_uri(iss)
        && string_or_uri(sub)
    {
        r.claims = Some(UnauthenticatedReceiptClaims {
            issuer: iss.into(),
            subject: sub.into(),
            authenticated: false,
        });
        r.required_claims = pass("text_claim_types_not_semantic_binding");
    }
    // Location is not repaired by reading the unprotected equivalent.
    if r.algorithm.is_none() {
        r.required_claims = fail("protected_algorithm_required");
    }
    match get(&r.effective_headers, 394) {
        None => r.container = ReceiptContainerState::Absent,
        Some(Value::Array(a))
            if !a.is_empty()
                && a.len() <= r.policy.max_receipts
                && a.iter().all(|x| matches!(x, Value::Bytes(_))) =>
        {
            r.container = ReceiptContainerState::Present;
            r.receipts = a
                .iter()
                .map(|x| {
                    if let Value::Bytes(b) = x {
                        b.clone()
                    } else {
                        unreachable!()
                    }
                })
                .collect();
        }
        Some(_) => {
            r.container = ReceiptContainerState::Malformed;
            return Err("receipt_container_malformed_or_limit");
        }
    }
    r.structure = pass("outer_structure_inspected");
    Ok(())
}

/// A single explicit issuer verification key, not a receipt-controlled kid lookup.
/// Time, permitted algorithm, exact issuer binding and origin are caller inputs.
#[derive(Debug, Clone)]
pub struct IssuerKeyInput<'a> {
    pub public_key: TsPublicKey<'a>,
    pub algorithm: i64,
    pub issuer: &'a str,
    pub provenance: BindingProvenance<'a>,
    pub origin: TrustInputOrigin,
    pub evaluation_time: Option<i64>,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    pub explicitly_distrusted: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestTarget {
    CandidateEntrySha256,
    PayloadSha256,
}
/// Expected value is never inferred from a producer file or from the statement.
#[derive(Debug, Clone)]
pub struct ExpectedDigest<'a> {
    pub target: DigestTarget,
    pub sha256: [u8; 32],
    pub provenance: BindingProvenance<'a>,
    pub origin: TrustInputOrigin,
}
/// Exact mapping row, including the TS identity. No normalization or wildcard.
#[derive(Debug, Clone)]
pub struct SubjectMapping<'a> {
    pub service_identity: &'a str,
    pub receipt_subject: &'a str,
    pub statement_subject: &'a str,
    pub site_id: &'a str,
}
#[derive(Debug, Clone, Default)]
pub enum SubjectPolicy<'a> {
    #[default]
    None,
    /// Local named convention, not a universal SCITT requirement.
    SharedJsonSiteV1,
    /// Caller asserts the mapping is independently authenticated.
    AuthenticatedMappingV1 {
        rows: &'a [SubjectMapping<'a>],
        provenance: BindingProvenance<'a>,
        origin: TrustInputOrigin,
    },
}
/// Named software-only JSON-site policy. It never establishes PSER conformance.
#[derive(Debug, Clone, Default)]
pub enum StatementApplicationPolicy {
    #[default]
    None,
    SignedJsonSiteV1 {
        require_subject: bool,
        require_all_receipts: bool,
        require_authenticated_digest: bool,
    },
}
#[derive(Debug)]
pub struct StatementVerificationInputs<'a> {
    pub issuer: Option<&'a IssuerKeyInput<'a>>,
    pub services: &'a TsTrustContext<'a>,
    pub expected_digest: Option<&'a ExpectedDigest<'a>>,
    pub subject: SubjectPolicy<'a>,
    pub application: StatementApplicationPolicy,
}

/// Owned per-Receipt findings, preserving every encoded input and proof outcome.
/// No borrowed self-reference and no collapsing a bad attachment into absence.
#[derive(Debug, Clone)]
pub struct StatementReceiptOutcome {
    pub index: usize,
    pub encoded_receipt: Vec<u8>,
    pub structure: Finding,
    pub required_claims: Finding,
    pub support: Finding,
    pub selected_policy: Finding,
    pub claims: Option<UnauthenticatedReceiptClaims>,
    pub candidate_derivation: Finding,
    pub key_configuration: Vec<Finding>,
    pub candidate_keys: Vec<VerifyingKeyEvidence>,
    pub proofs: Vec<ProofVerification>,
    pub signature_attempts: usize,
    pub ts_signature: Finding,
    pub inclusion: Finding,
    pub ts_key_association: Finding,
    pub ts_identity_trust: Finding,
    pub acceptable_for_registration: Finding,
    pub subject_policy: Finding,
}
#[derive(Debug)]
pub struct TransparentStatementReport<'a> {
    pub outer: OuterStatementReport<'a>,
    pub inputs: &'a StatementVerificationInputs<'a>,
    pub policy_id: &'static str,
    pub candidate_entry: Option<Vec<u8>>,
    pub candidate_derivation: Finding,
    pub digest_equality: Finding,
    pub digest_origin: Finding,
    pub issuer_signature: Finding,
    pub actual_issuer_key: Option<[u8; 32]>,
    pub issuer_key_association: Finding,
    pub issuer_identity_trust: Finding,
    pub payload_context: Finding,
    pub application_profile: Finding,
    pub included_site_id: Option<String>,
    pub receipts: Vec<StatementReceiptOutcome>,
    pub acceptable_receipt_indices: Vec<usize>,
    pub registration_evidence: Finding,
    pub subject_policy: Finding,
    pub application_policy: Finding,
    pub hardware_appraisal: Finding,
    pub overall_profile: Finding,
}

/// Coordinate exact transmitted bytes. A good Receipt never erases the findings
/// for others. Only malformed outer structure/policy stops all dependent work.
/// Passed origin/trust means conditional on explicit caller assertions, not an
/// authenticated transport observed by this library. LocalSimulation cannot pass
/// registration or application acceptance. No application policy means unestablished.
#[must_use]
pub fn verify_transparent_statement<'a>(
    bytes: &'a [u8],
    inputs: &'a StatementVerificationInputs<'a>,
    policy: &TransparentStatementPolicy,
) -> TransparentStatementReport<'a> {
    let mut r = TransparentStatementReport {
        outer: inspect_transparent_statement(bytes, policy),
        inputs,
        policy_id: TransparentStatementPolicy::ID,
        candidate_entry: None,
        candidate_derivation: skip(),
        digest_equality: unset("expected_digest_absent"),
        digest_origin: unset("expected_digest_origin_absent"),
        issuer_signature: skip(),
        actual_issuer_key: None,
        issuer_key_association: unset("issuer_key_absent"),
        issuer_identity_trust: unset("issuer_trust_absent"),
        payload_context: skip(),
        application_profile: unset("application_policy_absent"),
        included_site_id: None,
        receipts: Vec::new(),
        acceptable_receipt_indices: Vec::new(),
        registration_evidence: skip(),
        subject_policy: unset("subject_convention_absent"),
        application_policy: unset("application_policy_absent"),
        hardware_appraisal: f(Status::NotEvaluated, "hardware_not_implemented"),
        overall_profile: unset("full_pser_conformance_not_established"),
    };
    if !ok(&r.outer.structure) || !ok(&r.outer.selected_policy) {
        return r;
    }
    let Ok(candidate) = derive_candidate_entry(bytes) else {
        r.candidate_derivation = fail("candidate_derivation");
        return r;
    };
    r.candidate_entry = Some(candidate);
    r.candidate_derivation = pass("exact_candidate_derived");
    check_digest(&mut r);
    check_issuer(&mut r);
    // The local context convention is canonical JSON with a nonempty site.id.
    // Comparing canonical output to ORIGINAL bytes rejects duplicate keys and
    // normalization; it never replaces bytes used for signatures or inclusion.
    let payload = r.outer.payload_bytes.as_ref().expect("inspected payload");
    r.payload_context = fail("canonical_json_site_context_required");
    if canonicalize_json(payload).is_ok_and(|b| b == *payload)
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload)
        && let Some(site) = v
            .get("site")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .filter(|s| bounded_text(s))
    {
        r.included_site_id = Some(site.into());
        r.payload_context = pass("included_json_site_context_not_pser_validation");
    }
    for (index, encoded) in r.outer.receipts.iter().enumerate() {
        let result = verify_scitt_receipt(encoded, bytes, inputs.services, &policy.receipt);
        let subject = subject_finding(&r, result.envelope.unauthenticated_claims.as_ref());
        let selected_policy = if !ok(&result.envelope.selected_policy) {
            result.envelope.selected_policy.clone()
        } else {
            result.selected_policy.clone()
        };
        r.receipts.push(StatementReceiptOutcome {
            index,
            encoded_receipt: encoded.clone(),
            structure: result.envelope.structure,
            required_claims: result.envelope.required_claims,
            support: result.envelope.support,
            selected_policy,
            claims: result.envelope.unauthenticated_claims,
            candidate_derivation: result.candidate_derivation,
            key_configuration: result.key_configuration,
            candidate_keys: result.candidate_keys,
            proofs: result.proofs,
            signature_attempts: result.signature_attempts,
            ts_signature: result.ts_signature,
            inclusion: result.inclusion,
            ts_key_association: result.ts_key_association,
            ts_identity_trust: result.ts_identity_trust,
            acceptable_for_registration: result.acceptable_for_registration,
            subject_policy: subject,
        });
    }
    r.acceptable_receipt_indices = r
        .receipts
        .iter()
        .filter(|x| ok(&x.acceptable_for_registration))
        .map(|x| x.index)
        .collect();
    r.registration_evidence = if r.acceptable_receipt_indices.is_empty() {
        unset("no_acceptable_receipt")
    } else {
        pass("at_least_one_acceptable_receipt_caller_trust")
    };
    if !matches!(inputs.subject, SubjectPolicy::None) {
        r.subject_policy = if r
            .receipts
            .iter()
            .any(|x| ok(&x.acceptable_for_registration) && ok(&x.subject_policy))
        {
            pass("acceptable_receipt_has_subject_binding")
        } else if r.receipts.iter().any(|x| {
            ok(&x.acceptable_for_registration) && x.subject_policy.status == Status::Failed
        }) {
            fail("acceptable_receipt_subject_contradiction")
        } else {
            unset("subject_binding_not_established_for_acceptable_receipt")
        };
    }
    if let StatementApplicationPolicy::SignedJsonSiteV1 {
        require_subject,
        require_all_receipts,
        require_authenticated_digest,
    } = inputs.application
    {
        r.application_profile = match r.outer.protected_content_type.as_deref() {
            Some(SOFTWARE_SITE_CONTENT_TYPE) => pass("declared_software_site_v1"),
            Some(_) => f(Status::Unsupported, "application_declared_profile"),
            None => fail("application_protected_content_type_required"),
        };
        let required = [
            &r.outer.required_claims,
            &r.outer.support,
            &r.payload_context,
            &r.issuer_signature,
            &r.issuer_key_association,
            &r.issuer_identity_trust,
            &r.registration_evidence,
            &r.application_profile,
        ];
        r.application_policy = if required.iter().any(|x| x.status == Status::Failed) {
            fail("software_application_prerequisite_failed")
        } else if required.iter().any(|x| !ok(x)) {
            unset("software_application_prerequisite_unestablished")
        } else if require_all_receipts
            && r.receipts.iter().any(|x| {
                !ok(&x.acceptable_for_registration) || (require_subject && !ok(&x.subject_policy))
            })
        {
            fail("explicit_all_receipts_application_policy")
        } else if require_subject && !ok(&r.subject_policy) {
            r.subject_policy.clone()
        } else if require_authenticated_digest && (!ok(&r.digest_equality) || !ok(&r.digest_origin))
        {
            if r.digest_equality.status == Status::Failed {
                fail("expected_digest_mismatch")
            } else {
                unset("authenticated_digest_not_established")
            }
        } else {
            pass("signed_json_site_v1_only_not_pser_or_hardware")
        };
    }
    r
}
fn check_digest(r: &mut TransparentStatementReport<'_>) {
    let Some(d) = r.inputs.expected_digest else {
        return;
    };
    let bytes = match d.target {
        DigestTarget::CandidateEntrySha256 => r.candidate_entry.as_ref().unwrap(),
        DigestTarget::PayloadSha256 => r.outer.payload_bytes.as_ref().unwrap(),
    };
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    r.digest_equality = if actual == d.sha256 {
        pass("explicit_expected_digest_equal")
    } else {
        fail("expected_digest_mismatch")
    };
    r.digest_origin = if authenticated(d.provenance)
        && d.origin == TrustInputOrigin::CallerAuthenticatedExternal
    {
        pass("digest_origin_caller_assertion")
    } else {
        unset("digest_equality_not_authenticated_origin")
    };
}
fn check_issuer(r: &mut TransparentStatementReport<'_>) {
    let Some(k) = r.inputs.issuer else {
        r.issuer_signature = unset("issuer_key_absent");
        return;
    };
    if !bounded_text(k.issuer) || !bounded_provenance(k.provenance) {
        r.issuer_key_association = fail("issuer_input_limit");
        return;
    }
    if !ok(&r.outer.support) {
        r.issuer_signature = r.outer.support.clone();
        return;
    }
    if r.outer.algorithm != Some(i128::from(k.algorithm)) {
        r.issuer_signature = fail("issuer_algorithm_key_mismatch");
        return;
    }
    let TsPublicKey::Ed25519(bytes) = k.public_key else {
        r.issuer_signature = f(Status::Unsupported, "issuer_key_type");
        return;
    };
    let signed = encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(r.outer.protected_bytes.clone().unwrap()),
        Value::Bytes(vec![]),
        Value::Bytes(r.outer.payload_bytes.clone().unwrap()),
    ]));
    let valid = VerifyingKey::from_bytes(&bytes)
        .ok()
        .zip(Signature::from_slice(r.outer.signature_bytes.as_ref().unwrap()).ok())
        .is_some_and(|(key, sig)| key.verify_strict(&signed, &sig).is_ok());
    r.issuer_signature = if valid {
        pass("issuer_signature_exact_bytes")
    } else {
        fail("issuer_signature_invalid")
    };
    if !valid {
        return;
    }
    r.actual_issuer_key = Some(bytes);
    r.issuer_key_association = if r
        .outer
        .claims
        .as_ref()
        .is_some_and(|c| c.issuer == k.issuer)
        && authenticated(k.provenance)
    {
        pass("actual_issuer_key_caller_authenticated_binding")
    } else {
        unset("issuer_binding_provenance_missing_or_mismatched")
    };
    r.issuer_identity_trust = if k.explicitly_distrusted {
        fail("issuer_key_explicitly_distrusted")
    } else if !ok(&r.issuer_key_association) {
        unset("issuer_binding_unestablished")
    } else if !matches!((k.evaluation_time, k.valid_from, k.valid_until), (Some(now), Some(from), Some(until)) if from < until && now >= from && now < until)
    {
        unset("issuer_validity_not_established")
    } else if k.origin == TrustInputOrigin::LocalSimulation {
        unset("issuer_local_simulation_only")
    } else {
        pass("issuer_trust_conditional_on_caller_origin")
    };
}
fn subject_finding(
    r: &TransparentStatementReport<'_>,
    receipt: Option<&UnauthenticatedReceiptClaims>,
) -> Finding {
    if matches!(r.inputs.subject, SubjectPolicy::None) {
        return unset("subject_convention_absent");
    }
    let (Some(statement), Some(receipt), Some(site)) =
        (&r.outer.claims, receipt, &r.included_site_id)
    else {
        return unset("typed_subject_context_missing");
    };
    match &r.inputs.subject {
        SubjectPolicy::None => unreachable!(),
        SubjectPolicy::SharedJsonSiteV1 => {
            if receipt.subject == statement.subject && statement.subject == *site {
                pass("shared_json_site_v1_exact_correspondence")
            } else {
                fail("shared_json_site_v1_contradiction")
            }
        }
        SubjectPolicy::AuthenticatedMappingV1 {
            rows,
            provenance,
            origin,
        } => {
            if rows.len() > 64
                || rows.iter().any(|x| {
                    [
                        x.service_identity,
                        x.receipt_subject,
                        x.statement_subject,
                        x.site_id,
                    ]
                    .iter()
                    .any(|s| !bounded_text(s))
                })
            {
                return fail("subject_mapping_limit");
            }
            if rows.is_empty()
                || !authenticated(*provenance)
                || *origin != TrustInputOrigin::CallerAuthenticatedExternal
            {
                return unset("authenticated_mapping_missing");
            }
            // One exact source identity+subject must have one deterministic target.
            let mut matching = rows.iter().filter(|x| {
                x.service_identity == receipt.issuer && x.receipt_subject == receipt.subject
            });
            let Some(first) = matching.next() else {
                return unset("authenticated_mapping_missing");
            };
            if matching.any(|x| {
                x.statement_subject != first.statement_subject || x.site_id != first.site_id
            }) {
                return fail("ambiguous_subject_mapping");
            }
            if first.statement_subject == statement.subject && first.site_id == site {
                pass("authenticated_mapping_v1_exact_correspondence")
            } else {
                fail("mapping_contradiction")
            }
        }
    }
}
