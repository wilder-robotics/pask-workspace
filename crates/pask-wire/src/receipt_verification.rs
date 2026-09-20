// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.

//! Bounded offline Phase 2 coordination, not a transparent-statement verifier.
//!
//! Only caller-provisioned keys are tried. Receipt-controlled discovery is never
//! performed. An issuer string or kid match cannot introduce an authorized key.
//! Authentication of the trust configuration is the caller's responsibility:
//! `CallerAuthenticated` is an explicit assertion, not a protocol implemented here.
//! Local simulation is visibly distinguished and cannot pass registration acceptance.
//! Subject correspondence, statement issuer verification, application acceptance,
//! hardware appraisal and attachment-set coordination remain outside this API.

use alloc::{vec, vec::Vec};
use coset::cbor::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::receipt_cbor::{Budget, Role};
use crate::{
    EnvelopeReport, InspectionFinding as Finding, InspectionLimits, InspectionPolicy,
    InspectionStatus as Status, Receipt, derive_candidate_entry, inspect_scitt_receipt, leaf_hash,
};

/// This API does not authenticate an external configuration transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustInputOrigin {
    /// A local test/harness simulates authenticated provisioning. Never real TS evidence.
    LocalSimulation,
    /// Caller asserts its configuration came from an independently authenticated channel.
    CallerAuthenticatedExternal,
}

/// Evidence must bind this row's exact service identity, algorithm and public key.
/// These fields are caller assertions, not receipt fields and not fetched URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingProvenance<'a> {
    Missing,
    /// Discovery, including an issuer/key pair copied from a receipt, is not an anchor.
    Unauthenticated {
        origin: &'a str,
    },
    CallerAuthenticated {
        authority: &'a str,
        evidence_ref: &'a str,
    },
}

/// Algorithm and key type are independent inputs and must agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsPublicKey<'a> {
    Ed25519([u8; 32]),
    /// Represent unsupported input without reinterpreting it as Ed25519.
    Unsupported {
        key_type: &'a str,
        bytes: &'a [u8],
    },
}

/// An independently provisioned association, not an identity extracted from a Receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsKeyAssociation<'a> {
    pub service_identity: &'a str,
    pub public_key: TsPublicKey<'a>,
    pub algorithm: i64,
    pub provenance: BindingProvenance<'a>,
    /// Nonunique hint only. Lookup scans the entire bounded configured key set.
    pub kid_hint: Option<&'a [u8]>,
    /// Unix seconds, inclusive start and exclusive end, evaluated at caller-supplied time.
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    /// Conservative key-wide veto, across every row for the same actual public key.
    pub explicitly_distrusted: bool,
}

/// The only implemented rotation convention. No historical signing time is inferred
/// from untrusted claims; overlapping current windows permit key rollover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPolicy {
    ValidAtEvaluationTimeV1,
}

/// Borrowed offline input: no network, live clock, global key store, or hidden defaults.
#[derive(Debug)]
pub struct TsTrustContext<'a> {
    pub accepted_ts_identities: &'a [&'a str],
    pub associations: &'a [TsKeyAssociation<'a>],
    pub evaluation_time: Option<i64>,
    pub rotation_policy: Option<RotationPolicy>,
    pub provisioned_by: Option<&'a str>,
    pub origin: TrustInputOrigin,
}

/// Tightenable hard ceilings. Raw statement/trust limits precede allocating decoders
/// and key/proof Cartesian work is checked before the first signature attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationLimits {
    pub max_statement_bytes: usize,
    pub max_statement_cbor_items: usize,
    pub max_statement_cbor_nesting: usize,
    pub max_statement_map_entries: usize,
    pub max_associations: usize,
    pub max_accepted_identities: usize,
    pub max_candidate_keys: usize,
    pub max_signature_attempts: usize,
    pub max_trust_field_bytes: usize,
}
impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_statement_bytes: 1_048_576,
            max_statement_cbor_items: 4_096,
            max_statement_cbor_nesting: 16,
            max_statement_map_entries: 64,
            max_associations: 64,
            max_accepted_identities: 64,
            max_candidate_keys: 16,
            max_signature_attempts: 256,
            max_trust_field_bytes: 8_192,
        }
    }
}
impl VerificationLimits {
    fn valid(&self) -> bool {
        let d = Self::default();
        macro_rules! bounded { ($($f:ident),+) => { true $(&& self.$f > 0 && self.$f <= d.$f)+ }; }
        bounded!(
            max_statement_bytes,
            max_statement_cbor_items,
            max_statement_cbor_nesting,
            max_statement_map_entries,
            max_associations,
            max_accepted_identities,
            max_candidate_keys,
            max_signature_attempts,
            max_trust_field_bytes
        )
    }
}

/// Cross-map strictness remains OFF by default in Phase 1. No #70 helper is called.
/// Empty external AAD, strict Ed25519 verification and all-supplied-proofs success
/// are fixed local policy. A valid proof never hides another proof's failure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiptVerificationPolicy {
    pub envelope: InspectionPolicy,
    pub limits: VerificationLimits,
}
impl ReceiptVerificationPolicy {
    pub const ID: &'static str = "pask71-offline-service-association/1";
}

/// The actual crypto key, not kid. Indices reference the exact supplied context.
#[derive(Debug, Clone)]
pub struct VerifyingKeyEvidence {
    pub public_key: [u8; 32],
    pub sha256: [u8; 32],
    pub association_indices: Vec<usize>,
    pub kid_hint_match_indices: Vec<usize>,
}

/// Root reconstruction alone is explicitly not inclusion authentication.
#[derive(Debug, Clone)]
pub struct ProofVerification {
    pub proof_index: usize,
    pub reconstructed_root: Option<[u8; 32]>,
    pub root_reconstruction: Finding,
    pub attached_root_equality: Finding,
    pub ts_signature: Finding,
    pub inclusion: Finding,
    /// Indices into `ReceiptVerificationReport::candidate_keys`.
    pub verifying_key_indices: Vec<usize>,
}

/// Independent dimensions, with original inputs borrowed and signed bytes preserved.
#[derive(Debug)]
pub struct ReceiptVerificationReport<'a> {
    pub statement_bytes: &'a [u8],
    pub envelope: EnvelopeReport<'a>,
    pub trust_context: &'a TsTrustContext<'a>,
    pub policy: ReceiptVerificationPolicy,
    pub policy_id: &'static str,
    pub candidate_entry: Option<Vec<u8>>,
    pub candidate_derivation: Finding,
    pub selected_policy: Finding,
    pub candidate_keys: Vec<VerifyingKeyEvidence>,
    /// One finding per configured association, including skipped type/algorithm routes.
    pub key_configuration: Vec<Finding>,
    pub proofs: Vec<ProofVerification>,
    pub signature_attempts: usize,
    pub ts_signature: Finding,
    pub inclusion: Finding,
    pub ts_key_association: Finding,
    pub ts_identity_trust: Finding,
    pub subject_policy: Finding,
    pub issuer_signature: Finding,
    pub application_policy: Finding,
    pub hardware_appraisal: Finding,
    pub acceptable_for_registration: Finding,
}

fn finding(status: Status, code: &'static str, detail: &'static str) -> Finding {
    Finding {
        status,
        code,
        detail,
        evidence_refs: vec![
            "encoded_receipt",
            "statement_bytes",
            "trust_context",
            "policy",
        ],
    }
}
fn skipped() -> Finding {
    finding(
        Status::NotEvaluated,
        "prerequisite_not_established",
        "A dependent check was not run.",
    )
}
fn unestablished(code: &'static str) -> Finding {
    finding(
        Status::Unestablished,
        code,
        "Required independent evidence is absent; not acceptance.",
    )
}
fn failed(code: &'static str) -> Finding {
    finding(Status::Failed, code, "Failed only the named dimension.")
}
fn passed(code: &'static str) -> Finding {
    finding(
        Status::Passed,
        code,
        "Passed only the named dimension under the explicit supplied inputs.",
    )
}

/// Verify one supported Receipt against a candidate derived from those exact
/// statement bytes. This does NOT validate the outer statement's header semantics,
/// issuer signature, attachment container, application policy or physical-event truth.
/// `LocalSimulation` can demonstrate conditional trust but never passes registration.
/// `CallerAuthenticatedExternal` still relies on the caller to authenticate provisioning.
#[must_use]
pub fn verify_scitt_receipt<'a>(
    receipt_bytes: &'a [u8],
    statement_bytes: &'a [u8],
    trust_context: &'a TsTrustContext<'a>,
    policy: &ReceiptVerificationPolicy,
) -> ReceiptVerificationReport<'a> {
    let mut r = ReceiptVerificationReport {
        statement_bytes,
        envelope: inspect_scitt_receipt(receipt_bytes, &policy.envelope),
        trust_context,
        policy: policy.clone(),
        policy_id: ReceiptVerificationPolicy::ID,
        candidate_entry: None,
        candidate_derivation: skipped(),
        selected_policy: passed("phase2_policy_selected"),
        candidate_keys: Vec::new(),
        key_configuration: Vec::new(),
        proofs: Vec::new(),
        signature_attempts: 0,
        ts_signature: skipped(),
        inclusion: skipped(),
        ts_key_association: unestablished("verifying_key_not_established"),
        ts_identity_trust: unestablished("trust_not_established"),
        subject_policy: unestablished("phase3_subject_semantics_not_implemented"),
        issuer_signature: finding(
            Status::NotEvaluated,
            "outside_phase2",
            "Statement issuer verification is not implemented by this API.",
        ),
        application_policy: unestablished("phase3_application_not_implemented"),
        hardware_appraisal: finding(
            Status::NotEvaluated,
            "outside_phase2",
            "No hardware evidence is evaluated.",
        ),
        acceptable_for_registration: unestablished("registration_prerequisites_not_established"),
    };
    run(&mut r);
    r
}

fn run(r: &mut ReceiptVerificationReport<'_>) {
    let e = &r.envelope;
    if [
        &e.structure,
        &e.required_claims,
        &e.support,
        &e.selected_policy,
    ]
    .iter()
    .any(|f| f.status != Status::Passed)
    {
        return;
    }
    if !r.policy.limits.valid() {
        r.selected_policy = failed("invalid_phase2_limits");
        return;
    }
    let l = &r.policy.limits;
    if r.statement_bytes.len() > l.max_statement_bytes {
        r.candidate_derivation = failed("statement_byte_limit");
        return;
    }
    // General, allocation-free preflight only; do not accidentally inherit the
    // Receipt's claims rules or #70's unconditional outer cross-map strictness.
    let limits = InspectionLimits {
        max_receipt_bytes: l.max_statement_bytes,
        max_cbor_items: l.max_statement_cbor_items,
        max_cbor_nesting: l.max_statement_cbor_nesting,
        max_map_entries: l.max_statement_map_entries,
        ..InspectionLimits::default()
    };
    let mut budget = Budget {
        limits: &limits,
        items: 0,
        unprotected_x5t_invalid: false,
    };
    if budget
        .scan(r.statement_bytes, 0, Role::Any, "statement_trailing_data")
        .is_err()
    {
        r.candidate_derivation = failed("statement_cbor_preflight");
        return;
    }
    let Ok(candidate) = derive_candidate_entry(r.statement_bytes) else {
        r.candidate_derivation = failed("statement_candidate_shape");
        return;
    };
    r.candidate_derivation = passed("exact_statement_candidate_derived_not_outer_validation");
    r.candidate_entry = Some(candidate);
    if !bounded_context(r.trust_context, l) {
        r.selected_policy = failed("trust_context_limit");
        return;
    }
    let Ok(receipt) = Receipt::from_cose_sign1(r.envelope.encoded_receipt) else {
        r.selected_policy = failed("inspection_parser_disagreement");
        return;
    };
    let kid = r.envelope.effective_headers.iter().find_map(|(k, v)| {
        if *k == Value::Integer(4.into())
            && let Value::Bytes(b) = v
        {
            return Some(b.as_slice());
        }
        None
    });
    for (i, a) in r.trust_context.associations.iter().enumerate() {
        let TsPublicKey::Ed25519(key) = a.public_key else {
            r.key_configuration.push(finding(
                Status::Unsupported,
                "key_type_not_supported",
                "This row is not used for signature attempts; no key-type coercion.",
            ));
            continue;
        };
        if a.algorithm != -8 {
            r.key_configuration
                .push(failed("configured_algorithm_key_mismatch"));
            continue;
        }
        r.key_configuration
            .push(passed("configured_ed25519_algorithm_key_agreement"));
        let position = r.candidate_keys.iter().position(|k| k.public_key == key);
        let index = match position {
            Some(index) => index,
            None => {
                if r.candidate_keys.len() == l.max_candidate_keys {
                    r.selected_policy = failed("candidate_key_limit");
                    return;
                }
                r.candidate_keys.push(VerifyingKeyEvidence {
                    public_key: key,
                    sha256: Sha256::digest(key).into(),
                    association_indices: Vec::new(),
                    kid_hint_match_indices: Vec::new(),
                });
                r.candidate_keys.len() - 1
            }
        };
        r.candidate_keys[index].association_indices.push(i);
        if kid.is_some() && kid == a.kid_hint {
            r.candidate_keys[index].kid_hint_match_indices.push(i);
        }
    }
    if r.candidate_keys
        .len()
        .checked_mul(receipt.inclusion_proofs.len())
        .is_none_or(|n| n > l.max_signature_attempts)
    {
        r.selected_policy = failed("signature_attempt_limit");
        return;
    }
    let leaf = leaf_hash(r.candidate_entry.as_deref().unwrap_or_default());
    let signature =
        Signature::from_slice(r.envelope.signature_bytes.as_deref().unwrap_or_default());
    for (i, proof) in receipt.inclusion_proofs.iter().enumerate() {
        let mut p = ProofVerification {
            proof_index: i,
            reconstructed_root: None,
            root_reconstruction: skipped(),
            attached_root_equality: skipped(),
            ts_signature: skipped(),
            inclusion: unestablished("root_not_authenticated"),
            verifying_key_indices: Vec::new(),
        };
        if let Ok(root) = proof.reconstruct_root(leaf) {
            p.reconstructed_root = Some(root);
            p.root_reconstruction = passed("root_reconstructed_not_authenticated");
            if receipt
                .payload
                .as_ref()
                .is_some_and(|b| b.as_slice() != root)
            {
                p.attached_root_equality = failed("attached_root_mismatch");
                p.inclusion = failed("attached_root_mismatch");
            } else {
                p.attached_root_equality = if receipt.payload.is_some() {
                    passed("attached_root_equal_not_authenticated")
                } else {
                    finding(
                        Status::NotEvaluated,
                        "detached_payload",
                        "No attached root; signature must authenticate the reconstructed root.",
                    )
                };
                if let Ok(signature) = &signature {
                    // Never reserialize protected contents. Sig_structure outer encoding only.
                    let structure = Value::Array(vec![
                        Value::Text("Signature1".into()),
                        Value::Bytes(r.envelope.protected_bytes.clone().unwrap_or_default()),
                        Value::Bytes(Vec::new()),
                        Value::Bytes(root.to_vec()),
                    ]);
                    let mut signed = Vec::new();
                    if coset::cbor::ser::into_writer(&structure, &mut signed).is_err() {
                        r.selected_policy = failed("sig_structure_encoding");
                        return;
                    }
                    for (ki, key) in r.candidate_keys.iter().enumerate() {
                        r.signature_attempts += 1;
                        if VerifyingKey::from_bytes(&key.public_key)
                            .is_ok_and(|k| k.verify_strict(&signed, signature).is_ok())
                        {
                            p.verifying_key_indices.push(ki);
                        }
                    }
                    if p.verifying_key_indices.is_empty() {
                        p.ts_signature = if r.candidate_keys.is_empty() {
                            unestablished("no_algorithm_compatible_candidate_key")
                        } else {
                            failed("signature_did_not_verify")
                        };
                    } else {
                        p.ts_signature = passed("signature_under_actual_supplied_key");
                        p.inclusion = passed("candidate_included_in_signature_authenticated_root");
                    }
                } else {
                    p.ts_signature = failed("invalid_ed25519_signature_length");
                }
            }
        } else {
            p.root_reconstruction = failed("invalid_merkle_path");
            p.inclusion = failed("invalid_merkle_path");
        }
        r.proofs.push(p);
    }
    r.ts_signature = aggregate(
        r.proofs.iter().map(|p| &p.ts_signature),
        "all_proof_roots_signed",
    );
    r.inclusion = aggregate(
        r.proofs.iter().map(|p| &p.inclusion),
        "all_proofs_authenticated",
    );
    if r.ts_signature.status != Status::Passed || r.inclusion.status != Status::Passed {
        return;
    }
    // Fail closed if more than one actual key verifies, or proofs disagree on the signer.
    let first = &r.proofs[0].verifying_key_indices;
    if first.len() != 1 || r.proofs.iter().any(|p| p.verifying_key_indices != *first) {
        r.ts_key_association = failed("ambiguous_actual_verifying_key");
        r.ts_identity_trust = failed("ambiguous_actual_verifying_key");
        return;
    }
    associate(r, first[0]);
}

fn aggregate<'a>(items: impl Iterator<Item = &'a Finding>, code: &'static str) -> Finding {
    let statuses: Vec<Status> = items.map(|f| f.status).collect();
    if statuses.contains(&Status::Failed) {
        return failed(code);
    }
    if statuses.iter().all(|s| *s == Status::Passed) && !statuses.is_empty() {
        return passed(code);
    }
    if statuses.iter().all(|s| *s == Status::NotEvaluated) {
        return skipped();
    }
    unestablished(code)
}

fn bounded_context(c: &TsTrustContext<'_>, l: &VerificationLimits) -> bool {
    if c.associations.len() > l.max_associations
        || c.accepted_ts_identities.len() > l.max_accepted_identities
    {
        return false;
    }
    let bounded = |s: &str| s.len() <= l.max_trust_field_bytes;
    if !c.accepted_ts_identities.iter().all(|s| bounded(s))
        || c.provisioned_by.is_some_and(|s| !bounded(s))
    {
        return false;
    }
    c.associations.iter().all(|a| {
        bounded(a.service_identity)
            && a.kid_hint
                .is_none_or(|b| b.len() <= l.max_trust_field_bytes)
            && match a.public_key {
                TsPublicKey::Ed25519(_) => true,
                TsPublicKey::Unsupported { key_type, bytes } => {
                    bounded(key_type) && bytes.len() <= l.max_trust_field_bytes
                }
            }
            && match a.provenance {
                BindingProvenance::Missing => true,
                BindingProvenance::Unauthenticated { origin } => bounded(origin),
                BindingProvenance::CallerAuthenticated {
                    authority,
                    evidence_ref,
                } => bounded(authority) && bounded(evidence_ref),
            }
    })
}

fn associate(r: &mut ReceiptVerificationReport<'_>, key_index: usize) {
    let key = r.candidate_keys[key_index].public_key;
    let c = r.trust_context;
    let issuer = r
        .envelope
        .unauthenticated_claims
        .as_ref()
        .map(|v| v.issuer.as_str())
        .unwrap_or("");
    // Key-wide distrust wins even when another row has a different issuer, kid,
    // algorithm, validity window or provenance; input is a caller-owned deny list.
    if c.associations
        .iter()
        .any(|a| a.public_key == TsPublicKey::Ed25519(key) && a.explicitly_distrusted)
    {
        r.ts_key_association = failed("actual_key_explicitly_distrusted");
        r.ts_identity_trust = failed("actual_key_explicitly_distrusted");
        return;
    }
    let matching: Vec<_> = c
        .associations
        .iter()
        .filter(|a| {
            a.public_key == TsPublicKey::Ed25519(key)
                && a.algorithm == -8
                && a.service_identity == issuer
        })
        .collect();
    if matching.is_empty() {
        r.ts_key_association = failed("actual_key_not_associated_with_claimed_service");
        r.ts_identity_trust = failed("unauthorized_verifying_key");
        return;
    }
    let authenticated: Vec<_> = matching
        .iter()
        .filter(|a| {
            matches!(
                a.provenance, BindingProvenance::CallerAuthenticated { authority, evidence_ref }
                    if !authority.is_empty() && !evidence_ref.is_empty()
            )
        })
        .collect();
    if authenticated.is_empty() || c.provisioned_by.is_none_or(str::is_empty) {
        r.ts_key_association = unestablished("authenticated_binding_evidence_missing");
        return;
    }
    r.ts_key_association = passed("actual_key_has_caller_authenticated_service_binding");
    if !c.accepted_ts_identities.contains(&issuer) {
        r.ts_identity_trust = failed("service_identity_not_accepted");
        return;
    }
    let (Some(now), Some(RotationPolicy::ValidAtEvaluationTimeV1)) =
        (c.evaluation_time, c.rotation_policy)
    else {
        r.ts_identity_trust = unestablished("evaluation_time_or_rotation_policy_missing");
        return;
    };
    let mut missing_window = false;
    let valid = authenticated
        .iter()
        .any(|a| match (a.valid_from, a.valid_until) {
            (Some(from), Some(until)) => from < until && from <= now && now < until,
            _ => {
                missing_window = true;
                false
            }
        });
    if !valid {
        r.ts_identity_trust = if missing_window {
            unestablished("key_validity_evidence_missing")
        } else {
            failed("no_current_authorized_key_window")
        };
        return;
    }
    match c.origin {
        TrustInputOrigin::LocalSimulation => {
            r.ts_identity_trust = passed("local_simulation_conditional_trust_only");
            r.acceptable_for_registration =
                unestablished("simulation_is_not_real_registration_evidence");
        }
        TrustInputOrigin::CallerAuthenticatedExternal => {
            r.ts_identity_trust =
                passed("trusted_under_caller_authenticated_offline_configuration");
            r.acceptable_for_registration =
                passed("single_receipt_registration_evidence_only_not_application_acceptance");
        }
    }
}
