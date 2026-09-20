// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Producer and verifier for the `wilder.pser/0.5` signed-statement profile.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
mod canonical_example;
#[cfg(feature = "alloc")]
mod chain;
#[cfg(feature = "alloc")]
mod cwt;
#[cfg(feature = "alloc")]
mod digest;
#[cfg(feature = "alloc")]
mod entry;
#[cfg(feature = "alloc")]
mod envelope;
#[cfg(feature = "alloc")]
mod error;
#[cfg(feature = "alloc")]
mod payload;
#[cfg(feature = "alloc")]
mod receipt;
#[cfg(feature = "alloc")]
pub mod testvectors;

#[cfg(feature = "alloc")]
pub use canonical_example::{canonical_example, canonical_example_06};
#[cfg(feature = "alloc")]
pub use chain::{AffiliationChange, ChainReport, verify_chain};
#[cfg(feature = "alloc")]
pub use digest::{sha256_prefixed, validate_sha256};
#[cfg(feature = "alloc")]
pub use entry::{candidate_leaf_hash, derive_candidate_entry};
#[cfg(feature = "alloc")]
pub use envelope::{CONTENT_TYPE, CONTENT_TYPE_06, produce_ed25519, verify_ed25519};
#[cfg(feature = "es256")]
pub use envelope::{produce_es256, verify_es256};
#[cfg(feature = "alloc")]
pub use error::{Error, Result};
#[cfg(feature = "alloc")]
pub use payload::{
    AckProvenance, BindingMode, IssuerAffiliation, Payload, SPEC_VERSION, SPEC_VERSION_06,
    canonicalize_json, is_supported_spec,
};
#[cfg(feature = "alloc")]
pub use receipt::{
    AttachedReceipts, INCLUSION_PROOF_LABEL, InclusionProof, RECEIPTS_LABEL, RFC9162_SHA256,
    Receipt, VDP_LABEL, VDS_LABEL, VerifiedInclusion, attached_receipts, leaf_hash,
    verify_inclusion,
};

#[cfg(feature = "alloc")]
mod receipt_cbor;
#[cfg(feature = "alloc")]
mod receipt_inspection;
#[cfg(feature = "alloc")]
pub use receipt_inspection::{
    EnvelopeReport, InspectionFinding, InspectionLimits, InspectionPolicy, InspectionStatus,
    UnauthenticatedReceiptClaims, inspect_scitt_receipt,
};

#[cfg(feature = "alloc")]
mod receipt_verification;
#[cfg(feature = "alloc")]
pub use receipt_verification::{
    BindingProvenance, ProofVerification, ReceiptVerificationPolicy, ReceiptVerificationReport,
    RotationPolicy, TrustInputOrigin, TsKeyAssociation, TsPublicKey, TsTrustContext,
    VerificationLimits, VerifyingKeyEvidence, verify_scitt_receipt,
};

#[cfg(feature = "alloc")]
mod transparent_statement;
#[cfg(feature = "alloc")]
pub use transparent_statement::{
    DigestTarget, ExpectedDigest, IssuerKeyInput, OuterStatementReport, ReceiptContainerState,
    SOFTWARE_SITE_CONTENT_TYPE, StatementApplicationPolicy, StatementReceiptOutcome,
    StatementVerificationInputs, SubjectMapping, SubjectPolicy, TransparentStatementPolicy,
    TransparentStatementReport, inspect_transparent_statement, verify_transparent_statement,
};
