// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Locks the reference producer's public claim.
//!
//! `Ed25519SiteProducer` signs a `wilder.pser/0.5` statement and does not
//! attach a transparency receipt. KNOWN-LIMITATIONS.md §5.2 records that
//! registration is mandatory for a conforming receipt and that this
//! repository does not operate a production Transparency Service, so an
//! unregistered statement is non-conforming on purpose.
//!
//! The expected profile below is the literal `wilder.pser/0.5`. Keeping it
//! independent of `pask_wire::SPEC_VERSION` means a later constant edit fails
//! this test until the claim boundary is revised on purpose.

mod common;

use std::sync::Arc;

use pask_site::{Ed25519SiteProducer, SiteProducer};
use pask_wire::{
    InspectionStatus, ReceiptContainerState, TransparentStatementPolicy,
    inspect_transparent_statement, verify_ed25519,
};

/// Profile the reference producer is allowed to declare.
const DECLARED_PROFILE: &str = "wilder.pser/0.5";

/// Protected content type that declares [`DECLARED_PROFILE`].
const DECLARED_CONTENT_TYPE: &str = "application/pser+json; profile=wilder.pser/0.5";

/// COSE header label for an attached transparency receipt (`receipts`).
const RECEIPTS_HEADER: i128 = 394;

const CLAIM_BOUNDARY: &str = "this is a deliberate claim boundary. The reference site \
    producer verifies under its own key, declares profile wilder.pser/0.5, and attaches \
    no transparency receipt (COSE header 394 absent). A changed profile string or an \
    attached receipt would make the reference site appear to claim more than it does. \
    Update this test and KNOWN-LIMITATIONS.md together, and only with an architect decision.";

#[test]
fn reference_producer_declares_pser_0_5_without_transparency_receipt() {
    let (producer, verifying_key): (Arc<Ed25519SiteProducer>, _) = common::producer();
    let statement = producer
        .produce(&common::request())
        .unwrap_or_else(|error| {
            panic!("Ed25519SiteProducer failed to produce a statement: {error}. {CLAIM_BOUNDARY}")
        });

    let verified = verify_ed25519(&statement, &verifying_key);
    let outer = inspect_transparent_statement(&statement, &TransparentStatementPolicy::default());

    let mut problems = Vec::new();
    match &verified {
        Ok(payload) if payload.spec() == DECLARED_PROFILE => {}
        Ok(payload) => problems.push(format!(
            "verified profile is {:?}; the reference producer declares {DECLARED_PROFILE:?}",
            payload.spec()
        )),
        Err(error) => problems.push(format!(
            "statement did not verify under the producer's own key: {error}"
        )),
    }
    if outer.structure.status != InspectionStatus::Passed {
        problems.push(format!(
            "transparent-statement inspection status is {:?} ({})",
            outer.structure.status, outer.structure.code
        ));
    }
    if outer.protected_content_type.as_deref() != Some(DECLARED_CONTENT_TYPE) {
        problems.push(format!(
            "protected content type is {:?}; expected {DECLARED_CONTENT_TYPE:?}",
            outer.protected_content_type
        ));
    }
    // Header 394 is the `receipts` label. Absence, a malformed container, and
    // one or more attached receipts are distinct findings; only absence matches
    // what this producer emits today.
    if outer.container != ReceiptContainerState::Absent || !outer.receipts.is_empty() {
        problems.push(format!(
            "COSE header {RECEIPTS_HEADER} (receipts) is {:?}; attached receipt count is {}",
            outer.container,
            outer.receipts.len()
        ));
    }

    assert!(
        problems.is_empty(),
        "{}\n{CLAIM_BOUNDARY}",
        problems.join("\n")
    );
}
