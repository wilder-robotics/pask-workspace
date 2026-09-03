// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! Chain-Verifier: the chain-level checks that apply when two or more receipts
//! are presented as one contiguous chain.
//!
//! `-01` §4.1 adds two normative requirements on a Chain-Verifier presented
//! with such a presentation:
//!
//! 1. MUST check `chain.seq` contiguity across the presentation.
//! 2. MUST check each receipt's `chain.prevHash` equals the preceding
//!    receipt's `chain.hash`.
//!
//! [`Payload::from_json`](crate::Payload::from_json) already validates every
//! individual receipt on its own, including the seq0/prevHash-null pairing
//! and that a receipt's own `chain.hash` matches its content. This module
//! does not repeat that work: [`verify_chain`] does NOT re-verify each
//! receipt's own `chain.hash`, because parsing already did. It only checks
//! the relationships *between* adjacent receipts in a presentation.
//!
//! `-02` adds a third chain-level rule, over `issuerAffiliation`, and it is
//! deliberately not a rejection.
//!
//! The two `-01` checks are structural. Sequence numbering and the hash link
//! are entirely under the Issuer's control, so a violation of either is always
//! an error or tampering, with no honest explanation available. Affiliation is
//! not structural. It is a claim about the world outside the receipt, and the
//! world changes: an Issuer independent of the Site Owner in March can be
//! acquired by that Site Owner in September. Treating that as a malformed chain
//! would put an ordinary corporate event into the same bucket as tampering, and
//! would report it to a relying party in the same words.
//!
//! It would also be destructive. The only way to comply with a rejection rule
//! is to start a new chain, which resets `seq` to zero and `prevHash` to null,
//! and so deletes the link between the receipts from before the change and the
//! ones after. That is exactly the continuity a chain exists to carry.
//!
//! So [`verify_chain`] returns a [`ChainReport`] rather than a bare unit. A
//! chain whose `issuerAffiliation` changes is still a valid chain, and the
//! report names every point at which the value changed, identified by the
//! `chain.seq` of the receipt that changed it.
//!
//! What is prohibited is collapsing the presentation to one affiliation value.
//! That prohibition, not rejection, is what closes the relabelling attack: the
//! resolution a reader reaches for is to take the value from the newest
//! receipt, and doing that lets a whole chain be relabelled after the fact by
//! appending a single receipt, with nothing in the record showing the label
//! ever said anything else. Every reported value stays attached to the receipts
//! that actually carry it.

use crate::{Error, IssuerAffiliation, Payload, Result};
use alloc::vec::Vec;

/// One point inside a presentation at which `issuerAffiliation` changed.
///
/// `at_seq` is the `chain.seq` of the receipt carrying the new value, so a
/// report can be quoted against the presentation without recounting positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffiliationChange {
    /// `chain.seq` of the receipt that introduced the new value.
    pub at_seq: u64,
    /// The value carried by the preceding receipt.
    pub from: IssuerAffiliation,
    /// The value carried by the receipt at `at_seq`.
    pub to: IssuerAffiliation,
}

/// What a Chain-Verifier observed about a presentation it accepted.
///
/// An empty report is the ordinary case and means the presentation was
/// structurally sound and uniform in its `issuerAffiliation`.
///
/// There is deliberately no accessor returning a single affiliation value for
/// the chain. A caller wanting to know what a given receipt claims reads that
/// receipt. Supplying one value for the whole presentation is the collapse this
/// type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainReport {
    affiliation_changes: Vec<AffiliationChange>,
}

impl ChainReport {
    /// Every point at which `issuerAffiliation` changed, in presentation order.
    #[must_use]
    pub fn affiliation_changes(&self) -> &[AffiliationChange] {
        &self.affiliation_changes
    }

    /// True when every receipt in the presentation carried the same
    /// `issuerAffiliation`.
    #[must_use]
    pub fn affiliation_is_uniform(&self) -> bool {
        self.affiliation_changes.is_empty()
    }
}

/// Verifies a slice of receipts as one contiguous chain.
///
/// This checks only the chain-level relationships between adjacent receipts.
/// It does NOT re-verify any receipt's own `chain.hash` against its content.
/// `Payload::from_json` already did that at parse time, for every receipt in
/// the slice.
///
/// Rules, applied in this order:
///
/// - An empty slice is rejected.
/// - The head of the presentation (`receipts[0]`) MUST carry `seq == 0` and
///   `prevHash == None`. Per-receipt validation already enforces the
///   seq0/prevHash-null pairing in general; this is the additional
///   chain-level rule that the *head of a presentation* specifically must be
///   sequence zero.
/// - For each adjacent pair, `seq` MUST be contiguous: `seq[i] == seq[i-1] +
///   1`.
/// - For each adjacent pair, `prevHash[i]` MUST equal `Some(hash[i-1])`.
/// - A change in `issuerAffiliation` between adjacent receipts is recorded in
///   the returned [`ChainReport`] and does NOT invalidate the presentation.
///   See the module documentation for why this one is not a rejection.
///
/// # Errors
///
/// Returns [`Error::Validation`] on the first structural rule violated, in the
/// order listed above.
pub fn verify_chain(receipts: &[Payload]) -> Result<ChainReport> {
    let Some((head, rest)) = receipts.split_first() else {
        return Err(Error::Validation("chain must carry at least one receipt"));
    };

    if head.chain_seq() != 0 || head.chain_prev_hash().is_some() {
        return Err(Error::Validation(
            "chain head must have seq 0 and a null prevHash",
        ));
    }

    let mut report = ChainReport::default();
    let mut previous = head;
    for receipt in rest {
        if receipt.chain_seq() != previous.chain_seq() + 1 {
            return Err(Error::Validation("chain.seq is not contiguous"));
        }
        if receipt.chain_prev_hash() != Some(previous.chain_hash()) {
            return Err(Error::Validation(
                "chain.prevHash does not match the preceding receipt",
            ));
        }
        if receipt.issuer_affiliation() != previous.issuer_affiliation() {
            report.affiliation_changes.push(AffiliationChange {
                at_seq: receipt.chain_seq(),
                from: previous.issuer_affiliation().clone(),
                to: receipt.issuer_affiliation().clone(),
            });
        }
        previous = receipt;
    }

    Ok(report)
}
