// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Chain-Verifier: the two chain-level checks required by `-01` §4.1 when two
//! or more receipts are presented as one contiguous chain.
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

use crate::{Error, Payload, Result};

/// Verifies a slice of receipts as one contiguous chain.
///
/// This checks only the chain-level relationships between adjacent receipts.
/// It does NOT re-verify any receipt's own `chain.hash` against its content —
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
///
/// # Errors
///
/// Returns [`Error::Validation`] on the first rule violated, in the order
/// listed above.
pub fn verify_chain(receipts: &[Payload]) -> Result<()> {
    let Some((head, rest)) = receipts.split_first() else {
        return Err(Error::Validation("chain must carry at least one receipt"));
    };

    if head.chain_seq() != 0 || head.chain_prev_hash().is_some() {
        return Err(Error::Validation(
            "chain head must have seq 0 and a null prevHash",
        ));
    }

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
        previous = receipt;
    }

    Ok(())
}
