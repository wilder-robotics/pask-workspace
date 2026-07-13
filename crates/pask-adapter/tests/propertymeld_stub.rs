// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use pask_adapter::{AdapterError, AdapterWriteIn, PropertyMeldWriteIn};

#[test]
fn returns_partner_agreement_required() {
    let (receipt, key) = common::signed_receipt_for("propertymeld", "meld-1");
    assert!(matches!(
        PropertyMeldWriteIn.push(&receipt, &key),
        Err(AdapterError::PartnerAgreementRequired {
            adapter: "propertymeld",
            ..
        })
    ));
}
