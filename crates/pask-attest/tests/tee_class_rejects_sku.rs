// SPDX-License-Identifier: AGPL-3.0-only

//! PASK-COMPLIANCE-002 / PASK-COMPLIANCE-003 negative-test roster.
//!
//! This file asserts that `TeeClass::from_str` rejects SKU and ISA strings
//! with `AttestationError::UnsupportedTeeClass`.
//!
//! The governing doctrine is NOT restated here. It lives in
//! PASK-COMPLIANCE-002 / PASK-COMPLIANCE-003, as amended by Willa on
//! 2026-08-09 in
//! `willa-desk/witness-log/ietf-pask/2026-08-09-panel-ruling-q1-q2b-q3-01-blockers.md`.
//!
//! An earlier revision of this header restated the doctrine and then, on the
//! Axis-B branch, edited that restatement so a code change would read as
//! compliant. Willa ratified the substance and rejected the route: doctrine
//! does not live in a doc-comment, and no PASK-COMPLIANCE-NNN amendment may
//! be made inside a code commit. Read the ruling; do not re-derive the rule
//! from this file.
//!
//! Deny-list exemption: this file names SKU strings as negative-test inputs.
//! It is listed in `EXEMPT_FILES` in `scripts/compliance_grep.sh`, which is
//! run by CI. That script exists as of 2026-08-09; before then this comment
//! claimed exemption from an enforcement that was not running anywhere.

use std::str::FromStr;

use pask_attest::{AttestationError, TeeClass};

fn assert_unsupported(value: &str) {
    assert!(
        matches!(
            TeeClass::from_str(value),
            Err(AttestationError::UnsupportedTeeClass(_))
        ),
        "expected {value:?} to be rejected"
    );
}

#[test]
fn rejects_orin_sku() {
    assert_unsupported("nvidia.orin-cc");
}

#[test]
fn rejects_versioned_tdx_sku() {
    assert_unsupported("intel.tdx-v1");
}

#[test]
fn rejects_h200_sku() {
    assert_unsupported("nvidia.h200-cc");
}

#[test]
fn rejects_instruction_set_architectures() {
    assert_unsupported("arm64.tee-v1");
    assert_unsupported("x86_64.tee-v1");
    assert_unsupported("arm64");
    assert_unsupported("x86_64");
}

#[test]
fn rejects_case_variants() {
    assert_unsupported("Intel.TDX");
    assert_unsupported("ARM.CCA");
}

#[test]
fn rejects_empty_string() {
    assert_unsupported("");
}

#[test]
fn accepts_exactly_the_registry_seed() {
    for class in TeeClass::ALL {
        assert_eq!(TeeClass::from_str(class.as_str()).unwrap(), class);
    }
    assert_eq!(TeeClass::ALL.len(), 6);
}
