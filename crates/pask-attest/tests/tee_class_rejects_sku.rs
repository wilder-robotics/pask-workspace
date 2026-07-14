//! PASK-COMPLIANCE-002 & PASK-COMPLIANCE-003 negative-test roster.
//!
//! This file names specific vendor SKU strings solely as inputs to negative
//! tests that assert `TeeClass::from_str` rejects them with
//! `AttestationError::UnsupportedTeeClass`. Per PASK-COMPLIANCE-002, vendor
//! and SKU names are permitted on internal deny-list artifacts (this file and
//! `PASK-COMPLIANCE-003-INTERNAL-deny-list.md`) and MUST NOT appear on public
//! surfaces. This file is EXEMPT from `compliance_grep.sh` — the strings
//! below are the target of enforcement, not violations of it.

use std::str::FromStr;

use pask_attest::{AttestationError, TeeClass};

fn assert_unsupported(value: &str) {
    assert!(matches!(
        TeeClass::from_str(value),
        Err(AttestationError::UnsupportedTeeClass(_))
    ));
}

#[test]
fn rejects_jetson_thor() {
    assert_unsupported("nvidia.jetson-thor-cc");
}

#[test]
fn rejects_orin() {
    assert_unsupported("nvidia.orin-cc");
}

#[test]
fn rejects_sev_snp() {
    assert_unsupported("amd.sev-snp");
}

#[test]
fn rejects_tdx() {
    assert_unsupported("intel.tdx-v1");
}

#[test]
fn rejects_empty_string() {
    assert_unsupported("");
}
