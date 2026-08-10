mod common;

use pask_attest::TeeClass;

use common::verified_attestation;

#[test]
fn attestation_has_no_public_constructor() {
    let source = include_str!("../src/attestation.rs");
    assert!(!source.contains("pub fn new"));
    assert!(!source.contains("impl From<"));

    let attestation = verified_attestation();
    assert_eq!(attestation.tee_class(), TeeClass::ArmCca);
    assert!(!attestation.measured_boot().components().is_empty());
    assert_eq!(attestation.platform_evidence().encoding(), "opaque/1");
    assert_eq!(attestation.sealed_evidence().size_bytes(), 4096);
    assert!(!attestation.witness_key().as_str().is_empty());
    assert!(attestation.validity().not_before() < attestation.validity().not_after());

    let claims = attestation.claims();
    assert_eq!(claims.tee_class(), TeeClass::ArmCca);
}

#[test]
fn attestation_cannot_be_deserialized_from_json() {
    // A direct serde_json::from_str::<Attestation> call is intentionally not
    // expressible as a runtime test: it must fail during type checking.
    let source = include_str!("../src/attestation.rs");
    assert!(!source.contains("serde::Deserialize"));
    assert!(!source.contains("Deserialize for Attestation"));
    assert!(!source.contains("derive(Deserialize"));
}
