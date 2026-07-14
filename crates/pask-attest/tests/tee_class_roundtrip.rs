use std::str::FromStr;

use pask_attest::{AttestationError, TeeClass};
use proptest::prelude::*;

#[test]
fn arm64_display_parses_back() {
    let encoded = TeeClass::Arm64TeeV1.to_string();
    assert_eq!(TeeClass::from_str(&encoded).unwrap(), TeeClass::Arm64TeeV1);
}

#[test]
fn x86_display_parses_back() {
    let encoded = TeeClass::X86_64TeeV1.to_string();
    assert_eq!(TeeClass::from_str(&encoded).unwrap(), TeeClass::X86_64TeeV1);
}

proptest! {
    #[test]
    fn arbitrary_string_from_str_is_error_or_known(
        value in any::<String>(),
        class in prop_oneof![
            Just(TeeClass::Arm64TeeV1),
            Just(TeeClass::X86_64TeeV1),
        ],
    ) {
        let parsed = TeeClass::from_str(&value);
        let known = value == "arm64.tee-v1" || value == "x86_64.tee-v1";
        prop_assert_eq!(parsed.is_ok(), known);
        if !known {
            prop_assert!(matches!(
                parsed,
                Err(AttestationError::UnsupportedTeeClass(_))
            ));
        }

        let round_trip = TeeClass::from_str(&class.to_string()).unwrap();
        prop_assert_eq!(round_trip, class);
    }
}
