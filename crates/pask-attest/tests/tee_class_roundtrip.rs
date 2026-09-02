// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use pask_attest::{AttestationError, TeeClass};
use proptest::prelude::*;

#[test]
fn every_class_display_parses_back() {
    for class in TeeClass::ALL {
        let encoded = class.to_string();
        assert_eq!(TeeClass::from_str(&encoded).unwrap(), class);
    }
}

proptest! {
    #[test]
    fn arbitrary_string_from_str_is_error_or_known(
        value in any::<String>(),
        index in 0_usize..TeeClass::ALL.len(),
    ) {
        let class = TeeClass::ALL[index];
        let parsed = TeeClass::from_str(&value);
        let known = TeeClass::ALL.iter().any(|known| known.as_str() == value);
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
