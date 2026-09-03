// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! RFC 8785 JCS conformance vectors.

use pask_wire::{
    canonicalize_json,
    testvectors::{
        JCS_LITERALS_EXPECTED, JCS_LITERALS_INPUT, JCS_NUMBERS_EXPECTED, JCS_NUMBERS_INPUT,
        JCS_ORDER_EXPECTED, JCS_ORDER_INPUT,
    },
};

#[test]
fn rfc_8785_vectors_match_byte_for_byte() {
    for (input, expected) in [
        (JCS_NUMBERS_INPUT, JCS_NUMBERS_EXPECTED),
        (JCS_ORDER_INPUT, JCS_ORDER_EXPECTED),
        (JCS_LITERALS_INPUT, JCS_LITERALS_EXPECTED),
    ] {
        assert_eq!(
            canonicalize_json(input.as_bytes()).unwrap(),
            expected.as_bytes()
        );
    }
}
