// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

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
