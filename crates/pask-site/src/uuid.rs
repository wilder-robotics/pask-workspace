// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Deterministic UUIDv4-shaped identifiers.

use sha2::{Digest, Sha256};

/// Returns a UUIDv4-formatted string derived from `input`. Deterministic.
///
/// Format: 8-4-4-4-12 lowercase hex, with the "4" and "8-b" bits set at the
/// canonical positions per RFC 4122 §4.4.
pub(crate) fn deterministic_uuid_v4(input: &[u8]) -> String {
    let hash: [u8; 32] = Sha256::digest(input).into();
    let mut bytes: [u8; 16] = hash[..16].try_into().expect("16 bytes");
    // Set version 4 in the top 4 bits of byte 6.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant to RFC 4122 in the top 2 bits of byte 8.
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = lower_hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32],
    )
}

// Copied from pask-adapter::lower_hex to avoid coupling pask-site to
// pask-adapter for a 5-line utility.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
