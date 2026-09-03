// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

use alloc::string::String;
use core::fmt::Write;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Computes a lowercase `sha256:<hex>` digest.
#[must_use]
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

/// Validates the exact lowercase `sha256:<64 hex digits>` representation.
///
/// # Errors
///
/// Returns [`Error::Validation`] when the prefix, length, case, or digits are invalid.
pub fn validate_sha256(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(Error::Validation("digest prefix must be sha256:"));
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(Error::Validation(
            "digest must contain 64 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}
