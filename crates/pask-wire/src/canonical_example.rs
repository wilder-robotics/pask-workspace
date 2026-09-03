// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! The canonical example instance carried by the profile document.
//!
//! The example embedded in the Internet-Draft is emitted from this function,
//! never typed by hand. A test asserts the two are byte-identical, so a change
//! to the wire format that is not reflected in the document fails CI rather
//! than shipping.
//!
//! This exists because the `-00` revision embedded a hand-written figure that
//! used unquoted placeholders (`"sizeBytes": <int>`). It was a schema template
//! presented in a JSON code block, and it was never parseable JSON, so nothing
//! in the build could have caught the three attestation members that had
//! drifted away from the implementation.

use alloc::string::{String, ToString};

use crate::{Error, Payload, Result, testvectors::MINIMAL_VALID_JCS};

/// Emits the canonical example instance, pretty-printed for the document.
///
/// The value is parsed and validated as a [`Payload`], re-serialized to its
/// JCS form, and then indented. Key order is JCS key order; indentation is two
/// spaces. The output is deterministic.
///
/// # Errors
///
/// Returns an error if the canonical test vector fails payload validation or
/// cannot be serialized — either of which is a defect in this crate.
pub fn canonical_example() -> Result<String> {
    let payload = Payload::from_json(MINIMAL_VALID_JCS.as_bytes())?;
    let canonical = payload.to_jcs()?;
    let value: serde_json::Value =
        serde_json::from_slice(&canonical).map_err(|error| Error::Json(error.to_string()))?;
    serde_json::to_string_pretty(&value).map_err(|error| Error::Json(error.to_string()))
}
