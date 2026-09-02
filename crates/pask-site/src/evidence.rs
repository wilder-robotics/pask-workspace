// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Evidence-bundle v0 schema and canonicalization.

use serde::{Deserialize, Serialize};

use crate::SiteError;

/// Minimal evidence-bundle format for the reference site.
///
/// The producer hashes this structure, canonicalized as JCS, to produce the
/// engagement evidence digest. For v0, the sealed evidence blob is the same
/// JCS serialization. PASK-004 will replace this with the TEE-sealed
/// ciphertext digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceBundle {
    /// The engagement identifier this bundle belongs to.
    pub engagement_id: String,

    /// Sorted list of files included in the bundle.
    pub files: Vec<EvidenceFile>,
}

impl EvidenceBundle {
    /// Creates a bundle whose files are sorted by relative path.
    #[must_use]
    pub fn new_sorted(engagement_id: impl Into<String>, mut files: Vec<EvidenceFile>) -> Self {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            engagement_id: engagement_id.into(),
            files,
        }
    }

    pub(crate) fn to_jcs(&self) -> Result<Vec<u8>, SiteError> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| SiteError::JsonError(error.to_string()))?;
        pask_wire::canonicalize_json(&bytes)
            .map_err(|error| SiteError::WireError(error.to_string()))
    }
}

/// One file included in an evidence bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceFile {
    /// Relative path from the evidence root, using forward slashes.
    pub path: String,

    /// Byte size of the file.
    pub size_bytes: u64,

    /// Lowercase `sha256:<64 hex>` digest of the raw bytes.
    pub digest: String,
}
