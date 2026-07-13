// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

pub mod mapping;

use ed25519_dalek::VerifyingKey;

use crate::{AdapterError, AdapterOutcome, AdapterWriteIn, verify_before_push};

pub use mapping::{PropertyMeldComment, build_comment};

/// Verified PropertyMeld stub pending partner integration terms.
#[derive(Clone, Copy, Debug, Default)]
pub struct PropertyMeldWriteIn;

impl AdapterWriteIn for PropertyMeldWriteIn {
    fn push(
        &self,
        signed_receipt: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<AdapterOutcome, AdapterError> {
        let payload = verify_before_push(signed_receipt, verifying_key)?;

        if payload.adapter_system() != "propertymeld" {
            return Err(AdapterError::AdapterMismatch {
                expected: "propertymeld",
                actual: payload.adapter_system().to_owned(),
            });
        }

        // This code path is defense-in-depth; the pask-wire validator makes it
        // unreachable through parsing. Preserved for a future protocol revision
        // that adds a non-WRITE_ONLY mode.
        if !payload.adapter_is_write_only() {
            return Err(AdapterError::WriteOnlyRequired {
                actual: "<non-write-only>".to_owned(),
            });
        }

        Err(AdapterError::PartnerAgreementRequired {
            adapter: "propertymeld",
            reason: "PropertyMeld does not expose a public developer API. Access is granted only through their partner-integration program. Establish integration terms with PropertyMeld's partner program before enabling this adapter.".to_owned(),
        })
    }

    fn name(&self) -> &'static str {
        "propertymeld"
    }
}
