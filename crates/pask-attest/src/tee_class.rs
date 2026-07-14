// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::AttestationError;

/// A supported category-level confidential-compute profile.
///
///     use std::str::FromStr;
///     use pask_attest::TeeClass;
///
///     let class = TeeClass::from_str("arm64.tee-v1")?;
///     assert_eq!(class.to_string(), "arm64.tee-v1");
///     # Ok::<(), pask_attest::AttestationError>(())
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TeeClass {
    /// ARM64 with the confidential-compute v1 profile.
    #[serde(rename = "arm64.tee-v1")]
    Arm64TeeV1,
    /// x86_64 with the confidential-compute v1 profile.
    #[serde(rename = "x86_64.tee-v1")]
    X86_64TeeV1,
}

impl FromStr for TeeClass {
    type Err = AttestationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "arm64.tee-v1" => Ok(Self::Arm64TeeV1),
            "x86_64.tee-v1" => Ok(Self::X86_64TeeV1),
            other => Err(AttestationError::UnsupportedTeeClass(other.to_owned())),
        }
    }
}

impl Display for TeeClass {
    #[allow(unreachable_patterns)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arm64TeeV1 => formatter.write_str("arm64.tee-v1"),
            Self::X86_64TeeV1 => formatter.write_str("x86_64.tee-v1"),
            _ => Err(fmt::Error),
        }
    }
}
