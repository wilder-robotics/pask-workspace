// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::AttestationError;

/// A supported category-level confidential-compute profile.
///
/// The accepted set is the initial seed of the *TEE Class* registry requested
/// in the profile's IANA considerations. `arm64` and `x86_64` are instruction
/// set architectures, not confidential-compute environments, and the profile
/// states that the `platformEvidence` format is defined by the TEE class — a
/// property an architecture cannot carry.
///
///     use std::str::FromStr;
///     use pask_attest::TeeClass;
///
///     let class = TeeClass::from_str("arm.cca")?;
///     assert_eq!(class.to_string(), "arm.cca");
///     # Ok::<(), pask_attest::AttestationError>(())
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TeeClass {
    /// Intel Trust Domain Extensions.
    #[serde(rename = "intel.tdx")]
    IntelTdx,
    /// AMD Secure Encrypted Virtualization with Secure Nested Paging.
    #[serde(rename = "amd.sev-snp")]
    AmdSevSnp,
    /// Arm Confidential Compute Architecture.
    #[serde(rename = "arm.cca")]
    ArmCca,
    /// NVIDIA H100 confidential computing.
    #[serde(rename = "nvidia.h100-cc")]
    NvidiaH100Cc,
    /// NVIDIA Jetson Thor confidential computing.
    #[serde(rename = "nvidia.jetson-thor-cc")]
    NvidiaJetsonThorCc,
    /// AWS Nitro Enclaves.
    #[serde(rename = "aws.nitro-enclave")]
    AwsNitroEnclave,
}

impl TeeClass {
    /// Every accepted TEE class identifier, in registry order.
    pub const ALL: [Self; 6] = [
        Self::IntelTdx,
        Self::AmdSevSnp,
        Self::ArmCca,
        Self::NvidiaH100Cc,
        Self::NvidiaJetsonThorCc,
        Self::AwsNitroEnclave,
    ];

    /// Returns the registry identifier for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntelTdx => "intel.tdx",
            Self::AmdSevSnp => "amd.sev-snp",
            Self::ArmCca => "arm.cca",
            Self::NvidiaH100Cc => "nvidia.h100-cc",
            Self::NvidiaJetsonThorCc => "nvidia.jetson-thor-cc",
            Self::AwsNitroEnclave => "aws.nitro-enclave",
        }
    }
}

impl FromStr for TeeClass {
    type Err = AttestationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| AttestationError::UnsupportedTeeClass(value.to_owned()))
    }
}

impl Display for TeeClass {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
