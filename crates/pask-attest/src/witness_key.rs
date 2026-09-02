// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>

use std::fmt::{self, Display, Formatter};

/// The authenticated identifier used to select a root-of-trust key.
///
///     use pask_attest::WitnessKeyId;
///
///     fn inspect(identifier: &WitnessKeyId) {
///         assert_eq!(identifier.as_str(), identifier.to_string());
///     }
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WitnessKeyId(String);

impl WitnessKeyId {
    pub(crate) fn from_verified(value: String) -> Self {
        Self(value)
    }

    /// Returns the identifier exactly as authenticated by the quote signature.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for WitnessKeyId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
