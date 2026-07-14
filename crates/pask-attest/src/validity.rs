// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::AttestationError;

/// Maximum tolerated difference between the injected clock and quote validity.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// The inclusive validity interval authenticated by an attestation quote.
///
///     use std::time::SystemTime;
///     use pask_attest::ValidityWindow;
///
///     fn inspect(window: &ValidityWindow) {
///         let _ = window.contains(SystemTime::UNIX_EPOCH);
///         assert!(window.not_before() < window.not_after());
///     }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityWindow {
    not_before: SystemTime,
    not_after: SystemTime,
}

impl ValidityWindow {
    pub(crate) fn from_rfc3339(
        not_before: &str,
        not_after: &str,
    ) -> Result<Self, AttestationError> {
        let not_before = parse_rfc3339(not_before, "validity.notBefore")?;
        let not_after = parse_rfc3339(not_after, "validity.notAfter")?;
        if not_after <= not_before {
            return Err(AttestationError::MalformedQuote(
                "validity.notAfter must be later than validity.notBefore".to_owned(),
            ));
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    /// Returns whether an instant falls inside the interval, including both bounds.
    #[must_use]
    pub fn contains(&self, instant: SystemTime) -> bool {
        instant >= self.not_before && instant <= self.not_after
    }

    /// Returns the first valid instant.
    #[must_use]
    pub const fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// Returns the final valid instant.
    #[must_use]
    pub const fn not_after(&self) -> SystemTime {
        self.not_after
    }

    pub(crate) fn check_clock(&self, now: SystemTime) -> Result<(), AttestationError> {
        if let Ok(early_by) = self.not_before.duration_since(now) {
            if early_by > MAX_CLOCK_SKEW {
                return Err(AttestationError::ClockSkew {
                    not_before: self.not_before,
                    now,
                });
            }
        }

        if let Ok(late_by) = now.duration_since(self.not_after) {
            if late_by > MAX_CLOCK_SKEW {
                return Err(AttestationError::ExpiredEvidence {
                    not_after: self.not_after,
                    now,
                });
            }
        }

        Ok(())
    }
}

pub(crate) fn parse_rfc3339(
    value: &str,
    field: &'static str,
) -> Result<SystemTime, AttestationError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| AttestationError::MalformedQuote(format!("{field}: {error}")))?;
    system_time_from_unix_nanos(parsed.unix_timestamp_nanos()).ok_or_else(|| {
        AttestationError::MalformedQuote(format!("{field}: timestamp is outside SystemTime range"))
    })
}

fn system_time_from_unix_nanos(unix_nanos: i128) -> Option<SystemTime> {
    const NANOS_PER_SECOND: i128 = 1_000_000_000;

    let negative = unix_nanos.is_negative();
    let magnitude = if negative {
        unix_nanos.checked_abs()?
    } else {
        unix_nanos
    };
    let seconds = u64::try_from(magnitude / NANOS_PER_SECOND).ok()?;
    let nanos = u32::try_from(magnitude % NANOS_PER_SECOND).ok()?;
    let duration = Duration::new(seconds, nanos);

    if negative {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
}
