// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>

//! Clock trait for attestation and site producers.
//!
//! [`Clock`] is defined here in `pask-attest` and re-exported by `pask-site`
//! to preserve the historical import path.

use std::time::{SystemTime, UNIX_EPOCH};

/// Provides RFC 3339 UTC timestamps to the reference site.
pub trait Clock: Send + Sync {
    /// Returns the current instant as an RFC 3339 UTC string.
    fn now_rfc3339(&self) -> String;
}

/// System clock formatted as RFC 3339 UTC using only `std`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock earlier than UNIX epoch")
            .as_secs();
        format_rfc3339_utc(secs)
    }
}

/// Fixed clock that always returns the same timestamp.
#[derive(Clone, Debug)]
pub struct FixedClock {
    now: String,
}

impl FixedClock {
    /// Creates a fixed clock from an RFC 3339 UTC string.
    #[must_use]
    pub fn new(now: impl Into<String>) -> Self {
        Self { now: now.into() }
    }
}

impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        self.now.clone()
    }
}

fn format_rfc3339_utc(unix_secs: u64) -> String {
    // Days since 1970-01-01, then civil-from-days per Howard Hinnant's algorithm.
    let days = (unix_secs / 86_400) as i64;
    let sod = unix_secs % 86_400;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;

    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's date algorithm, adapted to u64/i64.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::format_rfc3339_utc;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_760_536_800), "2025-10-15T14:00:00Z");
        assert_eq!(format_rfc3339_utc(1_792_072_800), "2026-10-15T14:00:00Z");
    }
}
