// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Reference site producer for the `wilder.pser/0.2` profile.

#![forbid(unsafe_code)]

mod config;
mod error;
mod evidence;
pub mod fixtures;
mod producer;
mod reference;
mod uuid;

pub use config::SiteConfig;
pub use error::SiteError;
pub use evidence::{EvidenceBundle, EvidenceFile};
pub use pask_attest::clock::{Clock, FixedClock, SystemClock};
pub use producer::{Ed25519SiteProducer, EngagementRequest, SiteProducer};
pub use reference::ReferenceSite;
