// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Reference site producer for the `wilder.pser/0.5` profile (`pask_wire::SPEC_VERSION`).
//!
//! The durable operation store is a separate local module. It is not wired into
//! [`ReferenceSite`], it does not change the 0.5 producer, and it does not
//! register a `wilder.pser/0.7` profile.

#![forbid(unsafe_code)]

mod config;
mod error;
mod evidence;
pub mod fixtures;
mod producer;
mod reference;
mod store;
mod uuid;

pub use config::SiteConfig;
pub use error::SiteError;
pub use evidence::{EvidenceBundle, EvidenceFile};
pub use pask_attest::clock::{Clock, FixedClock, SystemClock};
pub use producer::{Ed25519SiteProducer, EngagementRequest, SiteProducer};
pub use reference::ReferenceSite;
pub use store::{
    AssignedPosition, AttemptView, ChainHead, ChainId, ChainStore, DeliveryOutcome, DeliveryState,
    EventRecord, FailureClass, FaultInjector, FaultPoint, HISTORY_LIMIT, MIGRATION_POLICY,
    MigrationPolicy, OpenAssurance, OperationView, OutboxPurpose, OutboxStatus, OutboxView,
    PersistedSettings, ReferenceState, ReferenceWriteEvidence, RegistrationState, SCHEMA_VERSION,
    SealState, StoreConfig, StoreError, TransportObservation,
};
