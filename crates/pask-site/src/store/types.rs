// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Local projections for one operation.
//!
//! The states in this module are application records. They are not profile
//! wire enums, and they are not collapsed into one success flag. Reference
//! progress, sealing, registration, and delivery stay independently readable.

use super::error::StoreError;

/// Schema this process can create and open.
///
/// Any other version is refused. This sprint does not migrate in place.
pub const SCHEMA_VERSION: u32 = 1;

/// What an open of a supported schema is willing to do with an older file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationPolicy {
    /// The only schema version open will accept.
    pub supported_version: u32,
    /// When false, open never rewrites an older or newer schema.
    pub in_place_production_migration: bool,
}

/// Migration policy for this sprint: refuse every version other than
/// [`SCHEMA_VERSION`], and do not rewrite the file.
pub const MIGRATION_POLICY: MigrationPolicy = MigrationPolicy {
    supported_version: SCHEMA_VERSION,
    in_place_production_migration: false,
};

/// Malicious database rollback beyond available external evidence is not
/// generally detected.
///
/// A successful open only shows that this file's schema and local chain
/// invariants hold. An earlier consistent copy of the same file passes those
/// checks. This store does not claim tamper-proof history, and it does not
/// claim that the opened head is the latest head known outside the file.
pub const HISTORY_LIMIT: &str =
    "Malicious database rollback beyond available external evidence is not generally detected.";

/// Assurance provided by a successful open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenAssurance {
    /// The schema and local chain invariants held for the bytes that were opened.
    pub local_invariants_hold: bool,
    /// This implementation does not report tamper-proof or latest-history assurance.
    ///
    /// The value is false. See [`HISTORY_LIMIT`].
    pub claims_tamper_proof_latest_history: bool,
}

/// Durability settings read back from the file and from the open connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedSettings {
    /// Schema version stored in the file.
    pub schema_version: u32,
    /// `PRAGMA journal_mode`, which SQLite persists in the database header.
    pub journal_mode: String,
    /// `PRAGMA synchronous` on this connection. `2` is `FULL`.
    pub synchronous: i64,
    /// Policy name stored beside the pragma value.
    pub synchronous_name: String,
    /// `PRAGMA foreign_keys` on this connection. `1` means enforced.
    pub foreign_keys: i64,
}

/// Exact chain namespace.
///
/// Both strings are matched and stored byte for byte. The store does not trim
/// them, fold case, or merge aliases. Empty strings and embedded NUL bytes are
/// rejected because they are not identities this schema can store, not because
/// they were normalized into some other identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainId {
    /// Issuer identity. On seal this must equal the statement `attestation.witnessKey`.
    pub issuer_identity: String,
    /// Subject or site identity. On seal this must equal the statement `site.id`.
    pub subject_identity: String,
}

impl ChainId {
    /// Builds a chain id from the two exact identity strings.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidConfig`] when either string is empty or
    /// contains a NUL byte.
    pub fn new(
        issuer_identity: impl Into<String>,
        subject_identity: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let issuer_identity = issuer_identity.into();
        let subject_identity = subject_identity.into();
        validate_text("issuer identity", &issuer_identity)?;
        validate_text("subject identity", &subject_identity)?;
        Ok(Self {
            issuer_identity,
            subject_identity,
        })
    }
}

pub(super) fn validate_text(label: &str, value: &str) -> Result<(), StoreError> {
    if value.is_empty() {
        return Err(StoreError::InvalidConfig(format!(
            "{label} must be non-empty and is stored exactly"
        )));
    }
    if value.as_bytes().contains(&0) {
        return Err(StoreError::InvalidConfig(format!(
            "{label} contains a NUL byte, which this store rejects without rewriting the value"
        )));
    }
    Ok(())
}

/// Chain position assigned by the store.
///
/// Callers receive this value. They do not pass `seq` or `prevHash` into the
/// seal API. `prev_hash` is the previous statement's payload `chain.hash`, or
/// `None` for genesis. It is never the COSE transport hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignedPosition {
    /// `chain.seq` the statement must carry.
    pub seq: u64,
    /// Payload `chain.hash` of the preceding sealed statement.
    pub prev_hash: Option<String>,
}

/// Last sealed head of one chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainHead {
    /// Highest sealed `chain.seq`.
    pub seq: u64,
    /// Payload `chain.hash` of that statement.
    pub chain_hash: String,
}

/// Where the transaction boundary fault hooks fire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    /// Before `BEGIN IMMEDIATE`.
    BeforeTransaction,
    /// After the write transaction has begun and before any row change.
    AfterBegin,
    /// After the row changes and before `COMMIT`.
    BeforeCommit,
    /// After `COMMIT` has returned.
    ///
    /// The commit is durable. The caller still observes an error, which is the
    /// crash window between the commit and a response.
    AfterCommit,
}

/// Stops a store transaction at one boundary.
///
/// Production opens leave this unset. A hook is how tests inject the failures
/// named by the durable-state contract. It must not call back into the store.
pub trait FaultInjector: Send + Sync {
    /// Returns an error when the transaction should stop at `point`.
    ///
    /// # Errors
    ///
    /// The returned error aborts the surrounding store call. Points before
    /// `COMMIT` roll the transaction back. [`FaultPoint::AfterCommit`] does
    /// not undo the commit.
    fn check(&self, point: FaultPoint) -> Result<(), StoreError>;
}

/// Reference-write projection.
///
/// `Observed` is recorded only from evidence the caller supplies. Restart does
/// not turn [`Self::Pending`] or [`Self::OutcomeUnknown`] into an observation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceState {
    /// No reference has been reserved.
    Absent,
    /// A stable reference is reserved and the write outcome is not known yet.
    Pending { reference: String },
    /// The caller recorded that the reference write was observed.
    Observed { reference: String, detail: String },
    /// The caller recorded that the reference-write outcome is unknown.
    ///
    /// This is not an acknowledgement.
    OutcomeUnknown {
        reference: String,
        diagnostic: String,
    },
}

/// Seal projection.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealState {
    /// The operation is open and has not been marked ready.
    NotReady,
    /// The operation may be sealed. Sequence is still unassigned.
    Ready,
    /// Statement bytes, transport hash, payload `chain.hash`, and the head committed together.
    Sealed {
        /// Assigned sequence.
        seq: u64,
        /// Payload `chain.hash` of the previous statement, or `None` at sequence 0.
        prev_hash: Option<String>,
        /// Payload `chain.hash` of this statement.
        chain_hash: String,
        /// `sha256:` digest of the exact statement bytes.
        transport_hash: String,
        /// Exact sealed statement bytes.
        statement: Vec<u8>,
    },
}

/// Registration projection.
///
/// A lost response stays pending, with any observed remote id retained. It does
/// not become [`Self::Verified`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistrationState {
    /// Registration has not started.
    Absent,
    /// Registration was submitted. `remote_tx_id` is set only when one was observed.
    Pending { remote_tx_id: Option<String> },
    /// A response identity was observed. This is not verification.
    ReceiptReceived {
        remote_tx_id: String,
        response_identity: String,
    },
    /// The caller explicitly recorded verification.
    ///
    /// The store does not infer this from a timeout or from a missing response.
    Verified {
        remote_tx_id: String,
        response_identity: String,
    },
}

/// Delivery projection. Independent of registration and of sealing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryState {
    /// No delivery outcome has been recorded.
    Absent,
    /// A caller-supplied delivery outcome.
    Recorded(DeliveryOutcome),
}

/// One delivery outcome.
///
/// There is no boolean success field. Completed, failed, and ambiguous stay
/// distinct, and none of them updates the seal or the registration projection.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryOutcome {
    /// Delivery was submitted and has no final outcome.
    Submitted { detail: String },
    /// The caller recorded completion.
    Completed { detail: String },
    /// The caller recorded failure.
    Failed { detail: String },
    /// The caller recorded that the delivery outcome is ambiguous.
    Ambiguous { detail: String },
}

/// Why an outbox row exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxPurpose {
    /// Bytes of a stable reference reserved before sealing.
    Reference,
    /// Exact sealed statement bytes submitted for registration.
    Registration,
}

/// Latest outbox status.
///
/// `Ambiguous` is a status of its own. It is not stored as success and it is
/// not stored as a clean failure that would justify a new signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboxStatus {
    /// Submitted, with no final observation.
    Pending,
    /// The caller recorded that the outcome is unknown.
    Ambiguous,
    /// The caller recorded a response identity.
    ResponseReceived,
    /// The attempt bound was reached.
    Exhausted,
}

/// One append-only outbox history row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptView {
    /// Monotonic id inside the database.
    pub attempt_id: i64,
    /// Position of this history row for its outbox item.
    pub attempt_number: i64,
    /// Local status string (`submitted`, `timeout`, `remote-id-observed`, ...).
    pub status: String,
    /// Remote transaction id observed on this row, when any.
    pub remote_tx_id: Option<String>,
    /// Response identity observed on this row, when any.
    pub response_identity: Option<String>,
    /// Whether this row records transport ambiguity.
    pub ambiguity: bool,
    /// Diagnostic supplied with the row. Empty when the transition had none.
    pub diagnostic: String,
}

/// Persistent outbox item.
///
/// `submitted_bytes` stay fixed across retries. A retry returns those bytes and
/// appends history. It does not sign a new statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxView {
    /// Database id of the item.
    pub outbox_id: i64,
    /// Operation the item belongs to.
    pub operation_id: String,
    /// Reference publication or registration.
    pub purpose: OutboxPurpose,
    /// Exact bytes that were submitted. Retries reuse this value.
    pub submitted_bytes: Vec<u8>,
    /// Remote transaction id, once observed.
    pub remote_tx_id: Option<String>,
    /// Response identity, once observed.
    pub response_identity: Option<String>,
    /// Current status.
    pub status: OutboxStatus,
    /// True when a transport observation was ambiguous.
    pub ambiguity: bool,
    /// Dispatch attempts already recorded.
    pub attempt_count: u32,
    /// Bound copied onto the row when it was created.
    pub max_attempts: u32,
    /// Append-only attempt and observation history.
    pub attempts: Vec<AttemptView>,
}

/// Current local projection of one operation.
///
/// Reference, seal, registration, and delivery are separate fields. This
/// struct has no combined success flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationView {
    /// Chain namespace.
    pub chain: ChainId,
    /// Caller-supplied operation id.
    pub operation_id: String,
    /// Exact request fingerprint bound to the operation id.
    pub request_fingerprint: Vec<u8>,
    /// Reference dimension.
    pub reference: ReferenceState,
    /// Seal dimension.
    pub seal: SealState,
    /// Registration dimension.
    pub registration: RegistrationState,
    /// Delivery dimension.
    pub delivery: DeliveryState,
    /// Outbox rows for this operation, oldest first.
    pub outbox: Vec<OutboxView>,
}

/// One append-only event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    /// Event id assigned in the same transaction as the change it records.
    pub event_id: i64,
    /// Operation the event belongs to.
    pub operation_id: String,
    /// Local event kind. Not a wire enum.
    pub kind: String,
    /// Exact detail stored with the event.
    pub detail: String,
    /// Timestamp from the configured clock.
    pub recorded_at: String,
}

/// Caller-supplied evidence of a reference write.
///
/// The store does not invent an acknowledgement when the caller passes
/// [`Self::OutcomeUnknown`], and it does not invent one on restart.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceWriteEvidence {
    /// The caller observed the remote reference write.
    Observed { detail: String },
    /// The caller does not know whether the remote write happened.
    OutcomeUnknown { diagnostic: String },
}

/// Caller-supplied observation of a registration transport attempt.
///
/// None of these variants sign a statement. [`Self::TimeoutOrLost`] keeps the
/// submitted bytes and any remote id already observed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportObservation {
    /// A remote transaction id was observed. Registration stays pending.
    RemoteId { remote_tx_id: String },
    /// A response identity was observed. This records receipt, not verification.
    Response {
        remote_tx_id: Option<String>,
        response_identity: String,
    },
    /// The response was lost or timed out.
    TimeoutOrLost { diagnostic: String },
}
