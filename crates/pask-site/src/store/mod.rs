// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Durable local operation and chain state.
//!
//! One SQLite file, opened at an explicit path, holds every chain namespace.
//! A namespace is the exact pair `(issuer identity, subject/site identity)`.
//! The store assigns `chain.seq` and `prevHash`. Callers do not pass either
//! value into the seal API. `prevHash` is the previous payload `chain.hash`.
//! The `sha256:` digest of the COSE statement bytes is the transport hash and
//! is stored beside the statement. It is not used as `prevHash`.
//!
//! Sealed statement bytes, that transport hash, the payload `chain.hash`, and
//! the new chain head commit in one transaction. A rollback of that
//! transaction does not publish the sequence. The same operation id with the
//! same request fingerprint returns the existing projection. The same id with
//! a different fingerprint conflicts.
//!
//! Reference progress, sealing, registration, and delivery are separate
//! projections. None of them is inferred from the others, and the projection
//! has no combined success flag. The outbox keeps the exact submitted bytes
//! and every attempt. A lost response is ambiguity. It does not sign a new
//! statement.
//!
//! Private signing keys and credentials are not accepted by this API and are
//! not written to the database.
//!
//! # History assurance
//!
//! Malicious database rollback beyond available external evidence is not
//! generally detected. [`HISTORY_LIMIT`] states that limit. A successful open
//! means the schema is the supported version and the local invariants hold for
//! this file. An earlier consistent snapshot passes the same checks. Open does
//! not claim tamper-proof history and does not claim that the head is the
//! latest head known outside the file.
//!
//! # What this module does not do
//!
//! It does not replace [`crate::ReferenceSite`], does not change the 0.5
//! producer, and does not register a `wilder.pser/0.7` profile. It does not
//! run a multi-writer lease, and it does not migrate an older schema in place.
//! Key rotation and cross-chain migration are out of scope. On inconsistency
//! the store stops. It does not rebuild a tail, reset an operation id, or
//! rewrite a sealed statement.
//!
//! The statement callback passed to [`ChainStore::commit_seal`] runs while the
//! write transaction is open. It must not call back into the store.

mod config;
mod error;
mod schema;
mod statement;
mod types;

pub use config::StoreConfig;
pub use error::{FailureClass, StoreError};
pub use types::{
    AssignedPosition, AttemptView, ChainHead, ChainId, DeliveryOutcome, DeliveryState, EventRecord,
    FaultInjector, FaultPoint, HISTORY_LIMIT, MIGRATION_POLICY, MigrationPolicy, OpenAssurance,
    OperationView, OutboxPurpose, OutboxStatus, OutboxView, PersistedSettings, ReferenceState,
    ReferenceWriteEvidence, RegistrationState, SCHEMA_VERSION, SealState, TransportObservation,
};

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use schema::{
    append_event, apply_connection_pragmas, check_invariants, create_schema,
    enable_wal_and_full_sync, journal_mode, require_meta, schema_is_empty, synchronous_pragma,
};
use statement::{read_statement, transport_hash};
use types::validate_text;

use self::error::from_sqlite;
use self::schema::{META_FOREIGN_KEYS, META_JOURNAL_MODE, META_SYNCHRONOUS, META_SYNCHRONOUS_NAME};

thread_local! {
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

struct CallbackGuard;

impl CallbackGuard {
    fn enter() -> Result<Self, StoreError> {
        IN_CALLBACK.with(|flag| {
            if flag.get() {
                Err(StoreError::Reentry)
            } else {
                flag.set(true);
                Ok(Self)
            }
        })
    }
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        IN_CALLBACK.with(|flag| flag.set(false));
    }
}

/// Local operation store for one explicit SQLite file.
pub struct ChainStore {
    conn: Mutex<Connection>,
    path: PathBuf,
    clock: Arc<dyn crate::Clock>,
    fault_injector: Option<Arc<dyn FaultInjector>>,
    outbox_max_attempts: u32,
}

impl std::fmt::Debug for ChainStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChainStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ChainStore {
    /// Opens the database at `config.database_path`.
    ///
    /// A new file is created only when schema initialization was requested.
    /// An existing file is checked. A different schema version, a failed
    /// invariant, or a durability policy other than WAL and `synchronous=FULL`
    /// stops the open. Nothing in this function repairs those conditions or
    /// inserts a genesis receipt.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the path, schema, durability settings, or
    /// local invariants cannot be accepted.
    pub fn open(config: StoreConfig) -> Result<Self, StoreError> {
        config.validate()?;
        reject_missing_parent(&config.database_path)?;
        let existed = config.database_path.exists();
        if existed {
            let length = std::fs::metadata(&config.database_path).map_err(|error| {
                StoreError::PublicationStopped {
                    class: FailureClass::Permission,
                    detail: format!("cannot read database metadata: {error}"),
                }
            })?;
            if length.len() == 0 && !config.initialize_schema {
                return Err(StoreError::SchemaNotInitialized {
                    path: config.database_path.display().to_string(),
                });
            }
        } else if !config.initialize_schema {
            return Err(StoreError::SchemaNotInitialized {
                path: config.database_path.display().to_string(),
            });
        }

        let conn = Connection::open(&config.database_path).map_err(from_sqlite)?;
        if let Err(error) = prepare_connection(&conn, config.initialize_schema) {
            drop(conn);
            if !existed {
                remove_sqlite_family(&config.database_path);
            }
            return Err(error);
        }

        Ok(Self {
            conn: Mutex::new(conn),
            path: config.database_path,
            clock: config.clock,
            fault_injector: config.fault_injector,
            outbox_max_attempts: config.outbox_max_attempts,
        })
    }

    /// Path passed to [`Self::open`]. It is not canonicalized.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Local assurance of the open file.
    ///
    /// See [`HISTORY_LIMIT`]. `claims_tamper_proof_latest_history` is false.
    #[must_use]
    pub fn open_assurance(&self) -> OpenAssurance {
        OpenAssurance {
            local_invariants_hold: true,
            claims_tamper_proof_latest_history: false,
        }
    }

    /// Schema migration policy implemented by this process.
    #[must_use]
    pub fn migration_policy(&self) -> MigrationPolicy {
        MIGRATION_POLICY
    }

    /// Durability policy recorded in the file and read back from this connection.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Inconsistent`] when the recorded policy and the
    /// live pragmas disagree. The recorded policy is not rewritten.
    pub fn persisted_settings(&self) -> Result<PersistedSettings, StoreError> {
        let conn = self.connection()?;
        read_settings(&conn)
    }

    /// Creates an operation, or returns the existing one when the fingerprint matches.
    ///
    /// This does not assign a sequence and does not insert a genesis receipt.
    /// A chain row may be created with a null head so the namespace exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OperationConflict`] when the operation id exists
    /// with a different fingerprint.
    pub fn open_operation(
        &self,
        chain: &ChainId,
        operation_id: &str,
        request_fingerprint: &[u8],
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let fingerprint = request_fingerprint.to_vec();
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            if let Some(existing) = fingerprint_of(conn, &issuer, &subject, &operation_id)? {
                if existing != fingerprint {
                    return Err(StoreError::OperationConflict {
                        operation_id: operation_id.clone(),
                    });
                }
                return load_view(conn, &issuer, &subject, &operation_id);
            }
            conn.execute(
                "INSERT INTO chains (issuer_identity, subject_identity, head_seq, head_hash)
                 VALUES (?1, ?2, NULL, NULL)
                 ON CONFLICT(issuer_identity, subject_identity) DO NOTHING",
                params![issuer, subject],
            )
            .map_err(from_sqlite)?;
            conn.execute(
                "INSERT INTO operations (
                    issuer_identity, subject_identity, operation_id, request_fingerprint,
                    reference_state, reference_value, reference_detail,
                    seal_state, registration_state, registration_remote_tx_id,
                    registration_response_identity, delivery_state, delivery_detail,
                    seq, prev_hash, chain_hash, transport_hash, statement_bytes
                 ) VALUES (
                    ?1, ?2, ?3, ?4,
                    'absent', NULL, NULL,
                    'not_ready', 'absent', NULL,
                    NULL, 'absent', NULL,
                    NULL, NULL, NULL, NULL, NULL
                 )",
                params![issuer, subject, operation_id, fingerprint],
            )
            .map_err(from_sqlite)?;
            append_event(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "operation-opened",
                "operation opened",
                &clock.now_rfc3339(),
            )?;
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Reads the current projection.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the operation does not exist.
    pub fn operation(
        &self,
        chain: &ChainId,
        operation_id: &str,
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        let conn = self.connection()?;
        load_view(
            &conn,
            &chain.issuer_identity,
            &chain.subject_identity,
            operation_id,
        )
    }

    /// Sealed head of the chain, or `None` when nothing has been sealed.
    ///
    /// `None` is not a genesis receipt. Genesis is the first successful seal.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Inconsistent`] when the head columns disagree.
    pub fn chain_head(&self, chain: &ChainId) -> Result<Option<ChainHead>, StoreError> {
        self.prepare_chain(chain)?;
        let conn = self.connection()?;
        match load_head(&conn, &chain.issuer_identity, &chain.subject_identity)? {
            (None, None) => Ok(None),
            (Some(seq), Some(chain_hash)) => Ok(Some(ChainHead {
                seq: u64::try_from(seq).map_err(|_| StoreError::Inconsistent {
                    detail: format!("head sequence {seq} is negative"),
                })?,
                chain_hash,
            })),
            _ => Err(StoreError::Inconsistent {
                detail: "chain head has only one of sequence and chain.hash".to_owned(),
            }),
        }
    }

    /// Reserves a stable reference before sealing.
    ///
    /// The reservation is local. It is not an acknowledgement of a remote write.
    ///
    /// # Errors
    ///
    /// Returns a store error when the operation is missing, already sealed, or
    /// already reserved under a different reference.
    pub fn reserve_reference(
        &self,
        chain: &ChainId,
        operation_id: &str,
        reference: &str,
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        validate_text("reference", reference)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let reference = reference.to_owned();
        let max_attempts = self.outbox_max_attempts;
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let raw = require_raw(conn, &issuer, &subject, &operation_id)?;
            if raw.seal_state == "sealed" {
                return Err(StoreError::InvalidTransition {
                    operation_id,
                    detail: "a sealed operation does not accept a new reference reservation"
                        .to_owned(),
                });
            }
            if raw.reference_state != "absent" {
                if raw.reference_value.as_deref() != Some(reference.as_str()) {
                    return Err(StoreError::ReferenceConflict { operation_id });
                }
                return load_view(conn, &issuer, &subject, &operation_id);
            }
            conn.execute(
                "UPDATE operations
                 SET reference_state = 'pending', reference_value = ?1, reference_detail = NULL
                 WHERE issuer_identity = ?2 AND subject_identity = ?3 AND operation_id = ?4",
                params![reference, issuer, subject, operation_id],
            )
            .map_err(from_sqlite)?;
            let now = clock.now_rfc3339();
            append_event(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "reference-reserved",
                &format!("reference={reference}"),
                &now,
            )?;
            insert_outbox(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "reference",
                reference.as_bytes(),
                max_attempts,
                &now,
            )?;
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Records caller-supplied evidence of the reference write.
    ///
    /// [`ReferenceWriteEvidence::OutcomeUnknown`] stays unknown across restart.
    /// This method does not invent an acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a store error when no reference was reserved.
    pub fn record_reference_write(
        &self,
        chain: &ChainId,
        operation_id: &str,
        evidence: ReferenceWriteEvidence,
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        let detail = match &evidence {
            ReferenceWriteEvidence::Observed { detail }
            | ReferenceWriteEvidence::OutcomeUnknown { diagnostic: detail } => detail.clone(),
        };
        reject_nul("reference evidence", &detail)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let raw = require_raw(conn, &issuer, &subject, &operation_id)?;
            if raw.reference_state == "absent" {
                return Err(StoreError::InvalidTransition {
                    operation_id,
                    detail: "no stable reference is reserved".to_owned(),
                });
            }
            let (state, kind, outbox_status, ambiguity) = match &evidence {
                ReferenceWriteEvidence::Observed { .. } => (
                    "observed",
                    "reference-write-observed",
                    "response_received",
                    0,
                ),
                ReferenceWriteEvidence::OutcomeUnknown { .. } => (
                    "outcome_unknown",
                    "reference-write-outcome-unknown",
                    "ambiguous",
                    1,
                ),
            };
            conn.execute(
                "UPDATE operations
                 SET reference_state = ?1, reference_detail = ?2
                 WHERE issuer_identity = ?3 AND subject_identity = ?4 AND operation_id = ?5",
                params![state, detail, issuer, subject, operation_id],
            )
            .map_err(from_sqlite)?;
            let now = clock.now_rfc3339();
            append_event(conn, &issuer, &subject, &operation_id, kind, &detail, &now)?;
            if let Some(outbox_id) =
                outbox_id_for(conn, &issuer, &subject, &operation_id, "reference")?
            {
                observe_outbox(
                    conn,
                    outbox_id,
                    outbox_status,
                    ambiguity,
                    None,
                    None,
                    &detail,
                    &now,
                )?;
            }
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Marks the operation ready to seal without assigning a sequence.
    ///
    /// # Errors
    ///
    /// Returns a store error when the operation is missing or already sealed.
    pub fn mark_ready_to_seal(
        &self,
        chain: &ChainId,
        operation_id: &str,
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let raw = require_raw(conn, &issuer, &subject, &operation_id)?;
            if raw.seal_state == "sealed" {
                return Err(StoreError::InvalidTransition {
                    operation_id,
                    detail: "the operation is already sealed".to_owned(),
                });
            }
            if raw.seal_state == "ready" {
                return load_view(conn, &issuer, &subject, &operation_id);
            }
            conn.execute(
                "UPDATE operations SET seal_state = 'ready'
                 WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3",
                params![issuer, subject, operation_id],
            )
            .map_err(from_sqlite)?;
            append_event(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "ready-to-seal",
                "ready to seal",
                &clock.now_rfc3339(),
            )?;
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Assigns the next chain position, accepts the statement for that position,
    /// and commits the statement, transport hash, payload `chain.hash`, and head.
    ///
    /// `produce` receives the assigned position. The seal API has no `seq` or
    /// `prevHash` argument. When the operation is already sealed and the
    /// fingerprint matches, `produce` is not called and the stored statement is
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OperationConflict`] for a different fingerprint,
    /// [`StoreError::StatementRejected`] when the statement is not the assigned
    /// position, and [`StoreError::PublicationStopped`] when a fault or SQLite
    /// failure stops the commit. A stop before commit leaves the head unchanged.
    pub fn commit_seal<F, E>(
        &self,
        chain: &ChainId,
        operation_id: &str,
        request_fingerprint: &[u8],
        produce: F,
    ) -> Result<OperationView, StoreError>
    where
        F: FnOnce(&AssignedPosition) -> Result<Vec<u8>, E>,
        E: std::fmt::Display,
    {
        self.prepare(chain, operation_id)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let fingerprint = request_fingerprint.to_vec();
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let raw = require_raw(conn, &issuer, &subject, &operation_id)?;
            if raw.fingerprint != fingerprint {
                return Err(StoreError::OperationConflict {
                    operation_id: operation_id.clone(),
                });
            }
            if raw.seal_state == "sealed" {
                return load_view(conn, &issuer, &subject, &operation_id);
            }
            let assigned = next_position(load_head(conn, &issuer, &subject)?)?;
            let statement = {
                let _entered = CallbackGuard::enter()?;
                produce(&assigned).map_err(|error| StoreError::StatementRejected {
                    detail: error.to_string(),
                })?
            };
            let payload = read_statement(&statement)?;
            if payload.chain_seq() != assigned.seq
                || payload.chain_prev_hash() != assigned.prev_hash.as_deref()
            {
                return Err(StoreError::StatementRejected {
                    detail: format!(
                        "statement carries seq {} prevHash {:?}; the store assigned seq {} prevHash {:?}",
                        payload.chain_seq(),
                        payload.chain_prev_hash(),
                        assigned.seq,
                        assigned.prev_hash
                    ),
                });
            }
            if payload.site_id() != subject || payload.witness_key() != issuer {
                return Err(StoreError::StatementRejected {
                    detail: "statement issuer or subject does not match the chain namespace"
                        .to_owned(),
                });
            }
            let chain_hash = payload.chain_hash().to_owned();
            let transport = transport_hash(&statement);
            let seq = i64::try_from(assigned.seq).map_err(|_| StoreError::Inconsistent {
                detail: "assigned sequence does not fit a sqlite integer".to_owned(),
            })?;
            let now = clock.now_rfc3339();
            if raw.seal_state != "ready" {
                conn.execute(
                    "UPDATE operations SET seal_state = 'ready'
                     WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3",
                    params![issuer, subject, operation_id],
                )
                .map_err(from_sqlite)?;
                append_event(
                    conn,
                    &issuer,
                    &subject,
                    &operation_id,
                    "ready-to-seal",
                    "ready to seal",
                    &now,
                )?;
            }
            conn.execute(
                "UPDATE operations
                 SET seal_state = 'sealed', seq = ?1, prev_hash = ?2, chain_hash = ?3,
                     transport_hash = ?4, statement_bytes = ?5
                 WHERE issuer_identity = ?6 AND subject_identity = ?7 AND operation_id = ?8",
                params![
                    seq,
                    assigned.prev_hash,
                    chain_hash,
                    transport,
                    statement,
                    issuer,
                    subject,
                    operation_id
                ],
            )
            .map_err(from_sqlite)?;
            conn.execute(
                "UPDATE chains SET head_seq = ?1, head_hash = ?2
                 WHERE issuer_identity = ?3 AND subject_identity = ?4",
                params![seq, chain_hash, issuer, subject],
            )
            .map_err(from_sqlite)?;
            append_event(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "sealed",
                &format!("seq={seq} chain.hash={chain_hash} transport={transport}"),
                &now,
            )?;
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Copies the sealed statement into the registration outbox.
    ///
    /// The outbox stores those exact bytes. This method does not sign.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotSealed`] when the operation has no statement.
    pub fn begin_registration(
        &self,
        chain: &ChainId,
        operation_id: &str,
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let max_attempts = self.outbox_max_attempts;
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let raw = require_raw(conn, &issuer, &subject, &operation_id)?;
            let Some(statement) = raw.statement_bytes.clone() else {
                return Err(StoreError::NotSealed {
                    operation_id: operation_id.clone(),
                });
            };
            if outbox_id_for(conn, &issuer, &subject, &operation_id, "registration")?.is_some() {
                return load_view(conn, &issuer, &subject, &operation_id);
            }
            conn.execute(
                "UPDATE operations
                 SET registration_state = 'pending'
                 WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3
                   AND registration_state = 'absent'",
                params![issuer, subject, operation_id],
            )
            .map_err(from_sqlite)?;
            let now = clock.now_rfc3339();
            append_event(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "registration-pending",
                "registration submitted",
                &now,
            )?;
            insert_outbox(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "registration",
                &statement,
                max_attempts,
                &now,
            )?;
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Records a caller-supplied registration transport observation.
    ///
    /// A timeout keeps the submitted bytes and any remote id already stored.
    /// It does not verify registration and it does not sign.
    ///
    /// # Errors
    ///
    /// Returns a store error when the outbox item is missing, the remote id
    /// conflicts, or verification would be downgraded.
    pub fn observe_registration(
        &self,
        outbox_id: i64,
        observation: TransportObservation,
    ) -> Result<OperationView, StoreError> {
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let item = require_outbox(conn, outbox_id)?;
            if item.purpose != "registration" {
                return Err(StoreError::InvalidTransition {
                    operation_id: item.operation_id,
                    detail: "observation is for a registration outbox item".to_owned(),
                });
            }
            let raw = require_raw(conn, &item.issuer, &item.subject, &item.operation_id)?;
            if raw.registration_state == "verified" {
                return Err(StoreError::InvalidTransition {
                    operation_id: item.operation_id,
                    detail: "verified registration is not downgraded by a later observation"
                        .to_owned(),
                });
            }
            let now = clock.now_rfc3339();
            match observation {
                TransportObservation::RemoteId { remote_tx_id } => {
                    validate_text("remote transaction id", &remote_tx_id)?;
                    same_remote_id(&item.remote_tx_id, Some(&remote_tx_id), &item.operation_id)?;
                    conn.execute(
                        "UPDATE operations
                         SET registration_remote_tx_id = ?1
                         WHERE issuer_identity = ?2 AND subject_identity = ?3 AND operation_id = ?4",
                        params![remote_tx_id, item.issuer, item.subject, item.operation_id],
                    )
                    .map_err(from_sqlite)?;
                    let status = if item.ambiguity == 1 {
                        "ambiguous"
                    } else {
                        "pending"
                    };
                    observe_outbox(
                        conn,
                        outbox_id,
                        status,
                        item.ambiguity,
                        Some(&remote_tx_id),
                        item.response_identity.as_deref(),
                        "remote transaction id observed",
                        &now,
                    )?;
                }
                TransportObservation::Response {
                    remote_tx_id,
                    response_identity,
                } => {
                    validate_text("response identity", &response_identity)?;
                    if let Some(remote) = &remote_tx_id {
                        validate_text("remote transaction id", remote)?;
                    }
                    same_remote_id(
                        &item.remote_tx_id,
                        remote_tx_id.as_deref(),
                        &item.operation_id,
                    )?;
                    let remote = remote_tx_id.or(item.remote_tx_id.clone());
                    let Some(remote) = remote else {
                        return Err(StoreError::InvalidTransition {
                            operation_id: item.operation_id,
                            detail: "a registration response needs a remote transaction id"
                                .to_owned(),
                        });
                    };
                    conn.execute(
                        "UPDATE operations
                         SET registration_state = 'receipt_received',
                             registration_remote_tx_id = ?1,
                             registration_response_identity = ?2
                         WHERE issuer_identity = ?3 AND subject_identity = ?4 AND operation_id = ?5",
                        params![
                            remote,
                            response_identity,
                            item.issuer,
                            item.subject,
                            item.operation_id
                        ],
                    )
                    .map_err(from_sqlite)?;
                    append_event(
                        conn,
                        &item.issuer,
                        &item.subject,
                        &item.operation_id,
                        "receipt-received",
                        &format!("remote={remote} response={response_identity}"),
                        &now,
                    )?;
                    observe_outbox(
                        conn,
                        outbox_id,
                        "response_received",
                        0,
                        Some(&remote),
                        Some(&response_identity),
                        "response identity observed",
                        &now,
                    )?;
                }
                TransportObservation::TimeoutOrLost { diagnostic } => {
                    reject_nul("timeout diagnostic", &diagnostic)?;
                    observe_outbox(
                        conn,
                        outbox_id,
                        "ambiguous",
                        1,
                        item.remote_tx_id.as_deref(),
                        item.response_identity.as_deref(),
                        &diagnostic,
                        &now,
                    )?;
                }
            }
            load_view(conn, &item.issuer, &item.subject, &item.operation_id)
        })
    }

    /// Records explicit registration verification.
    ///
    /// The caller supplies the remote id and response identity. A timeout does
    /// not call this, and this does not sign.
    ///
    /// # Errors
    ///
    /// Returns a store error when the outbox item is missing or the ids conflict.
    pub fn mark_registration_verified(
        &self,
        outbox_id: i64,
        remote_tx_id: &str,
        response_identity: &str,
    ) -> Result<OperationView, StoreError> {
        validate_text("remote transaction id", remote_tx_id)?;
        validate_text("response identity", response_identity)?;
        let remote_tx_id = remote_tx_id.to_owned();
        let response_identity = response_identity.to_owned();
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let item = require_outbox(conn, outbox_id)?;
            same_remote_id(&item.remote_tx_id, Some(&remote_tx_id), &item.operation_id)?;
            if let Some(existing) = &item.response_identity
                && existing != &response_identity
            {
                return Err(StoreError::InvalidTransition {
                    operation_id: item.operation_id,
                    detail: "response identity differs from the recorded response".to_owned(),
                });
            }
            let now = clock.now_rfc3339();
            let raw = require_raw(conn, &item.issuer, &item.subject, &item.operation_id)?;
            if raw.registration_state != "receipt_received" {
                append_event(
                    conn,
                    &item.issuer,
                    &item.subject,
                    &item.operation_id,
                    "receipt-received",
                    &format!("remote={remote_tx_id} response={response_identity}"),
                    &now,
                )?;
            }
            conn.execute(
                "UPDATE operations
                 SET registration_state = 'verified',
                     registration_remote_tx_id = ?1,
                     registration_response_identity = ?2
                 WHERE issuer_identity = ?3 AND subject_identity = ?4 AND operation_id = ?5",
                params![
                    remote_tx_id,
                    response_identity,
                    item.issuer,
                    item.subject,
                    item.operation_id
                ],
            )
            .map_err(from_sqlite)?;
            append_event(
                conn,
                &item.issuer,
                &item.subject,
                &item.operation_id,
                "registration-verified",
                &format!("remote={remote_tx_id} response={response_identity}"),
                &now,
            )?;
            observe_outbox(
                conn,
                outbox_id,
                "response_received",
                0,
                Some(&remote_tx_id),
                Some(&response_identity),
                "registration verified by caller",
                &now,
            )?;
            load_view(conn, &item.issuer, &item.subject, &item.operation_id)
        })
    }

    /// Records another dispatch of the same submitted bytes.
    ///
    /// The bound is the value stored on the row. Exhaustion does not change
    /// the bytes and does not sign. Ambiguity already recorded on the row stays
    /// recorded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RetriesExhausted`] when the bound is already met.
    pub fn retry_outbox(&self, outbox_id: i64) -> Result<OperationView, StoreError> {
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            let item = require_outbox(conn, outbox_id)?;
            if item.attempt_count >= item.max_attempts {
                conn.execute(
                    "UPDATE outbox SET status = 'exhausted' WHERE outbox_id = ?1",
                    [outbox_id],
                )
                .map_err(from_sqlite)?;
                let now = clock.now_rfc3339();
                insert_attempt(
                    conn,
                    outbox_id,
                    "exhausted",
                    item.ambiguity,
                    item.remote_tx_id.as_deref(),
                    item.response_identity.as_deref(),
                    "retry bound reached",
                    &now,
                )?;
                // Commit the exhaustion marker, then report the bound to the caller.
                return Ok(Err(StoreError::RetriesExhausted {
                    outbox_id,
                    attempts: item.attempt_count,
                    max_attempts: item.max_attempts,
                }));
            }
            let now = clock.now_rfc3339();
            let next_count = item.attempt_count + 1;
            let status = if item.ambiguity == 1 {
                "ambiguous"
            } else {
                item.status.as_str()
            };
            conn.execute(
                "UPDATE outbox SET attempt_count = ?1, status = ?2 WHERE outbox_id = ?3",
                params![next_count, status, outbox_id],
            )
            .map_err(from_sqlite)?;
            insert_attempt(
                conn,
                outbox_id,
                "submitted",
                item.ambiguity,
                item.remote_tx_id.as_deref(),
                item.response_identity.as_deref(),
                "retry of the original submitted bytes",
                &now,
            )?;
            append_event(
                conn,
                &item.issuer,
                &item.subject,
                &item.operation_id,
                "outbox-submitted",
                &format!("outbox={outbox_id} attempt={next_count}"),
                &now,
            )?;
            Ok(Ok(load_view(
                conn,
                &item.issuer,
                &item.subject,
                &item.operation_id,
            )?))
        })?
    }

    /// Records a delivery outcome without changing seal or registration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the operation does not exist.
    pub fn record_delivery(
        &self,
        chain: &ChainId,
        operation_id: &str,
        outcome: DeliveryOutcome,
    ) -> Result<OperationView, StoreError> {
        self.prepare(chain, operation_id)?;
        let (state, detail) = match &outcome {
            DeliveryOutcome::Submitted { detail }
            | DeliveryOutcome::Completed { detail }
            | DeliveryOutcome::Failed { detail }
            | DeliveryOutcome::Ambiguous { detail } => (
                match &outcome {
                    DeliveryOutcome::Submitted { .. } => "submitted",
                    DeliveryOutcome::Completed { .. } => "completed",
                    DeliveryOutcome::Failed { .. } => "failed",
                    DeliveryOutcome::Ambiguous { .. } => "ambiguous",
                },
                detail.clone(),
            ),
        };
        reject_nul("delivery detail", &detail)?;
        let issuer = chain.issuer_identity.clone();
        let subject = chain.subject_identity.clone();
        let operation_id = operation_id.to_owned();
        let clock = Arc::clone(&self.clock);
        self.transact(move |conn| {
            require_raw(conn, &issuer, &subject, &operation_id)?;
            conn.execute(
                "UPDATE operations
                 SET delivery_state = ?1, delivery_detail = ?2
                 WHERE issuer_identity = ?3 AND subject_identity = ?4 AND operation_id = ?5",
                params![state, detail, issuer, subject, operation_id],
            )
            .map_err(from_sqlite)?;
            append_event(
                conn,
                &issuer,
                &subject,
                &operation_id,
                "delivery-recorded",
                &format!("delivery={state} {detail}"),
                &clock.now_rfc3339(),
            )?;
            load_view(conn, &issuer, &subject, &operation_id)
        })
    }

    /// Append-only events for one operation, oldest first.
    ///
    /// # Errors
    ///
    /// Returns a store error when the read fails.
    pub fn events(
        &self,
        chain: &ChainId,
        operation_id: &str,
    ) -> Result<Vec<EventRecord>, StoreError> {
        self.prepare(chain, operation_id)?;
        let conn = self.connection()?;
        let mut statement = conn
            .prepare(
                "SELECT event_id, operation_id, kind, detail, recorded_at
                 FROM events
                 WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3
                 ORDER BY event_id",
            )
            .map_err(from_sqlite)?;
        let rows = statement
            .query_map(
                params![chain.issuer_identity, chain.subject_identity, operation_id],
                |row| {
                    Ok(EventRecord {
                        event_id: row.get(0)?,
                        operation_id: row.get(1)?,
                        kind: row.get(2)?,
                        detail: row.get(3)?,
                        recorded_at: row.get(4)?,
                    })
                },
            )
            .map_err(from_sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(from_sqlite)?;
        Ok(rows)
    }

    #[cfg(test)]
    pub(crate) fn page_count_for_test(&self) -> Result<u32, StoreError> {
        let conn = self.connection()?;
        let count: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(from_sqlite)?;
        u32::try_from(count).map_err(|_| StoreError::Sqlite {
            detail: "page_count does not fit u32".to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn limit_page_count_for_test(&self, pages: u32) -> Result<(), StoreError> {
        let conn = self.connection()?;
        conn.pragma_update(None, "max_page_count", pages)
            .map_err(from_sqlite)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_fault_for_test(&mut self, fault: Option<Arc<dyn FaultInjector>>) {
        self.fault_injector = fault;
    }

    #[cfg(test)]
    pub(crate) fn checkpoint_for_test(&self) -> Result<(), StoreError> {
        let conn = self.connection()?;
        conn.execute_batch("PRAGMA wal_checkpoint(FULL)")
            .map_err(from_sqlite)?;
        Ok(())
    }

    fn prepare(&self, chain: &ChainId, operation_id: &str) -> Result<(), StoreError> {
        self.prepare_chain(chain)?;
        validate_text("operation id", operation_id)
    }

    fn prepare_chain(&self, chain: &ChainId) -> Result<(), StoreError> {
        self.ensure_not_reentering()?;
        validate_text("issuer identity", &chain.issuer_identity)?;
        validate_text("subject identity", &chain.subject_identity)
    }

    fn ensure_not_reentering(&self) -> Result<(), StoreError> {
        IN_CALLBACK.with(|flag| {
            if flag.get() {
                Err(StoreError::Reentry)
            } else {
                Ok(())
            }
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.ensure_not_reentering()?;
        self.conn.lock().map_err(|_| StoreError::LockPoisoned)
    }

    fn transact<T>(
        &self,
        body: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_not_reentering()?;
        let fault = self.fault_injector.clone();
        check_fault(&fault, FaultPoint::BeforeTransaction)?;
        let mut guard = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(from_sqlite)?;
        check_fault(&fault, FaultPoint::AfterBegin)?;
        let value = body(&tx)?;
        check_fault(&fault, FaultPoint::BeforeCommit)?;
        tx.commit().map_err(from_sqlite)?;
        drop(guard);
        check_fault(&fault, FaultPoint::AfterCommit)?;
        Ok(value)
    }
}

fn check_fault(
    fault: &Option<Arc<dyn FaultInjector>>,
    point: FaultPoint,
) -> Result<(), StoreError> {
    if let Some(injector) = fault {
        injector.check(point)?;
    }
    Ok(())
}

fn reject_missing_parent(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(StoreError::PublicationStopped {
            class: FailureClass::Permission,
            detail: format!(
                "parent directory {} does not exist; the store does not create directories",
                parent.display()
            ),
        });
    }
    Ok(())
}

fn remove_sqlite_family(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(sidecar(path, "-wal"));
    let _ = std::fs::remove_file(sidecar(path, "-shm"));
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn prepare_connection(conn: &Connection, initialize_schema: bool) -> Result<(), StoreError> {
    apply_connection_pragmas(conn)?;
    if schema_is_empty(conn)? {
        if !initialize_schema {
            return Err(StoreError::SchemaNotInitialized {
                path: "existing file has no schema".to_owned(),
            });
        }
        enable_wal_and_full_sync(conn)?;
        create_schema(conn)?;
        return check_invariants(conn).map_err(as_inconsistent);
    }
    require_supported_schema_mapped(conn)?;
    check_invariants(conn).map_err(as_inconsistent)
}

fn require_supported_schema_mapped(conn: &Connection) -> Result<(), StoreError> {
    schema::require_supported_schema(conn).map_err(as_inconsistent)
}

fn as_inconsistent(error: StoreError) -> StoreError {
    match error {
        StoreError::Sqlite { detail } => StoreError::Inconsistent {
            detail: format!("existing database is not a consistent store: {detail}"),
        },
        other => other,
    }
}

fn read_settings(conn: &Connection) -> Result<PersistedSettings, StoreError> {
    let schema_version = require_meta(conn, schema::META_SCHEMA_VERSION)?;
    let schema_version: u32 = schema_version
        .parse()
        .map_err(|_| StoreError::Inconsistent {
            detail: format!("schema_version {schema_version} is not an integer"),
        })?;
    let journal = journal_mode(conn)?;
    let recorded_journal = require_meta(conn, META_JOURNAL_MODE)?;
    if journal != recorded_journal {
        return Err(StoreError::Inconsistent {
            detail: format!("journal_mode is {journal} but schema_meta records {recorded_journal}"),
        });
    }
    let synchronous = synchronous_pragma(conn)?;
    let recorded_sync = require_meta(conn, META_SYNCHRONOUS)?;
    if recorded_sync != synchronous.to_string() {
        return Err(StoreError::Inconsistent {
            detail: format!("synchronous is {synchronous} but schema_meta records {recorded_sync}"),
        });
    }
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(from_sqlite)?;
    let recorded_fk = require_meta(conn, META_FOREIGN_KEYS)?;
    if recorded_fk != foreign_keys.to_string() {
        return Err(StoreError::Inconsistent {
            detail: format!("foreign_keys is {foreign_keys} but schema_meta records {recorded_fk}"),
        });
    }
    Ok(PersistedSettings {
        schema_version,
        journal_mode: journal,
        synchronous,
        synchronous_name: require_meta(conn, META_SYNCHRONOUS_NAME)?,
        foreign_keys,
    })
}

fn reject_nul(label: &str, value: &str) -> Result<(), StoreError> {
    if value.as_bytes().contains(&0) {
        return Err(StoreError::InvalidConfig(format!(
            "{label} contains a NUL byte, which this store rejects without rewriting the value"
        )));
    }
    Ok(())
}

struct RawOperation {
    fingerprint: Vec<u8>,
    reference_state: String,
    reference_value: Option<String>,
    seal_state: String,
    registration_state: String,
    statement_bytes: Option<Vec<u8>>,
}

fn require_raw(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
) -> Result<RawOperation, StoreError> {
    let row = conn
        .query_row(
            "SELECT request_fingerprint, reference_state, reference_value, seal_state,
                    registration_state, statement_bytes
             FROM operations
             WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3",
            params![issuer, subject, operation_id],
            |row| {
                Ok(RawOperation {
                    fingerprint: row.get(0)?,
                    reference_state: row.get(1)?,
                    reference_value: row.get(2)?,
                    seal_state: row.get(3)?,
                    registration_state: row.get(4)?,
                    statement_bytes: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(from_sqlite)?;
    row.ok_or_else(|| StoreError::NotFound {
        operation_id: operation_id.to_owned(),
    })
}

fn fingerprint_of(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
) -> Result<Option<Vec<u8>>, StoreError> {
    conn.query_row(
        "SELECT request_fingerprint FROM operations
         WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3",
        params![issuer, subject, operation_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(from_sqlite)
}

fn load_head(
    conn: &Connection,
    issuer: &str,
    subject: &str,
) -> Result<(Option<i64>, Option<String>), StoreError> {
    let row = conn
        .query_row(
            "SELECT head_seq, head_hash FROM chains
             WHERE issuer_identity = ?1 AND subject_identity = ?2",
            params![issuer, subject],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(from_sqlite)?;
    Ok(row.unwrap_or((None, None)))
}

fn next_position(head: (Option<i64>, Option<String>)) -> Result<AssignedPosition, StoreError> {
    match head {
        (None, None) => Ok(AssignedPosition {
            seq: 0,
            prev_hash: None,
        }),
        (Some(seq), Some(chain_hash)) if seq >= 0 => {
            let next = seq.checked_add(1).ok_or_else(|| StoreError::Inconsistent {
                detail: "chain sequence cannot advance".to_owned(),
            })?;
            Ok(AssignedPosition {
                seq: u64::try_from(next).map_err(|_| StoreError::Inconsistent {
                    detail: "chain sequence overflow".to_owned(),
                })?,
                prev_hash: Some(chain_hash),
            })
        }
        _ => Err(StoreError::Inconsistent {
            detail: "chain head is incomplete; not initializing genesis".to_owned(),
        }),
    }
}

struct OutboxRaw {
    issuer: String,
    subject: String,
    operation_id: String,
    purpose: String,
    remote_tx_id: Option<String>,
    response_identity: Option<String>,
    status: String,
    ambiguity: i64,
    attempt_count: u32,
    max_attempts: u32,
}

fn require_outbox(conn: &Connection, outbox_id: i64) -> Result<OutboxRaw, StoreError> {
    let row = conn
        .query_row(
            "SELECT issuer_identity, subject_identity, operation_id, purpose, remote_tx_id,
                    response_identity, status, ambiguity, attempt_count, max_attempts
             FROM outbox WHERE outbox_id = ?1",
            [outbox_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()
        .map_err(from_sqlite)?;
    let Some(row) = row else {
        return Err(StoreError::OutboxNotFound { outbox_id });
    };
    Ok(OutboxRaw {
        issuer: row.0,
        subject: row.1,
        operation_id: row.2,
        purpose: row.3,
        remote_tx_id: row.4,
        response_identity: row.5,
        status: row.6,
        ambiguity: row.7,
        attempt_count: u32::try_from(row.8).map_err(|_| StoreError::Inconsistent {
            detail: format!("outbox {outbox_id} attempt count is invalid"),
        })?,
        max_attempts: u32::try_from(row.9).map_err(|_| StoreError::Inconsistent {
            detail: format!("outbox {outbox_id} max attempts is invalid"),
        })?,
    })
}

fn outbox_id_for(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
    purpose: &str,
) -> Result<Option<i64>, StoreError> {
    conn.query_row(
        "SELECT outbox_id FROM outbox
         WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3 AND purpose = ?4",
        params![issuer, subject, operation_id, purpose],
        |row| row.get(0),
    )
    .optional()
    .map_err(from_sqlite)
}

fn same_remote_id(
    existing: &Option<String>,
    incoming: Option<&str>,
    operation_id: &str,
) -> Result<(), StoreError> {
    if let (Some(existing), Some(incoming)) = (existing, incoming)
        && existing != incoming
    {
        return Err(StoreError::RemoteIdConflict {
            operation_id: operation_id.to_owned(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_outbox(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
    purpose: &str,
    submitted: &[u8],
    max_attempts: u32,
    now: &str,
) -> Result<i64, StoreError> {
    let outbox_id = schema::alloc_id(conn, schema::META_OUTBOX_NEXT_ID)?;
    conn.execute(
        "INSERT INTO outbox (
            outbox_id, issuer_identity, subject_identity, operation_id, purpose,
            submitted_bytes, remote_tx_id, response_identity, status, ambiguity,
            attempt_count, max_attempts
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, 'pending', 0, 1, ?7)",
        params![
            outbox_id,
            issuer,
            subject,
            operation_id,
            purpose,
            submitted,
            max_attempts
        ],
    )
    .map_err(from_sqlite)?;
    insert_attempt(
        conn,
        outbox_id,
        "submitted",
        0,
        None,
        None,
        "initial submission",
        now,
    )?;
    append_event(
        conn,
        issuer,
        subject,
        operation_id,
        "outbox-submitted",
        &format!("outbox={outbox_id} purpose={purpose}"),
        now,
    )?;
    Ok(outbox_id)
}

#[allow(clippy::too_many_arguments)]
fn observe_outbox(
    conn: &Connection,
    outbox_id: i64,
    status: &str,
    ambiguity: i64,
    remote_tx_id: Option<&str>,
    response_identity: Option<&str>,
    diagnostic: &str,
    now: &str,
) -> Result<(), StoreError> {
    let item = require_outbox(conn, outbox_id)?;
    let remote = remote_tx_id
        .map(str::to_owned)
        .or(item.remote_tx_id.clone());
    let response = response_identity
        .map(str::to_owned)
        .or(item.response_identity.clone());
    conn.execute(
        "UPDATE outbox
         SET status = ?1, ambiguity = ?2, remote_tx_id = ?3, response_identity = ?4
         WHERE outbox_id = ?5",
        params![status, ambiguity, remote, response, outbox_id],
    )
    .map_err(from_sqlite)?;
    insert_attempt(
        conn,
        outbox_id,
        status,
        ambiguity,
        remote.as_deref(),
        response.as_deref(),
        diagnostic,
        now,
    )?;
    append_event(
        conn,
        &item.issuer,
        &item.subject,
        &item.operation_id,
        "outbox-observation",
        &format!("outbox={outbox_id} status={status} ambiguity={ambiguity}"),
        now,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_attempt(
    conn: &Connection,
    outbox_id: i64,
    status: &str,
    ambiguity: i64,
    remote_tx_id: Option<&str>,
    response_identity: Option<&str>,
    diagnostic: &str,
    _now: &str,
) -> Result<(), StoreError> {
    let attempt_id = schema::alloc_id(conn, schema::META_ATTEMPT_NEXT_ID)?;
    let attempt_number: i64 = conn
        .query_row(
            "SELECT COUNT(*) + 1 FROM outbox_attempts WHERE outbox_id = ?1",
            [outbox_id],
            |row| row.get(0),
        )
        .map_err(from_sqlite)?;
    conn.execute(
        "INSERT INTO outbox_attempts (
            attempt_id, outbox_id, attempt_number, status, remote_tx_id, response_identity,
            ambiguity, diagnostic
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            attempt_id,
            outbox_id,
            attempt_number,
            status,
            remote_tx_id,
            response_identity,
            ambiguity,
            diagnostic
        ],
    )
    .map_err(from_sqlite)?;
    Ok(())
}

fn load_view(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
) -> Result<OperationView, StoreError> {
    let row = conn
        .query_row(
            "SELECT request_fingerprint, reference_state, reference_value, reference_detail,
                    seal_state, registration_state, registration_remote_tx_id,
                    registration_response_identity, delivery_state, delivery_detail,
                    seq, prev_hash, chain_hash, transport_hash, statement_bytes
             FROM operations
             WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3",
            params![issuer, subject, operation_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(from_sqlite)?
        .ok_or_else(|| StoreError::NotFound {
            operation_id: operation_id.to_owned(),
        })?;
    let reference = match row.1.as_str() {
        "absent" => ReferenceState::Absent,
        "pending" => ReferenceState::Pending {
            reference: required_text(&row.2, "pending reference")?,
        },
        "observed" => ReferenceState::Observed {
            reference: required_text(&row.2, "observed reference")?,
            detail: row.3.clone().unwrap_or_default(),
        },
        "outcome_unknown" => ReferenceState::OutcomeUnknown {
            reference: required_text(&row.2, "unknown reference")?,
            diagnostic: row.3.clone().unwrap_or_default(),
        },
        other => {
            return Err(StoreError::Inconsistent {
                detail: format!("unknown reference state {other}"),
            });
        }
    };
    let seal = match row.4.as_str() {
        "not_ready" => SealState::NotReady,
        "ready" => SealState::Ready,
        "sealed" => SealState::Sealed {
            seq: u64::try_from(row.10.ok_or_else(|| StoreError::Inconsistent {
                detail: "sealed operation has no sequence".to_owned(),
            })?)
            .map_err(|_| StoreError::Inconsistent {
                detail: "sealed sequence is negative".to_owned(),
            })?,
            prev_hash: row.11.clone(),
            chain_hash: row.12.clone().ok_or_else(|| StoreError::Inconsistent {
                detail: "sealed operation has no chain.hash".to_owned(),
            })?,
            transport_hash: row.13.clone().ok_or_else(|| StoreError::Inconsistent {
                detail: "sealed operation has no transport hash".to_owned(),
            })?,
            statement: row.14.clone().ok_or_else(|| StoreError::Inconsistent {
                detail: "sealed operation has no statement".to_owned(),
            })?,
        },
        other => {
            return Err(StoreError::Inconsistent {
                detail: format!("unknown seal state {other}"),
            });
        }
    };
    let registration = match row.5.as_str() {
        "absent" => RegistrationState::Absent,
        "pending" => RegistrationState::Pending {
            remote_tx_id: row.6.clone(),
        },
        "receipt_received" => RegistrationState::ReceiptReceived {
            remote_tx_id: required_text(&row.6, "receipt remote id")?,
            response_identity: required_text(&row.7, "receipt response identity")?,
        },
        "verified" => RegistrationState::Verified {
            remote_tx_id: required_text(&row.6, "verified remote id")?,
            response_identity: required_text(&row.7, "verified response identity")?,
        },
        other => {
            return Err(StoreError::Inconsistent {
                detail: format!("unknown registration state {other}"),
            });
        }
    };
    let delivery = match row.8.as_str() {
        "absent" => DeliveryState::Absent,
        "submitted" => DeliveryState::Recorded(DeliveryOutcome::Submitted {
            detail: row.9.clone().unwrap_or_default(),
        }),
        "completed" => DeliveryState::Recorded(DeliveryOutcome::Completed {
            detail: row.9.clone().unwrap_or_default(),
        }),
        "failed" => DeliveryState::Recorded(DeliveryOutcome::Failed {
            detail: row.9.clone().unwrap_or_default(),
        }),
        "ambiguous" => DeliveryState::Recorded(DeliveryOutcome::Ambiguous {
            detail: row.9.clone().unwrap_or_default(),
        }),
        other => {
            return Err(StoreError::Inconsistent {
                detail: format!("unknown delivery state {other}"),
            });
        }
    };
    Ok(OperationView {
        chain: ChainId {
            issuer_identity: issuer.to_owned(),
            subject_identity: subject.to_owned(),
        },
        operation_id: operation_id.to_owned(),
        request_fingerprint: row.0,
        reference,
        seal,
        registration,
        delivery,
        outbox: load_outbox(conn, issuer, subject, operation_id)?,
    })
}

fn required_text(value: &Option<String>, label: &str) -> Result<String, StoreError> {
    value.clone().ok_or_else(|| StoreError::Inconsistent {
        detail: format!("{label} is missing"),
    })
}

fn load_outbox(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
) -> Result<Vec<OutboxView>, StoreError> {
    let mut statement = conn
        .prepare(
            "SELECT outbox_id, purpose, submitted_bytes, remote_tx_id, response_identity,
                    status, ambiguity, attempt_count, max_attempts
             FROM outbox
             WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3
             ORDER BY outbox_id",
        )
        .map_err(from_sqlite)?;
    let rows = statement
        .query_map(params![issuer, subject, operation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(from_sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_sqlite)?;
    let mut views = Vec::with_capacity(rows.len());
    for row in rows {
        views.push(OutboxView {
            outbox_id: row.0,
            operation_id: operation_id.to_owned(),
            purpose: match row.1.as_str() {
                "reference" => OutboxPurpose::Reference,
                "registration" => OutboxPurpose::Registration,
                other => {
                    return Err(StoreError::Inconsistent {
                        detail: format!("unknown outbox purpose {other}"),
                    });
                }
            },
            submitted_bytes: row.2,
            remote_tx_id: row.3,
            response_identity: row.4,
            status: match row.5.as_str() {
                "pending" => OutboxStatus::Pending,
                "ambiguous" => OutboxStatus::Ambiguous,
                "response_received" => OutboxStatus::ResponseReceived,
                "exhausted" => OutboxStatus::Exhausted,
                other => {
                    return Err(StoreError::Inconsistent {
                        detail: format!("unknown outbox status {other}"),
                    });
                }
            },
            ambiguity: row.6 == 1,
            attempt_count: u32::try_from(row.7).unwrap_or(0),
            max_attempts: u32::try_from(row.8).unwrap_or(0),
            attempts: load_attempts(conn, row.0)?,
        });
    }
    Ok(views)
}

#[cfg(test)]
mod tests;

fn load_attempts(conn: &Connection, outbox_id: i64) -> Result<Vec<AttemptView>, StoreError> {
    let mut statement = conn
        .prepare(
            "SELECT attempt_id, attempt_number, status, remote_tx_id, response_identity,
                    ambiguity, diagnostic
             FROM outbox_attempts WHERE outbox_id = ?1 ORDER BY attempt_id",
        )
        .map_err(from_sqlite)?;
    let rows = statement
        .query_map([outbox_id], |row| {
            Ok(AttemptView {
                attempt_id: row.get(0)?,
                attempt_number: row.get(1)?,
                status: row.get(2)?,
                remote_tx_id: row.get(3)?,
                response_identity: row.get(4)?,
                ambiguity: row.get::<_, i64>(5)? == 1,
                diagnostic: row.get(6)?,
            })
        })
        .map_err(from_sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_sqlite)?;
    Ok(rows)
}
