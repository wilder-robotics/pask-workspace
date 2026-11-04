// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Versioned schema, durability pragmas, and open-time invariant checks.
//!
//! Open refuses a schema it does not implement. It does not migrate, does not
//! rebuild a tail, and does not insert a genesis receipt.

use rusqlite::{Connection, OptionalExtension, params};

use super::error::{StoreError, from_sqlite};
use super::statement::{read_statement, transport_hash};
use super::types::SCHEMA_VERSION;

pub(super) const META_SCHEMA_VERSION: &str = "schema_version";
pub(super) const META_JOURNAL_MODE: &str = "journal_mode";
pub(super) const META_SYNCHRONOUS: &str = "synchronous";
pub(super) const META_SYNCHRONOUS_NAME: &str = "synchronous_name";
pub(super) const META_FOREIGN_KEYS: &str = "foreign_keys";
pub(super) const META_EVENT_NEXT_ID: &str = "event_next_id";
pub(super) const META_EVENT_COUNT: &str = "event_count";
pub(super) const META_EVENT_TIP: &str = "event_tip";
pub(super) const META_OUTBOX_NEXT_ID: &str = "outbox_next_id";
pub(super) const META_ATTEMPT_NEXT_ID: &str = "attempt_next_id";

const EXPECTED_TABLES: &[&str] = &[
    "chains",
    "events",
    "operations",
    "outbox",
    "outbox_attempts",
    "schema_meta",
];

const DDL: &str = "
CREATE TABLE schema_meta (
    meta_key TEXT PRIMARY KEY,
    meta_value TEXT NOT NULL
) STRICT;
CREATE TABLE chains (
    issuer_identity TEXT NOT NULL COLLATE BINARY,
    subject_identity TEXT NOT NULL COLLATE BINARY,
    head_seq INTEGER,
    head_hash TEXT COLLATE BINARY,
    PRIMARY KEY (issuer_identity, subject_identity)
) STRICT;
CREATE TABLE operations (
    issuer_identity TEXT NOT NULL COLLATE BINARY,
    subject_identity TEXT NOT NULL COLLATE BINARY,
    operation_id TEXT NOT NULL COLLATE BINARY,
    request_fingerprint BLOB NOT NULL,
    reference_state TEXT NOT NULL,
    reference_value TEXT,
    reference_detail TEXT,
    seal_state TEXT NOT NULL,
    registration_state TEXT NOT NULL,
    registration_remote_tx_id TEXT,
    registration_response_identity TEXT,
    delivery_state TEXT NOT NULL,
    delivery_detail TEXT,
    seq INTEGER,
    prev_hash TEXT COLLATE BINARY,
    chain_hash TEXT COLLATE BINARY,
    transport_hash TEXT COLLATE BINARY,
    statement_bytes BLOB,
    PRIMARY KEY (issuer_identity, subject_identity, operation_id),
    FOREIGN KEY (issuer_identity, subject_identity)
        REFERENCES chains (issuer_identity, subject_identity)
) STRICT;
CREATE UNIQUE INDEX operations_chain_seq
    ON operations (issuer_identity, subject_identity, seq)
    WHERE seq IS NOT NULL;
CREATE TABLE events (
    event_id INTEGER PRIMARY KEY,
    issuer_identity TEXT NOT NULL COLLATE BINARY,
    subject_identity TEXT NOT NULL COLLATE BINARY,
    operation_id TEXT NOT NULL COLLATE BINARY,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    prev_tip TEXT NOT NULL,
    tip TEXT NOT NULL
) STRICT;
CREATE TABLE outbox (
    outbox_id INTEGER PRIMARY KEY,
    issuer_identity TEXT NOT NULL COLLATE BINARY,
    subject_identity TEXT NOT NULL COLLATE BINARY,
    operation_id TEXT NOT NULL COLLATE BINARY,
    purpose TEXT NOT NULL,
    submitted_bytes BLOB NOT NULL,
    remote_tx_id TEXT,
    response_identity TEXT,
    status TEXT NOT NULL,
    ambiguity INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL
) STRICT;
CREATE TABLE outbox_attempts (
    attempt_id INTEGER PRIMARY KEY,
    outbox_id INTEGER NOT NULL,
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL,
    remote_tx_id TEXT,
    response_identity TEXT,
    ambiguity INTEGER NOT NULL,
    diagnostic TEXT NOT NULL,
    FOREIGN KEY (outbox_id) REFERENCES outbox (outbox_id)
) STRICT;
";

pub(super) fn apply_connection_pragmas(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(from_sqlite)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(from_sqlite)?;
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(from_sqlite)?;
    if foreign_keys != 1 {
        return Err(StoreError::PublicationStopped {
            class: super::error::FailureClass::Io,
            detail: format!("foreign_keys pragma read back as {foreign_keys}, expected 1"),
        });
    }
    Ok(())
}

pub(super) fn journal_mode(conn: &Connection) -> Result<String, StoreError> {
    conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(from_sqlite)
}

/// Set WAL and `synchronous=FULL` on a database this process is creating.
///
/// Both values are read back. A filesystem that does not keep WAL is refused.
pub(super) fn enable_wal_and_full_sync(conn: &Connection) -> Result<(), StoreError> {
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .map_err(from_sqlite)?;
    if mode != "wal" {
        return Err(StoreError::PublicationStopped {
            class: super::error::FailureClass::Io,
            detail: format!("journal_mode read back as {mode}, expected wal"),
        });
    }
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(from_sqlite)?;
    let synchronous = synchronous_pragma(conn)?;
    if synchronous != 2 {
        return Err(StoreError::PublicationStopped {
            class: super::error::FailureClass::Io,
            detail: format!("synchronous read back as {synchronous}, expected 2 (FULL)"),
        });
    }
    Ok(())
}

pub(super) fn synchronous_pragma(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(from_sqlite)
}

pub(super) fn create_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(DDL).map_err(from_sqlite)?;
    let tip = genesis_tip();
    let rows = [
        (META_SCHEMA_VERSION, SCHEMA_VERSION.to_string()),
        (META_JOURNAL_MODE, "wal".to_owned()),
        (META_SYNCHRONOUS, "2".to_owned()),
        (META_SYNCHRONOUS_NAME, "full".to_owned()),
        (META_FOREIGN_KEYS, "1".to_owned()),
        (META_EVENT_NEXT_ID, "1".to_owned()),
        (META_EVENT_COUNT, "0".to_owned()),
        (META_EVENT_TIP, tip),
        (META_OUTBOX_NEXT_ID, "1".to_owned()),
        (META_ATTEMPT_NEXT_ID, "1".to_owned()),
    ];
    for (key, value) in rows {
        meta_set(conn, key, &value)?;
    }
    Ok(())
}

pub(super) fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    conn.query_row(
        "SELECT meta_value FROM schema_meta WHERE meta_key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(from_sqlite)
}

pub(super) fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO schema_meta (meta_key, meta_value) VALUES (?1, ?2)
         ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value",
        params![key, value],
    )
    .map_err(from_sqlite)?;
    Ok(())
}

pub(super) fn require_meta(conn: &Connection, key: &str) -> Result<String, StoreError> {
    meta_get(conn, key)?.ok_or_else(|| StoreError::Inconsistent {
        detail: format!("schema_meta is missing {key}"),
    })
}

/// Confirm an existing file is WAL and records the FULL synchronous policy.
///
/// This does not change `journal_mode` and does not rewrite `schema_meta`.
/// `synchronous` is a connection setting, so it is applied and then read back.
pub(super) fn verify_existing_durability(conn: &Connection) -> Result<(), StoreError> {
    let live_mode = journal_mode(conn)?;
    if live_mode != "wal" {
        return Err(StoreError::Inconsistent {
            detail: format!("journal_mode is {live_mode}, expected wal; not switching it"),
        });
    }
    let recorded_mode = require_meta(conn, META_JOURNAL_MODE)?;
    let recorded_sync = require_meta(conn, META_SYNCHRONOUS)?;
    let recorded_name = require_meta(conn, META_SYNCHRONOUS_NAME)?;
    let recorded_fk = require_meta(conn, META_FOREIGN_KEYS)?;
    if recorded_mode != "wal"
        || recorded_sync != "2"
        || recorded_name != "full"
        || recorded_fk != "1"
    {
        return Err(StoreError::Inconsistent {
            detail: format!(
                "persisted durability policy is journal_mode={recorded_mode}, synchronous={recorded_sync}, synchronous_name={recorded_name}, foreign_keys={recorded_fk}; not rewriting it"
            ),
        });
    }
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(from_sqlite)?;
    let synchronous = synchronous_pragma(conn)?;
    if synchronous != 2 {
        return Err(StoreError::PublicationStopped {
            class: super::error::FailureClass::Io,
            detail: format!("synchronous read back as {synchronous}, expected 2 (FULL)"),
        });
    }
    Ok(())
}

pub(super) fn user_tables(conn: &Connection) -> Result<Vec<String>, StoreError> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(from_sqlite)?;
    let names = statement
        .query_map([], |row| row.get(0))
        .map_err(from_sqlite)?
        .collect::<Result<Vec<String>, _>>()
        .map_err(from_sqlite)?;
    Ok(names)
}

pub(super) fn schema_is_empty(conn: &Connection) -> Result<bool, StoreError> {
    Ok(user_tables(conn)?.is_empty())
}

/// Read the schema version and refuse anything other than [`SCHEMA_VERSION`].
///
/// The version row is not updated.
pub(super) fn require_supported_schema(conn: &Connection) -> Result<(), StoreError> {
    let found = require_meta(conn, META_SCHEMA_VERSION)?;
    if found != SCHEMA_VERSION.to_string() {
        return Err(StoreError::SchemaRefused {
            found,
            supported: SCHEMA_VERSION,
            detail: "in-place migration is not implemented; the stored version was left unchanged"
                .to_owned(),
        });
    }
    let tables = user_tables(conn)?;
    let expected: Vec<&str> = EXPECTED_TABLES.to_vec();
    let actual: Vec<&str> = tables.iter().map(String::as_str).collect();
    if actual != expected {
        return Err(StoreError::Inconsistent {
            detail: format!(
                "schema tables are {tables:?}, expected {expected:?}; not altering them"
            ),
        });
    }
    let index: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'operations_chain_seq'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(from_sqlite)?;
    if index.is_none() {
        return Err(StoreError::Inconsistent {
            detail: "operations_chain_seq is missing; not recreating it".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn genesis_tip() -> String {
    pask_wire::sha256_prefixed(b"pask-site-store/event-tip/v1")
}

#[allow(clippy::too_many_arguments)]
pub(super) fn event_tip(
    prev: &str,
    event_id: i64,
    issuer: &str,
    subject: &str,
    operation_id: &str,
    kind: &str,
    detail: &str,
    recorded_at: &str,
) -> String {
    let mut bytes = Vec::new();
    for part in [
        prev,
        &event_id.to_string(),
        issuer,
        subject,
        operation_id,
        kind,
        detail,
        recorded_at,
    ] {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0xff);
    }
    pask_wire::sha256_prefixed(&bytes)
}

pub(super) fn alloc_id(conn: &Connection, key: &str) -> Result<i64, StoreError> {
    let current = require_meta(conn, key)?;
    let id: i64 = current.parse().map_err(|_| StoreError::Inconsistent {
        detail: format!("{key} is not an integer"),
    })?;
    if id <= 0 {
        return Err(StoreError::Inconsistent {
            detail: format!("{key} is {id}"),
        });
    }
    let next = id.checked_add(1).ok_or_else(|| StoreError::Inconsistent {
        detail: format!("{key} overflow"),
    })?;
    meta_set(conn, key, &next.to_string())?;
    Ok(id)
}

pub(super) fn append_event(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    operation_id: &str,
    kind: &str,
    detail: &str,
    recorded_at: &str,
) -> Result<i64, StoreError> {
    let event_id = alloc_id(conn, META_EVENT_NEXT_ID)?;
    let count: i64 =
        require_meta(conn, META_EVENT_COUNT)?
            .parse()
            .map_err(|_| StoreError::Inconsistent {
                detail: "event_count is not an integer".to_owned(),
            })?;
    let prev = require_meta(conn, META_EVENT_TIP)?;
    let tip = event_tip(
        &prev,
        event_id,
        issuer,
        subject,
        operation_id,
        kind,
        detail,
        recorded_at,
    );
    conn.execute(
        "INSERT INTO events (
            event_id, issuer_identity, subject_identity, operation_id, kind, detail,
            recorded_at, prev_tip, tip
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            event_id,
            issuer,
            subject,
            operation_id,
            kind,
            detail,
            recorded_at,
            prev,
            tip
        ],
    )
    .map_err(from_sqlite)?;
    meta_set(conn, META_EVENT_COUNT, &(count + 1).to_string())?;
    meta_set(conn, META_EVENT_TIP, &tip)?;
    Ok(event_id)
}

/// Re-check schema compatibility and chain invariants.
///
/// A failure returns before any repair. Genesis is not inserted here.
pub(super) fn check_invariants(conn: &Connection) -> Result<(), StoreError> {
    require_supported_schema(conn)?;
    verify_existing_durability(conn)?;
    check_event_log(conn)?;
    check_chains(conn)?;
    check_outbox(conn)?;
    Ok(())
}

fn check_event_log(conn: &Connection) -> Result<(), StoreError> {
    let expected_count: i64 =
        require_meta(conn, META_EVENT_COUNT)?
            .parse()
            .map_err(|_| StoreError::Inconsistent {
                detail: "event_count is not an integer".to_owned(),
            })?;
    let expected_tip = require_meta(conn, META_EVENT_TIP)?;
    let mut statement = conn
        .prepare(
            "SELECT event_id, issuer_identity, subject_identity, operation_id, kind, detail,
                    recorded_at, prev_tip, tip
             FROM events ORDER BY event_id",
        )
        .map_err(from_sqlite)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(from_sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_sqlite)?;
    if rows.len() as i64 != expected_count {
        return Err(StoreError::Inconsistent {
            detail: format!(
                "event_count is {expected_count} but {} event rows are present; not repairing the log",
                rows.len()
            ),
        });
    }
    let mut prev = genesis_tip();
    for (index, row) in rows.iter().enumerate() {
        let expected_id = (index as i64) + 1;
        if row.0 != expected_id {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "event id {} breaks the append-only sequence at {expected_id}; not renumbering",
                    row.0
                ),
            });
        }
        if row.7 != prev {
            return Err(StoreError::Inconsistent {
                detail: format!("event {} prev_tip does not match the preceding tip", row.0),
            });
        }
        let tip = event_tip(&prev, row.0, &row.1, &row.2, &row.3, &row.4, &row.5, &row.6);
        if row.8 != tip {
            return Err(StoreError::Inconsistent {
                detail: format!("event {} tip does not match its contents", row.0),
            });
        }
        if !known_event_kind(&row.4) {
            return Err(StoreError::Inconsistent {
                detail: format!("event {} has unknown kind {}", row.0, row.4),
            });
        }
        prev = tip;
    }
    if prev != expected_tip {
        return Err(StoreError::Inconsistent {
            detail: "event_tip does not match the recomputed log; not resetting it".to_owned(),
        });
    }
    Ok(())
}

fn known_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "operation-opened"
            | "reference-reserved"
            | "reference-write-observed"
            | "reference-write-outcome-unknown"
            | "ready-to-seal"
            | "sealed"
            | "registration-pending"
            | "receipt-received"
            | "registration-verified"
            | "delivery-recorded"
            | "outbox-submitted"
            | "outbox-observation"
    )
}

struct SealedRow {
    seq: i64,
    prev_hash: Option<String>,
    chain_hash: String,
    transport_hash: String,
    statement: Vec<u8>,
}

fn check_chains(conn: &Connection) -> Result<(), StoreError> {
    let mut statement = conn
        .prepare("SELECT issuer_identity, subject_identity, head_seq, head_hash FROM chains ORDER BY issuer_identity, subject_identity")
        .map_err(from_sqlite)?;
    let chains = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(from_sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_sqlite)?;
    for (issuer, subject, head_seq, head_hash) in chains {
        check_one_chain(conn, &issuer, &subject, head_seq, head_hash)?;
    }
    Ok(())
}

fn check_one_chain(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    head_seq: Option<i64>,
    head_hash: Option<String>,
) -> Result<(), StoreError> {
    let mut statement = conn
        .prepare(
            "SELECT seal_state, seq, prev_hash, chain_hash, transport_hash, statement_bytes,
                    reference_state, registration_state, delivery_state, operation_id
             FROM operations
             WHERE issuer_identity = ?1 AND subject_identity = ?2
             ORDER BY seq",
        )
        .map_err(from_sqlite)?;
    let rows = statement
        .query_map(params![issuer, subject], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(from_sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_sqlite)?;

    let mut sealed = Vec::new();
    for row in &rows {
        if !known_projection(&row.6, &row.0, &row.7, &row.8) {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "operation {} has an unknown projection state; not rewriting it",
                    row.9
                ),
            });
        }
        if row.0 == "sealed" {
            let (Some(seq), Some(chain_hash), Some(transport), Some(statement)) =
                (row.1, row.3.clone(), row.4.clone(), row.5.clone())
            else {
                return Err(StoreError::Inconsistent {
                    detail: format!(
                        "sealed operation {} is missing sequence or statement bytes",
                        row.9
                    ),
                });
            };
            sealed.push(SealedRow {
                seq,
                prev_hash: row.2.clone(),
                chain_hash,
                transport_hash: transport,
                statement,
            });
        } else if row.1.is_some() || row.5.is_some() {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "operation {} is not sealed but has sequence or statement bytes",
                    row.9
                ),
            });
        }
    }

    match (head_seq, head_hash, sealed.last()) {
        (None, None, None) => return Ok(()),
        (Some(seq), Some(hash), Some(last)) if seq == last.seq && hash == last.chain_hash => {}
        _ => {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain head ({issuer}, {subject}) does not match the sealed tail; not repairing it and not initializing genesis"
                ),
            });
        }
    }

    let mut expected_prev: Option<String> = None;
    for (index, row) in sealed.iter().enumerate() {
        let expected_seq = i64::try_from(index).map_err(|_| StoreError::Inconsistent {
            detail: "sealed sequence index overflow".to_owned(),
        })?;
        if row.seq != expected_seq {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) sequence {} is not the contiguous successor of {expected_seq}",
                    row.seq
                ),
            });
        }
        if row.prev_hash != expected_prev {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} prevHash does not match the preceding payload chain.hash",
                    row.seq
                ),
            });
        }
        let digest = transport_hash(&row.statement);
        if digest != row.transport_hash {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} transport hash does not match the statement bytes",
                    row.seq
                ),
            });
        }
        let payload = read_statement(&row.statement).map_err(|error| StoreError::Inconsistent {
            detail: format!(
                "chain ({issuer}, {subject}) seq {} statement is not readable: {error}",
                row.seq
            ),
        })?;
        if payload.chain_seq() != u64::try_from(row.seq).unwrap_or(u64::MAX) {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} payload sequence differs from the stored sequence",
                    row.seq
                ),
            });
        }
        if payload.chain_prev_hash() != row.prev_hash.as_deref() {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} payload prevHash differs from the stored predecessor",
                    row.seq
                ),
            });
        }
        if payload.chain_hash() != row.chain_hash {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} payload chain.hash differs from the stored head link",
                    row.seq
                ),
            });
        }
        if payload.site_id() != subject || payload.witness_key() != issuer {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} statement identity does not match the chain namespace",
                    row.seq
                ),
            });
        }
        if expected_seq > 0 && row.prev_hash.as_deref() == Some(row.transport_hash.as_str()) {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "chain ({issuer}, {subject}) seq {} prevHash is the COSE transport hash",
                    row.seq
                ),
            });
        }
        expected_prev = Some(row.chain_hash.clone());
    }
    Ok(())
}

fn known_projection(reference: &str, seal: &str, registration: &str, delivery: &str) -> bool {
    matches!(
        reference,
        "absent" | "pending" | "observed" | "outcome_unknown"
    ) && matches!(seal, "not_ready" | "ready" | "sealed")
        && matches!(
            registration,
            "absent" | "pending" | "receipt_received" | "verified"
        )
        && matches!(
            delivery,
            "absent" | "submitted" | "completed" | "failed" | "ambiguous"
        )
}

fn check_outbox(conn: &Connection) -> Result<(), StoreError> {
    let mut statement = conn
        .prepare(
            "SELECT outbox_id, issuer_identity, subject_identity, operation_id, purpose,
                    submitted_bytes, remote_tx_id, response_identity, status, ambiguity,
                    attempt_count, max_attempts
             FROM outbox ORDER BY outbox_id",
        )
        .map_err(from_sqlite)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
            ))
        })
        .map_err(from_sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_sqlite)?;
    for row in rows {
        if !matches!(row.4.as_str(), "reference" | "registration") {
            return Err(StoreError::Inconsistent {
                detail: format!("outbox {} has unknown purpose {}", row.0, row.4),
            });
        }
        if !matches!(
            row.8.as_str(),
            "pending" | "ambiguous" | "response_received" | "exhausted"
        ) {
            return Err(StoreError::Inconsistent {
                detail: format!("outbox {} has unknown status {}", row.0, row.8),
            });
        }
        if row.5.is_empty() {
            return Err(StoreError::Inconsistent {
                detail: format!("outbox {} has empty submitted bytes", row.0),
            });
        }
        if row.9 != 0 && row.9 != 1 {
            return Err(StoreError::Inconsistent {
                detail: format!("outbox {} ambiguity flag is {}", row.0, row.9),
            });
        }
        if row.8 == "ambiguous" && row.9 != 1 {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "outbox {} status is ambiguous but the flag is {}",
                    row.0, row.9
                ),
            });
        }
        if row.10 < 1 || row.11 < 1 || row.10 > row.11 {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "outbox {} attempt count {} is outside 1..={}",
                    row.0, row.10, row.11
                ),
            });
        }
        let submitted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbox_attempts WHERE outbox_id = ?1 AND status = 'submitted'",
                [row.0],
                |count| count.get(0),
            )
            .map_err(from_sqlite)?;
        if submitted != row.10 {
            return Err(StoreError::Inconsistent {
                detail: format!(
                    "outbox {} history has {submitted} submissions but attempt_count is {}",
                    row.0, row.10
                ),
            });
        }
        if row.4 == "registration" {
            let statement_bytes: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT statement_bytes FROM operations
                     WHERE issuer_identity = ?1 AND subject_identity = ?2 AND operation_id = ?3",
                    params![row.1, row.2, row.3],
                    |operation| operation.get(0),
                )
                .map_err(from_sqlite)?;
            if statement_bytes.as_ref() != Some(&row.5) {
                return Err(StoreError::Inconsistent {
                    detail: format!(
                        "outbox {} registration bytes differ from the sealed statement",
                        row.0
                    ),
                });
            }
        }
        let _ = (row.6, row.7);
    }
    Ok(())
}
