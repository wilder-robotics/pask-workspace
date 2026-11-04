// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{
    ChainId, ChainStore, DeliveryOutcome, DeliveryState, FailureClass, FaultInjector, FaultPoint,
    HISTORY_LIMIT, MIGRATION_POLICY, OutboxPurpose, OutboxStatus, ReferenceState,
    ReferenceWriteEvidence, RegistrationState, SCHEMA_VERSION, SealState, StoreConfig, StoreError,
    TransportObservation,
};
use crate::fixtures::res_001;
use crate::{Ed25519SiteProducer, FixedClock, ReferenceSite, SiteProducer};

const _: () = assert!(!MIGRATION_POLICY.in_place_production_migration);

const ISSUER: &str = "key:tee:res-001-witness-01";
const SUBJECT: &str = "site:res-001";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pask-t04-{name}-{}-{}",
            std::process::id(),
            unique()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique() -> u64 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    u64::from(NEXT.fetch_add(1, Ordering::Relaxed))
}

fn config(path: &Path, initialize: bool, attempts: u32) -> StoreConfig {
    StoreConfig {
        database_path: path.to_path_buf(),
        initialize_schema: initialize,
        outbox_max_attempts: attempts,
        clock: Arc::new(FixedClock::new("2026-10-15T14:00:00Z")),
        fault_injector: None,
    }
}

fn open_store(path: &Path) -> ChainStore {
    ChainStore::open(config(path, true, 3)).unwrap()
}

fn chain(issuer: &str, subject: &str) -> ChainId {
    ChainId::new(issuer, subject).unwrap()
}

fn keypair() -> (SigningKey, VerifyingKey) {
    let seed: [u8; 32] = Sha256::digest(b"pask-site::res-001::v0").into();
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

fn producer_for(subject: &str, issuer: &str) -> Ed25519SiteProducer {
    let mut site = res_001::site_config();
    site.site_id = subject.to_owned();
    site.attestation_witness_key = issuer.to_owned();
    let (signing, _) = keypair();
    Ed25519SiteProducer::new(
        site,
        Arc::new(FixedClock::new("2026-10-15T14:00:00Z")),
        signing,
    )
}

fn produce_at(
    producer: &Ed25519SiteProducer,
    position: &super::AssignedPosition,
) -> Result<Vec<u8>, String> {
    let mut request = res_001::engagement_request(res_001::evidence_bundle());
    request.chain_seq = position.seq;
    request.chain_prev_hash = position.prev_hash.clone();
    producer
        .produce(&request)
        .map_err(|error| error.to_string())
}

fn seal(
    store: &ChainStore,
    producer: &Ed25519SiteProducer,
    chain_id: &ChainId,
    operation_id: &str,
    fingerprint: &[u8],
) -> super::OperationView {
    store
        .open_operation(chain_id, operation_id, fingerprint)
        .unwrap();
    store
        .commit_seal(chain_id, operation_id, fingerprint, |position| {
            produce_at(producer, position)
        })
        .unwrap()
}

fn sealed_bytes(view: &super::OperationView) -> Vec<u8> {
    match &view.seal {
        SealState::Sealed { statement, .. } => statement.clone(),
        other => panic!("expected a sealed operation, got {other:?}"),
    }
}

fn family_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let file = sidecar(path, suffix);
        if file.exists() {
            bytes.extend(fs::read(file).unwrap());
        }
    }
    bytes
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn snapshot_family(path: &Path, dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let source = sidecar(path, suffix);
        if source.exists() {
            fs::copy(&source, dir.join(source.file_name().unwrap())).unwrap();
        }
    }
}

fn restore_family(path: &Path, dir: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let file = sidecar(path, suffix);
        let _ = fs::remove_file(&file);
        let saved = dir.join(file.file_name().unwrap());
        if saved.exists() {
            fs::copy(saved, file).unwrap();
        }
    }
}

struct FailAt {
    point: FaultPoint,
    class: FailureClass,
}

impl FaultInjector for FailAt {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point {
            Err(StoreError::PublicationStopped {
                class: self.class,
                detail: format!("injected at {point:?}"),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn st01_explicit_path_and_persisted_settings() {
    let scratch = Scratch::new("st01-settings");
    let path = scratch.db();
    let missing = scratch.0.join("no-parent").join("state.db");
    let error = ChainStore::open(config(&missing, true, 3)).unwrap_err();
    assert!(matches!(
        error,
        StoreError::PublicationStopped {
            class: FailureClass::Permission,
            ..
        }
    ));
    assert!(!scratch.0.join("no-parent").exists());

    let absent = scratch.0.join("absent.db");
    let error = ChainStore::open(config(&absent, false, 3)).unwrap_err();
    assert!(matches!(error, StoreError::SchemaNotInitialized { .. }));
    assert!(!absent.exists());

    let store = open_store(&path);
    assert_eq!(store.path(), path.as_path());
    let settings = store.persisted_settings().unwrap();
    assert_eq!(settings.schema_version, SCHEMA_VERSION);
    assert_eq!(settings.journal_mode, "wal");
    assert_eq!(settings.synchronous, 2);
    assert_eq!(settings.synchronous_name, "full");
    assert_eq!(settings.foreign_keys, 1);
    assert!(store.chain_head(&chain(ISSUER, SUBJECT)).unwrap().is_none());
    store.checkpoint_for_test().unwrap();
    drop(store);

    let store = ChainStore::open(config(&path, true, 3)).unwrap();
    let settings = store.persisted_settings().unwrap();
    assert_eq!(settings.journal_mode, "wal");
    assert_eq!(settings.synchronous, 2);
    drop(store);

    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE schema_meta SET meta_value = 'off' WHERE meta_key = 'synchronous_name'",
        [],
    )
    .unwrap();
    drop(raw);
    let error = ChainStore::open(config(&path, true, 3)).unwrap_err();
    assert!(matches!(error, StoreError::Inconsistent { .. }), "{error}");
    let raw = rusqlite::Connection::open(&path).unwrap();
    let name: String = raw
        .query_row(
            "SELECT meta_value FROM schema_meta WHERE meta_key = 'synchronous_name'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, "off");
}

#[test]
fn st01_does_not_persist_keys_or_credentials() {
    let scratch = Scratch::new("st01-keys");
    let path = scratch.db();
    let store = open_store(&path);
    let producer = producer_for(SUBJECT, ISSUER);
    let view = seal(
        &store,
        &producer,
        &chain(ISSUER, SUBJECT),
        "op-1",
        b"request-1",
    );
    assert!(matches!(view.seal, SealState::Sealed { .. }));
    store.checkpoint_for_test().unwrap();
    drop(store);

    let raw = rusqlite::Connection::open(&path).unwrap();
    let mut statement = raw.prepare("SELECT sql FROM sqlite_master").unwrap();
    let schema = statement
        .query_map([], |row| row.get::<_, Option<String>>(0))
        .unwrap()
        .map(|row| row.unwrap().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for banned in [
        "private_key",
        "signing_key",
        "credential",
        "password",
        "secret",
    ] {
        assert!(!schema.contains(banned), "{banned} appears in schema");
    }
    drop(statement);
    drop(raw);

    let secret = keypair().0.to_bytes();
    let stored = family_bytes(&path);
    assert!(!stored.windows(secret.len()).any(|window| window == secret));
    let text = String::from_utf8_lossy(&stored);
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert!(!text.contains("client_secret"));
}

#[test]
fn st02_concurrent_tasks_cannot_commit_the_same_sequence() {
    let scratch = Scratch::new("st02-seq");
    let store = Arc::new(open_store(&scratch.db()));
    let producer = Arc::new(producer_for(SUBJECT, ISSUER));
    let mut handles = Vec::new();
    for (operation_id, fingerprint) in [("op-a", &b"req-a"[..]), ("op-b", &b"req-b"[..])] {
        let store = Arc::clone(&store);
        let producer = Arc::clone(&producer);
        let fingerprint = fingerprint.to_vec();
        let operation_id = operation_id.to_owned();
        handles.push(thread::spawn(move || {
            let chain_id = chain(ISSUER, SUBJECT);
            store
                .open_operation(&chain_id, &operation_id, &fingerprint)
                .unwrap();
            store
                .commit_seal(&chain_id, &operation_id, &fingerprint, |position| {
                    produce_at(&producer, position)
                })
                .unwrap()
        }));
    }
    let views: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let mut seqs = Vec::new();
    for view in &views {
        match &view.seal {
            SealState::Sealed { seq, prev_hash, .. } => {
                if *seq == 0 {
                    assert!(prev_hash.is_none());
                }
                seqs.push(*seq);
            }
            other => panic!("expected sealed, got {other:?}"),
        }
    }
    seqs.sort_unstable();
    assert_eq!(seqs, vec![0, 1]);
    let head = store.chain_head(&chain(ISSUER, SUBJECT)).unwrap().unwrap();
    assert_eq!(head.seq, 1);

    let forced = {
        let mut request = res_001::engagement_request(res_001::evidence_bundle());
        request.chain_seq = 0;
        request.chain_prev_hash = None;
        producer.produce(&request).unwrap()
    };
    let force_scratch = Scratch::new("st02-force");
    let store = Arc::new(open_store(&force_scratch.db()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for operation_id in ["force-a", "force-b"] {
        let store = Arc::clone(&store);
        let forced = forced.clone();
        let errors = Arc::clone(&errors);
        let operation_id = operation_id.to_owned();
        handles.push(thread::spawn(move || {
            let chain_id = chain(ISSUER, SUBJECT);
            let fingerprint = operation_id.as_bytes().to_vec();
            store
                .open_operation(&chain_id, &operation_id, &fingerprint)
                .unwrap();
            let result = store.commit_seal(&chain_id, &operation_id, &fingerprint, |_| {
                Ok::<_, String>(forced.clone())
            });
            if let Err(error) = result {
                errors.lock().unwrap().push(error.to_string());
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(
        errors.lock().unwrap().len(),
        1,
        "{:?}",
        errors.lock().unwrap()
    );
    let head = store.chain_head(&chain(ISSUER, SUBJECT)).unwrap().unwrap();
    assert_eq!(head.seq, 0);
}

#[test]
fn st02_distinct_chains_and_unnormalized_identities() {
    let scratch = Scratch::new("st02-chains");
    let store = open_store(&scratch.db());
    let pairs = [
        ("Issuer", "site"),
        ("issuer", "site"),
        ("Issuer", "site "),
        ("issuer", "site "),
    ];
    for (issuer, subject) in pairs {
        let producer = producer_for(subject, issuer);
        let view = seal(
            &store,
            &producer,
            &chain(issuer, subject),
            "op",
            format!("{issuer}|{subject}").as_bytes(),
        );
        match view.seal {
            SealState::Sealed { seq, prev_hash, .. } => {
                assert_eq!(seq, 0);
                assert!(prev_hash.is_none());
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        store
            .chain_head(&chain("issuer", "site"))
            .unwrap()
            .unwrap()
            .seq,
        0
    );
    assert!(
        store
            .chain_head(&chain("issuer", "other"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn st03_injected_faults_keep_statement_and_head_atomic() {
    let points = [
        FaultPoint::BeforeTransaction,
        FaultPoint::AfterBegin,
        FaultPoint::BeforeCommit,
    ];
    for point in points {
        let scratch = Scratch::new(&format!("st03-{point:?}"));
        let path = scratch.db();
        let mut store = open_store(&path);
        let producer = producer_for(SUBJECT, ISSUER);
        let chain_id = chain(ISSUER, SUBJECT);
        store.open_operation(&chain_id, "op", b"req").unwrap();
        store.set_fault_for_test(Some(fault(point, FailureClass::FaultInjected)));
        let error = store
            .commit_seal(&chain_id, "op", b"req", |position| {
                produce_at(&producer, position)
            })
            .unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::PublicationStopped {
                    class: FailureClass::FaultInjected,
                    ..
                }
            ),
            "{point:?}: {error}"
        );
        drop(store);
        let store = open_store(&path);
        assert!(store.chain_head(&chain_id).unwrap().is_none());
        let view = store.operation(&chain_id, "op").unwrap();
        assert!(matches!(view.seal, SealState::NotReady));
    }

    let scratch = Scratch::new("st03-after");
    let path = scratch.db();
    let mut store = open_store(&path);
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    store.open_operation(&chain_id, "op", b"req").unwrap();
    store.set_fault_for_test(Some(fault(
        FaultPoint::AfterCommit,
        FailureClass::FaultInjected,
    )));
    let error = store
        .commit_seal(&chain_id, "op", b"req", |position| {
            produce_at(&producer, position)
        })
        .unwrap_err();
    assert!(matches!(
        error,
        StoreError::PublicationStopped {
            class: FailureClass::FaultInjected,
            ..
        }
    ));
    drop(store);
    let store = open_store(&path);
    let head = store.chain_head(&chain_id).unwrap().unwrap();
    let view = store.operation(&chain_id, "op").unwrap();
    match &view.seal {
        SealState::Sealed {
            seq,
            chain_hash,
            statement,
            transport_hash,
            ..
        } => {
            assert_eq!(*seq, 0);
            assert_eq!(head.seq, 0);
            assert_eq!(head.chain_hash, *chain_hash);
            assert_eq!(*transport_hash, pask_wire::sha256_prefixed(statement));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn st03_rollback_does_not_publish_a_gap_or_reuse_a_sequence() {
    let scratch = Scratch::new("st03-gap");
    let path = scratch.db();
    let mut store = open_store(&path);
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    store.open_operation(&chain_id, "op", b"req").unwrap();
    store.set_fault_for_test(Some(fault(FaultPoint::BeforeCommit, FailureClass::Io)));
    assert!(
        store
            .commit_seal(&chain_id, "op", b"req", |position| produce_at(
                &producer, position
            ))
            .is_err()
    );
    drop(store);
    let store = open_store(&path);
    let view = seal(&store, &producer, &chain_id, "op", b"req");
    match view.seal {
        SealState::Sealed { seq, .. } => assert_eq!(seq, 0),
        other => panic!("{other:?}"),
    }
    let mut store = open_store(&path);
    store.open_operation(&chain_id, "op-2", b"req-2").unwrap();
    store.set_fault_for_test(Some(fault(FaultPoint::BeforeCommit, FailureClass::Io)));
    assert!(
        store
            .commit_seal(&chain_id, "op-2", b"req-2", |position| {
                produce_at(&producer, position)
            })
            .is_err()
    );
    drop(store);
    let store = open_store(&path);
    assert_eq!(store.chain_head(&chain_id).unwrap().unwrap().seq, 0);
    let view = seal(&store, &producer, &chain_id, "op-2", b"req-2");
    match view.seal {
        SealState::Sealed { seq, prev_hash, .. } => {
            assert_eq!(seq, 1);
            assert!(prev_hash.is_some());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn st04_restart_returns_the_existing_statement_and_conflicts_on_change() {
    let scratch = Scratch::new("st04");
    let path = scratch.db();
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    let store = open_store(&path);
    let first = seal(&store, &producer, &chain_id, "op", b"request");
    let bytes = sealed_bytes(&first);
    drop(store);

    let store = open_store(&path);
    let calls = AtomicU32::new(0);
    let again = store
        .commit_seal(&chain_id, "op", b"request", |position| {
            calls.fetch_add(1, Ordering::SeqCst);
            produce_at(&producer, position)
        })
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(sealed_bytes(&again), bytes);
    let error = store
        .commit_seal(&chain_id, "op", b"request-changed", |_| {
            Ok::<_, String>(Vec::new())
        })
        .unwrap_err();
    assert!(matches!(error, StoreError::OperationConflict { .. }));
    assert_eq!(
        sealed_bytes(&store.operation(&chain_id, "op").unwrap()),
        bytes
    );
    let missing = store
        .commit_seal(&chain_id, "missing", b"request", |_| {
            Ok::<_, String>(Vec::new())
        })
        .unwrap_err();
    assert!(matches!(missing, StoreError::NotFound { .. }));
}

#[test]
fn st05_prev_hash_is_payload_chain_hash_and_sequence_is_assigned() {
    let scratch = Scratch::new("st05");
    let path = scratch.db();
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    let store = open_store(&path);
    let first = seal(&store, &producer, &chain_id, "op-0", b"one");
    let (first_hash, first_transport, first_bytes) = match &first.seal {
        SealState::Sealed {
            seq,
            prev_hash,
            chain_hash,
            transport_hash,
            statement,
        } => {
            assert_eq!(*seq, 0);
            assert!(prev_hash.is_none());
            assert_ne!(chain_hash, transport_hash);
            (
                chain_hash.clone(),
                transport_hash.clone(),
                statement.clone(),
            )
        }
        other => panic!("{other:?}"),
    };
    let forced = store
        .open_operation(&chain_id, "forced", b"forced")
        .unwrap();
    assert!(matches!(forced.seal, SealState::NotReady));
    let error = store
        .commit_seal(&chain_id, "forced", b"forced", |_| {
            Ok::<_, String>(first_bytes.clone())
        })
        .unwrap_err();
    assert!(
        matches!(error, StoreError::StatementRejected { .. }),
        "{error}"
    );
    assert_eq!(store.chain_head(&chain_id).unwrap().unwrap().seq, 0);

    let second = seal(&store, &producer, &chain_id, "op-1", b"two");
    match &second.seal {
        SealState::Sealed {
            seq,
            prev_hash,
            chain_hash,
            transport_hash,
            ..
        } => {
            assert_eq!(*seq, 1);
            assert_eq!(prev_hash.as_deref(), Some(first_hash.as_str()));
            assert_ne!(prev_hash.as_deref(), Some(first_transport.as_str()));
            assert_ne!(chain_hash, transport_hash);
        }
        other => panic!("{other:?}"),
    }
    drop(store);

    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE operations SET prev_hash = ?1 WHERE operation_id = 'op-1'",
        [&first_transport],
    )
    .unwrap();
    drop(raw);
    let error = ChainStore::open(config(&path, false, 3)).unwrap_err();
    assert!(matches!(error, StoreError::Inconsistent { .. }), "{error}");
    let raw = rusqlite::Connection::open(&path).unwrap();
    let prev: String = raw
        .query_row(
            "SELECT prev_hash FROM operations WHERE operation_id = 'op-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(prev, first_transport);
}

#[test]
fn st06_crash_before_seal_preserves_pending_or_unknown_reference() {
    let scratch = Scratch::new("st06");
    let path = scratch.db();
    let chain_id = chain(ISSUER, SUBJECT);
    let mut store = open_store(&path);
    store.open_operation(&chain_id, "op", b"req").unwrap();
    store.set_fault_for_test(Some(fault(
        FaultPoint::AfterCommit,
        FailureClass::FaultInjected,
    )));
    let error = store
        .reserve_reference(&chain_id, "op", "ref-stable-1")
        .unwrap_err();
    assert!(matches!(error, StoreError::PublicationStopped { .. }));
    drop(store);

    let store = open_store(&path);
    let view = store.operation(&chain_id, "op").unwrap();
    assert!(matches!(
        view.reference,
        ReferenceState::Pending { ref reference } if reference == "ref-stable-1"
    ));
    assert!(matches!(view.seal, SealState::NotReady));
    let kinds: Vec<_> = store
        .events(&chain_id, "op")
        .unwrap()
        .into_iter()
        .map(|event| event.kind)
        .collect();
    assert!(kinds.contains(&"reference-reserved".to_owned()));
    assert!(!kinds.iter().any(|kind| kind.contains("observed")));
    store
        .record_reference_write(
            &chain_id,
            "op",
            ReferenceWriteEvidence::OutcomeUnknown {
                diagnostic: "response lost before seal".to_owned(),
            },
        )
        .unwrap();
    drop(store);

    let producer = producer_for(SUBJECT, ISSUER);
    let store = open_store(&path);
    let view = store.operation(&chain_id, "op").unwrap();
    assert!(matches!(
        view.reference,
        ReferenceState::OutcomeUnknown { .. }
    ));
    let sealed = store
        .commit_seal(&chain_id, "op", b"req", |position| {
            produce_at(&producer, position)
        })
        .unwrap();
    assert!(matches!(sealed.seal, SealState::Sealed { .. }));
    assert!(matches!(
        sealed.reference,
        ReferenceState::OutcomeUnknown { .. }
    ));
    let stored = family_bytes(&path);
    let text = String::from_utf8_lossy(&stored);
    assert!(!text.contains("fabricated-acknowledgement"));
}

#[test]
fn st07_registration_timeout_keeps_bytes_and_remote_id_without_resigning() {
    let scratch = Scratch::new("st07");
    let path = scratch.db();
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    let store = open_store(&path);
    let sealed = seal(&store, &producer, &chain_id, "op", b"req");
    let bytes = sealed_bytes(&sealed);
    let view = store.begin_registration(&chain_id, "op").unwrap();
    let outbox_id = registration_id(&view);
    assert_eq!(registration_bytes(&view), bytes);
    store
        .observe_registration(
            outbox_id,
            TransportObservation::RemoteId {
                remote_tx_id: "remote-77".to_owned(),
            },
        )
        .unwrap();
    store
        .observe_registration(
            outbox_id,
            TransportObservation::TimeoutOrLost {
                diagnostic: "http response lost".to_owned(),
            },
        )
        .unwrap();
    drop(store);

    let calls = AtomicU32::new(0);
    let store = open_store(&path);
    let view = store.operation(&chain_id, "op").unwrap();
    assert_eq!(sealed_bytes(&view), bytes);
    match &view.registration {
        RegistrationState::Pending {
            remote_tx_id: Some(remote),
        } => assert_eq!(remote, "remote-77"),
        other => panic!("registration must stay pending with the remote id, got {other:?}"),
    }
    let outbox = registration_outbox(&view);
    assert!(outbox.ambiguity);
    assert_eq!(outbox.status, OutboxStatus::Ambiguous);
    assert_eq!(outbox.submitted_bytes, bytes);
    let again = store
        .retry_outbox(outbox_id)
        .expect("one configured retry remains");
    assert_eq!(registration_bytes(&again), bytes);
    let _ = store
        .commit_seal(&chain_id, "op", b"req", |position| {
            calls.fetch_add(1, Ordering::SeqCst);
            produce_at(&producer, position)
        })
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.chain_head(&chain_id).unwrap().unwrap().seq, 0);
}

#[test]
fn st08_disk_full_io_permission_schema_and_corruption_stop_publication() {
    let scratch = Scratch::new("st08-disk");
    let path = scratch.db();
    let store = open_store(&path);
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    seal(&store, &producer, &chain_id, "op", b"req");
    let pages = store.page_count_for_test().unwrap();
    store.limit_page_count_for_test(pages).unwrap();
    store.open_operation(&chain_id, "op-2", b"req-2").unwrap();
    let error = store
        .reserve_reference(&chain_id, "op-2", &"r".repeat(256 * 1024))
        .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::PublicationStopped {
                class: FailureClass::DiskFull,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(store.chain_head(&chain_id).unwrap().unwrap().seq, 0);
    assert!(matches!(
        store.operation(&chain_id, "op-2").unwrap().reference,
        ReferenceState::Absent
    ));
    drop(store);

    let scratch = Scratch::new("st08-io");
    let path = scratch.db();
    let mut store = open_store(&path);
    let chain_id = chain(ISSUER, SUBJECT);
    store.open_operation(&chain_id, "op", b"req").unwrap();
    store.set_fault_for_test(Some(fault(FaultPoint::BeforeCommit, FailureClass::Io)));
    let error = store
        .commit_seal(&chain_id, "op", b"req", |position| {
            produce_at(&producer_for(SUBJECT, ISSUER), position)
        })
        .unwrap_err();
    assert!(matches!(
        error,
        StoreError::PublicationStopped {
            class: FailureClass::Io,
            ..
        }
    ));
    drop(store);
    let store = open_store(&path);
    assert!(store.chain_head(&chain_id).unwrap().is_none());

    let scratch = Scratch::new("st08-perm");
    let blocker = scratch.0.join("not-a-directory");
    fs::write(&blocker, b"file").unwrap();
    let error = ChainStore::open(config(&blocker.join("state.db"), true, 3)).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::PublicationStopped {
                class: FailureClass::Permission,
                ..
            }
        ),
        "{error}"
    );

    let scratch = Scratch::new("st08-schema");
    let path = scratch.db();
    drop(open_store(&path));
    for version in ["0", "2"] {
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute(
            "UPDATE schema_meta SET meta_value = ?1 WHERE meta_key = 'schema_version'",
            [version],
        )
        .unwrap();
        drop(raw);
        let error = ChainStore::open(config(&path, true, 3)).unwrap_err();
        match error {
            StoreError::SchemaRefused {
                found, supported, ..
            } => {
                assert_eq!(found, version);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("{other:?}"),
        }
        let raw = rusqlite::Connection::open(&path).unwrap();
        let stored: String = raw
            .query_row(
                "SELECT meta_value FROM schema_meta WHERE meta_key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, version);
    }
    let scratch = Scratch::new("st08-corrupt");
    let path = scratch.db();
    let store = open_store(&path);
    seal(
        &store,
        &producer_for(SUBJECT, ISSUER),
        &chain(ISSUER, SUBJECT),
        "op",
        b"req",
    );
    store.checkpoint_for_test().unwrap();
    drop(store);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE chains SET head_seq = 9 WHERE issuer_identity = ?1",
        [ISSUER],
    )
    .unwrap();
    drop(raw);
    let error = ChainStore::open(config(&path, false, 3)).unwrap_err();
    assert!(matches!(error, StoreError::Inconsistent { .. }), "{error}");
    let raw = rusqlite::Connection::open(&path).unwrap();
    let head: i64 = raw
        .query_row("SELECT head_seq FROM chains", [], |row| row.get(0))
        .unwrap();
    assert_eq!(head, 9);
}

#[test]
fn st09_outbox_retries_are_bounded_and_ambiguity_is_explicit() {
    let scratch = Scratch::new("st09");
    let path = scratch.db();
    let mut settings = config(&path, true, 2);
    settings.outbox_max_attempts = 2;
    let store = ChainStore::open(settings).unwrap();
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    let bytes = sealed_bytes(&seal(&store, &producer, &chain_id, "op", b"req"));
    let view = store.begin_registration(&chain_id, "op").unwrap();
    let outbox_id = registration_id(&view);
    let retried = store.retry_outbox(outbox_id).unwrap();
    let outbox = registration_outbox(&retried);
    assert_eq!(outbox.attempt_count, 2);
    assert_eq!(outbox.max_attempts, 2);
    assert_eq!(outbox.submitted_bytes, bytes);
    let error = store.retry_outbox(outbox_id).unwrap_err();
    assert!(matches!(
        error,
        StoreError::RetriesExhausted {
            attempts: 2,
            max_attempts: 2,
            ..
        }
    ));
    let view = store.operation(&chain_id, "op").unwrap();
    let outbox = registration_outbox(&view);
    assert_eq!(outbox.status, OutboxStatus::Exhausted);
    assert_eq!(outbox.submitted_bytes, bytes);
    let submitted = outbox
        .attempts
        .iter()
        .filter(|attempt| attempt.status == "submitted")
        .count();
    assert_eq!(submitted, 2);
    assert!(
        outbox
            .attempts
            .iter()
            .any(|attempt| attempt.status == "exhausted")
    );
    store
        .observe_registration(
            outbox_id,
            TransportObservation::TimeoutOrLost {
                diagnostic: "transport ambiguous".to_owned(),
            },
        )
        .unwrap();
    let view = store.operation(&chain_id, "op").unwrap();
    let outbox = registration_outbox(&view);
    assert!(outbox.ambiguity);
    assert!(
        outbox
            .attempts
            .iter()
            .any(|attempt| attempt.diagnostic == "transport ambiguous" && attempt.ambiguity)
    );
    assert_eq!(outbox.submitted_bytes, bytes);
    assert!(matches!(
        view.registration,
        RegistrationState::Pending { .. }
    ));
    assert!(matches!(view.delivery, DeliveryState::Absent));
    store
        .record_delivery(
            &chain_id,
            "op",
            DeliveryOutcome::Ambiguous {
                detail: "delivery not confirmed".to_owned(),
            },
        )
        .unwrap();
    let view = store.operation(&chain_id, "op").unwrap();
    assert!(matches!(
        view.delivery,
        DeliveryState::Recorded(DeliveryOutcome::Ambiguous { .. })
    ));
    assert!(matches!(
        view.registration,
        RegistrationState::Pending { .. }
    ));
    assert!(matches!(view.seal, SealState::Sealed { .. }));
}

#[test]
fn st10_consistent_rollback_is_not_reported_as_tamper_proof_history() {
    let scratch = Scratch::new("st10");
    let path = scratch.db();
    let producer = producer_for(SUBJECT, ISSUER);
    let chain_id = chain(ISSUER, SUBJECT);
    let store = open_store(&path);
    seal(&store, &producer, &chain_id, "op-0", b"one");
    store.checkpoint_for_test().unwrap();
    drop(store);
    let snap = scratch.0.join("snap");
    snapshot_family(&path, &snap);

    let store = open_store(&path);
    seal(&store, &producer, &chain_id, "op-1", b"two");
    store.checkpoint_for_test().unwrap();
    assert_eq!(store.chain_head(&chain_id).unwrap().unwrap().seq, 1);
    drop(store);

    restore_family(&path, &snap);
    let store = ChainStore::open(config(&path, false, 3)).unwrap();
    let assurance = store.open_assurance();
    assert!(assurance.local_invariants_hold);
    assert!(!assurance.claims_tamper_proof_latest_history);
    assert!(HISTORY_LIMIT.contains(
        "Malicious database rollback beyond available external evidence is not generally detected."
    ));
    assert_eq!(store.chain_head(&chain_id).unwrap().unwrap().seq, 0);
    assert!(store.operation(&chain_id, "op-1").is_err());
}

#[test]
fn st11_producer_and_reference_site_remain_unchanged() {
    let (signing, verifying) = keypair();
    let producer = Ed25519SiteProducer::new(
        res_001::site_config(),
        Arc::new(FixedClock::new("2026-10-15T14:00:00Z")),
        signing,
    );
    let mut request = res_001::engagement_request(res_001::evidence_bundle());
    request.chain_seq = 7;
    request.chain_prev_hash =
        Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned());
    let statement = producer.produce(&request).unwrap();
    let payload = pask_wire::verify_ed25519(&statement, &verifying).unwrap();
    assert_eq!(payload.chain_seq(), 7);
    assert_eq!(
        payload.chain_prev_hash(),
        Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );

    let request = res_001::engagement_request(res_001::evidence_bundle());
    let (signing, _) = keypair();
    let producer = Ed25519SiteProducer::new(
        res_001::site_config(),
        Arc::new(FixedClock::new("2026-10-15T14:00:00Z")),
        signing,
    );
    let site = ReferenceSite::new(
        Arc::new(producer),
        Arc::new(pask_adapter::mock::MockAdapter::default()),
    );
    let outcome = site.run_engagement(&request).unwrap();
    assert!(matches!(
        outcome,
        pask_adapter::AdapterOutcome::Pushed { .. }
    ));
}

fn fault(point: FaultPoint, class: FailureClass) -> Arc<dyn FaultInjector> {
    Arc::new(FailAt { point, class })
}

fn registration_id(view: &super::OperationView) -> i64 {
    registration_outbox(view).outbox_id
}

fn registration_bytes(view: &super::OperationView) -> Vec<u8> {
    registration_outbox(view).submitted_bytes.clone()
}

fn registration_outbox(view: &super::OperationView) -> &super::OutboxView {
    view.outbox
        .iter()
        .find(|item| item.purpose == OutboxPurpose::Registration)
        .unwrap_or_else(|| panic!("missing registration outbox in {view:?}"))
}
