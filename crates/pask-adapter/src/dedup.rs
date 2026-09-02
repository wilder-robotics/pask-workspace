// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapter is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use sha2::{Digest, Sha256};

/// Records completed writes by raw signed-receipt digest.
pub trait DedupLog: Send + Sync {
    /// Returns whether the receipt digest was recorded.
    fn is_pushed(&self, receipt_digest: &[u8; 32]) -> bool;

    /// Records the adapter identifier returned by a successful write.
    fn record_pushed(&self, receipt_digest: &[u8; 32], adapter_receipt_id: &str);

    /// Returns the adapter identifier recorded for a prior push, when known.
    /// Implementations MAY return `None` for externally-populated dedup logs.
    fn prior_receipt_id(&self, receipt_digest: &[u8; 32]) -> Option<String>;
}

/// Process-local deduplication log.
#[derive(Debug, Default)]
pub struct InMemoryDedupLog {
    entries: Mutex<HashMap<[u8; 32], String>>,
}

impl InMemoryDedupLog {
    /// Creates an empty deduplication log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<[u8; 32], String>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl DedupLog for InMemoryDedupLog {
    fn is_pushed(&self, receipt_digest: &[u8; 32]) -> bool {
        self.entries().contains_key(receipt_digest)
    }

    fn record_pushed(&self, receipt_digest: &[u8; 32], adapter_receipt_id: &str) {
        self.entries()
            .insert(*receipt_digest, adapter_receipt_id.to_owned());
    }

    fn prior_receipt_id(&self, receipt_digest: &[u8; 32]) -> Option<String> {
        self.entries().get(receipt_digest).cloned()
    }
}

/// Computes SHA-256 over the raw signed receipt.
#[must_use]
pub fn receipt_digest(signed_receipt: &[u8]) -> [u8; 32] {
    Sha256::digest(signed_receipt).into()
}

/// Encodes bytes using lowercase hexadecimal.
#[must_use]
pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
