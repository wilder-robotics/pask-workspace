// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! LOCAL PROPOSAL: salted fact membership, not a frozen PSER wire format.
//!
//! The input is canonical fact JSON, not original evidence bytes. This component
//! never rewrites a signed statement or evidence object. A matched caller root
//! does not authenticate its origin, a receipt, a fact attribution, or the truth
//! of a value. Vocabulary constraints and evidence comparison remain separate.

use alloc::{string::String, vec::Vec};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CONSTRUCTION: &str = "pask-local-content-tree/1";
pub const SCOPE: &str = "PRESENTED_AT_SEAL";
pub const MAX_FACTS: usize = 256;
pub const MAX_FACT_BYTES: usize = 16_384;
pub const MAX_TOTAL_FACT_BYTES: usize = 1_048_576;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_PROOF_HASHES: usize = 8;
const DOMAIN: &[u8] = b"PASK-LOCAL-CONTENT-TREE/1\0";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentError {
    UnsupportedConstruction,
    InvalidScope,
    InvalidDigest,
    FactCountLimit,
    FactByteLimit,
    TotalByteLimit,
    JsonDepthLimit,
    InvalidFactJson,
    NonCanonicalFact,
    UnsupportedNumber,
    InvalidFactShape,
    InvalidFactName,
    DuplicateFactName,
    ReusedSalt,
    UnknownFactName,
    InvalidIndex,
    InvalidProofLength,
    RootMismatch,
    DuplicateDisclosure,
    UnorderedNames,
}

#[derive(Clone, Copy, Debug)]
pub struct ContentHeader<'a> {
    pub construction: &'a str,
    pub scope: &'a str,
    /// Digest identifies the vocabulary; this API does not retrieve or validate it.
    pub vocabulary_digest: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct SaltedFact<'a> {
    /// Complete canonical JSON object, including all extra properties.
    pub record: &'a [u8],
    /// Caller supplies a fresh unpredictable salt; entropy is not verified here.
    pub salt: Hash,
}

#[derive(Clone, Debug)]
pub struct DisclosedFact<'a> {
    pub record: &'a [u8],
    pub salt: Hash,
    pub index: u32,
    /// Bottom-up siblings; directions follow index and total count, not caller flags.
    pub siblings: Vec<Hash>,
}

#[derive(Debug, Serialize)]
pub struct DisclosureReport {
    pub schema: &'static str,
    pub membership: &'static str,
    pub disclosure: &'static str,
    pub presented_facts: usize,
    /// Authenticated to the supplied root only if membership is MATCHED.
    pub claimed_fact_count: usize,
    pub count_bound_to_supplied_root: bool,
    pub root_origin: &'static str,
    pub receipt_binding: &'static str,
    pub fact_constraints: &'static str,
    pub evidence_comparison: &'static str,
    pub attributed_party_authenticated: bool,
    pub latest_or_complete_history_established: bool,
    pub semantic_absence_established: bool,
}

/// Validated bounded material for producing full or selected disclosures.
/// Sorted order is ASCII fact-name order. Neither facts nor salts are regenerated.
#[derive(Debug)]
pub struct PreparedContent<'a> {
    root: Hash,
    header_hash: Hash,
    facts: Vec<SaltedFact<'a>>,
    names: Vec<String>,
    leaves: Vec<Hash>,
}

fn hash(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn digest_bytes(text: &str) -> Result<Hash, ContentError> {
    if text.len() != 71 || !text.starts_with("sha256:") {
        return Err(ContentError::InvalidDigest);
    }
    let mut result = [0; 32];
    let (pairs, remainder) = text.as_bytes()[7..].as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ContentError::InvalidDigest);
    }
    fn nibble(b: u8) -> Result<u8, ContentError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(ContentError::InvalidDigest),
        }
    }
    for (out, pair) in result.iter_mut().zip(pairs) {
        *out = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(result)
}

fn header_hash(header: &ContentHeader<'_>, count: usize) -> Result<Hash, ContentError> {
    if header.construction != CONSTRUCTION {
        return Err(ContentError::UnsupportedConstruction);
    }
    if header.scope != SCOPE {
        return Err(ContentError::InvalidScope);
    }
    if count > MAX_FACTS {
        return Err(ContentError::FactCountLimit);
    }
    let vocabulary = digest_bytes(header.vocabulary_digest)?;
    // Fixed construction and scope are bound literally. No caller-selected encoding.
    Ok(hash(&[
        &[0],
        &(count as u64).to_be_bytes(),
        &(CONSTRUCTION.len() as u64).to_be_bytes(),
        CONSTRUCTION.as_bytes(),
        &(SCOPE.len() as u64).to_be_bytes(),
        SCOPE.as_bytes(),
        &vocabulary,
    ]))
}

// Bound bytes and syntactic nesting before serde allocates the parsed tree.
// This does not validate JSON syntax; the subsequent parser must consume all input.
fn raw_preflight(bytes: &[u8]) -> Result<(), ContentError> {
    if bytes.len() > MAX_FACT_BYTES {
        return Err(ContentError::FactByteLimit);
    }
    let (mut depth, mut string, mut escaped) = (0usize, false, false);
    for &b in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(ContentError::JsonDepthLimit);
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(ContentError::InvalidFactJson)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn safe_numbers(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer.unsigned_abs() <= MAX_SAFE_INTEGER
            } else if let Some(integer) = number.as_u64() {
                integer <= MAX_SAFE_INTEGER
            } else {
                number.as_f64().is_some_and(f64::is_finite)
            }
        }
        Value::Array(items) => items.iter().all(safe_numbers),
        Value::Object(items) => items.values().all(safe_numbers),
        _ => true,
    }
}

fn fact_name(bytes: &[u8]) -> Result<String, ContentError> {
    raw_preflight(bytes)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ContentError::InvalidFactJson)?;
    if !safe_numbers(&value) {
        return Err(ContentError::UnsupportedNumber);
    }
    let canonical = crate::canonicalize_json(bytes).map_err(|_| ContentError::InvalidFactJson)?;
    if canonical != bytes {
        // Also rejects duplicate properties: their original input cannot equal
        // canonical serialization of the unique-property parsed object.
        return Err(ContentError::NonCanonicalFact);
    }
    let object = value.as_object().ok_or(ContentError::InvalidFactShape)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or(ContentError::InvalidFactShape)?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(ContentError::InvalidFactName);
    }
    if !object.contains_key("value")
        || object.get("assertedBy").and_then(Value::as_str).is_none()
        || object.get("basis").and_then(Value::as_str).is_none()
    {
        return Err(ContentError::InvalidFactShape);
    }
    // Deliberately do not run the vocabulary constraint classifier here.
    // A well-formed forbidden attribution must remain provable and reportable.
    Ok(String::from(name))
}

fn leaf(header: &Hash, index: usize, fact: &SaltedFact<'_>) -> Hash {
    hash(&[
        &[1],
        header,
        &(index as u64).to_be_bytes(),
        &fact.salt,
        &(fact.record.len() as u64).to_be_bytes(),
        fact.record,
    ])
}

fn split(count: usize) -> usize {
    // Used only for 2..=MAX_FACTS. Largest power of two strictly below count.
    let mut result = 1;
    while result * 2 < count {
        result *= 2;
    }
    result
}

fn tree_hash(leaves: &[Hash], header: &Hash) -> Hash {
    match leaves {
        [] => hash(&[&[2], header]),
        [only] => *only,
        _ => {
            let (left, right) = leaves.split_at(split(leaves.len()));
            hash(&[&[3], &tree_hash(left, header), &tree_hash(right, header)])
        }
    }
}

fn root_hash(header: &Hash, tree: &Hash) -> Hash {
    hash(&[&[4], header, tree])
}

fn inclusion_path(leaves: &[Hash], index: usize, header: &Hash, path: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    let (left, right) = leaves.split_at(k);
    if index < k {
        inclusion_path(left, index, header, path);
        path.push(tree_hash(right, header));
    } else {
        inclusion_path(right, index - k, header, path);
        path.push(tree_hash(left, header));
    }
}

fn reconstructed_tree(
    count: usize,
    index: usize,
    value: Hash,
    path: &[Hash],
    used: &mut usize,
) -> Result<Hash, ContentError> {
    if count == 1 {
        return Ok(value);
    }
    let k = split(count);
    let child = if index < k {
        reconstructed_tree(k, index, value, path, used)?
    } else {
        reconstructed_tree(count - k, index - k, value, path, used)?
    };
    let sibling = path.get(*used).ok_or(ContentError::InvalidProofLength)?;
    *used += 1;
    Ok(if index < k {
        hash(&[&[3], &child, sibling])
    } else {
        hash(&[&[3], sibling, &child])
    })
}

fn report(count: usize, presented: usize, matched: bool) -> DisclosureReport {
    DisclosureReport {
        schema: "pask-local-content-disclosure-report/1",
        membership: if matched { "MATCHED" } else { "NOT_PRESENTED" },
        disclosure: if matched && presented == count {
            "ALL_COMMITTED_SLOTS"
        } else if matched {
            "SELECTED_SLOTS_ONLY"
        } else {
            "NOT_PRESENTED"
        },
        presented_facts: presented,
        claimed_fact_count: count,
        count_bound_to_supplied_root: matched,
        root_origin: "CALLER_SUPPLIED_UNAUTHENTICATED",
        receipt_binding: "NOT_EVALUATED",
        fact_constraints: "NOT_EVALUATED",
        evidence_comparison: "NOT_RUN",
        attributed_party_authenticated: false,
        latest_or_complete_history_established: false,
        semantic_absence_established: false,
    }
}

/// Prepare bounded local commitments. Input order is irrelevant; ASCII fact names
/// determine leaf order. Duplicate names and repeated salts in this block reject.
/// Salt freshness/randomness across blocks cannot be established by this function.
pub fn prepare_content<'a>(
    header: &ContentHeader<'_>,
    facts: &[SaltedFact<'a>],
) -> Result<PreparedContent<'a>, ContentError> {
    let h = header_hash(header, facts.len())?;
    let mut total = 0usize;
    let mut rows = Vec::with_capacity(facts.len());
    for (i, fact) in facts.iter().enumerate() {
        if fact.record.len() > MAX_TOTAL_FACT_BYTES - total {
            return Err(ContentError::TotalByteLimit);
        }
        total += fact.record.len();
        if facts[..i].iter().any(|previous| previous.salt == fact.salt) {
            return Err(ContentError::ReusedSalt);
        }
        rows.push((fact_name(fact.record)?, *fact));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ContentError::DuplicateFactName);
    }
    let mut sorted = Vec::with_capacity(rows.len());
    let mut names = Vec::with_capacity(rows.len());
    let mut leaves = Vec::with_capacity(rows.len());
    for (index, (name, fact)) in rows.into_iter().enumerate() {
        leaves.push(leaf(&h, index, &fact));
        names.push(name);
        sorted.push(fact);
    }
    Ok(PreparedContent {
        root: root_hash(&h, &tree_hash(&leaves, &h)),
        header_hash: h,
        facts: sorted,
        names,
        leaves,
    })
}

impl<'a> PreparedContent<'a> {
    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn root_digest(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::from("sha256:");
        for byte in self.root {
            result.push(HEX[usize::from(byte >> 4)] as char);
            result.push(HEX[usize::from(byte & 15)] as char);
        }
        result
    }

    pub fn fact_count(&self) -> u32 {
        self.facts.len() as u32
    }

    pub fn disclose(&self, name: &str) -> Result<DisclosedFact<'a>, ContentError> {
        let index = self
            .names
            .iter()
            .position(|item| item == name)
            .ok_or(ContentError::UnknownFactName)?;
        let fact = self.facts[index];
        let mut siblings = Vec::new();
        inclusion_path(&self.leaves, index, &self.header_hash, &mut siblings);
        Ok(DisclosedFact {
            record: fact.record,
            salt: fact.salt,
            index: index as u32,
            siblings,
        })
    }
}

/// Verify selected disclosures relative ONLY to the caller-supplied root.
/// Empty disclosure of a nonempty block is NOT_PRESENTED, not a verified header
/// or proven absence. For an empty committed block, the header/root can be checked.
/// Successful proofs bind count and presented values, not the global ordering or
/// metadata validity of withheld facts, physical truth, or complete history.
///
/// Total input facts <=256, bytes <=1 MiB, each fact <=16 KiB and JSON container
/// nesting <=16 before parsing; <=8 siblings per proof. The API does not bound
/// the caller's previous allocation of records/proofs, nor parse a wire container.
pub fn verify_content_disclosures(
    expected_digest: &str,
    header: &ContentHeader<'_>,
    count: u32,
    disclosures: &[DisclosedFact<'_>],
) -> Result<DisclosureReport, ContentError> {
    let expected = digest_bytes(expected_digest)?;
    let count = count as usize;
    let h = header_hash(header, count)?;
    if disclosures.len() > count {
        return Err(ContentError::DuplicateDisclosure);
    }
    if disclosures.is_empty() {
        if count == 0 {
            if root_hash(&h, &tree_hash(&[], &h)) != expected {
                return Err(ContentError::RootMismatch);
            }
            return Ok(report(0, 0, true));
        }
        return Ok(report(count, 0, false));
    }
    let mut total = 0usize;
    let mut presented = Vec::with_capacity(disclosures.len());
    for (position, d) in disclosures.iter().enumerate() {
        let index = d.index as usize;
        if index >= count {
            return Err(ContentError::InvalidIndex);
        }
        if d.siblings.len() > MAX_PROOF_HASHES {
            return Err(ContentError::InvalidProofLength);
        }
        if d.record.len() > MAX_TOTAL_FACT_BYTES - total {
            return Err(ContentError::TotalByteLimit);
        }
        total += d.record.len();
        if disclosures[..position]
            .iter()
            .any(|earlier| earlier.index == d.index)
        {
            return Err(ContentError::DuplicateDisclosure);
        }
        if disclosures[..position]
            .iter()
            .any(|earlier| earlier.salt == d.salt)
        {
            return Err(ContentError::ReusedSalt);
        }
        let name = fact_name(d.record)?;
        if presented
            .iter()
            .any(|(_, prior): &(usize, String)| prior == &name)
        {
            return Err(ContentError::DuplicateFactName);
        }
        let fact = SaltedFact {
            record: d.record,
            salt: d.salt,
        };
        let mut used = 0;
        let tree =
            reconstructed_tree(count, index, leaf(&h, index, &fact), &d.siblings, &mut used)?;
        if used != d.siblings.len() {
            return Err(ContentError::InvalidProofLength);
        }
        if root_hash(&h, &tree) != expected {
            return Err(ContentError::RootMismatch);
        }
        presented.push((index, name));
    }
    presented.sort_by_key(|item| item.0);
    if presented.windows(2).any(|pair| pair[0].1 >= pair[1].1) {
        return Err(ContentError::UnorderedNames);
    }
    Ok(report(count, disclosures.len(), true))
}
