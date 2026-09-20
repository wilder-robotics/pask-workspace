// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// See LICENSING.md in the workspace root.

//! Allocation-free CBOR resource preflight. Decode only after this succeeds.
use crate::receipt_inspection::{InspectionLimits, Problem};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Role {
    Any,
    Envelope,
    Sign1,
    Protected,
    Unprotected,
    ProtectedMap,
    Claims,
    Issuer,
    Subject,
    Signature,
    Vdp,
    Proofs,
    Proof,
    Path,
    Chain,
    Certificate,
    HeaderLabel,
    ClaimLabel,
    RequiredInteger,
    Critical,
    CriticalLabel,
    TreeSize,
    LeafIndex,
    Thumbprint,
    ThumbprintAlgorithm,
    UnprotectedThumbprint,
    UnprotectedThumbprintAlgorithm,
}

pub(crate) struct Budget<'a> {
    pub limits: &'a InspectionLimits,
    pub items: usize,
    pub unprotected_x5t_invalid: bool,
}

impl Budget<'_> {
    pub fn scan(
        &mut self,
        bytes: &[u8],
        depth: usize,
        role: Role,
        trailing: &'static str,
    ) -> Result<(), Problem> {
        let mut reader = Reader {
            bytes,
            pos: 0,
            budget: self,
            issuer_characters: 0,
            subject_characters: 0,
            x509: false,
        };
        reader.item(depth, role)?;
        if reader.pos != bytes.len() {
            return Err(Problem::structure(trailing));
        }
        if reader.x509 && reader.issuer_characters > 8192 {
            return Err(Problem::claims("issuer_length"));
        }
        if reader.issuer_characters > reader.budget.limits.max_claim_text_characters
            || reader.subject_characters > reader.budget.limits.max_claim_text_characters
        {
            return Err(Problem::policy("claim_text_limit"));
        }
        Ok(())
    }
}

struct Reader<'a, 'b, 'c> {
    bytes: &'a [u8],
    pos: usize,
    budget: &'b mut Budget<'c>,
    issuer_characters: usize,
    subject_characters: usize,
    x509: bool,
}

impl Reader<'_, '_, '_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Problem> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Problem::structure("invalid_cbor"))?;
        let part = self
            .bytes
            .get(self.pos..end)
            .ok_or(Problem::structure("invalid_cbor"))?;
        self.pos = end;
        Ok(part)
    }
    fn argument(&mut self, ai: u8) -> Result<Option<u64>, Problem> {
        Ok(match ai {
            0..=23 => Some(u64::from(ai)),
            24 => Some(u64::from(self.take(1)?[0])),
            25 => Some(u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().unwrap(),
            ))),
            26 => Some(u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().unwrap(),
            ))),
            27 => Some(u64::from_be_bytes(self.take(8)?.try_into().unwrap())),
            31 => None,
            _ => return Err(Problem::structure("invalid_cbor")),
        })
    }
    fn length(n: u64) -> Result<usize, Problem> {
        n.try_into().map_err(|_| Problem::policy("cbor_item_limit"))
    }
    fn bump(&mut self) -> Result<(), Problem> {
        self.budget.items = self
            .budget
            .items
            .checked_add(1)
            .ok_or(Problem::policy("cbor_item_limit"))?;
        if self.budget.items > self.budget.limits.max_cbor_items {
            return Err(Problem::policy("cbor_item_limit"));
        }
        Ok(())
    }
    fn byte_limit(&self, role: Role) -> (usize, &'static str) {
        match role {
            Role::Protected => (
                self.budget.limits.max_protected_bytes,
                "protected_byte_limit",
            ),
            Role::Signature => (
                self.budget.limits.max_signature_bytes,
                "signature_byte_limit",
            ),
            Role::Chain | Role::Certificate => (
                self.budget.limits.max_certificate_bytes,
                "certificate_byte_limit",
            ),
            _ => (self.budget.limits.max_receipt_bytes, "receipt_byte_limit"),
        }
    }
    fn array_limit(&self, role: Role) -> (usize, &'static str) {
        match role {
            Role::Proofs => (self.budget.limits.max_proofs_per_receipt, "proof_limit"),
            Role::Path => (self.budget.limits.max_path_nodes_per_proof, "path_limit"),
            Role::Chain => (
                self.budget.limits.max_certificate_chain_length,
                "certificate_count_limit",
            ),
            _ => (self.budget.limits.max_cbor_items, "cbor_item_limit"),
        }
    }
    // Returns integer atoms for role selection, not semantic header lookup.
    fn item(&mut self, depth: usize, role: Role) -> Result<Option<i128>, Problem> {
        self.bump()?;
        let head = self.take(1)?[0];
        let major = head >> 5;
        // ciborium's generic Value decoder normalizes small tag-2/tag-3
        // bignums into Integer. Wire labels/int/uint fields must be checked
        // from their actual major type before that decoding or allocation.
        // Do not reject tags in opaque, unrecognized extension values.
        match role {
            Role::HeaderLabel if !matches!(major, 0 | 1 | 3) => {
                return Err(Problem::structure("header_label_type"));
            }
            Role::ClaimLabel if !matches!(major, 0 | 1 | 3) => {
                return Err(Problem::claims("claim_label_type"));
            }
            Role::RequiredInteger if !matches!(major, 0 | 1) => {
                return Err(Problem::claims("required_header_type"));
            }
            Role::CriticalLabel if !matches!(major, 0 | 1 | 3) => {
                return Err(Problem::structure("crit_label_type"));
            }
            Role::TreeSize if major != 0 => {
                return Err(Problem::structure("tree_type"));
            }
            Role::LeafIndex if major != 0 => {
                return Err(Problem::structure("leaf_type"));
            }
            Role::ThumbprintAlgorithm if !matches!(major, 0 | 1 | 3) => {
                return Err(Problem::claims("x5t_shape"));
            }
            Role::UnprotectedThumbprintAlgorithm if !matches!(major, 0 | 1 | 3) => {
                // Record the raw type before decode, but an otherwise permitted
                // protected x5t overlap must still take precedence. The caller
                // applies this finding only if the unprotected value is effective.
                self.budget.unprotected_x5t_invalid = true;
            }
            _ => (),
        }
        let ai = head & 31;
        let arg = self.argument(ai)?;
        if matches!(major, 4..=6) && depth >= self.budget.limits.max_cbor_nesting {
            return Err(Problem::policy("cbor_nesting_limit"));
        }
        match major {
            0 | 1 => {
                let n = i128::from(arg.ok_or(Problem::structure("invalid_cbor"))?);
                return Ok(Some(if major == 0 { n } else { -1 - n }));
            }
            2 | 3 => {
                let (limit, code) = self.byte_limit(role);
                let mut characters = 0usize;
                if let Some(n) = arg {
                    let len = Self::length(n)?;
                    if len > limit {
                        return Err(Problem::policy(code));
                    }
                    let bytes = self.take(len)?;
                    if major == 3 {
                        characters = core::str::from_utf8(bytes)
                            .map_err(|_| Problem::structure("invalid_cbor"))?
                            .chars()
                            .count();
                    }
                } else {
                    let mut total = 0usize;
                    while self.bytes.get(self.pos) != Some(&0xff) {
                        self.bump()?; // String chunks are counted too (conservative local budget).
                        let chunk = self.take(1)?[0];
                        if chunk >> 5 != major {
                            return Err(Problem::structure("invalid_cbor"));
                        }
                        let len = Self::length(
                            self.argument(chunk & 31)?
                                .ok_or(Problem::structure("invalid_cbor"))?,
                        )?;
                        total = total.checked_add(len).ok_or(Problem::policy(code))?;
                        if total > limit {
                            return Err(Problem::policy(code));
                        }
                        let bytes = self.take(len)?;
                        if major == 3 {
                            characters = characters
                                .checked_add(
                                    core::str::from_utf8(bytes)
                                        .map_err(|_| Problem::structure("invalid_cbor"))?
                                        .chars()
                                        .count(),
                                )
                                .ok_or(Problem::policy("claim_text_limit"))?;
                        }
                    }
                    self.take(1)?;
                }
                if role == Role::Issuer {
                    self.issuer_characters = self.issuer_characters.max(characters);
                }
                if role == Role::Subject {
                    self.subject_characters = self.subject_characters.max(characters);
                }
            }
            4 | 5 => {
                let count = arg.map(Self::length).transpose()?;
                let (limit, code) = if major == 5 {
                    (self.budget.limits.max_map_entries, "map_entry_limit")
                } else {
                    self.array_limit(role)
                };
                if count.is_some_and(|n| n > limit) {
                    return Err(Problem::policy(code));
                }
                if let Some(n) = count {
                    let items = n
                        .checked_mul(if major == 5 { 2 } else { 1 })
                        .ok_or(Problem::policy("cbor_item_limit"))?;
                    if items
                        > self
                            .budget
                            .limits
                            .max_cbor_items
                            .saturating_sub(self.budget.items)
                    {
                        return Err(Problem::policy("cbor_item_limit"));
                    }
                }
                let mut i = 0usize;
                loop {
                    if count == Some(i) {
                        break;
                    }
                    if count.is_none() && self.bytes.get(self.pos) == Some(&0xff) {
                        self.take(1)?;
                        break;
                    }
                    if i >= limit {
                        return Err(Problem::policy(code));
                    }
                    let child = if major == 5 {
                        let key_role = match role {
                            Role::ProtectedMap | Role::Unprotected | Role::Vdp => Role::HeaderLabel,
                            Role::Claims => Role::ClaimLabel,
                            _ => Role::Any,
                        };
                        let key = self.item(depth + 1, key_role)?;
                        if role == Role::ProtectedMap && matches!(key, Some(33 | 34)) {
                            self.x509 = true;
                        }
                        match (role, key) {
                            (Role::ProtectedMap, Some(1 | 395)) => Role::RequiredInteger,
                            (Role::ProtectedMap, Some(2)) => Role::Critical,
                            (Role::ProtectedMap, Some(15)) => Role::Claims,
                            (Role::ProtectedMap, Some(34)) => Role::Thumbprint,
                            (Role::Unprotected, Some(34)) => Role::UnprotectedThumbprint,
                            (Role::ProtectedMap | Role::Unprotected, Some(33)) => Role::Chain,
                            (Role::Claims, Some(1)) => Role::Issuer,
                            (Role::Claims, Some(2)) => Role::Subject,
                            (Role::Unprotected, Some(396)) => Role::Vdp,
                            (Role::Vdp, Some(-1)) => Role::Proofs,
                            _ => Role::Any,
                        }
                    } else {
                        match (role, i) {
                            (Role::Sign1, 0) => Role::Protected,
                            (Role::Sign1, 1) => Role::Unprotected,
                            (Role::Sign1, 3) => Role::Signature,
                            (Role::Proof, 0) => Role::TreeSize,
                            (Role::Proof, 1) => Role::LeafIndex,
                            (Role::Proof, 2) => Role::Path,
                            (Role::Critical, _) => Role::CriticalLabel,
                            (Role::Thumbprint, 0) => Role::ThumbprintAlgorithm,
                            (Role::UnprotectedThumbprint, 0) => {
                                Role::UnprotectedThumbprintAlgorithm
                            }
                            (Role::Chain, _) => Role::Certificate,
                            _ => Role::Any,
                        }
                    };
                    self.item(depth + 1, child)?;
                    i += 1;
                }
            }
            6 => {
                let tag = arg.ok_or(Problem::structure("invalid_cbor"))?;
                self.item(
                    depth + 1,
                    if role == Role::Envelope && tag == 18 {
                        Role::Sign1
                    } else {
                        Role::Any
                    },
                )?;
            }
            7 => {
                if ai == 31 || (ai == 24 && arg.is_some_and(|v| v < 32)) {
                    return Err(Problem::structure("invalid_cbor"));
                }
            }
            _ => unreachable!(),
        }
        Ok(None)
    }
}
