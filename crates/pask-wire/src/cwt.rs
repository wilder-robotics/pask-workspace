// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use alloc::{string::String, vec, vec::Vec};
use coset::cbor::Value;

use crate::{Error, Result};

pub(crate) const CWT_CLAIMS_LABEL: i64 = 15;
const ISS_LABEL: i64 = 1;
const SUB_LABEL: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CwtClaims {
    pub(crate) issuer: String,
    pub(crate) subject: Vec<u8>,
}

impl CwtClaims {
    pub(crate) fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Integer(ISS_LABEL.into()),
                Value::Text(self.issuer.clone()),
            ),
            (
                Value::Integer(SUB_LABEL.into()),
                Value::Bytes(self.subject.clone()),
            ),
        ])
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let Value::Map(entries) = value else {
            return Err(Error::Header("CWT_Claims must be a CBOR map"));
        };
        let mut issuer = None;
        let mut subject = None;
        for (label, claim) in entries {
            match label {
                Value::Integer(integer) if i128::from(*integer) == i128::from(ISS_LABEL) => {
                    let Value::Text(value) = claim else {
                        return Err(Error::Header("CWT iss must be text"));
                    };
                    issuer = Some(value.clone());
                }
                Value::Integer(integer) if i128::from(*integer) == i128::from(SUB_LABEL) => {
                    let Value::Bytes(value) = claim else {
                        return Err(Error::Header("CWT sub must be bytes"));
                    };
                    subject = Some(value.clone());
                }
                _ => {}
            }
        }
        Ok(Self {
            issuer: issuer.ok_or(Error::Header("CWT iss is missing"))?,
            subject: subject.ok_or(Error::Header("CWT sub is missing"))?,
        })
    }
}
