// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Producer and verifier for the `wilder.pser/0.2` signed-statement profile.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
mod cwt;
#[cfg(feature = "alloc")]
mod digest;
#[cfg(feature = "alloc")]
mod envelope;
#[cfg(feature = "alloc")]
mod error;
#[cfg(feature = "alloc")]
mod payload;
#[cfg(feature = "alloc")]
pub mod testvectors;

#[cfg(feature = "alloc")]
pub use digest::{sha256_prefixed, validate_sha256};
#[cfg(feature = "alloc")]
pub use envelope::{CONTENT_TYPE, produce_ed25519, verify_ed25519};
#[cfg(feature = "es256")]
pub use envelope::{produce_es256, verify_es256};
#[cfg(feature = "alloc")]
pub use error::{Error, Result};
#[cfg(feature = "alloc")]
pub use payload::{Payload, SPEC_VERSION, canonicalize_json};
