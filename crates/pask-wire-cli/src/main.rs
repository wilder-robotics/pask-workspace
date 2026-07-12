// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Command-line wrapper for producing and verifying PSER statements.

#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{
    SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use pask_wire::{Payload, produce_ed25519, verify_ed25519};

#[derive(Debug, Parser)]
#[command(name = "pask-wire", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Produce {
        payload: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        statement: PathBuf,
        #[arg(long = "trust-anchor")]
        trust_anchor: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Produce { payload, key, out } => {
            let input = fs::read(&payload)
                .with_context(|| format!("failed to read payload {}", payload.display()))?;
            let payload = Payload::from_json_for_production(&input)
                .context("payload does not conform to wilder.pser/0.1")?;
            let pem = fs::read_to_string(&key)
                .with_context(|| format!("failed to read signing key {}", key.display()))?;
            let key = SigningKey::from_pkcs8_pem(&pem)
                .map_err(|error| anyhow::anyhow!("invalid Ed25519 PKCS#8 key: {error}"))?;
            let statement = produce_ed25519(&payload, payload.witness_key(), &key)
                .context("failed to produce statement")?;
            fs::write(&out, statement)
                .with_context(|| format!("failed to write statement {}", out.display()))?;
        }
        Command::Verify {
            statement,
            trust_anchor,
        } => {
            let statement_bytes = fs::read(&statement)
                .with_context(|| format!("failed to read statement {}", statement.display()))?;
            let pem = fs::read_to_string(&trust_anchor).with_context(|| {
                format!("failed to read trust anchor {}", trust_anchor.display())
            })?;
            let key = VerifyingKey::from_public_key_pem(&pem)
                .map_err(|error| anyhow::anyhow!("invalid Ed25519 public key: {error}"))?;
            let payload =
                verify_ed25519(&statement_bytes, &key).context("statement verification failed")?;
            let canonical =
                String::from_utf8(payload.to_jcs()?).context("canonical payload was not UTF-8")?;
            println!("{canonical}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pask_wire::testvectors::MINIMAL_VALID_PAYLOAD;

    #[test]
    fn cli_library_round_trip() {
        let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let statement = produce_ed25519(&payload, payload.witness_key(), &key).unwrap();
        let verified = verify_ed25519(&statement, &key.verifying_key()).unwrap();
        assert_eq!(verified, payload);
    }
}
