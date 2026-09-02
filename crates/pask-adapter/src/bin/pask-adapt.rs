// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-adapt is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.
//
// This command used to live in pask-wire-cli behind an `adapter` feature
// flag. It was moved here on 2026-09-02 when the workspace license was split.
// The reason is licensing, not ergonomics: pask-wire-cli is now Apache-2.0 so
// that an implementer can run it against their own implementation without a
// copyleft review, and a binary whose license changed depending on which Cargo
// features were enabled would have made that promise conditional and therefore
// untrue. Write-in to an operations system is product surface and belongs on
// the copyleft side. See LICENSING.md.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use pask_adapter::{
    AdapterWriteIn, BuildiumWriteIn, EnvironmentCredentials, InMemoryDedupLog, PropertyMeldWriteIn,
    ReqwestHttpTransport, RetryPolicy,
};

#[derive(Debug, Parser)]
#[command(name = "pask-adapt")]
#[command(about = "Push a verified Pask receipt into an operations system")]
struct Cli {
    /// The receipt to push. It is verified before any write is attempted.
    #[arg(long)]
    input: PathBuf,
    /// PEM-encoded Ed25519 public key the receipt is verified against.
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long, value_enum)]
    adapter: AdapterSelection,
    #[arg(long)]
    base_url: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AdapterSelection {
    Buildium,
    Propertymeld,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let statement = std::fs::read(&cli.input)
        .with_context(|| format!("failed to read receipt {}", cli.input.display()))?;

    let public_key_pem = std::fs::read_to_string(&cli.public_key)
        .with_context(|| format!("failed to read public key {}", cli.public_key.display()))?;
    let verifying_key = VerifyingKey::from_public_key_pem(&public_key_pem)
        .map_err(|error| anyhow::anyhow!("invalid Ed25519 public key: {error}"))?;

    let outcome = match cli.adapter {
        AdapterSelection::Buildium => {
            let base_url = cli
                .base_url
                .ok_or_else(|| anyhow::anyhow!("--base-url is required for Buildium"))?;
            let adapter = BuildiumWriteIn::new(
                &base_url,
                Arc::new(ReqwestHttpTransport::new()),
                Arc::new(EnvironmentCredentials),
                Arc::new(InMemoryDedupLog::new()),
                RetryPolicy::default(),
            )?;
            adapter.push(&statement, &verifying_key)?
        }
        AdapterSelection::Propertymeld => PropertyMeldWriteIn.push(&statement, &verifying_key)?,
    };

    println!("{outcome:?}");
    Ok(())
}
