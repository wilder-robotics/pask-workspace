// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire-cli is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{
    SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use pask_wire::{Payload, produce_ed25519, verify_ed25519};

#[cfg(feature = "adapter")]
use {
    clap::ValueEnum,
    pask_adapter::{
        AdapterWriteIn, BuildiumWriteIn, EnvironmentCredentials, InMemoryDedupLog,
        PropertyMeldWriteIn, ReqwestHttpTransport, RetryPolicy,
    },
    std::sync::Arc,
};

#[derive(Debug, Parser)]
#[command(name = "pask-wire")]
#[command(about = "Produce, verify, and optionally push Pask receipts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Produce {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "adapter")]
    Push {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, value_enum)]
        adapter: AdapterSelection,
        #[arg(long)]
        base_url: Option<String>,
    },
}

#[cfg(feature = "adapter")]
#[derive(Clone, Copy, Debug, ValueEnum)]
enum AdapterSelection {
    Buildium,
    Propertymeld,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Produce {
            input,
            private_key,
            output,
        } => produce(input, private_key, output),
        Command::Verify {
            input,
            public_key,
            output,
        } => verify(input, public_key, output),
        #[cfg(feature = "adapter")]
        Command::Push {
            input,
            public_key,
            adapter,
            base_url,
        } => push(input, public_key, adapter, base_url),
    }
}

fn produce(input: PathBuf, private_key: PathBuf, output: PathBuf) -> Result<()> {
    let input = fs::read(&input)
        .with_context(|| format!("failed to read payload input {}", input.display()))?;
    let private_key_pem = fs::read_to_string(&private_key)
        .with_context(|| format!("failed to read private key {}", private_key.display()))?;
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|error| anyhow::anyhow!("invalid Ed25519 private key: {error}"))?;
    let payload =
        Payload::from_json_for_production(&input).context("invalid producer payload input")?;
    let issuer = payload.witness_key().to_owned();
    let statement =
        produce_ed25519(&payload, &issuer, &signing_key).context("failed to produce receipt")?;
    fs::write(&output, statement)
        .with_context(|| format!("failed to write receipt {}", output.display()))
}

fn verify(input: PathBuf, public_key: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let statement =
        fs::read(&input).with_context(|| format!("failed to read receipt {}", input.display()))?;
    let verifying_key = read_verifying_key(&public_key)?;
    let payload =
        verify_ed25519(&statement, &verifying_key).context("receipt verification failed")?;
    let canonical = payload
        .to_jcs()
        .context("failed to serialize verified payload")?;

    if let Some(output) = output {
        fs::write(&output, canonical)
            .with_context(|| format!("failed to write payload {}", output.display()))
    } else {
        io::stdout()
            .write_all(&canonical)
            .context("failed to write verified payload")
    }
}

fn read_verifying_key(path: &PathBuf) -> Result<VerifyingKey> {
    let public_key_pem = fs::read_to_string(path)
        .with_context(|| format!("failed to read public key {}", path.display()))?;
    VerifyingKey::from_public_key_pem(&public_key_pem)
        .map_err(|error| anyhow::anyhow!("invalid Ed25519 public key: {error}"))
}

#[cfg(feature = "adapter")]
fn push(
    input: PathBuf,
    public_key: PathBuf,
    adapter: AdapterSelection,
    base_url: Option<String>,
) -> Result<()> {
    let statement =
        fs::read(&input).with_context(|| format!("failed to read receipt {}", input.display()))?;
    let verifying_key = read_verifying_key(&public_key)?;

    let outcome = match adapter {
        AdapterSelection::Buildium => {
            let base_url =
                base_url.ok_or_else(|| anyhow::anyhow!("--base-url is required for Buildium"))?;
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
