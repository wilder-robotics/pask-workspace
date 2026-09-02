// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire-cli is licensed Apache-2.0. It is a conformance tool: it produces
// receipts, verifies them, and emits the canonical example figure carried in
// the profile document. An implementer must be able to run it against their
// own implementation without a copyleft review, so it takes no dependency on
// the operational crates. Pushing a verified receipt into an operations
// system lives in the `pask-adapt` binary in the AGPL-3.0-only pask-adapter
// crate. See LICENSING.md.

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
use pask_wire::{Payload, canonical_example, produce_ed25519, verify_ed25519};

#[derive(Debug, Parser)]
#[command(name = "pask-wire")]
#[command(about = "Produce, verify, and emit canonical Pask receipts")]
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
    /// Emit the canonical example instance embedded in the profile document.
    ///
    /// The Internet-Draft's example figure is this output verbatim. A test
    /// asserts they are byte-identical.
    CanonicalExample,
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Produce {
            input,
            private_key,
            output,
        } => produce(input, private_key, output),
        Command::CanonicalExample => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(canonical_example()?.as_bytes())
                .context("failed to write the canonical example to stdout")
        }
        Command::Verify {
            input,
            public_key,
            output,
        } => verify(input, public_key, output),
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
