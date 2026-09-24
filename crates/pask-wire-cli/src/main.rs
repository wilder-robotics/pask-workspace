// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire-cli is licensed Apache-2.0. It is a conformance tool: it produces
// receipts, verifies them, and emits the legacy 0.5 canonical example.
// The posted -04 figure uses the library's 0.6 generator. An implementer can use
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
#[command(name = "pask-wire-cli", bin_name = "pask-wire-cli")]
#[command(about = "Produce, verify, and emit canonical Pask receipts")]
// A `push` subcommand used to live here behind an `adapter` feature. It moved
// to the `pask-adapt` binary when the workspace license was split, so a user
// who types `pask-wire push` needs to be told where it went rather than left
// with "unrecognized subcommand".
#[command(after_help = "Pushing a verified receipt into an operations system \
moved to the `pask-adapt` binary (cargo run -p pask-adapter --features cli \
--bin pask-adapt). It is licensed AGPL-3.0-only; this tool is Apache-2.0. \
See LICENSING.md.")]
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
    /// Emit the legacy wilder.pser/0.5 canonical example.
    /// The posted -04 figure instead uses pask_wire::canonical_example_06().
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

#[cfg(test)]
mod usage_contract_tests {
    use super::Cli;
    use clap::{Parser, error::ErrorKind};

    // Exercise the real derived parser with either runtime filename spelling.
    // This is not a replacement for the executable tests on native Windows.
    fn assert_canonical_usage(error: &clap::Error, subcommand: Option<&str>) {
        let text = error.to_string();
        let usage = text
            .lines()
            .find_map(|line| line.strip_prefix("Usage: "))
            .unwrap_or_else(|| panic!("missing usage line in parser output:\n{text}"));
        let mut words = usage.split_whitespace();
        assert_eq!(words.next(), Some("pask-wire-cli"), "{text}");
        if let Some(subcommand) = subcommand {
            assert_eq!(words.next(), Some(subcommand), "{text}");
        }
    }

    #[test]
    fn help_uses_canonical_invocation_for_both_argv0_spellings() {
        let cases: &[(&[&str], Option<&str>)] = &[
            (&["--help"], None),
            (&["verify", "--help"], Some("verify")),
            (&["produce", "--help"], Some("produce")),
            (&["canonical-example", "--help"], Some("canonical-example")),
        ];
        for program in ["pask-wire-cli", "pask-wire-cli.exe"] {
            for &(args, subcommand) in cases {
                let argv = std::iter::once(program).chain(args.iter().copied());
                let error = Cli::try_parse_from(argv)
                    .expect_err("help must terminate parsing before command execution");
                assert_eq!(error.kind(), ErrorKind::DisplayHelp, "{program} {args:?}");
                assert_canonical_usage(&error, subcommand);
            }
        }
    }

    #[test]
    fn errors_use_canonical_invocation_for_both_argv0_spellings() {
        let cases: &[(&[&str], Option<&str>, ErrorKind)] = &[
            (
                &["verify"],
                Some("verify"),
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &["produce"],
                Some("produce"),
                ErrorKind::MissingRequiredArgument,
            ),
            (&["not-a-command"], None, ErrorKind::InvalidSubcommand),
        ];
        for program in ["pask-wire-cli", "pask-wire-cli.exe"] {
            for (args, subcommand, kind) in cases {
                let argv = std::iter::once(program).chain(args.iter().copied());
                let error = Cli::try_parse_from(argv)
                    .expect_err("invalid arguments must not reach command execution");
                assert_eq!(&error.kind(), kind, "{program} {args:?}");
                assert_canonical_usage(&error, *subcommand);
            }
        }
    }
}
