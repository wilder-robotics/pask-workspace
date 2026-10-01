// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! Emit the dedicated proposed-0.7 draft figure without changing the released CLI.
use std::io::{self, Write};

fn main() {
    if run().is_err() {
        let _ = io::stderr().write_all(b"draft07_payload: generation or output failed\n");
        std::process::exit(2);
    }
}

#[cfg(feature = "alloc")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let example =
        pask_wire::canonical_example_07().map_err(|error| io::Error::other(error.to_string()))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(example.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

#[cfg(not(feature = "alloc"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err(io::Error::other("the example requires alloc").into())
}
