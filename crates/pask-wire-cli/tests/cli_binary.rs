// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire-cli is licensed Apache-2.0. See LICENSING.md.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pask-wire-cli"))
        .args(args)
        .output()
        .expect("the pask-wire CLI executes")
}

#[test]
fn canonical_example_matches_library_bytes() {
    let output = run(&["canonical-example"]);
    assert!(
        output.status.success(),
        "canonical-example failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let expected = pask_wire::canonical_example().expect("the canonical example emits");
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn bad_subcommand_fails_with_usable_message() {
    let output = run(&["not-a-command"]);
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unrecognized subcommand"), "{stderr}");
    assert!(stderr.contains("--help"), "{stderr}");
}

#[test]
fn help_succeeds() {
    let output = run(&["--help"]);
    assert!(
        output.status.success(),
        "--help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(stdout.contains("canonical-example"), "{stdout}");
}
