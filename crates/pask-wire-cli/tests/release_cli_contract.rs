// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pask-wire-cli"))
        .args(args)
        .output()
        .expect("actual CLI executable")
}

// Check the command token, not a substring that also accepts an .exe suffix.
fn assert_canonical_usage(text: &str, subcommand: Option<&str>) {
    let usage = text
        .lines()
        .find_map(|line| line.strip_prefix("Usage: "))
        .unwrap_or_else(|| panic!("missing usage line in executable output:\n{text}"));
    let mut words = usage.split_whitespace();
    assert_eq!(words.next(), Some("pask-wire-cli"), "{text}");
    if let Some(subcommand) = subcommand {
        assert_eq!(words.next(), Some(subcommand), "{text}");
    }
}

#[test]
fn help_names_actual_executable() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Usage: pask-wire-cli"), "{text}");
    assert_canonical_usage(&text, None);
    assert!(text.contains("pask-adapt"));
    assert!(!text.contains("Usage: pask-wire "));
}

#[test]
fn missing_verify_options_are_explicit() {
    let out = run(&["verify"]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("--input"));
    assert!(text.contains("--public-key"));
    assert!(text.contains("Usage: pask-wire-cli verify"), "{text}");
    assert_canonical_usage(&text, Some("verify"));
}

#[test]
fn errors_and_subcommand_help_use_actual_binary() {
    let error = run(&["not-a-command"]);
    assert_eq!(error.status.code(), Some(2));
    let error_text = String::from_utf8(error.stderr).unwrap();
    assert!(error_text.contains("Usage: pask-wire-cli"), "{error_text}");
    assert_canonical_usage(&error_text, None);
    let help = run(&["verify", "--help"]);
    assert!(help.status.success());
    let help_text = String::from_utf8(help.stdout).unwrap();
    assert!(
        help_text.contains("Usage: pask-wire-cli verify"),
        "{help_text}"
    );
    assert_canonical_usage(&help_text, Some("verify"));
}

#[test]
fn example_default_remains_exact_05_not_06() {
    let out = run(&["canonical-example"]);
    assert!(out.status.success());
    assert_eq!(
        out.stdout,
        pask_wire::canonical_example().unwrap().as_bytes()
    );
    assert_ne!(
        out.stdout,
        pask_wire::canonical_example_06().unwrap().as_bytes()
    );
}
