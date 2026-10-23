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

#[test]
fn canonical_example_without_a_flag_is_byte_for_byte_the_05_example() {
    let out = run(&["canonical-example"]);
    assert!(
        out.status.success(),
        "canonical-example failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let expected = pask_wire::canonical_example().expect("the 0.5 example emits");
    assert_eq!(
        out.stdout,
        expected.as_bytes(),
        "no-flag canonical-example must stay the current 0.5 output"
    );

    let explicit = run(&["canonical-example", "--profile", "0.5"]);
    assert!(
        explicit.status.success(),
        "--profile 0.5 failed: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    assert_eq!(explicit.stdout, expected.as_bytes());
}

#[test]
fn canonical_example_profiles_match_the_library_figures_exactly() {
    let cases = [
        ("0.6", pask_wire::canonical_example_06()),
        ("0.7", pask_wire::canonical_example_07()),
    ];
    let legacy = pask_wire::canonical_example().unwrap();
    for (profile, expected) in cases {
        let expected = expected.expect("the library example emits");
        let out = run(&["canonical-example", "--profile", profile]);
        assert!(
            out.status.success(),
            "--profile {profile} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout,
            expected.as_bytes(),
            "--profile {profile} must match the library emitter"
        );
        assert_ne!(out.stdout, legacy.as_bytes());
    }
}

#[test]
fn canonical_example_help_names_the_profile_choices() {
    let out = run(&["canonical-example", "--help"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_canonical_usage(&text, Some("canonical-example"));
    assert!(text.contains("--profile"), "{text}");
    for profile in ["0.5", "0.6", "0.7"] {
        assert!(text.contains(profile), "{text}");
    }
}

#[test]
fn canonical_example_rejects_an_unknown_profile() {
    let out = run(&["canonical-example", "--profile", "0.8"]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("invalid value"), "{text}");
    assert!(text.contains("--profile"), "{text}");
    for profile in ["0.5", "0.6", "0.7"] {
        assert!(text.contains(profile), "{text}");
    }
    assert!(
        out.stdout.is_empty(),
        "a rejected profile must not print an example"
    );
}
