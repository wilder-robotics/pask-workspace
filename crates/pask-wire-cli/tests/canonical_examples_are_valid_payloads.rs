// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
// pask-wire-cli is licensed Apache-2.0. See LICENSING.md.

//! Portable canonical-example checks that ship inside the package archive.
//!
//! `draft_example_is_generated.rs` and `draft_examples_are_validated.rs`
//! compare the emitters against the Internet-Draft and the vocabulary files at
//! the repository root, so they run only from a workspace checkout and are
//! excluded from the archive (see `exclude` in `Cargo.toml`). This file keeps
//! the part that needs no repository asset: the existing 0.7 emitter must
//! produce a payload that validates, and the documented 0.7
//! input -> `produce` -> supplied-key `verify` procedure must round-trip
//! through the actual executable, with its runtime rejections intact.
//!
//! The keys are the Ed25519 examples from RFC 8410 sections 10.1 and 10.3
//! (public and corresponding private key); they are test material, not a
//! trust anchor. The `sha256:abab...ab` value is a syntactic commitment
//! placeholder: it demonstrates the digest form, not a real retained block.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

const RFC8410_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
";

const RFC8410_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
";

/// An unrelated Ed25519 public key; verification under it must fail.
const OTHER_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAKbwB1ImO6sjiCT1IPkDCml9nmRz1W1wi9+ey5fhIWTs=
-----END PUBLIC KEY-----
";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pask-wire-cli"))
        .args(args)
        .output()
        .expect("the pask-wire CLI executes")
}

/// A fresh scratch directory per test, under the system temporary directory.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pask-wire-cli-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    fs::create_dir_all(&dir).expect("scratch directory is created");
    fs::write(dir.join("private.pem"), RFC8410_PRIVATE_KEY_PEM).unwrap();
    fs::write(dir.join("public.pem"), RFC8410_PUBLIC_KEY_PEM).unwrap();
    fs::write(dir.join("other-public.pem"), OTHER_PUBLIC_KEY_PEM).unwrap();
    dir
}

fn path(dir: &Path, file: &str) -> String {
    dir.join(file).to_str().expect("UTF-8 path").to_owned()
}

fn example_07() -> Value {
    let emitted = pask_wire::canonical_example_07().expect("the 0.7 canonical example emits");
    serde_json::from_str(&emitted).expect("the emitted 0.7 example is JSON")
}

/// Runs `produce` on `input` and returns the produce output and, if it
/// succeeded, the `verify` output under `public_key`.
fn produce_then_verify(dir: &Path, input: &Value, public_key: &str) -> (Output, Option<Output>) {
    fs::write(dir.join("input.json"), serde_json::to_vec(input).unwrap()).unwrap();
    let produced = run(&[
        "produce",
        "--input",
        &path(dir, "input.json"),
        "--private-key",
        &path(dir, "private.pem"),
        "--output",
        &path(dir, "statement.cbor"),
    ]);
    if !produced.status.success() {
        return (produced, None);
    }
    let verified = run(&[
        "verify",
        "--input",
        &path(dir, "statement.cbor"),
        "--public-key",
        &path(dir, public_key),
    ]);
    (produced, Some(verified))
}

#[test]
fn the_emitted_07_example_is_a_valid_payload_with_an_explicit_null_digest() {
    let emitted = pask_wire::canonical_example_07().expect("the 0.7 canonical example emits");
    let payload = pask_wire::Payload::from_json(emitted.as_bytes())
        .expect("the emitted 0.7 example validates as a payload");
    assert_eq!(payload.spec(), pask_wire::SPEC_VERSION_07);
    assert_eq!(payload.spec(), "wilder.pser/0.7");

    let value: Value = serde_json::from_str(&emitted).unwrap();
    let digest = value["engagement"]
        .get("contentDigest")
        .expect("0.7 carries an explicit contentDigest member");
    assert!(
        digest.is_null(),
        "the canonical 0.7 example commits to no content: {digest}"
    );

    // Deterministic output.
    assert_eq!(emitted, pask_wire::canonical_example_07().unwrap());
}

#[test]
fn the_legacy_examples_still_validate_and_name_their_own_profiles() {
    for (emitted, spec) in [
        (pask_wire::canonical_example(), pask_wire::SPEC_VERSION),
        (
            pask_wire::canonical_example_06(),
            pask_wire::SPEC_VERSION_06,
        ),
    ] {
        let emitted = emitted.expect("the legacy canonical example emits");
        let payload = pask_wire::Payload::from_json(emitted.as_bytes())
            .expect("the legacy canonical example validates as a payload");
        assert_eq!(payload.spec(), spec);
        let value: Value = serde_json::from_str(&emitted).unwrap();
        assert!(
            value["engagement"].get("contentDigest").is_none(),
            "legacy profiles carry no contentDigest member"
        );
    }
    assert!(pask_wire::is_supported_spec("wilder.pser/0.7"));
}

#[test]
fn documented_07_null_digest_procedure_round_trips_through_the_executable() {
    let dir = scratch("null-digest");
    let input = example_07();
    let (produced, verified) = produce_then_verify(&dir, &input, "public.pem");
    assert!(
        produced.status.success(),
        "produce failed: {}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let verified = verified.unwrap();
    assert!(
        verified.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let output: Value = serde_json::from_slice(&verified.stdout).expect("verify writes JSON");
    assert_eq!(output["spec"], "wilder.pser/0.7");
    assert!(
        output["engagement"]
            .get("contentDigest")
            .is_some_and(Value::is_null)
    );
    assert_eq!(
        output, input,
        "verify returns the payload that was produced"
    );

    // The protected header of the produced statement names the 0.7 content type.
    let statement = fs::read(dir.join("statement.cbor")).unwrap();
    let verifying_key = {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        ed25519_dalek::VerifyingKey::from_public_key_pem(RFC8410_PUBLIC_KEY_PEM).unwrap()
    };
    let payload = pask_wire::verify_ed25519(&statement, &verifying_key)
        .expect("the library verifies what the executable produced");
    assert_eq!(payload.spec(), pask_wire::SPEC_VERSION_07);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_sha256_content_digest_placeholder_round_trips_as_a_syntactic_commitment() {
    let dir = scratch("sha256-digest");
    let placeholder = format!("sha256:{}", "ab".repeat(32));
    let mut input = example_07();
    input["engagement"]["contentDigest"] = Value::String(placeholder.clone());
    let (produced, verified) = produce_then_verify(&dir, &input, "public.pem");
    assert!(
        produced.status.success(),
        "produce failed: {}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let verified = verified.unwrap();
    assert!(verified.status.success());
    let output: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(output["engagement"]["contentDigest"], placeholder);
    // The chain hash covers the digest member, so it differs from the null example.
    let null_example = example_07();
    assert_ne!(output["chain"]["hash"], null_example["chain"]["hash"]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_under_an_unrelated_public_key_fails() {
    let dir = scratch("wrong-key");
    let (produced, verified) = produce_then_verify(&dir, &example_07(), "other-public.pem");
    assert!(produced.status.success());
    let verified = verified.unwrap();
    assert_eq!(verified.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(stderr.contains("receipt verification failed"), "{stderr}");
    assert!(stderr.contains("signature error"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_07_input_without_an_explicit_content_digest_is_rejected() {
    let dir = scratch("missing-digest");
    let mut input = example_07();
    let removed = input["engagement"]
        .as_object_mut()
        .unwrap()
        .remove("contentDigest");
    assert!(removed.is_some(), "the 0.7 example carries contentDigest");
    let (produced, verified) = produce_then_verify(&dir, &input, "public.pem");
    assert!(verified.is_none());
    assert_eq!(produced.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&produced.stderr);
    assert!(
        stderr.contains("0.7 requires explicit null or SHA-256 contentDigest"),
        "{stderr}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_malformed_digest_prefix_is_rejected() {
    let dir = scratch("bad-prefix");
    let mut input = example_07();
    input["engagement"]["contentDigest"] = Value::String(format!("sha-256:{}", "ab".repeat(32)));
    let (produced, verified) = produce_then_verify(&dir, &input, "public.pem");
    assert!(verified.is_none());
    assert_eq!(produced.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&produced.stderr);
    assert!(stderr.contains("digest prefix must be sha256:"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_legacy_05_input_with_a_content_digest_is_rejected() {
    let dir = scratch("legacy-digest");
    let legacy = pask_wire::canonical_example().unwrap();
    let mut input: Value = serde_json::from_str(&legacy).unwrap();
    assert_eq!(input["spec"], "wilder.pser/0.5");
    input["engagement"]["contentDigest"] = Value::Null;
    let (produced, verified) = produce_then_verify(&dir, &input, "public.pem");
    assert!(verified.is_none());
    assert_eq!(produced.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&produced.stderr);
    assert!(
        stderr.contains("contentDigest is not permitted in legacy profiles"),
        "{stderr}"
    );
    let _ = fs::remove_dir_all(dir);
}
