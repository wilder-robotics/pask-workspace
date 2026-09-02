// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire-cli is licensed Apache-2.0. See LICENSING.md.

//! Asserts the Internet-Draft's example payload is byte-identical to the
//! example the reference implementation emits.
//!
//! This is the structural guard against document-implementation drift. The
//! `-00` revision shipped a hand-written figure containing unquoted
//! placeholders, so it was never parseable JSON and nothing in the build could
//! observe that three of its attestation members no longer matched the code.
//!
//! If this test fails, do not edit the document by hand. Run
//! `cargo run -p pask-wire-cli -- canonical-example` and paste the output.

use std::{fs, path::PathBuf};

const FIGURE_TITLE: &str = r#"{: title="Physical-Site Engagement Receipt payload"}"#;
const FENCE_OPEN: &str = "~~~ json\n";
const FENCE_CLOSE: &str = "\n~~~\n";

fn draft_path() -> PathBuf {
    let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let mut found: Vec<PathBuf> = fs::read_dir(&docs)
        .expect("the workspace carries a docs directory")
        .map(|entry| entry.expect("docs directory is readable").path())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            name.starts_with("draft-wilder-scitt-physical-site-engage-receipt-")
                && name.ends_with(".md")
        })
        .collect();
    found.sort();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one revision of the profile document in docs/, found {found:?}. \
         Two revisions in the tree means one of them is unmaintained."
    );
    found.remove(0)
}

/// Returns the contents of the fenced JSON block that the figure title labels.
fn figure_body(draft: &str) -> &str {
    let title_at = draft
        .find(FIGURE_TITLE)
        .expect("the profile document labels its payload figure");
    let before = &draft[..title_at];
    let open_at = before
        .rfind(FENCE_OPEN)
        .expect("the payload figure is a fenced json block")
        + FENCE_OPEN.len();
    let close_at = before
        .rfind(FENCE_CLOSE)
        .expect("the payload figure's fence is closed");
    &before[open_at..close_at]
}

#[test]
fn draft_payload_figure_is_byte_identical_to_the_emitted_example() {
    let draft = fs::read_to_string(draft_path()).expect("the profile document is readable");
    let emitted = pask_wire::canonical_example().expect("the canonical example emits");

    assert_eq!(
        figure_body(&draft),
        emitted,
        "the profile document's payload figure has drifted from the reference \
         implementation. Regenerate it with `cargo run -p pask-wire-cli -- canonical-example` \
         rather than editing the document."
    );
}

#[test]
fn the_emitted_example_is_parseable_json() {
    let emitted = pask_wire::canonical_example().expect("the canonical example emits");
    pask_wire::Payload::from_json(emitted.as_bytes())
        .expect("the emitted example validates as a payload");
}
