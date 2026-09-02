// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire-cli is licensed Apache-2.0. See LICENSING.md.

//! MEM-P1 — Phase 1 CI: every example embedded in the specification is
//! validated against the reference parser.
//!
//! `draft_example_is_generated.rs` already pins the payload figure to the
//! emitter, byte for byte. It finds that figure by its title. The gap it
//! leaves is the one that matters for revisions after `-01`: if somebody adds
//! a *second* example to the document, nothing observes it. It is not
//! byte-checked, it is not parsed, and the build stays green while the
//! document acquires an example the code has never seen. That is exactly how
//! `-00` shipped a figure with unquoted placeholders.
//!
//! So this file does not look for a known example. It enumerates every fenced
//! block in the document and requires each one to be *accounted for*. An
//! unaccounted block is a failure, and the failure message says what to do.
//!
//! Three ways a block can be accounted for:
//!
//!   1. It is the canonical payload figure. Byte-identity is asserted by
//!      `draft_example_is_generated.rs`; here it is only required to parse.
//!   2. It is a JSON block that parses as a `Payload`.
//!   3. It is listed in `EXPLAINED_BLOCKS` below with a written reason —
//!      a fragment, a non-JSON diagram, a counter-example that is *supposed*
//!      to be invalid. The reason is prose a reviewer can disagree with, not
//!      a boolean.
//!
//! `EXPLAINED_BLOCKS` is checked for staleness. An entry that no longer
//! matches any block in the document fails, so an explanation cannot outlive
//! the thing it explained.

use std::{fs, path::PathBuf};

/// A fenced block the parser is not expected to accept, with the reason.
///
/// `marker` is a distinctive substring of the block's body. `reason` is why
/// the reference parser is not the right judge of it.
struct ExplainedBlock {
    info: &'static str,
    marker: &'static str,
    reason: &'static str,
}

/// Empty as of `-01`: the document carries exactly one example and it is the
/// payload figure, which parses. Entries get added here only with a reason
/// somebody would sign their name to.
const EXPLAINED_BLOCKS: &[ExplainedBlock] = &[];

/// The number of fenced blocks the document is known to contain.
///
/// Pinned deliberately. A new example should make somebody update this line
/// and, in doing so, decide which of the three accounting routes it takes.
const EXPECTED_BLOCK_COUNT: usize = 1;

struct Block {
    /// The fence info string: `json`, `aasvg`, or empty.
    info: String,
    body: String,
    /// 1-based line number of the opening fence, for the failure message.
    line: usize,
}

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
        "expected exactly one revision of the profile document in docs/, found {found:?}"
    );
    found.remove(0)
}

/// Enumerates every `~~~`-fenced block in the document.
///
/// kramdown-rfc uses `~~~` fences. Backtick fences are not used in this
/// document and are treated as prose; `no_backtick_fences_have_appeared`
/// asserts that assumption rather than leaving it implicit, because if it
/// ever stops holding this enumerator would silently miss examples.
fn fenced_blocks(draft: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut open: Option<(String, usize, Vec<String>)> = None;

    for (index, raw) in draft.lines().enumerate() {
        let line_no = index + 1;
        if let Some(rest) = raw.strip_prefix("~~~") {
            match open.take() {
                None => open = Some((rest.trim().to_string(), line_no, Vec::new())),
                Some((info, start, body)) => blocks.push(Block {
                    info,
                    body: body.join("\n"),
                    line: start,
                }),
            }
        } else if let Some((_, _, body)) = open.as_mut() {
            body.push(raw.to_string());
        }
    }

    assert!(
        open.is_none(),
        "an unclosed ~~~ fence in the profile document; xml2rfc would not \
         survive this either"
    );
    blocks
}

#[test]
fn no_backtick_fences_have_appeared() {
    let draft = fs::read_to_string(draft_path()).expect("the profile document is readable");
    let backticked: Vec<usize> = draft
        .lines()
        .enumerate()
        .filter(|(_, line)| line.starts_with("```"))
        .map(|(index, _)| index + 1)
        .collect();
    assert!(
        backticked.is_empty(),
        "the document has grown ``` fences at lines {backticked:?}. This test \
         suite enumerates ~~~ fences only, so those examples are invisible to \
         it. Convert them to ~~~ or teach fenced_blocks() to read both."
    );
}

#[test]
fn the_document_carries_the_expected_number_of_examples() {
    let draft = fs::read_to_string(draft_path()).expect("the profile document is readable");
    let blocks = fenced_blocks(&draft);
    assert_eq!(
        blocks.len(),
        EXPECTED_BLOCK_COUNT,
        "the profile document now has {} fenced blocks, not {EXPECTED_BLOCK_COUNT}. \
         This is not a failure of the document -- it is a prompt. Update \
         EXPECTED_BLOCK_COUNT and decide how the new block is accounted for: \
         it parses as a Payload, or it goes in EXPLAINED_BLOCKS with a reason.",
        blocks.len()
    );
}

#[test]
fn every_json_example_validates_against_the_reference_parser() {
    let draft = fs::read_to_string(draft_path()).expect("the profile document is readable");
    let blocks = fenced_blocks(&draft);

    for block in &blocks {
        if let Some(explained) = EXPLAINED_BLOCKS
            .iter()
            .find(|candidate| candidate.info == block.info && block.body.contains(candidate.marker))
        {
            let _ = explained.reason;
            continue;
        }

        if block.info != "json" {
            // A block with no info string that looks like an object is a json
            // example that forgot to say so, and kramdown will render it
            // without syntax awareness while this test skips it.
            let trimmed = block.body.trim_start();
            assert!(
                !trimmed.starts_with('{') && !trimmed.starts_with('['),
                "the fenced block at line {} looks like JSON but is labelled \
                 `{}`. Label it `json` so it gets validated.",
                block.line,
                if block.info.is_empty() {
                    "(nothing)"
                } else {
                    &block.info
                }
            );
            continue;
        }

        pask_wire::Payload::from_json(block.body.as_bytes()).unwrap_or_else(|error| {
            panic!(
                "the json example at line {} of the profile document does not \
                 validate against the reference parser: {error}\n\n\
                 The document may only describe what the code does. Either \
                 regenerate the example with `cargo run -p pask-wire-cli -- \
                 canonical-example`, or add it to EXPLAINED_BLOCKS with a \
                 reason the parser is not the right judge of it.",
                block.line
            )
        });
    }
}

#[test]
fn no_explanation_outlives_the_block_it_explained() {
    let draft = fs::read_to_string(draft_path()).expect("the profile document is readable");
    let blocks = fenced_blocks(&draft);

    for explained in EXPLAINED_BLOCKS {
        let matched = blocks
            .iter()
            .any(|block| block.info == explained.info && block.body.contains(explained.marker));
        assert!(
            matched,
            "EXPLAINED_BLOCKS carries an entry for a `{}` block containing {:?}, \
             and no such block is in the document. The explanation has outlived \
             its example. Remove the entry.\n\nIts stated reason was: {}",
            explained.info, explained.marker, explained.reason
        );
    }
}
