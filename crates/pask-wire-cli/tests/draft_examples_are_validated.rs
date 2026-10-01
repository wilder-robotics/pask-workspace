// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! Every fenced block is explicitly accounted for: one generated payload,
//! 48 complete vocabulary definitions, and four exact explanatory fragments.
//! Row meanings/global string annotations are losslessly reconstructed from
//! adjacent prose. An arbitrary JSON/text fence is never silently skipped.

use std::{collections::BTreeMap, fs, path::PathBuf};
use serde_json::Value;

const EXPECTED_BLOCK_COUNT: usize = 53;
const FIGURE_TITLE: &str = r#"{: title="Physical-Site Engagement Receipt payload"}"#;
const V1_PATH: &str = "schemas/proposed/pser-0.7/content-vocabulary.json";
const V2_PATH: &str = "schemas/proposed/pser-0.7/content-vocabulary-v2-candidate.json";
const V1_HASH: &str = "sha256:030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d";
const V2_HASH: &str = "sha256:2fb4e3a099003638d318333dee66fe2b710fb39b6dec78f570f6ecf31592a248";
const ANNOTATIONS: [&str; 3] = ["numbers", "operatorPseudonym", "remoteOrigin"];

// These bodies are explanatory, not complete Payload instances. Exact text
// and language are pinned so a marker hidden inside a changed block is not an
// exemption. Changing one needs a corresponding reviewed test change.
const EXPLANATORY: &[(&str, &str, &str)] = &[
    ("content-hash-formulas", "text", r###"H = SHA-256(D || 0x00 || U64(N) ||
            U64(len(C)) || C || U64(len(S)) || S || V)

L_i = SHA-256(D || 0x01 || H || U64(i) || salt_i ||
              U64(len(F_i)) || F_i)

Empty(H) = SHA-256(D || 0x02 || H)
Node(A, B) = SHA-256(D || 0x03 || A || B)
Root = SHA-256(D || 0x04 || H || Tree(L_0, ..., L_(N-1)))"###),
    ("content-evidence-digest-fragment", "json", r###"{"digest":"sha256:<64 lowercase hexadecimal digits>"}"###),
    ("content-evidence-pointer-fragment", "json", r###"{"pointer":"<nonempty locator of at most 2048 UTF-8 octets>"}"###),
    ("corrective-report-illustration", "", r###"Corrective statement C1, challenging original O1
Declared kind: CHALLENGE
C1 signature: verified
O1 signature: verified
C1 inclusion evidence: verified under accepted service key
Signing-key relationship C1/O1: same verified public key
Kind consistency: failed - same-key CHALLENGE
Organizational independence: not established by these checks
Effect on O1: no automatic invalidation or modification
Local policy: evaluated separately"###),
];


fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn draft_text() -> String {
    let mut paths: Vec<_> = fs::read_dir(root().join("docs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.starts_with("draft-wilder-scitt-physical-site-engage-receipt-")
                && name.ends_with(".md")
        })
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 1, "exactly one active draft is required");
    fs::read_to_string(&paths[0]).unwrap()
}

fn vocabularies() -> (Value, Value) {
    let one = fs::read(root().join(V1_PATH)).unwrap();
    let two = fs::read(root().join(V2_PATH)).unwrap();
    assert_eq!(pask_wire::sha256_prefixed(&one), V1_HASH);
    assert_eq!(pask_wire::sha256_prefixed(&two), V2_HASH);
    let one: Value = serde_json::from_slice(&one).unwrap();
    let two: Value = serde_json::from_slice(&two).unwrap();
    assert_eq!(one["facts"].as_array().unwrap().len(), 46);
    assert_eq!(two["facts"].as_array().unwrap().len(), 47);
    assert_eq!(one["facts"].as_array().unwrap(), &two["facts"].as_array().unwrap()[..46]);
    for name in ["assertedBy", "basis", "globalRules", "remoteOrigin"] {
        assert_eq!(one[name], two[name]);
    }
    (one, two)
}

#[derive(Debug)]
struct Block {
    id: String,
    info: String,
    body: String,
    preceding: String,
    line: usize,
}

fn fenced_blocks(draft: &str) -> Result<Vec<Block>, String> {
    let lines: Vec<_> = draft.lines().collect();
    let mut index = 0;
    let mut blocks = Vec::new();
    while index < lines.len() {
        let raw = lines[index];
        if raw.trim_start().starts_with("```") {
            return Err(format!("backtick fence at line {}", index + 1));
        }
        if !raw.trim_start().starts_with("~~~") {
            index += 1;
            continue;
        }
        if !raw.starts_with("~~~") {
            return Err(format!("indented fence at line {}", index + 1));
        }
        let info = raw[3..].trim();
        if !["", "json", "text"].contains(&info) {
            return Err(format!("unsupported fence language {info}"));
        }
        let start = index;
        let before = lines[..start].join("\n");
        let preceding = before.trim_end().rsplit("\n\n").next().unwrap_or("")
            .lines().collect::<Vec<_>>().join(" ");
        index += 1;
        let body_start = index;
        while index < lines.len() && lines[index] != "~~~" {
            if lines[index].trim_start().starts_with("~~~")
                || lines[index].trim_start().starts_with("```")
            {
                return Err(format!("invalid fence terminator at {}", index + 1));
            }
            index += 1;
        }
        if index == lines.len() {
            return Err(format!("unclosed fence at {}", start + 1));
        }
        let body = lines[body_start..index].join("\n");
        let annotation = lines.get(index + 1).ok_or("unlabelled final block")?;
        let id = if *annotation == FIGURE_TITLE {
            "payload-example".to_string()
        } else {
            annotation.strip_prefix("{: #").and_then(|s| s.strip_suffix('}'))
                .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
                .ok_or_else(|| format!("missing/invalid block identity at {}", index + 2))?
                .to_string()
        };
        blocks.push(Block { id, info: info.to_string(), body, preceding, line: start + 1 });
        index += 2;
    }
    Ok(blocks)
}

// Fixed JSON layout; if a pattern line is too long, break between key and
// string token, never inside a token. Comparing the entire display also catches
// duplicate JSON members that Value parsing alone would overwrite.
fn display_json(value: &Value) -> String {
    let json = serde_json::to_string_pretty(value).unwrap();
    let mut lines = Vec::new();
    for line in json.lines() {
        if line.chars().count() > 72 {
            let (key, token) = line.split_once(": ").expect("a long pattern property");
            assert!(key.chars().count() + 1 <= 72 && token.chars().count() <= 72);
            lines.push(format!("{key}:"));
            lines.push(token.to_string());
        } else {
            lines.push(line.to_string());
        }
    }
    lines.join("\n")
}

fn annotation(draft: &str, key: &str) -> Result<String, String> {
    let prefix = format!("Artifact annotation `{key}`: ");
    let found: Vec<_> = draft.split("\n\n")
        .filter_map(|p| p.strip_prefix(&prefix))
        .map(|p| p.lines().collect::<Vec<_>>().join(" "))
        .collect();
    if found.len() != 1 {
        return Err(format!("expected one annotation {key}, got {}", found.len()));
    }
    Ok(found[0].clone())
}

fn check_draft(draft: &str) -> Result<(), String> {
    let blocks = fenced_blocks(draft)?;
    if blocks.len() != EXPECTED_BLOCK_COUNT {
        return Err(format!("expected {EXPECTED_BLOCK_COUNT} blocks, got {}", blocks.len()));
    }
    let (_, vocab) = vocabularies();
    let mut expected: BTreeMap<String, (String, String, Option<String>)> = BTreeMap::new();
    expected.insert("payload-example".into(), (
        "json".into(), pask_wire::canonical_example_07().map_err(|e| e.to_string())?, None
    ));
    for &(id, info, body) in EXPLANATORY {
        expected.insert(id.into(), (info.into(), body.into(), None));
    }
    let mut global = vocab.as_object().unwrap().clone();
    global.remove("version");
    global.remove("facts");
    let global_rules = global.get_mut("globalRules").unwrap().as_object_mut().unwrap();
    for key in ANNOTATIONS {
        let text = global_rules.remove(key).unwrap();
        if annotation(draft, key)? != text.as_str().unwrap() {
            return Err(format!("global annotation {key} differs from pinned artifact"));
        }
    }
    expected.insert("vocabulary-global-definition".into(), (
        "json".into(), display_json(&Value::Object(global)), None
    ));
    let mut expected_order = Vec::new();
    for row in vocab["facts"].as_array().unwrap() {
        let mut object = row.as_object().unwrap().clone();
        let name = row["name"].as_str().unwrap();
        let meaning = object.remove("meaning").unwrap().as_str().unwrap().to_string();
        let id = format!("vocabulary-rule-{}", name.replace('.', "-"));
        expected_order.push(id.clone());
        expected.insert(id, ("json".into(), display_json(&Value::Object(object)), Some(meaning)));
    }
    let mut actual_order = Vec::new();
    for block in blocks {
        let (info, body, meaning) = expected.remove(&block.id)
            .ok_or_else(|| format!("unknown or duplicate block {} at {}", block.id, block.line))?;
        if block.info != info || block.body != body {
            return Err(format!("block {} differs from its complete checked definition", block.id));
        }
        if let Some(meaning) = meaning {
            if block.preceding != format!("Meaning: {meaning}") {
                return Err(format!("meaning for {} differs from pinned artifact", block.id));
            }
            actual_order.push(block.id.clone());
        }
        if block.id == "payload-example" {
            pask_wire::Payload::from_json(block.body.as_bytes()).map_err(|e| e.to_string())?;
        } else if block.info == "json" {
            serde_json::from_str::<Value>(&block.body).map_err(|e| e.to_string())?;
        }
    }
    if !expected.is_empty() || actual_order != expected_order {
        return Err("missing definitions or changed vocabulary row order".into());
    }
    Ok(())
}

#[test]
fn every_fenced_block_and_all_rule_annotations_are_checked() {
    check_draft(&draft_text()).unwrap();
}

#[test]
fn expected_count_is_one_payload_48_rules_and_four_explanations() {
    assert_eq!(fenced_blocks(&draft_text()).unwrap().len(), 1 + 48 + 4);
}

#[test]
fn old_and_new_artifacts_remain_exact_and_legacy_rows_unchanged() {
    vocabularies();
}

#[test]
fn an_extra_unaccounted_block_fails_even_if_it_is_valid_json() {
    let mut text = draft_text();
    text.push_str("\n~~~ json\n{}\n~~~\n{: #unreviewed}\n");
    assert!(check_draft(&text).is_err());
}

#[test]
fn duplicate_block_identity_is_not_an_exemption() {
    let text = draft_text().replace("{: #content-evidence-pointer-fragment}", "{: #content-evidence-digest-fragment}");
    assert!(check_draft(&text).is_err());
}

#[test]
fn backtick_and_indented_fences_cannot_hide_examples() {
    assert!(check_draft(&draft_text().replacen("~~~ json", "```json", 1)).is_err());
    assert!(check_draft(&draft_text().replacen("~~~ json", "  ~~~ json", 1)).is_err());
}

#[test]
fn malformed_or_unclosed_fence_fails() {
    assert!(fenced_blocks("~~~ json\n{}\n").is_err());
    assert!(fenced_blocks("~~~ json\n{}\n~~~ wrong\n").is_err());
}

#[test]
fn changed_rule_is_not_excused_as_a_nonpayload() {
    let text = draft_text().replacen("\"maxLength\": 64", "\"maxLength\": 65", 1);
    assert!(check_draft(&text).is_err());
}

#[test]
fn changed_meaning_and_global_annotation_fail() {
    let text = draft_text().replacen("Meaning: Model designation", "Meaning: Altered designation", 1);
    assert!(check_draft(&text).is_err());
    let text = draft_text().replacen("All numeric values are integers", "All numeric values are floats", 1);
    assert!(check_draft(&text).is_err());
}

#[test]
fn identical_duplicate_json_key_is_still_rejected() {
    let text = draft_text().replacen("\"maxLength\": 64,", "\"maxLength\": 64,\n    \"maxLength\": 64,", 1);
    assert!(check_draft(&text).is_err());
}

#[test]
fn changed_explanatory_block_cannot_borrow_its_marker() {
    let text = draft_text().replacen("L_i = SHA-256", "L_i = SHA-512", 1);
    assert!(check_draft(&text).is_err());
}

#[test]
fn mislabelled_json_is_rejected() {
    let text = draft_text().replacen("~~~ json", "~~~ text", 1);
    assert!(check_draft(&text).is_err());
}
