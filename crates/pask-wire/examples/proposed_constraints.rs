// SPDX-License-Identifier: Apache-2.0
use pask_wire::proposed_constraints::{EvidenceState, classify, inspect_fact};
use std::io::{self, Read};
fn main() {
    let mut s = String::new();
    io::stdin().take(1_048_577).read_to_string(&mut s).unwrap();
    assert!(s.len() <= 1_048_576, "input limit");
    let input: serde_json::Value = serde_json::from_str(&s).unwrap();
    let rows = input.as_array().unwrap();
    assert!(rows.len() <= 1000);
    let output: Vec<_> = rows
        .iter()
        .map(|v| {
            if v.get("value").is_some() {
                serde_json::to_value(inspect_fact(v, EvidenceState::NotResolved)).unwrap()
            } else {
                serde_json::to_value(classify(
                    v["name"].as_str().unwrap(),
                    v["party"].as_str().unwrap(),
                    v["basis"].as_str().unwrap(),
                ))
                .unwrap()
            }
        })
        .collect();
    println!("{}", serde_json::to_string(&output).unwrap());
}
