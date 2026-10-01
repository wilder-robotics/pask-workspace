// SPDX-License-Identifier: Apache-2.0
use ed25519_dalek::SigningKey;
use pask_wire::{Payload, canonical_example_06, produce_ed25519};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, time::Instant};
fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap());
    fs::create_dir_all(&dir).unwrap();
    let v: Value = serde_json::from_str(&canonical_example_06().unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[17; 32]); // synthetic, public test key
    let mut records = Vec::new();
    for mode in ["baseline06", "candidate07-null", "candidate07-digest"] {
        let mut value = v.clone();
        if mode != "baseline06" {
            value["spec"] = json!("wilder.pser/0.7");
            value["engagement"]["contentDigest"] = if mode.ends_with("null") {
                Value::Null
            } else {
                json!(format!("sha256:{}", "a".repeat(64)))
            };
        }
        let p = Payload::from_json_for_production(&serde_json::to_vec(&value).unwrap()).unwrap();
        let bytes = produce_ed25519(&p, p.witness_key(), &key).unwrap();
        let payload = p.to_jcs().unwrap();
        fs::write(dir.join(format!("{mode}.json")), &payload).unwrap();
        fs::write(dir.join(format!("{mode}.cbor")), &bytes).unwrap();
        let start = Instant::now();
        for _ in 0..100 {
            pask_wire::verify_ed25519(&bytes, &key.verifying_key()).unwrap();
        }
        records.push(
            json!({"case":mode,"payload_bytes":payload.len(),"statement_bytes":bytes.len(),
            "verification_iterations":100,"elapsed_nanos":start.elapsed().as_nanos(),
            "input":"synthetic canonical 0.6 example","content_proof_verified":false}),
        );
    }
    println!("{}", serde_json::to_string_pretty(&records).unwrap());
}
