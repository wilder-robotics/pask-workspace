//! Capture the first real-ledger interop observation for issue #100.
//!
//! Inputs (the same three the ignored `pask-ts-client` test uses):
//! `PASK_TS_URL`, `PASK_SIGNED_STATEMENT_PATH`, `PASK_TS_SERVICE_KEY_PATH`.
//! Output directory: `CCF_EVIDENCE_OUT`.
//!
//! Nothing here verifies a CCF receipt. It records what the unchanged
//! verifier reports when handed one.
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use coset::{CborSerializable, CoseSign1, TaggedCborSerializable, cbor::Value};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn label(v: &Value) -> String {
    match v {
        Value::Integer(i) => format!("{}", i128::from(*i)),
        Value::Text(t) => format!("{t:?}"),
        other => format!("{other:?}"),
    }
}

fn shape(v: &Value) -> String {
    match v {
        Value::Integer(i) => format!("int {}", i128::from(*i)),
        Value::Bytes(b) => format!("bstr[{}]", b.len()),
        Value::Text(t) => format!("tstr {t:?}"),
        Value::Array(a) => format!("array[{}]", a.len()),
        Value::Map(m) => {
            let keys: Vec<String> = m.iter().map(|(k, _)| label(k)).collect();
            format!("map{{{}}}", keys.join(", "))
        }
        Value::Bool(b) => format!("bool {b}"),
        Value::Null => "null".into(),
        Value::Tag(t, inner) => format!("tag({t}) {}", shape(inner)),
        other => format!("{other:?}"),
    }
}

fn main() {
    let url = std::env::var("PASK_TS_URL").expect("PASK_TS_URL");
    let statement_path =
        std::env::var("PASK_SIGNED_STATEMENT_PATH").expect("PASK_SIGNED_STATEMENT_PATH");
    let cert_path = std::env::var("PASK_TS_SERVICE_KEY_PATH").expect("PASK_TS_SERVICE_KEY_PATH");
    let out = PathBuf::from(std::env::var("CCF_EVIDENCE_OUT").expect("CCF_EVIDENCE_OUT"));
    fs::create_dir_all(&out).expect("create output dir");

    let statement = fs::read(&statement_path).expect("read signed statement");
    let cert = fs::read(&cert_path).expect("read service certificate");

    let client = pask_ts_client::TsClient::new_with_root_certificate(&url, &cert).expect("client");
    let receipt = client
        .submit(&statement)
        .expect("submit and retrieve receipt");
    let transparent = pask_ts_client::attach_receipt(&statement, &receipt).expect("attach receipt");

    fs::write(out.join("signed-statement.cose"), &statement).unwrap();
    fs::write(out.join("service_cert.pem"), &cert).unwrap();
    fs::write(out.join("ccf-receipt.cose"), &receipt).unwrap();
    fs::write(out.join("transparent-statement.cose"), &transparent).unwrap();

    let mut summary = String::new();
    writeln!(summary, "receipt_bytes={}", receipt.len()).unwrap();
    writeln!(summary, "receipt_sha256={}", hex(&Sha256::digest(&receipt))).unwrap();
    writeln!(
        summary,
        "statement_sha256={}",
        hex(&Sha256::digest(&statement))
    )
    .unwrap();
    writeln!(
        summary,
        "service_cert_sha256={}",
        hex(&Sha256::digest(&cert))
    )
    .unwrap();
    writeln!(
        summary,
        "first_byte=0x{:02x} (0xd2 = tag 18 COSE_Sign1)",
        receipt.first().copied().unwrap_or(0)
    )
    .unwrap();

    match CoseSign1::from_tagged_slice(&receipt).or_else(|_| CoseSign1::from_slice(&receipt)) {
        Ok(sign1) => {
            writeln!(summary, "cose_sign1_parse=ok").unwrap();
            writeln!(summary, "protected.alg={:?}", sign1.protected.header.alg).unwrap();
            writeln!(
                summary,
                "protected.kid_len={}",
                sign1.protected.header.key_id.len()
            )
            .unwrap();
            writeln!(
                summary,
                "protected.x5chain_present={}",
                sign1
                    .protected
                    .header
                    .rest
                    .iter()
                    .any(|(k, _)| *k == coset::Label::Int(33))
            )
            .unwrap();
            for (k, v) in &sign1.protected.header.rest {
                writeln!(summary, "protected[{k:?}]={}", shape(v)).unwrap();
            }
            for (k, v) in &sign1.unprotected.rest {
                writeln!(summary, "unprotected[{k:?}]={}", shape(v)).unwrap();
            }
            writeln!(
                summary,
                "payload={}",
                match &sign1.payload {
                    Some(p) => format!("attached[{}]", p.len()),
                    None => "detached".into(),
                }
            )
            .unwrap();
            writeln!(summary, "signature_len={}", sign1.signature.len()).unwrap();
        }
        Err(e) => writeln!(summary, "cose_sign1_parse=error {e}").unwrap(),
    }

    // 1. The low-level verifier. The Ed25519 key is a fixed test key: the
    //    VDS check runs before any signature is examined, so the key value
    //    cannot influence the result being captured.
    let dummy = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let mut verify_out = String::new();
    match pask_wire::Receipt::from_cose_sign1(&receipt) {
        Ok(parsed) => writeln!(
            verify_out,
            "Receipt::from_cose_sign1: ok, vds={}, inclusion_proofs={}, payload={}",
            parsed.vds,
            parsed.inclusion_proofs.len(),
            parsed
                .payload
                .as_ref()
                .map(|p| p.len().to_string())
                .unwrap_or("detached".into())
        )
        .unwrap(),
        Err(e) => writeln!(verify_out, "Receipt::from_cose_sign1: Err({e})").unwrap(),
    }
    match pask_wire::verify_inclusion(&receipt, &statement, &dummy) {
        Ok(v) => writeln!(
            verify_out,
            "verify_inclusion: UNEXPECTED Ok tree_size={} leaf_index={}",
            v.tree_size, v.leaf_index
        )
        .unwrap(),
        Err(e) => writeln!(verify_out, "verify_inclusion: Err({e})").unwrap(),
    }

    // 2. The envelope inspector, default policy.
    let policy = pask_wire::InspectionPolicy::default();
    let report = pask_wire::inspect_scitt_receipt(&receipt, &policy);
    let mut inspect_out = String::new();
    writeln!(inspect_out, "policy_id={}", report.policy_id).unwrap();
    writeln!(inspect_out, "structure={:?}", report.structure).unwrap();
    writeln!(inspect_out, "required_claims={:?}", report.required_claims).unwrap();
    writeln!(inspect_out, "support={:?}", report.support).unwrap();
    writeln!(inspect_out, "ts_signature={:?}", report.ts_signature).unwrap();
    writeln!(inspect_out, "inclusion={:?}", report.inclusion).unwrap();
    writeln!(
        inspect_out,
        "unauthenticated_claims={:?}",
        report.unauthenticated_claims
    )
    .unwrap();

    fs::write(out.join("receipt-summary.txt"), &summary).unwrap();
    fs::write(out.join("verify-inclusion-output.txt"), &verify_out).unwrap();
    fs::write(out.join("inspect-scitt-receipt-output.txt"), &inspect_out).unwrap();
    print!(
        "{summary}\n--- verify_inclusion ---\n{verify_out}\n--- inspect_scitt_receipt ---\n{inspect_out}"
    );
}
