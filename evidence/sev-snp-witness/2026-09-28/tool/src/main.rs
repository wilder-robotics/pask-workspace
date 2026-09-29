// snp-witness: experiment helper for the Pask half of the SEV-SNP test.
// Uses only published crates: pask-attest 0.1.0, pask-wire 0.1.0.
// Nothing here is a Pask profile rule. Where a convention is invented for the
// experiment it is marked EXPERIMENT CONVENTION and named in the accompanying README.
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pask_attest::clock::Clock;
use pask_attest::{AttestationVerifier, Ed25519RootOfTrust};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{env, fs, process};

const FRAME_VERSION: [u8; 8] = [b'a', 0, 0, 0, 0, 0, 0, 1];
// AMD SEV-SNP ATTESTATION_REPORT field offsets (SEV-SNP ABI spec, Table "ATTESTATION_REPORT").
// The procedure cross-checks these against `snpguest display report` before they are relied on.
const OFF_VERSION: usize = 0x000;
const OFF_REPORT_DATA: usize = 0x050;
const OFF_MEASUREMENT: usize = 0x090;
const OFF_REPORT_ID: usize = 0x140;
const REPORT_MIN_LEN: usize = 0x2A0;

struct SystemClock;
impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        time::OffsetDateTime::now_utc()
            .replace_nanosecond(0).unwrap()
            .format(&time::format_description::well_known::Rfc3339).unwrap()
    }
}
struct FixedClock(String);
impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String { self.0.clone() }
}

fn die(msg: &str) -> ! { eprintln!("error: {msg}"); process::exit(2) }

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(&args[2..]),
        Some("report-data") => report_data(&args[2..]),
        Some("quote") => quote(&args[2..]),
        Some("verify") => verify(&args[2..]),
        _ => die("usage: snp-witness keygen <out-dir> | report-data <witness.pub.pem> <out.bin> | quote <dir> <witness-key-id> <report.bin> <evidence.json> <sealed.tar> <notBefore> <notAfter> | verify <quote.bin> <witness.pub.pem> <witness-key-id> [now-rfc3339]"),
    }
}

// Key generation happens inside the VM. pask-attest and pask-wire-cli do not generate keys.
fn keygen(a: &[String]) {
    let dir = a.get(0).unwrap_or_else(|| die("keygen <out-dir>"));
    fs::create_dir_all(dir).unwrap();
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let priv_pem = sk.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF).unwrap();
    let pub_pem = sk.verifying_key().to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF).unwrap();
    fs::write(format!("{dir}/witness.priv.pem"), priv_pem.as_bytes()).unwrap();
    fs::write(format!("{dir}/witness.pub.pem"), pub_pem.as_bytes()).unwrap();
    println!("witness.pub raw hex: {}", hex::encode(sk.verifying_key().to_bytes()));
}

// EXPERIMENT CONVENTION EXP-SNP-RD-1:
// REPORT_DATA (64 bytes) = SHA-512 over the DER SubjectPublicKeyInfo of the witness public key.
fn spki_der(pub_pem_path: &str) -> Vec<u8> {
    let pem = fs::read_to_string(pub_pem_path).unwrap_or_else(|_| die("cannot read public key"));
    let vk = VerifyingKey::from_public_key_pem(&pem).unwrap_or_else(|_| die("not an Ed25519 SPKI PEM"));
    vk.to_public_key_der().unwrap().as_bytes().to_vec()
}
fn report_data(a: &[String]) {
    let (pubkey, out) = (a.get(0).unwrap_or_else(|| die("args")), a.get(1).unwrap_or_else(|| die("args")));
    let rd = Sha512::digest(spki_der(pubkey));
    fs::write(out, rd).unwrap();
    println!("REPORT_DATA (EXP-SNP-RD-1) = sha512(spki-der) = {}", hex::encode(rd));
}

fn sha256_prefixed(bytes: &[u8]) -> String { pask_wire::sha256_prefixed(bytes) }

// Builds the framed wilder.attest/0.1 quote that pask-attest 0.1.0 verifies.
fn quote(a: &[String]) {
    if a.len() < 7 { die("quote <dir> <witness-key-id> <report.bin> <evidence.json> <sealed.tar> <notBefore> <notAfter>"); }
    let (dir, kid, report_p, evidence_p, sealed_p, nb, na) = (&a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6]);
    let sk_pem = fs::read_to_string(format!("{dir}/witness.priv.pem")).unwrap_or_else(|_| die("no witness.priv.pem"));
    let sk = SigningKey::from_pkcs8_pem(&sk_pem).unwrap_or_else(|_| die("bad private key"));
    let report = fs::read(report_p).unwrap_or_else(|_| die("cannot read report"));
    if report.len() < REPORT_MIN_LEN { die("report too short for an SNP attestation report"); }
    let version = u32::from_le_bytes(report[OFF_VERSION..OFF_VERSION + 4].try_into().unwrap());
    let measurement = &report[OFF_MEASUREMENT..OFF_MEASUREMENT + 48];
    let report_id = &report[OFF_REPORT_ID..OFF_REPORT_ID + 32];
    let rd_in_report = &report[OFF_REPORT_DATA..OFF_REPORT_DATA + 64];
    let expected_rd = Sha512::digest(sk.verifying_key().to_public_key_der().unwrap().as_bytes());
    if rd_in_report != expected_rd.as_slice() { die("REPORT_DATA in report does not equal sha512(witness SPKI); wrong report or wrong key"); }
    let evidence = fs::read(evidence_p).unwrap_or_else(|_| die("cannot read evidence manifest"));
    let sealed = fs::read(sealed_p).unwrap_or_else(|_| die("cannot read sealed tar"));
    // EXPERIMENT CONVENTION EXP-SNP-MB-1: measured-boot components taken from the report.
    let components = json!([
        {"name": "snp.launch-measurement", "digest": sha256_prefixed(measurement)},
        {"name": "snp.report-id", "digest": sha256_prefixed(report_id)}
    ]);
    let chain = sha256_prefixed(&pask_wire::canonicalize_json(&serde_json::to_vec(&components).unwrap()).unwrap());
    let claims = json!({
        "spec": "wilder.attest/0.1",
        "teeClass": env::var("SNP_WITNESS_TEE_CLASS_OVERRIDE").unwrap_or_else(|_| "amd.sev-snp".to_owned()),
        "measuredBoot": {"chain": chain, "components": components},
        "platformEvidence": {"encoding": "opaque/1", "digest": sha256_prefixed(&evidence)},
        "sealedEvidence": {"encoding": "opaque/1", "digest": sha256_prefixed(&sealed), "sizeBytes": sealed.len()},
        "witnessKey": kid,
        "validity": {"notBefore": nb, "notAfter": na}
    });
    let jcs = pask_wire::canonicalize_json(&serde_json::to_vec(&claims).unwrap()).unwrap();
    let sig = sk.sign(&jcs);
    let mut q = FRAME_VERSION.to_vec();
    q.extend_from_slice(&jcs);
    q.extend_from_slice(&sig.to_bytes());
    fs::write(format!("{dir}/witness-quote.bin"), &q).unwrap();
    fs::write(format!("{dir}/witness-quote.claims.json"), &jcs).unwrap();
    println!("report version {version}; quote written: {} bytes; quote sha256 {}", q.len(), sha256_prefixed(&q));
    println!("platformEvidence.digest = {}", sha256_prefixed(&evidence));
    println!("sealedEvidence.digest   = {} ({} bytes)", sha256_prefixed(&sealed), sealed.len());
}

// Runs pask-attest 0.1.0 against a quote and prints the typed outcome.
fn verify(a: &[String]) {
    if a.len() < 3 { die("verify <quote.bin> <witness.pub.pem> <witness-key-id> [now-rfc3339]"); }
    let q = fs::read(&a[0]).unwrap_or_else(|_| die("cannot read quote"));
    let vk = VerifyingKey::from_public_key_pem(&fs::read_to_string(&a[1]).unwrap()).unwrap_or_else(|_| die("bad public key"));
    let root = Ed25519RootOfTrust::new().with_key(a[2].clone(), vk);
    let clock: Box<dyn Clock> = match a.get(3) { Some(t) => Box::new(FixedClock(t.clone())), None => Box::new(SystemClock) };
    match root.verify(&q, clock.as_ref()) {
        Ok(att) => {
            println!("RESULT: VERIFIED teeClass={} witnessKey={} platformEvidence={} sealedEvidence={}B",
                att.tee_class(), att.witness_key().as_str(), att.platform_evidence().digest(), att.sealed_evidence().size_bytes());
        }
        Err(e) => { println!("RESULT: REJECTED {e:?}"); process::exit(1); }
    }
}

#[allow(dead_code)]
fn _unused(_: Value) {}
