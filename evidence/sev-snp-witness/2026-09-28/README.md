# SEV-SNP witness experiment, 2026-09-28 (run 2026-09-29 UTC)

Public half of the record for the AMD SEV-SNP test configuration described in
KNOWN-LIMITATIONS 5.2. The witness key was generated inside an AMD SEV-SNP confidential
VM, an attestation report bound to that key was verified with snpguest v0.10.0 and
independently, and a `wilder.attest/0.1` quote plus one `wilder.pser/0.6` statement were
produced and verified with the published crates `pask-attest 0.1.0` and
`pask-wire-cli 0.1.0`. No code under `crates/` is changed by this record.

## What is here

| File | What it is |
|---|---|
| `transcript.log` | The in-VM command transcript. Redactions: the VM hostname and the login user name are replaced with `[vm-hostname redacted]` and `[user]`; one line that echoed a PEM header from a sanity step was removed; the STEP 7 heading was reworded to name the fixtures it covers. Nothing else is altered. |
| `run_witness.sh` | The script that produced the transcript, with the sanity step changed so it prints nothing, and the copy-out rule added as a comment. |
| `tool/` | Source and lock file of the `snp-witness` helper. Depends only on crates.io `pask-attest 0.1.0`, `pask-wire 0.1.0`, `ed25519-dalek 2.2.0`, `sha2`, `serde_json`, `hex`, `time`. Not a workspace member. |
| `tool-hashes.txt` | SHA-256 of the helper binary and of the installed `pask-wire-cli` as built in the VM. |
| `payload.template.json` | The `wilder.pser/0.6` producer input before the attestation block was spliced in. |
| `witness-quote.claims.json` | The canonical JSON claims of the verified quote (digests only; no evidence bytes). |
| `witness.pub.pem` | The witness public key. Its SHA-512 SPKI digest is the REPORT_DATA in the transcript. |
| `validity.txt` | The quote's `notBefore` and `notAfter`. |

## What is not here, on purpose

The raw attestation report, the ARK/ASK/VCEK certificate chain, the evidence manifest,
the sealed bundle, the signed quote bytes, the signed statement, the cloud project, zone,
instance and hardware identifiers. They are retained privately. A reader can check every
digest printed in the transcript against these files' digests but cannot recompute them.
The private keys never left the VM disk.

## Conventions used here are not profile rules

`EXP-SNP-RD-1` (REPORT_DATA = SHA-512 of the witness public key's SubjectPublicKeyInfo),
`EXP-SNP-EV-1` (evidence manifest), `EXP-SNP-SE-1` (sealed tar), and `EXP-SNP-MB-1`
(measured-boot components derived from the report's MEASUREMENT and REPORT_ID) exist
for this experiment only. `pask-attest 0.1.0` accepts `platformEvidence.encoding`
`opaque/1` and a SHA-256 digest; it defines no SEV-SNP evidence format.

## Copy-out rule

Before anything leaves the VM, grep the copied tree for `PRIVATE KEY`. The check must
match PEM headers (`-----BEGIN PRIVATE KEY-----`, `BEGIN OPENSSH PRIVATE KEY`,
`BEGIN EC PRIVATE KEY`), not only base64 key bodies. It caught the header line in the
first transcript.
