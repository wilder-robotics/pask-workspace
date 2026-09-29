# Issue #100 evidence, 2026-09-28: first real-ledger CCF interop observation

Captured by the manual workflow `.github/workflows/ccf-interop-evidence.yml`
(run 36497964897) on branch `evidence/issue-100-ccf-interop` at commit
`4c2084ae746d37ed3d1d539edd9ec8e783ac003f`, whose `crates/` tree is identical
to main `9ba85f1034145de9e8670a83ffc26ca6608fcec6` (the `pask-wire` 0.1.0
release). Ledger: `microsoft/scitt-ccf-ledger` at
`bffdf529185ba7767db5f2cfc4c1898ec8ad3364`, self-hosted in Docker on the
runner. Verify file integrity with `sha256sum -c SHA256SUMS`.

| File | What it is |
|---|---|
| `signed-statement.cose` | The pyscitt-signed statement the dev script produced and the tool submitted |
| `service_cert.pem` | The ledger's service certificate (TLS root and receipt-signing identity for this dev network) |
| `ccf-receipt.cose` | The 508-byte tag-18 `COSE_Sign1` receipt returned by the ledger, unmodified |
| `transparent-statement.cose` | The statement with that receipt attached under label 394 by `pask_ts_client::attach_receipt` |
| `receipt-summary.txt` | Header shape of the receipt as parsed by `coset` (no verification) |
| `verify-inclusion-output.txt` | Exact output of `pask_wire::Receipt::from_cose_sign1` and `pask_wire::verify_inclusion` on the receipt |
| `inspect-scitt-receipt-output.txt` | Exact `pask_wire::inspect_scitt_receipt` report, default policy |
| `real-ledger-test.log` | `cargo test -p pask-ts-client -- --ignored --nocapture`, unchanged test, separate registration |
| `run-dev-ts.log`, `capture.log`, `provenance.txt` | Ledger bring-up log, tool stdout, source and ledger revisions |
| `tool/` | The capture program. Not a workspace member; depends on the workspace crates by path |

## Result in one line

Statement registered, receipt retrieved, Pask reports the receipt as
unsupported (`ccf_profile_not_implemented`, VDS 2) and does not count it as
verified inclusion. The low-level `verify_inclusion` path refuses earlier,
at the RFC 9162 proof-shape check (`inclusion proof must be a CBOR array`).

## Not claimed

No CCF receipt was verified. No VDS registration is asserted: the value `2`
is the requested assignment in `draft-ietf-scitt-receipts-ccf-profile-05`
and is not in the IANA registry as of this capture. Dev-network keys and
certificates here are throwaway and are not trust anchors.
