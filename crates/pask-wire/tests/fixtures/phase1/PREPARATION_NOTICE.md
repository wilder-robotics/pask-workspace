# Local provenance and license notice

This directory contains new local fixture-preparation work and exact preserved
copies. No external publication or license change is performed.
`LICENSES/README.md` explicitly scopes the proposed Apache-2.0 placement for the
new preparation code, separates original Apache/AGPL materials, and records the
owner-approval boundary. It is not a blanket license for this directory.

`preserved/legacy-receipts/` was copied byte-for-byte from
`../pask70-independent-snapshot/crates/pask-wire/fixtures/receipts/`.
Its upstream project is
[wilder-robotics/pask-workspace](https://github.com/wilder-robotics/pask-workspace).
Preserve the original project's applicable license and notices when packaging or
later integrating those files; this preparation does not relicense them.
The inspected `pask-wire` crate declares Apache-2.0 separately from the workspace's
AGPL-3.0-only default; do not label all preserved materials by the root default.
`preserved/source-manifest.json` identifies each inspected local source and digest.

The fixture generator is newly authored and imports no Pask implementation.
It uses installed cryptography for development-key signing, cbor2 only in
independent tests, and OpenSSL only as an independent signature oracle.
Installed dependencies are not vendored or relicensed.

The reproducible development seed in `crypto-preparation/oracle.json` is public
test material, protects nothing, and must never be deployed as a real key.
No private-key file is exported, and no test public key is automatically a trust anchor.
No client data, live service response, restricted standard or paid document is included.
