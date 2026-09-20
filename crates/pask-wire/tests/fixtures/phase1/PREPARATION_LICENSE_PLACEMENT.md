# License placement for the local prototype

**Scope: documentation-only placement record. No public distribution, copyright
assignment, certification or blanket relicensing is performed.**

## Newly authored preparation code

Proposed local license placement: **Apache-2.0**, limited to:

- `generate_fixtures.py`
- `interfaces.py`
- `prepare_report_schema.py`
- `run_preparation.py`
- `snapshot_inputs.py`
- `test_fixture_preparation.py`

These files were prepared for Wilder Robotics, the assumed name of Wilder
Management Inc. This record does not determine copyright ownership or invent a
copyright assignment. The placement is an explicit local proposal for the owner
to carry into approved distribution, not an independently issued public license
grant. No new SPDX claim is stamped onto preserved or third-party files.

The applicable proposed license text is
[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
Include its full text and required notices in any owner-approved distribution.
This placement does not change the code or its previously recorded test results.

## Preserved project materials

The inspected `pask-wire` crate explicitly declares `Apache-2.0`, and has its own
Apache license file. The preserved Receipt fixtures came from that crate.
([Inspected crate declaration](../../pask70-independent-snapshot/crates/pask-wire/Cargo.toml),
[crate license](../../pask70-independent-snapshot/crates/pask-wire/LICENSE))

The inspected workspace default separately declares `AGPL-3.0-only`; do not
extend the crate exception or this local proposal to operational or other
AGPL-covered code.
([Inspected workspace declaration](../../pask70-independent-snapshot/Cargo.toml),
[workspace license](../../pask70-independent-snapshot/LICENSE))

Honor original file/crate-level Apache or AGPL placement and retain applicable
notices. No operational implementation was copied into this preparation package.
Contracts, historical README prose and owner-supplied materials retain their
original status; they are not swept into the new-code proposal.

Installed cbor2, cryptography and OpenSSL retain their own applicable licenses.
They are not vendored or relicensed here. The ROS wrapper was inspected, not
copied or edited; this package's mapping does not relicense its source.

## Current-delivery filtering

The workspace retains `preserved/contract-before-three-phase.md` as requested.
The parent may omit that superseded backup and superseded handoff documents from
the current user-facing package without deleting the workspace originals.

For such a filtered copy, regenerate its checksum manifest. If retaining portable
snapshot verification, also remove the omitted backup's row from the filtered
`preserved/source-manifest.json`; otherwise it will correctly report a missing
preserved file. Keep the current contract backup and original checksums intact.
The full-lane test results describe the full local lane, not an independently
tested filtered package. No filtered-package reproduction is claimed here.
