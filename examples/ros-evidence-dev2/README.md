# Local ROS evidence demo: visible-source integration candidate

This directory is a source-review addition based on main
`b20a68e61092fbfeb67e6086488ca6acf4899596`. It is not a rebase or merge of the
experimental branch. No existing repository file or workflow is changed.

The accepted fifth experiment ran a different repository tree:
`6a2b0d828a3a63bb76b058d982bcd333773af24c`, tree
`d572501143794ffc1e1eaba6adbec3d98008e506`.
Its [run record](https://github.com/wilder-robotics/pask-workspace/actions/runs/35470820929)
establishes that bounded experiment, not execution of this integration tree.
This candidate has only ordinary local Python tests. Its ROS build and runtime
remain unexecuted. No sixth run is requested to reconfirm the accepted milestone.

## Source and licensing

`SOURCE_MAP.json` maps 13 byte-identical files to the reviewed fifth source:
the 12 expanded payload files, including the full Apache-2.0 license, and the
probe. Six runtime helper function bodies are extracted verbatim from the
reviewed runner; the local entry point is new. Two test suites have path-only
adaptations. `local_run.py plan` verifies these source relationships.
RINT-01 adds the omitted module-level `sys` import to the integration helper
module. No helper function body changed. The historical integration package is
preserved with its defect; the accepted fifth experiment source was not affected.

All code in this demo is Apache-2.0. Historical source comments saying
"recipe only" or "not run in the sandbox" are preserved original wording.
The previous isolated hosted run succeeded; this new integration tree remains
runtime-pending. `bundle.py` alone is not middleware: the ROS node and probe
supply actual middleware bytes.

The AGPL/reference bridge is **not copied, imported, linked or relicensed here**.
Its code, binaries, license obligations, tests and release decision belong to
the separate reviewed bridge distribution. The optional commands below invoke
it as a separate process. This is not a license opinion about future combined
distribution; any such distribution needs its own boundary review.

## Install and fast local checks

Use an ordinary Unix Python environment. This candidate was tested with Python
3.14.3 and cryptography 50.0.1, using dependencies already installed. Installation
commands below are instructions, not actions executed in this handoff.

```sh
cd examples/ros-evidence-dev2
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-offline.txt
.venv/bin/python local_run.py plan
.venv/bin/python tests/test_offline.py
.venv/bin/python tests/test_smoke.py
.venv/bin/python tests/test_local_runtime.py
.venv/bin/python tests/test_runtime_module.py
```

The 21 offline tests replay the actual three exports and full hosted finding
objects, compare all 214 bag records through read-only SQLite, preserve the
eight unequal encoding pairs, exercise altered-object/signature/missing-object
negatives, and mock the new local command adapter. The 39 smoke and 27 runtime
tests use mocks and ordinary Python. They are not another ROS run or independently
authored middleware implementation. Generated test work is retained and ignored
by Git and the Docker build context.
Ten additional RINT-01 tests import the actual runtime module without supplying
missing globals. They mock only subprocess/filesystem failure boundaries and
exercise successful finalization, primary errors, timeouts, secondary evidence
and kill failures, and nonzero/OOM container reports. The total is 97 local tests.
The original 87 tests did not cover the missing module binding; their earlier
passes did not establish that the imported runtime module could finalize.

## Materialize and check the actual exports

Choose new output paths. The materializer refuses overwrites and verifies the
archive and every indexed file before extraction:

```sh
.venv/bin/python fixtures.py --output /tmp/pask-actual-five-NEW
.venv/bin/python recipient.py /tmp/pask-actual-five-NEW/clean/export \
  --public-trust /tmp/pask-actual-five-NEW/clean/public-trust.json \
  --output /tmp/pask-clean-findings-NEW.json
```

Repeat with `scenario` and `missing-stream` as needed. All three have valid
original integrity and signatures under the supplied software test keys.
Only clean passes sampled coverage; scenario and missing control remain adverse.
Recipient exit 0 means its bounded local integrity/key checks pass, **not**
application acceptance or PSER conformance. Inspect each finding.

The included public trust files reproduce the experiment's automatic test
enrollment. They are not independently authenticated organizational trust.
For a separately approved test enrollment, explicitly supply the independently
checked key, issuer and record instead of extracting authority from a manifest:

```sh
.venv/bin/python provision_trust.py --public-key "$PUBLIC_KEY_HEX" \
  --issuer "$APPROVED_TEST_ISSUER" --record "$APPROVED_RECORD" \
  --output /tmp/approved-test-trust-NEW.json
```

That command records a local test decision; it does not establish a real PKI.

## Future local install, capture and export

**Not executed or authorized as part of this integration preparation.** The
explicit command exists for a later authorized operator. It requires existing
Docker, Ubuntu 24.04 x86_64, 4 GiB available host RAM, 12 GiB free workspace and
Docker backing storage, and noninteractive permission to inspect Docker disk
space. It installs nothing on the host. It refuses existing experiment container
names and requires a new output directory outside source.

```sh
.venv/bin/python local_run.py all --execute --output /absolute/new/pask-local-run
```

This resolves the base image once, records its digest, builds the unchanged
selected-version ROS recipe and separate recipient image, inventories installed
packages, runs all 48 fixed smoke cases, then clean/scenario/missing-stream
capture, export, bag reopen and recipient gates. It stops on failure, with no
retry, pin substitution or alternate runner. Network access is confined to
dependency/image preparation. Runtime containers retain network-none, read-only
root, one CPU, 256 MiB, 96 processes, nonroot identity, bounded tmpfs, explicit
mounts and 60-second per-container deadlines.

Export is part of successful capture, not a second serializer:
`capture-clean/final-bundle`, `capture-scenario/final-bundle` and
`capture-missing-stream/final-bundle` below the output root. Failed stages retain
partial diagnostics rather than final-looking exports. The helper enforces a
20 MiB recorded-evidence ceiling and preserves image/package inventories,
individual command logs, container inspection and final findings. Build commands
have the original 900/180-second limits; the local adapter is not a hosted job
scheduler and does not add a total wall-clock timeout.

The base tag and unpinned transitive packages can resolve differently in a future
build. Selected ROS package pins are unchanged; actual resolved identities must
be recorded anew. The offline Python requirements do not replace the image's
installed cryptography version.

## Read-only bag reopen

After a separately authorized build, the following uses the existing local
capture image and mounts the selected export read-only:

```sh
.venv/bin/python local_run.py reopen --execute \
  --bundle /absolute/path/final-bundle \
  --output /absolute/new/pask-bag-reopen
```

This reopens and checks stored bytes and type/schema information. It does not
publish the bag onto a ROS network. For ordinary offline replay without ROS,
use the recipient and SQLite regression commands above.

## Separate bridge process

Use the reviewed bridge distribution and its own installation instructions.
No binary or AGPL source is supplied by this directory:

```sh
PASK_BRIDGE_BINARY="$REVIEWED_BRIDGE_BINARY" \
  "$BRIDGE_PYTHON" "$BRIDGE_ROOT/dev2_bridge.py" \
  /tmp/pask-actual-five-NEW/clean/export /absolute/new/bridge-output
"$BRIDGE_PYTHON" "$BRIDGE_ROOT/independent_dev2_verify.py" \
  /absolute/new/bridge-output/evidence-bundle.jcs \
  /absolute/new/bridge-output/root \
  --expected-digest "$CALLER_EXPECTED_DIGEST"
```

Check the bridge kit's recorded root convention and expected-digest provenance
before invoking it. An expected hash copied from the same unsigned producer
output establishes equality context, not independent origin. This integration
does not execute the bridge or complete #71, PSER validation, external-recipient
acceptance or hardware appraisal.

## Review and automation boundary

See `CONTRACT.md`, `CI_PROPOSAL.md` and `fixtures/INDEX.json`. The index preserves
canonical package identities without recursively vendoring historical archives.
No existing `.github` file, DCO record or protection setting is changed.
Source-review publication does not supply DCO certification or merge permission.
Rob remains the sole maintainer and final decision-maker.
