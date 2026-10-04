# Local recipient replay, proposal 1

This is a private-development reproduction interface, not an installed
`pask-wire-cli` command, frozen PSER/content wire format, or a public release.
Its library entry point is `pask_wire::proposed_replay::inspect_replay_document`.
The unchanged RECIPIENT-01 inspector runs on every entry. CHAIN mode separately
calls the existing `verify_chain` with individually checked Payloads.

## Native build and real file-based execution

Use an already available supported Rust toolchain. No script installs one.
Keep build output outside the source so the source manifest stays meaningful.

```sh
export CARGO_TARGET_DIR=/absolute/path/to/disposable-replay-target
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
cargo +1.98.1 build --locked -p pask-wire --features alloc --example proposed_recipient_replay

FIXTURES=crates/pask-wire/tests/fixtures/proposed07/replay
"$CARGO_TARGET_DIR/debug/examples/proposed_recipient_replay" \
  --mode single --input "$FIXTURES/single-match.json" \
  --key "$FIXTURES/public-key.hex" --output /new/path/single-report.json

"$CARGO_TARGET_DIR/debug/examples/proposed_recipient_replay" \
  --mode chain --input "$FIXTURES/chain-three.json" \
  --key "$FIXTURES/public-key.hex" --output /new/path/chain-report.json

python3 tools/proposed07/run_portable_replay.py \
  --binary "$CARGO_TARGET_DIR/debug/examples/proposed_recipient_replay" \
  --fixtures "$FIXTURES" --output /new/path/replay-results
```

The output directory's parent must exist for the example's individual files.
The full runner creates its fresh results directory and never uses an existing
one. On Windows the built example uses the normal executable suffix; supply
that actual path. The documented native review target is Linux, not an implied
Windows run. This example reads the exact files selected by the caller. It is
not a filesystem, process, symlink, or race sandbox. It checks regular-file
status and finite read size but cannot guarantee disk I/O completion time.

**Exit 0 means report produced, including adverse findings.** Exit 2 means an
invocation, framing/resource, key, or I/O failure. There is no application-
acceptance exit code. An existing report/input cannot be overwritten. A write
error can leave an incomplete newly-created output: nonzero exit and stderr
must not be discarded. A pipe/stdout write can also fail.

## Input contract

`replay-envelope.schema.json` is an informative shape aid for
`pask-local-recipient-replay/1`; the closed native deserializer and explicit
limits are authoritative for this local proposal. Every named member is
required, including nullable presentation/context/byte fields. Missing is not
silently replaced with null. Unknown or duplicate fields, including escaped
aliases of names, are rejected. No path, URL fetch, expected-root override,
mode, or key member is accepted in the document. Per-entry policy and context
are intentionally unauthenticated input; signing a PSER does not sign them.

Statement, canonical fact, and evidence byte strings use strict lowercase hex.
They are decoded by bytes, not parsed and rewritten as a substitute. Salt/hash
widths and proof limits are exact. BYTES carries a hex string (empty allowed);
UNAVAILABLE and NOT_REQUESTED carry explicit null. All documents/entries decode
before any batch report is returned. Later semantic failures remain per-check
findings, not overall success or disappearance of other entries.

The separate public-key file is a caller-selected Ed25519 public verification
key: exactly 64 lowercase hex characters, with optional outer ASCII JSON
whitespace in the file interface only. The API itself accepts no whitespace in
the hex key. It is not a secret, proof of key provenance, authenticated person,
organization, hardware, or service. One explicit key applies to this complete
batch; key rotation/provisioning is not supplied.

## Modes and ordering

SINGLE requires exactly one entry. It checks that entry and explicitly leaves
chain contiguity NOT EVALUATED, including when its sequence is nonzero.

CHAIN accepts 1–16 ordered entries. Every statement must pass its existing
signature/payload/header check before chain checking. Checked Payloads are
obtained by re-running the existing verifier; this deliberately repeats signature
work and is not hidden as a performance optimization. An arithmetic ceiling
check protects the inherited predecessor increment before calling `verify_chain`.

The existing chain function requires a genesis head (seq 0 and null predecessor),
contiguous sequence numbers and exact previous-payload-hash links. Input is
never sorted or gap-filled. A one-element genesis prefix can pass. A presented
suffix without genesis fails this selected contract. A valid prefix does not
establish latest or complete history: suffix withholding survives. These links
do not additionally guarantee site/issuer continuity, physical chronology,
independent observation, or independent history storage.

Affiliation changes are reported, not treated as invalid chains. Each unchanged
RecipientReport remains the result of its single-statement call; its own chain
finding is not relabeled. The extra top-level chain report covers the ordered
batch. A chain pass may coexist with bad content proofs, contradictory evidence,
forbidden metadata or failing disclosure policy. A chain failure does not erase
valid individual memberships. No aggregate `valid`/`accepted` property exists.

## Limits and measurements

Limits: 8 MiB raw document, lexical container depth 32, at most 16 entries, 3 MiB
aggregate decoded statement/fact/evidence/salt/proof bytes, plus inherited
per-field and recipient limits. Keys/context are length-bounded. Raw bounds
precede typed allocation; decoded lengths are checked before their allocation.
The typed parser still allocates within that raw input domain; no streaming,
constant-memory, process-resource cap or input-acquisition guarantee is made.
The shape schema's character counts and JSON numeric meaning cannot replace
native byte, token/type, duplicate-key, depth and aggregate-budget checks.

One recipient can store 1 MiB of objects yet hash up to 16 MiB across repeated
references; a bounded 16-entry batch can induce up to 256 MiB of that work.
Document-byte counts are not a CPU budget. Reports contain decoded input sizes.
The subprocess harness separately measures actual output byte sizes and one
process elapsed time: not a production benchmark or formal peak-memory bound.

## Reproduction and history

The catalog has 21 synthetic documents and 30 signed statement occurrences
(including one deliberately invalid signature). Its 25 membership calculations
include one deliberately invalid proof. The Python fixture generator uses an
explicit PUBLIC development seed and public key; these are never deployment
keys. It independently constructs byte framing and signatures, reusing the
existing Python content oracle, not a second independently audited construction.
Expected report projections are assertions for Rust to satisfy, not Python
execution of the native recipient.

There are 38 authored library-test functions (one reads the 21-case table), five
example argument-parser tests, and 31 planned actual example invocations. Counts
overlap where tests and the portable harness replay the same fixtures. Run the
native targets and portable harness on a relocated source copy to substantiate
portability. The harness does not build or repair code, and preserves each actual
exit, original output, source-file inventory, report and byte/time measurement.

No remote evidence, TS/Receipt verification, hardware appraisal, asserting-party
authentication, real-world clock, full application acceptance, or full PSER
conformance follows. The local schema is reviewable and not adopted normative
-05 text. Existing distribution and incomplete name-scan limitations remain.
