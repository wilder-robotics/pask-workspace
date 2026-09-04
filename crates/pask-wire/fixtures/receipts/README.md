# Attached SCITT Receipt fixtures

Interoperability vectors for the half of the registration obligation a relying
party actually performs: checking that an attached Receipt verifies.

The profile requires registration, and it requires that a relying party not
accept a Physical-Site Engagement Receipt as conforming unless at least one
attached Receipt from a Transparency Service that relying party trusts verifies
per RFC 9942. This directory is for the verifier side of that sentence. It says
nothing about obtaining a Receipt, which this repository still does not do.

| File | Expect |
|---|---|
| `valid-detached-payload.json` | verifies |
| `invalid-unsupported-vds.json` | rejected |
| `invalid-leaf-index-outside-tree.json` | rejected |
| `invalid-empty-inclusion-path.json` | rejected |
| `invalid-short-path-element.json` | rejected |
| `invalid-foreign-signature.json` | rejected |

## Reading a vector

Each file is flat and self-contained. `receipt` is the hex-encoded
`COSE_Sign1` Receipt. `entry` is the hex-encoded log entry the proof is
presented for. `transparencyServiceVerifyingKey` is the Ed25519 public key,
hex-encoded. `expectedRoot`, `treeSize` and `leafIndex` are stated so that an
implementation which fails can see where it diverged rather than only that it
did. `purpose` says what the vector is for in prose, because a vector whose
reason lives only in a commit message stops being a vector and becomes a file.

The signing key is the fixed byte string `07` repeated 32 times. It is a test
key, it is published here on purpose, and it protects nothing.

## What these vectors are for

The valid vector is the least interesting one. It pins the field order in the
RFC 9942 CDDL, where `tree_size` precedes `leaf_index`, and an implementation
that reverses them produces a proof that decodes cleanly and then verifies
against nothing. That is the kind of error a green test suite hides.

The five rejections each name a specific way a verifier passes while being
wrong, and none of them is caught by parsing:

`invalid-unsupported-vds.json` carries the Reserved value 0 in the `vds`
header and is otherwise a genuine, correctly signed Receipt over a real root. A
verifier that never reads `vds` applies the RFC9162_SHA256 walk anyway, gets the
right answer, and reports a proof it had no basis to interpret. It is right by
accident here and wrong the first time a second verifiable data structure is
registered.

`invalid-leaf-index-outside-tree.json` sets `leaf_index` equal to `tree_size`.
RFC 9162 Section 2.1.3.2 refuses this at step 1, before any hashing. A verifier
that omits the check does not crash; the walk terminates and yields a root, and
the verifier reports inclusion of an entry the log never claimed to hold.

`invalid-empty-inclusion-path.json` has a path with no elements, which the CDDL
`[ + bstr ]` forbids. In a nine-leaf tree the empty path reconstructs the leaf
hash and calls it the root, so accepting it means treating one unlogged entry as
an entire log.

`invalid-short-path-element.json` carries a 31-byte element where SHA-256
requires 32. This is here because copying path elements into a fixed buffer
without checking the length is the ordinary way this goes wrong, and the result
is a root that depends on whatever the buffer held.

`invalid-foreign-signature.json` is structurally perfect and proves inclusion
correctly. Only the signer is wrong. A verifier that checks the proof and stops
accepts a log entry from a Transparency Service the relying party never trusted,
which is the failure that matters most and looks least like a failure.

## What no vector here covers

There is no vector distinguishing a statement with no attached Receipt from a
statement whose `receipts` header is present and unreadable. That distinction is
real and the library keeps it, but it is a property of the statement envelope
rather than of a Receipt, so it is tested in `tests/receipt.rs` instead.

There is also no vector for the entry bytes themselves. Neither RFC 9942 nor the
profile says what byte sequence a SCITT log entry covers for this profile, so
two conforming implementations can produce proofs neither can check against the
other. No fixture can resolve that; it is document work, recorded in
`KNOWN-LIMITATIONS.md` §5.3.

## Regenerating

These files are generated, not hand-written, by
`crates/pask-wire/tests/receipt_fixtures.rs`:

```text
PASK_REGEN_FIXTURES=1 cargo test -p pask-wire --features std --test receipt_fixtures
```

Regeneration is opt-in and never runs in CI, so drift is still caught. Review
the diff afterwards. These are signed inputs, and a change to any of them
changes what conformance means.
