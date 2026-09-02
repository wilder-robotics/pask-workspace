# `adapter.ackProvenance` fixtures

Test data for the two rules that govern `adapter.ackProvenance`, the REQUIRED
enumerated member added at `wilder.pser/0.4`.

The member records how the acknowledgement covered by `adapter.ackDigest` was
obtained. Its closed set is `THIRD_PARTY`, `ISSUER_ASSERTED`, and `NONE`.

| File | Expect |
|---|---|
| `collapsed-unrecognized-and-NONE.json` | distinguishable |

## What this vector is for

The vector holds two receipts identical but for `adapter.ackProvenance`. The
first carries a value outside the closed set. The second carries `NONE`.

A verifier MUST accept both, and MUST report them as different states. Reading
the first as `NONE`, or as `THIRD_PARTY`, is the failure the vector names.

`expect` is `distinguishable` rather than `verifies` or `rejected` because the
requirement is neither an acceptance nor a rejection. A verifier that accepted
both and reported them as the same state would satisfy `verifies` and would
still be wrong. That is the whole reason this vector exists, and it is why a
parse-only test does not cover the rule.

## Why an unrecognised value is accepted at all

This member is a descriptive property of a record read after an engagement has
already happened, frequently by somebody reconstructing an event months later.
Refusing the record at that point destroys the reconstruction the record exists
to serve, while telling the reader nothing they could not have been told by
surfacing the value as unrecognised.

That cost function is the inverse of the one that applies to an enumeration
feeding a pre-action gate, where refusing an unknown value costs only
availability. `actor.class` and `adapter.mode` remain fail-closed for that
reason, and this member's tolerance is not a precedent for relaxing them.

Tolerance is not the same as silence. The original string is preserved exactly,
so the record round-trips byte-identically through JCS and any signature over it
remains valid, and the reader is told the value is outside the set.

## Naming

The file name uses `unrecognized` with a z, mirroring the convention in
`verify-failure-mode-ref-v1`'s `collapsed-unreachable-and-invalid`. The prose in
this repository uses `unrecognised` with an s. Both spellings are correct as
publicly committed and neither is to be harmonised into the other.

## Generation

Generated, not hand-written. Both receipts derive from the canonical example
instance in `crates/pask-wire/src/testvectors.rs` with `id` and
`adapter.ackProvenance` overridden, then rebuilt through
`Payload::from_json_for_production`, which recomputes `chain.hash` over the
result. `crates/pask-wire/tests/ack_provenance.rs` reads the committed file and
asserts the distinction directly.
