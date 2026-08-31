# Chain fixtures

Test data for the two Chain-Verifier requirements in Section 4.1 of
`draft-wilder-scitt-physical-site-engage-receipt-01`: `chain.seq` contiguity
across adjacent pairs, and `chain.prevHash` equal to the preceding receipt's
`chain.hash`.

`chain.hash` is SHA-256 over the JCS serialization of the receipt with the
`chain.hash` member absent. `chain.prevHash` carries the preceding receipt's
`chain.hash` value. The digest prefix is `sha256:` (no hyphen), matching both
the `-01` draft and this crate's `validate_sha256`.

| File | Expect |
|---|---|
| `valid-3.json` | verifies |
| `invalid-seq-gap.json` | rejected — seq 0 then seq 2 |
| `invalid-broken-link.json` | rejected — prevHash was altered after sealing, so it no longer matches the preceding receipt's `chain.hash`. That alteration also leaves the receipt's own `chain.hash` stale relative to its (now-altered) content, which is the realistic shape of in-band tampering, so per-receipt parsing (`Payload::from_json`) rejects it before a chain-level check ever runs. `crates/pask-wire/tests/chain.rs` covers the chain-level link check itself with a second, narrower case whose tampered receipt still parses on its own. |
| `invalid-head-not-zero.json` | rejected — head does not carry seq 0 |

These fixtures are generated, not hand-written. Each receipt is derived from
`pask_wire::canonical_example()` — the profile's canonical example instance —
with `id`, `chain.seq`, and `chain.prevHash` overridden per position, then
rebuilt with `Payload::from_json_for_production`, which recomputes
`chain.hash` correctly for the result. `crates/pask-wire/tests/chain.rs`
regenerates the expected content on every run and asserts each committed
file is byte-identical, so they cannot drift from the implementation again.

`crates/pask-wire/src/chain.rs` (`verify_chain`) consumes these fixtures. See
issue #41.

The values are synthetic and illustrative. `evidenceDigest` and the other
attestation digests are placeholders inherited from the canonical example.
