# Chain fixtures

Test data for the two Chain-Verifier requirements in Section 4.1 of
`draft-wilder-scitt-physical-site-engage-receipt-01`: `chain.seq` contiguity
across adjacent pairs, and `chain.prevHash` equal to the preceding receipt's
`chain.hash`.

`chain.hash` is SHA-256 over the JCS serialization of the receipt with the
`chain.hash` member absent. `chain.prevHash` carries the preceding receipt's
`chain.hash` value.

| File | Expect |
|---|---|
| `valid-3.json` | verifies |
| `invalid-seq-gap.json` | rejected — seq 0 then seq 2 |
| `invalid-broken-link.json` | rejected — prevHash does not match. Its `chain.hash` is also stale, since the member was altered after sealing; that is the realistic shape of in-band tampering and both checks catch it. |
| `invalid-head-not-zero.json` | rejected — head does not carry seq 0 |

**No crate consumes these yet.** See issue #41. They were produced to evaluate
the Section 4.1 requirement against a concrete instance before the text froze,
and doing so found an inconsistency in the `-01` draft: `chain.prevHash` had
been defined as a digest of the preceding receipt while `chain.hash` was
defined with the `chain.hash` member excluded, so the required adjacent-pair
check would have rejected every honest chain. The draft was corrected before
filing. Recorded in Appendix A.2.

The values are synthetic and illustrative. `evidenceDigest` is a placeholder.
