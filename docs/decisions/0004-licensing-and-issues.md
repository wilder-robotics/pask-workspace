# 0004. Commercial-licensing scope and issue status

- Status: Accepted by the architect (ChatGPT) on 2026-10-23.
- Implementation of the grant: not done. No grant-changing text merges in the task that records this selection.
- Implementation of the issue sections: the dated text below is the status to append to issues #66 and #76. The original issue text stays.

## Selection

`pask-ts-client` is inside the intended commercial-licensing scope. Legal review is required before any text that changes a grant merges. Until that review, [`COMMERCIAL-EXCEPTION.md`](../../COMMERCIAL-EXCEPTION.md) remains the grant. As of its 2026-09-02 scope statement, that grant names `pask-site` and `pask-adapter` and does not name `pask-ts-client`. This record does not edit `LICENSE`, `LICENSING.md`, or `COMMERCIAL-EXCEPTION.md`.

Issues [#66](https://github.com/wilder-robotics/pask-workspace/issues/66) and [#76](https://github.com/wilder-robotics/pask-workspace/issues/76) gain a dated implementation-status section. Their history is not erased, rewritten, or closed by this status.

The sections below were read from base `fa78e8be7243df772eb37cf0fbead61a5d2bb047` on 2026-10-23. Task T01 did not change Rust code and did not re-run the tests those files contain.

## Status appended to issue #66

### Implementation status (2026-10-23)

Recorded by task T01 from base `fa78e8be7243df772eb37cf0fbead61a5d2bb047`. This section does not close the issue, does not replace the request above, and is not a disposition of authentic key association or hardware provenance.

- `crates/pask-wire/src/envelope.rs` rejects a `wilder.pser/0.6` statement, and a proposed `wilder.pser/0.7` statement, when `bindingMode` is `DIRECT_WITNESS` and `attestation.witnessKey` is not textually equal to the protected CWT `iss`. The comment on that check states that it establishes a naming convention and does not establish that the signature-verification key is authentically associated with either identifier, or that genuine TEE hardware produced the signature.
- `crates/pask-wire/tests/issue_30_66.rs` contains tests for that textual comparison, including cases the test commentary treats as out of scope for 0.5 and for `DELEGATED_WITNESS`.
- `crates/pask-attest/src/verifier.rs` checks a quote-local `witnessKey` against keys configured on the verifier. This read did not find a comparison there between `witnessKey` and a statement `iss`. The request to implement the check in both `pask-wire` and `pask-attest` is only partly present in `pask-wire`.
- T01 did not execute those tests. Result of this inspection: source present as described. Test result: `NOT_RUN`.

## Status appended to issue #76

### Implementation status (2026-10-23)

Recorded by task T01 from base `fa78e8be7243df772eb37cf0fbead61a5d2bb047`. This section does not close the issue and does not replace the request above.

- `crates/pask-wire/src/cwt.rs` writes CWT claim 2 as a byte string unless the caller passes text mode. The reader accepts a text subject only in text mode. Otherwise it requires a byte string. The text-mode error string says `0.7 CWT sub must be text`.
- `crates/pask-wire/src/envelope.rs` enables that text mode only when the payload spec is `wilder.pser/0.7` (`claims.to_value` and `CwtClaims::from_value` at the call sites that compare the spec with `SPEC_VERSION_07`). On this path, `wilder.pser/0.5` and `wilder.pser/0.6` still use a byte-string subject.
- The acceptance items in the original issue remain open: an explicit compatibility strategy for existing signed 0.5 and 0.6 statements, the relationship between a text `sub` and `site.id`, producer and reader handling with positive and negative type tests and independent exact-byte fixtures, preservation of original signed bytes, and documentation that separates generic signature success from SCITT conformance.
- T01 did not execute tests. Result of this inspection: source present as described. Test result: `NOT_RUN`.
