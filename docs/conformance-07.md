# Implementer guide: the 0.7 wire rules and their limits

Status: successor guide for the in-tree -05 draft and `pask-wire` 0.2.0 at
integration base `e725a53c2bbd90f3dcac1c06128ad4a367be5bd1`. The private author
package held by the owner described these same rules at historical public
commit `2adf75ec66630ba8525d8dfdfc3e71afe87bceec` and was not compiled or
executed. This guide does not claim those author tests ran. It is not a new
profile and it is not a claim of full conformance. No signed historical object
is repaired or upgraded by this guide.

## 1. Where the rules already live

The -05 source already specifies these rules. See [Profile identifier and media
types, payload definitions, COSE header requirements, and Content commitment and
explicit null](draft-wilder-scitt-physical-site-engage-receipt-05.md).
In particular, the in-tree -05 source ranges are 325–345, 596–602, 653–670,
843–855, and 995–1014. Those ranges are unchanged from historical public
commit `2adf75ec66630ba8525d8dfdfc3e71afe87bceec`. This guide collects those
existing requirements in one producer-facing place; it does not introduce
them retrospectively.

The implementation clauses are in `Payload::validate` in
[`payload.rs`](../crates/pask-wire/src/payload.rs), `CwtClaims::from_value` in
[`cwt.rs`](../crates/pask-wire/src/cwt.rs), and `validate_headers` in
[`envelope.rs`](../crates/pask-wire/src/envelope.rs).

## 2. Three checks a 0.7 generator must satisfy

### 2.1 The content member is nested, present, and typed

For `wilder.pser/0.7`, `engagement.contentDigest` must be present. Its value is
JSON `null` or a string consisting of `sha256:` and exactly 64 lowercase
hexadecimal digits. `sha256:` is case-sensitive. Absence is not null; a Boolean,
number, array, object, uppercase digest, different hash scheme, or wrong digest
length is not a supported root. A top-level `contentDigest` is an unknown payload
field, not a substitute for the nested member.

These are member fragments, not complete statements:

```json
{"engagement":{"contentDigest":null}}
```

```json
{"engagement":{"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
```

The second fragment illustrates syntax only; that arbitrary value is not a
verified retained-content root. The defined non-null value is the root of the
retained-content construction, not the digest of the entire content JSON file.
`contentDigest`, `engagement.evidenceDigest`, `site.envelope.digest`, and
`chain.hash` serve different purposes.

Null means that this statement commits no retained-content root. It does not mean
no evidence existed, no fact was known, or no relevant physical event occurred.
A syntactically valid digest does not prove that any content is available or that
a disclosed fact, attribution, or source record has been verified.

### 2.2 CWT subject is text, not a byte string

The protected CWT claims map (COSE header label 15) contains `sub` at claim label
2. For 0.7 it is a **CBOR text string**, exactly matching `site.id`. Encoding the
same UTF-8 bytes as a CBOR byte string is rejected. Case folding, Unicode
normalization, and byte-to-text coercion are not substitutes for the exact check.
The protected content type and payload `spec` must also agree.

This is a check on declared values and their representation. It does not prove
that the signing key controls, visited, or has authority over that Site.

### 2.3 DIRECT_WITNESS identifiers are textually equal

For 0.6 and 0.7 with `attestation.bindingMode = DIRECT_WITNESS`, protected CWT
`iss` (claim label 1, nonempty text) must textually equal
`attestation.witnessKey`. One-character and case differences are differences.
The rule does not map an identifier to a trusted key, prove custody, or appraise
hardware evidence. The verification key must still be selected under the
relying party's applicable trust arrangement.

The particular naming-equality check is not imposed on `DELEGATED_WITNESS` or
0.5 by the pinned implementation. A delegated-mode statement passing this wire
check does not establish that a delegation credential exists or is authentic.
The producer's ability to sign an object does not substitute for verifying it.

## 3. Compatibility matrix — pinned implementation, not universal conformance

| Property | 0.5 | 0.6 | 0.7 |
|---|---|---|---|
| `engagement.contentDigest` | Absent; presence rejected, including null | Same as 0.5 | Required; null or supported digest |
| CWT `sub` representation | Legacy CBOR byte string | Legacy CBOR byte string | CBOR text string |
| `sub` value equals `site.id` | Checked | Checked | Checked |
| DIRECT_WITNESS `iss` = `witnessKey` naming equality | Not imposed | Checked | Checked |
| Receipt `ts` in attestation interval | Not imposed | Checked, inclusive endpoints | Checked, inclusive endpoints |
| Attestation interval length | Strictly positive | Strictly positive | Strictly positive |
| Vendor-root appraisal or hardware custody from these checks | Not established | Not established | Not established |

The legacy byte-string subject is preserved implementation compatibility, not a
claim that it meets the CWT text-subject definition. Do not change the profile
string, add content, rewrite a CWT claim type, or normalize an old signed object
and call it the same original. A changed signed input requires its own signing
and version/compatibility treatment.

## 4. Checks are not interchangeable

**Recorded-time consistency:** `Payload::validate` checks the declared window
shapes and, for 0.6/0.7, declared receipt `ts` against the attestation interval.
It does not recompute `engagement.envelopeConformance`, prove engagement-window
containment in the site envelope, compare all receipts for overlap, or establish
an independent physical-event time. `UNKNOWN` remains a producer-declared
unknown; do not convert it to `WITHIN` after signature verification.

**Quote-time checking is a different API:** `pask_attest::Ed25519RootOfTrust`
implements `AttestationVerifier::verify(quote_bytes, clock)`. It authenticates its
quote under the configured key and calls `ValidityWindow::check_clock` using the
injected Clock, with the existing 60-second skew tolerance. In contrast,
`pask_wire::verify_ed25519(statement, key)` has no clock argument and does not
invoke that quote verifier. Success of the statement call is not an
appraisal-time acceptance of a separate quote. Neither a clock check nor a
caller-selected historical instant is proof of a fresh platform response.

**Evidence integrity versus appraisal:** hash-matching supplied evidence is not
native report authentication, an approved-measurement decision, private-key
non-exportability, or physical truth. The quote-only attestation path still has
no mechanism to retrieve the referenced platform bytes or authenticate their
native hardware format. Its opaque claims therefore do not reject a newly
fabricated underlying report merely because that report's digest was signed,
and do not require the referenced bytes to be available. This does not erase the
separate retained-evidence APIs that check supplied byte integrity.

See [Known limitations](../KNOWN-LIMITATIONS.md), especially §§1.3, 1.4, 2, 3,
5.2a and its new implementation-boundary addendum.

## 5. Exact bytes are not a representation-independent identity

The statement parser accepts a single outer CBOR tag 18 as well as
the local untagged COSE_Sign1 form. A signature-valid pair can have unchanged
protected bytes, payload and signature but different presented byte strings.
Hashes computed over those whole presented strings will differ. This observation
is not a signature break and is not a claim that every vendor API exposes a
`statement_sha256` field.

Retain the original presented bytes and identify which bytes a digest covers.
Do not silently strip a tag, reserialize CBOR, or equate `chain.hash` with a
whole-statement digest. This addition defines no canonical statement identifier,
registration-normalization rule, de-duplication behavior, or replay defense.

## 6. Test-source map and limits

Existing regression sources include
[`proposed07_envelope.rs`](../crates/pask-wire/tests/proposed07_envelope.rs) and
[`issue_30_66.rs`](../crates/pask-wire/tests/issue_30_66.rs). The successor
[`p06_conformance_01.rs`](../crates/pask-wire/tests/p06_conformance_01.rs) adds a
consolidated, signature-positive negative matrix and explicit characterization
records. It does not replace those tests, import a separate verifier, or mutate
historical fixtures. It is a new file identity. The historical author candidate
was not compiled or executed, and a static count of its functions is not a
native pass count.

A native run of this successor must use `alloc`. A zero-test run without that
feature does not exercise this suite and is not acceptance. Its Ed25519-only
cases are not a complete algorithm, CBOR, CWT, SCITT, attestation or
interoperability suite. Execution evidence belongs with the integrating pull
request, not in this guide.

Every controlled profile-negative input is rehashed and signed correctly; a
separate signature-positive control checks the serialized input before the
vendor verifier is called. Exact error classes/messages distinguish the intended
profile refusal from a signature failure. Generated records identify the
synthetic input, supplied public key, input hash and observed result.

The synthetic tag-twin test is not a replay of the exact closed-audit
baseline/test-key pair. That pair is not included in this public test. No real
hardware-positive receipt is generated or distributed by this guide.
