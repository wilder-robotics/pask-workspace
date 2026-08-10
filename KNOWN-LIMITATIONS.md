# Known limitations

| | |
| --- | --- |
| Applies to | `draft-wilder-scitt-physical-site-engage-receipt-01` and this repository |
| Profile identifier in the implementation | `wilder.pser/0.3` |
| Last reviewed | 2026-08-09 |
| Status | Pre-alpha reference implementation |

This file is maintained alongside the code. It records what the profile and
the reference implementation **do not** do, in the present tense, so that an
implementer or reviewer does not have to discover it by reading the source.

Three things it is not. It is not a conformance statement — absence from this
file does not establish that a property has been implemented or demonstrated.
It is not a roadmap; where an item has a tracker, the tracker is linked and
nothing here promises a date. And it is not a disclosure of past error: the
`-00` payload figure was a schema template, and it is described below as one.

The Internet-Draft is an IETF individual submission. It has no IETF standing,
has not been adopted by any working group, and carries no production-readiness,
safety, insurance, or regulatory-compliance claim.

---

## 1. Document and implementation

### 1.1 The profile identifier is not published in any register

The implementation emits `wilder.pser/0.3`. The document that defines `0.3` is
`-01`. Until `-01` is posted, the most recent identifier described by a posted
revision is `wilder.pser/0.2`, and an implementer working from a posted
document is working from `0.2`.

### 1.2 One figure is generated; the rest of the document is prose

The Section 4 payload figure in `-01` is emitted by `pask-wire` and asserted
byte-identical in CI, and every fenced example in the document is now required
to be accounted for — parsed by the reference parser, or listed with a written
reason it should not be. That guarantee covers the examples only.

The normative member definitions in Section 4.1, the security considerations,
and the IANA request are maintained by hand and are not mechanically checked
against the implementation. Nothing in the build would observe a member
definition drifting away from the type that implements it.

`-00` presented its payload structure as a schema template — unquoted
placeholders showing member names and value shapes rather than a literal
instance. A template is not machine-checkable, which is why four attestation
members came to be described differently by `-00` and by the implementation.
`-01` reconciles all four and replaces the template with a generated instance.

---

## 2. What the attestation layer does not verify

The three-party trust model is normative in the profile and is **not
demonstrated** by this implementation.

### 2.1 No vendor quote is carried

`attestation` has no `quote` member. `-01` is silent on quote transport rather
than prohibitive, so a later revision can add it as a pure addition.

The consequence is worth stating plainly. Without a vendor quote, the
attestation members in a receipt are asserted by the witness rather than
evidenced by hardware, and a relying party that wants hardware-rooted evidence
does not get it from a `-01` receipt. Tracked at
[#28](https://github.com/wilder-robotics/pask-workspace/issues/28), which
carries the standing condition that if a later revision does not deliver
verifiable quotes, the language describing what a receipt is worth has to
change before the capability does.

### 2.2 No certificate supply-chain verification

Nothing validates an attestation certificate chain to a vendor root. The
configured root of trust can be self-signed.

### 2.3 Evidence metadata is not evidence verification

`platformEvidence` and `sealedEvidence` carry a digest, an encoding, and a
size. The implementation checks that these members are well-formed. It does
not obtain, parse, or verify the evidence they describe.

### 2.4 Measured boot is self-consistency only

`measuredBoot.chain` is checked for consistency against the component digests
listed beside it. It is not compared against any reference measurement, so a
self-consistent chain of arbitrary values passes.

### 2.5 There is no replay defence

Nothing in the wire format or the implementation prevents a well-formed
receipt from being presented again.

---

## 3. Timestamps and validity

`attestation.validity` is REQUIRED and carries `notBefore` and `notAfter`.
Both `pask-wire` and `pask-attest` require `notAfter` to be **strictly** later
than `notBefore`; an equal-instant interval is rejected by both. `-01` states
that rule normatively.

Neither crate tests a receipt's `ts` against its validity interval, and `-01`
does not require a Verifier to do so. A relying party that needs the receipt
timestamp to fall inside the attestation's validity window must enforce that
itself. Tracked at
[#30](https://github.com/wilder-robotics/pask-workspace/issues/30).

---

## 4. The TEE Class registry

`-01` requests an IANA registry seeded with `intel.tdx`, `amd.sev-snp`,
`arm.cca`, `nvidia.h100-cc`, `nvidia.jetson-thor-cc`, and `aws.nitro-enclave`.
**The registry does not exist and IANA has allocated nothing.** `-01` says so
in the document and specifies Specification Required as the registration
policy, so there is a defined route for a seventh value. There is no allocated
value to use today.

The implementation accepts exactly those six strings and rejects everything
else, including SKU-level and instruction-set-architecture names. An operator
whose confidential-compute environment is outside the six is excluded rather
than degraded.

The six sit at three different levels of abstraction, so the taxonomy is less
principled than a registry ought to be. Tracked at
[#29](https://github.com/wilder-robotics/pask-workspace/issues/29).

The `teeClass` values in the fixtures reflect a mapping choice, not measured
hardware. The reference site's fixtures use `arm.cca`.

---

## 5. What the reference producer simulates

The producer is a reference, not a deployment. Specifically:

- **Chain state is not produced.** `chain.prevHash` and `chain.seq` are not
  maintained against a persistent log.
- **Adapter acknowledgement is asserted before the adapter runs.** The
  `adapter.ackDigest` in a produced receipt does not attest that a downstream
  system accepted anything.
- **The evidence bundle is declarative.** It describes evidence rather than
  containing it.
- **Reference-site attestation values are stand-ins**, not measurements taken
  from a device.
- **Receipt identity collides on reissue.** Reissuing produces the same `id`.

---

## 6. Wire format and tooling

- **A supplied chain hash is silently replaced.** `pask-wire` recomputes
  `chain.hash` rather than rejecting a payload whose supplied value is wrong.
  A caller cannot use the library to detect a bad hash.
- **COSE content-type parsing mutates protected bytes.** Round-tripping is
  affected; see `crates/pask-wire/src/cose.rs`.
- **The command-line binary has no test that executes it.** The tests under
  `crates/pask-wire-cli/tests/` exercise the library and the document, not the
  binary's argument handling or output.
- **No conformance vectors are published.** `pask-conformance-vectors` does
  not exist. The canonical vector lives inside `pask-wire` as a Rust constant,
  so an independent implementer has no published vector set and must derive
  one from this source.

---

## 7. Adapters

- `WRITE_ONLY` is enforced at runtime, not guaranteed by the type system.
- Health checking reads the operations layer, so a healthy report does not
  establish that the write path works.
- The PropertyMeld adapter is a fail-closed stub.
- Local deduplication does not establish remote idempotency.
- Credentials can appear in debug output.

---

## 8. Verification maturity

Verification gates V1 through V5 are unmet. V1 requires the generated-figure
CI assertion to hold green for thirty consecutive days; its clock starts when
that assertion first lands on the default branch, which has not yet happened.

---

## 9. What would have to change before any production claim

Not a roadmap — a floor. At minimum: hardware-rooted evidence actually carried
and verified (§2), a published conformance vector set (§6), chain state
produced against a persistent log (§5), an allocated registry (§4), and V1
through V5 met (§8).

---

## Reporting

If you find a limitation that is not recorded here, please open an issue. An
inaccurate entry is worth reporting too — a limitations file that overstates
what is missing is as misleading as one that understates it.
