# pask-attest

`pask-attest` verifies Pask's framed `wilder.attest/0.1` canonical JSON using caller-configured Ed25519 keys and exposes its checked claims through typed values. It is not a general verifier for vendor-native hardware Evidence. A TEE class field does not supply that capability. An `Attestation` can only be produced by a successful verifier call: callers cannot construct or deserialize one directly.

Create an `Ed25519RootOfTrust`, add each trusted witness-key identifier and verifying key with `with_key`, then pass an opaque quote and an injected `Clock` to `AttestationVerifier::verify`. The verifier checks framing, the canonical JSON signature, measured-boot binding, claim encodings, and the validity window before it returns an `Attestation`.

## Scope

`pask-attest` checks that a framed attestation quote verifies against a configured root
of trust and that its claims decode into the supported category-level profiles. It does
not establish hardware custody, and it does not establish that the platform presenting a
quote is the platform that performed the described work. Those are separate mechanisms
and are outside this crate.

`pask-attest` is a software package name. `wilder.pser/<version>` names the receipt
profile that consumes these claims, and the two are versioned separately. This crate
verifies its own supported framed attestation representation; it does not implement the
receipt profile itself.

## Specification

The receipt profile that consumes these claims is specified in
`draft-wilder-scitt-physical-site-engage-receipt`:
<https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/>

An Internet-Draft is a work in progress. It is not a standard, and publication does not
imply IETF endorsement.

## What verification does and does not establish

These are distinct operations, and passing one does not imply another:

- **Supplied-key quote verification** is implemented: the framed `wilder.attest/0.1`
  canonical JSON is checked against the Ed25519 keys the caller placed in an
  `Ed25519RootOfTrust`, and the measured-boot binding, claim encodings and validity
  window are checked before an `Attestation` is returned. Success establishes that
  the quote verifies under a configured key, not who controls that key.
- **Platform-evidence appraisal is not implemented.** `PlatformEvidence` and
  `SealedEvidence` are digest-addressed opaque objects: the crate validates the
  `sha256:` digest syntax and the `opaque/1` encoding label. It does not parse,
  retrieve, or appraise vendor-native hardware evidence, and a `TeeClass` value does
  not supply that capability. Hardware custody is not established.
- **Receipt processing** (statement signature verification, retained-content checks
  and registration verification) belongs to `pask-wire`, not to this crate.
- **Full PSER or SCITT conformance** is not established by this crate. Remaining gaps
  are recorded in the repository's KNOWN-LIMITATIONS.md.

## Releases and evaluation

`pask-attest` 0.1.0 is the historical first release on crates.io; it depends on
`pask-wire` 0.1.0.

This source is prepared as `pask-attest` 0.2.0, which depends on `pask-wire` 0.2.0.
Once that exact version has been published, it installs with:

```
cargo add pask-attest@0.2.0
```

Until then, evaluate from a checkout with
`cargo test --locked -p pask-attest --all-features`, or use a path dependency on
`crates/pask-attest`; it depends on the sibling `pask-wire` crate. The minimum
supported Rust version is 1.88.

## License

Apache-2.0. No commercial agreement is required to use, modify, or redistribute it.
