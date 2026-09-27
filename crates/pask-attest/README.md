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

## Current source evaluation

From a checkout, run `cargo test --locked -p pask-attest --all-features`.
For a local consumer use a path dependency on `crates/pask-attest`; it depends on
the sibling `pask-wire` crate. Registry installation below is prospective,
after authorized publication:

```
cargo add pask-attest@0.1.0
```

## License

Apache-2.0. No commercial agreement is required to use, modify, or redistribute it.
