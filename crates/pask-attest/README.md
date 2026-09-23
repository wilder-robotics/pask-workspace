# pask-attest

`pask-attest` verifies framed, signed TEE attestation quotes and exposes their claims through typed values. An `Attestation` can only be produced by a successful verifier call: callers cannot construct or deserialize one directly, and `TeeClass` restricts receipt claims to the supported category-level profiles.

Create an `Ed25519RootOfTrust`, add each trusted witness-key identifier and verifying key with `with_key`, then pass an opaque quote and an injected `Clock` to `AttestationVerifier::verify`. The verifier checks framing, the canonical JSON signature, measured-boot binding, claim encodings, and the validity window before it returns an `Attestation`.

## Scope

`pask-attest` checks that a framed attestation quote verifies against a configured root
of trust and that its claims decode into the supported category-level profiles. It does
not establish hardware custody, and it does not establish that the platform presenting a
quote is the platform that performed the described work. Those are separate mechanisms
and are outside this crate.

## Specification

The receipt profile that consumes these claims is specified in
`draft-wilder-scitt-physical-site-engage-receipt`:
<https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/>

An Internet-Draft is a work in progress. It is not a standard, and publication does not
imply IETF endorsement.

## Install

```
cargo add pask-attest
```

## License

Apache-2.0. No commercial agreement is required to use, modify, or redistribute it.
