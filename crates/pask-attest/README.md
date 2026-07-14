# pask-attest

`pask-attest` verifies framed, signed TEE attestation quotes and exposes their claims through typed values. An `Attestation` can only be produced by a successful verifier call: callers cannot construct or deserialize one directly, and `TeeClass` restricts receipt claims to the supported category-level profiles.

Create an `Ed25519RootOfTrust`, add each trusted witness-key identifier and verifying key with `with_key`, then pass an opaque quote and an injected `Clock` to `AttestationVerifier::verify`. The verifier checks framing, the canonical JSON signature, measured-boot binding, claim encodings, and the validity window before it returns an `Attestation`.
