# pask-wire

Producer and verifier for Physical-Site Engagement Receipts: SCITT-style signed
statements that record work performed by an autonomous or human-directed actor at a
regulated physical site.

This crate is the reference implementation of the wire format. It builds a canonical
payload, signs it, and verifies a received receipt against the profile rules.

## Supported profile versions

| Profile | Constant | Content type |
| --- | --- | --- |
| `wilder.pser/0.5` | `SPEC_VERSION` | `application/pser+json; profile=wilder.pser/0.5` |
| `wilder.pser/0.6` | `SPEC_VERSION_06` | `application/pser+json; profile=wilder.pser/0.6` |

Both are accepted on verification. The crate version tracks this crate's Rust API and
is deliberately independent of the profile version, because more than one profile
version is supported at a time.

## Specification

The profile is specified in `draft-wilder-scitt-physical-site-engage-receipt`, an
Internet-Draft published through the IETF Datatracker:
<https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/>

An Internet-Draft is a work in progress. It is not a standard, and publication does not
imply IETF endorsement.

The canonical example figure in the draft is emitted verbatim by `pask-wire-cli`, and a
test asserts the two are byte-identical.

## Install

```
cargo add pask-wire
```

`#![no_std]` with `default = []`. Enable `alloc` for the producer and verifier, or `std`
for the standard-library integration.

## What a receipt does and does not establish

A verified receipt establishes that the signer produced this payload and that the bytes
have not changed since. It does not establish that a described event physically
happened, and it does not establish that a party named as the source of a recorded fact
actually asserted or sensed it. Authenticated actor identity, hardware custody, and the
independence of a Transparency Service are separate mechanisms and are not provided by
this crate.

## License

Apache-2.0. No commercial agreement is required to use, modify, or redistribute it.
