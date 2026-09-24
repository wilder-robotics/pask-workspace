# pask-wire

Producer and verifier for Physical-Site Engagement Receipts: SCITT-style signed
statements that record work performed by an autonomous or human-directed actor at a
regulated physical site.

This crate is the reference implementation of the wire format. It builds a canonical
payload, signs it, and implements specified processing for supported profile
identifiers. This is not complete profile certification; conformance and
assurance gaps remain documented in the repository's KNOWN-LIMITATIONS.md.

## Names and versions

Pask is the software family for working with Physical-Site Engagement Receipts (PSER).
The `wilder.pser/<version>` identifier names the profile a receipt declares; the `pask-*`
names identify software packages. Package versions, profile versions, and Internet-Draft
revision numbers are three separate things and are versioned independently. Passing this
crate's checks does not establish complete profile conformance, and it does not establish
the truth of a physical-world claim.

## Supported profile versions

| Profile | Constant | Content type |
| --- | --- | --- |
| `wilder.pser/0.5` | `SPEC_VERSION` | `application/pser+json; profile=wilder.pser/0.5` |
| `wilder.pser/0.6` | `SPEC_VERSION_06` | `application/pser+json; profile=wilder.pser/0.6` |

Both identifiers are supported for the implemented checks. Crate versions describe
software releases and compatibility; they are independent of profile versions because
one software release can support more than one profile.

## Specification

The profile is specified in `draft-wilder-scitt-physical-site-engage-receipt`, an
Internet-Draft published through the IETF Datatracker:
<https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/>

An Internet-Draft is a work in progress. It is not a standard, and publication does not
imply IETF endorsement.

The posted -04 figure uses `pask_wire::canonical_example_06()`, checked by a
workspace document test. `pask-wire-cli canonical-example` continues to emit the
legacy 0.5 generator's output; these are distinct tests and outputs.

## Current source evaluation

From a checkout, run `cargo test --locked -p pask-wire --features alloc`.
For a local consumer, use a path dependency with `features = ["alloc"]`.
Registry installation below is prospective, after authorized publication:

```
cargo add pask-wire@0.1.0 --features alloc
```

`#![no_std]` with `default = []`, so the example above enables `alloc` for the
producer and verifier APIs. Use `std` for standard-library integration. ECDSA
P-256 signing and verification are optional and enabled by `es256`.

## What a receipt does and does not establish

Successful signature verification establishes validity under the supplied key,
not authenticated ownership of that key by a named organization or actor.
It does not establish that a described event physically
happened, and it does not establish that a party named as the source of a recorded fact
actually asserted or sensed it. Authenticated actor identity, hardware custody, and the
independence of a Transparency Service are separate mechanisms and are not provided by
this crate.

## License

Apache-2.0. No commercial agreement is required to use, modify, or redistribute it.
