# pask-wire-cli

Command-line conformance tool for Physical-Site Engagement Receipts. Produce a receipt,
verify one you were sent, and emit the canonical example from the profile document.

The intended first use is checking your own encoder against this one without adopting
the library.

## Install

```
cargo install pask-wire-cli
```

## Commands

```
pask-wire-cli canonical-example
pask-wire-cli produce --input <payload.json> --private-key <key> --output <receipt>
pask-wire-cli verify  --input <receipt> --public-key <key> [--output <report>]
```

`canonical-example` writes the example instance embedded in the profile document to
standard output. The Internet-Draft's example figure is this output verbatim, and a test
asserts they are byte-identical, so it is the quickest way to confirm your encoder agrees
with the specification.

## Supported profile versions

`wilder.pser/0.5` and `wilder.pser/0.6`. The crate version tracks this tool's interface
and is independent of the profile version.

## Specification

<https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/>

An Internet-Draft is a work in progress. It is not a standard, and publication does not
imply IETF endorsement.

## What verification establishes

That the signer produced these bytes and they have not changed. It does not establish
that the described work physically happened, or that a party named as the source of a
recorded fact actually asserted it. Pushing a verified receipt into an operations system
is a separate decision with its own controls.

## License

Apache-2.0.
