# pask-workspace

Cargo workspace for the production Rust implementation of Pask, a SCITT-based
system for producing tamper-evident, TEE-anchored receipts of physical work
performed by autonomous or human-directed actors at regulated real-world
sites.

## What lives here

This repository is the code home for the reference producer and verifier of
**Physical-Site Engagement Receipts** as defined in
[`docs/draft-wilder-scitt-physical-site-engagement-receipt-00.md`](docs/draft-wilder-scitt-physical-site-engagement-receipt-00.md).

Physical-Site Engagement Receipts are a profile of the IETF SCITT
architecture ([RFC 9943](https://datatracker.ietf.org/doc/rfc9943/)) that
uses [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html) COSE Receipts
to carry a five-artifact vocabulary (Site, Actor, Engagement, Attestation,
Adapter Write-In) describing what physically occurred at a specific site,
under what operating envelope, and whether the resulting receipt was
posted into the operations layer the site already runs.

## Repository layout (initial scaffold)

```
pask-workspace/
├── docs/
│   └── draft-wilder-scitt-physical-site-engagement-receipt-00.md   ← authoritative spec
├── .github/workflows/ci.yml                                        ← CI (Rust)
├── LICENSE                                                         ← AGPL-3.0-only
├── COMMERCIAL-EXCEPTION.md                                         ← commercial licensing terms
├── CODEOWNERS
└── README.md
```

Rust crates (`crates/pask-wire`, `crates/pask-wire-cli`, etc.) are added in
later commits per the ticket queue.

## License

Licensed under [AGPL-3.0-only](LICENSE) with a commercial exception. See
[COMMERCIAL-EXCEPTION.md](COMMERCIAL-EXCEPTION.md) for the terms under which
Wilder Robotics grants a commercial license outside the AGPL's
network-copyleft obligations.

## Trust model

The trust model that this codebase implements is deliberately three-party
and non-collapsible:

- The **site owner** physically hosts and controls the appliance. They can
  power it off; they cannot extract the signing key or forge signatures.
- The **TEE silicon vendor** attests, through a hardware root of trust,
  that the signing key lives inside a specific measured platform.
- **Pask** writes the vocabulary (this profile), operates the Issuer and
  Transparency Service, and performs the WRITE_ONLY adapter push into the
  operations layer the customer already uses.

No single party can unilaterally forge, backdate, or repudiate a receipt.
See §Security Considerations of the profile draft for the full model.

## Status

Pre-alpha. This is a spec-conformance library under active development. No
production-readiness claims. No safety, insurance, or regulatory-compliance
claims. Test vectors, unit tests, and CI-verified conformance to the
embedded specification only.

## Contact

Rob Wilder — rob@wilder-robotics.com
