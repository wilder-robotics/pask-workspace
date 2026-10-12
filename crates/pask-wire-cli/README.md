# pask-wire-cli

Apache-2.0 command-line producer and supplied-key verifier for Pask statements.
The executable is `pask-wire-cli`. It supports implemented processing for
`wilder.pser/0.5`, `wilder.pser/0.6` and `wilder.pser/0.7`, not complete profile
certification.

## Releases and evaluation

`pask-wire-cli` 0.1.0 is the historical first release on crates.io. It was built
on `pask-wire` 0.1.0 and handles the 0.5 and 0.6 profiles only.

This source is prepared as `pask-wire-cli` 0.2.0 on `pask-wire` 0.2.0, which adds
0.7 processing. Once that exact version has been published, it installs with:

```sh
cargo install pask-wire-cli --version 0.2.0 --locked
```

Until then, evaluate from a checkout of the reviewed source, with Rust stable
(declared minimum 1.88):

```sh
cargo run --locked -p pask-wire-cli -- --help
cargo run --locked -p pask-wire-cli -- canonical-example
cargo install --locked --path crates/pask-wire-cli --root ./local-install
./local-install/bin/pask-wire-cli --help
```

## Commands and formats

```text
pask-wire-cli canonical-example
pask-wire-cli produce --input payload.json --private-key private.pem --output statement.cbor
pask-wire-cli verify --input statement.cbor --public-key public.pem --output payload.json
```

The private key is an Ed25519 PKCS#8 PEM (`PRIVATE KEY`). The public key is
Ed25519 SubjectPublicKeyInfo PEM (`PUBLIC KEY`), not an SSH public-key line.
`verify` writes canonical verified payload JSON to stdout or `--output`.
It does not output the full recipient coordinator report, automatically verify
attached SCITT Receipts, or establish a presented chain's contiguity.

`canonical-example` deliberately emits the legacy 0.5 example, byte for byte,
and a packaged test pins that output. The historical -04/0.6 figure used
`pask_wire::canonical_example_06()`. The current in-tree draft figure uses
`pask_wire::canonical_example_07()` and is checked by repository-only document
tests. The portable packaged test separately validates the legacy and 0.7
emitters; it does not compare the historical -04 document. No profile-selection
option is provided: the profile a statement carries is the `spec` of the
payload given to `produce`.

## Producing and verifying a 0.7 statement

The CLI has no 0.7 subcommand. A 0.7 statement is produced from a 0.7 input:
a payload whose `spec` is `wilder.pser/0.7` and whose `engagement` carries an
explicit `contentDigest` member. The package includes tests for the 0.7
emitter, the `produce`/`verify` path and specified rejection cases in
`tests/canonical_examples_are_valid_payloads.rs`. Those tests use public
Ed25519 example keys; they do not execute the OpenSSL or shell commands below.
Use freshly generated keys for your own trials.

For checkout-only evaluation after the local installation above, use
`./local-install/bin/pask-wire-cli` in place of the bare `pask-wire-cli`
commands below. After registry installation, ensure Cargo's binary directory
is on `PATH`.

1. Keys. An Ed25519 PKCS#8 private key and its SubjectPublicKeyInfo public key,
   for example with OpenSSL:

   ```sh
   openssl genpkey -algorithm ed25519 -out private.pem
   openssl pkey -in private.pem -pubout -out public.pem
   ```

2. Input. Start from the 0.7 canonical example, which commits to no retained
   content (`"contentDigest": null`). From a checkout:

   ```sh
   cargo run --locked -p pask-wire --features alloc --example draft07_payload > payload-07.json
   ```

   Its `engagement` object contains `"contentDigest": null` and its `spec` is
   `"wilder.pser/0.7"`. The producer still applies its normal value and
   cross-field validation; a matching JSON shape alone is insufficient.

3. Produce and verify under the supplied key:

   ```sh
   pask-wire-cli produce --input payload-07.json --private-key private.pem --output statement-07.cbor
   pask-wire-cli verify  --input statement-07.cbor --public-key public.pem
   ```

   `verify` exits 0 and prints the canonical payload: `"spec":"wilder.pser/0.7"`
   with `"contentDigest":null` present under `engagement`. The statement's
   protected header carries `application/pser+json; profile=wilder.pser/0.7` and a
   text CWT `sub` claim, as the 0.7 profile requires (0.5 and 0.6 statements carry
   a byte-string `sub`).

4. Committing to retained content. Replace the `null` with a `sha256:` digest of
   64 lowercase hexadecimal digits, for example
   `"contentDigest": "sha256:abababab…ab"`; `produce` then recomputes `chain.hash`
   and `verify` returns the same digest string. This value is a **syntactic
   commitment placeholder**: `produce` and `verify` check its form only. Neither
   command retrieves, stores, or checks any content block, so a digest in a
   verified payload is not evidence that retained content exists or was examined.
   Retained-content checks are a separate, offline `pask-wire` library operation.

Runtime rejections on this path:

| Input | Result |
| --- | --- |
| `verify` with a public key that did not sign the statement | exit 1, `receipt verification failed … signature error` |
| 0.7 payload with `contentDigest` omitted | exit 1, `0.7 requires explicit null or SHA-256 contentDigest` |
| 0.7 payload with a `sha-256:` or other prefix | exit 1, `digest prefix must be sha256:` |
| 0.5 or 0.6 payload carrying `contentDigest` | exit 1, `contentDigest is not permitted in legacy profiles` |

## Verification boundary

Success checks the statement signature under the caller-supplied Ed25519 key
and the implemented payload checks for the declared profile. It does not
authenticate the named organization or actor, establish physical truth, key
hardware custody, or Transparency Service independence. It performs no
retained-content check, registration verification, or hardware-evidence
appraisal; the library's layered Receipt-validation and content APIs are
separate from this CLI path. Legacy outer-subject typing and other known
conformance limits remain disclosed in the repository's
[KNOWN-LIMITATIONS](https://github.com/wilder-robotics/pask-workspace/blob/main/KNOWN-LIMITATIONS.md).

Crate semver, supported profile identifiers and draft revision are separate.
The [posted -04 draft](https://datatracker.ietf.org/doc/draft-wilder-scitt-physical-site-engage-receipt/04/)
is an Internet-Draft, not an IETF standard or endorsement.

## Packaged tests

The package archive carries `tests/cli_binary.rs`, `tests/release_cli_contract.rs`
and `tests/canonical_examples_are_valid_payloads.rs`, which run against the built
executable with no files outside the archive. `tests/draft_example_is_generated.rs`
and `tests/draft_examples_are_validated.rs` compare the emitters with the
Internet-Draft and vocabulary files at the repository root; they stay in the
repository and in workspace CI but are excluded from the archive.

## License

Apache-2.0. The separate `pask-adapt` operational binary remains AGPL-3.0-only.
