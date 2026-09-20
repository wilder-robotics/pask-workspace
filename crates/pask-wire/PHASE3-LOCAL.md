# Bounded local recipient coordination

This is a local Phase 3 candidate on accepted Phase 2 tree
`810c6557a2c6ae8e1634c84e17319a4b53a5a2ea`, not a published API or issue closure.
Accepted inputs: `pask71_implementation_contract.md`, the detailed premerge
`PASK_71_CONTRACT.md` Phase 3, and September 19 authorization Track B.

## API and scope

`inspect_transparent_statement(bytes, policy)` checks the final transmitted outer
COSE_Sign1. `verify_transparent_statement(bytes, inputs, policy)` derives exact
`[P, {}, M, S]`, checks issuer Ed25519 independently, invokes preserved Phase 2 on
**every** encoded Receipt, and returns separate findings. It never uses the #70
strict extraction helper or the old issuer helper to silently coerce policy.
Existing Phase 1/2 modules, #70, core schemas and Cargo dependencies are unchanged.

Default outer cross-map strictness is off with protected precedence. Opt-in
strictness rejects all overlaps. Within-map duplicates, label-15 single occurrence,
required protected locations and critical semantics are separate gates. Receipt
containers must be nonempty arrays of encoded byte strings. An invalid encoded
Receipt is an indexed finding; a malformed enclosing array is an outer failure.
Both original outer bytes and each extracted encoded Receipt are preserved.

Registration evidence requires at least one Phase 2 acceptable Receipt and does
not hide any other outcome. Preserved Phase 2 still uses all supplied proofs
inside one Receipt as its LOCAL policy, not an RFC mandate. Only explicitly chosen
`require_all_receipts` makes extra unacceptable Receipts an application failure.

Issuer key, permitted algorithm, exact issuer binding, provenance, explicit
validity window, caller evaluation time and distrust are inputs. Signature and
association/trust are distinct. No network or live clock. External-origin enums
mean caller assertions, not independently authenticated provisioning observed
by this library. Local simulation never passes registration/application acceptance.
Expected SHA256 target (exact candidate or exact payload), value and provenance
are explicit inputs. Producer-copied digest equality is not authenticated origin.

## Named implemented policies

* `pask71-recipient-offline/1`: coordination and resource limits.
* `SubjectPolicy::SharedJsonSiteV1`: exact Receipt text subject, included protected
  statement text subject, and site.id extracted from original canonical JSON.
* `SubjectPolicy::AuthenticatedMappingV1`: at most 64 exact rows keyed by actual
  signed TS identity and Receipt subject, with explicit authenticated provenance.
  Missing evidence is unestablished; conflicting targets and contradictions fail.
* `StatementApplicationPolicy::SignedJsonSiteV1`: SOFTWARE-ONLY local convention,
  protected content type `application/json; profile=pask71-software-site/1`,
  canonical JSON nonempty site.id, valid text claims, issuer signature and trust,
  and at least one acceptable Receipt. Explicit knobs require optional subject,
  all-Receipts or authenticated expected-digest evidence. Absent policy means
  unestablished. Other declared versions are unsupported, never auto-selected.

Canonical JSON is compared with original bytes for context validity only. It never
replaces signature/inclusion input. Required text type failure remains visible
when semantic policy is absent. Legacy producer byte-string subjects are not cast
or re-signed. No TS/issuer identity equality or universal subject equality exists.

**Not implemented or claimed:** full PSER profile validation/acceptance, remedy of
legacy outer subject types, ES256 issuer coordination, ES256 TS, CCF, X.509 discovery,
hardware appraisal, physical truth, ROS/bridge parsing, independently authenticated
expected/key origins, external relying-party acceptance. `overall_profile` stays
unestablished and hardware appraisal stays not-evaluated. The software-only policy
is an explicitly bounded application implementation, not a bypass of PSER fields.

## Bounds and reproduction

Outer statement <= 1 MiB, protected <= 64 KiB, signature <= 1024 bytes, nesting
<=16, CBOR items <=4096 (outer plus embedded protected), maps <=64 entries, at most
8 Receipts. Statement size and raw CBOR budget precede allocating decode. The
attachment count is checked after bounded decode and before crypto. Total encoded
attachment contents cannot exceed the 1 MiB outer byte cap. No silent truncation.
Per-Receipt Phase 2 limits are unchanged, independently enforced and tightenable:
<=16 unique candidates, <=256 signature attempts. Whole-presentation ceiling is
8*256+1=2049 crypto attempts including issuer, with <=8*4096 additional Receipt
CBOR item budgets and <=8 repeated bounded statement preflights. Inputs remain
borrowed; trust/mapping fields are capped at 8192 bytes. These tighter Phase 3
limits are local implementation choices, not the older proposal's larger defaults.

From repository root, with offline dependencies already cached:

```sh
export CARGO_TARGET_DIR=/dev/shm/pask71-phase3-target
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=2
cargo test --offline --locked -p pask-wire --features alloc --test transparent_statement_phase3
cargo test --offline --locked -p pask-wire --all-features
cargo clippy --offline --locked -p pask-wire --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```

The fixture generator uses independent Python cbor2/hashlib/cryptography, no Rust
producer/verifier helpers, with public fixed software-test seeds. Test cases that
exercise CallerAuthenticatedExternal only model that assertion; they do not
establish real authentication. The recipient API itself needs public keys only.
