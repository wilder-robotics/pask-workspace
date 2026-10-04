# Local `site.pose` v2 candidate: author decisions and exact scope

Status: proposed local implementation for native review. This is not a frozen
0.7 encoding, an IETF submission, a public release, or new evidence of location.
The accepted source baseline is `96e12a4a10c03df2694f1ac27d73014416e2c861`.

## Representation

The supplied r2 row is retained without semantic edits (review-only `_status` and
`_requires` members are not part of the vocabulary). The candidate adds one
position-only observation, not heading, speed, trajectory or orientation.
All eight value members are required; height, accuracy and observedAt alone are
nullable. The `value` object is closed, not the historical outer fact wrapper.

- `crs`: `EPSG:4979`. The scaled encoding references this CRS: degrees = E7 / 10^7,
  ellipsoidal metres = heightMm / 1000. No WGS84 realization or transform supplied.
- `referencePoint`: 1–64 characters from the specified ASCII identifier pattern.
  The recipient does not resolve its definition in the retained envelope.
- `latE7`: integer -900000000 through 900000000, inclusive.
- `lonE7`: integer -1800000000 through 1799999999, inclusive.
- `heightMm`: null or integer -20000000 through 100000000.
- `horizontalAccuracyMm`: null or integer 0 through 100000000.
- `observedAt`: null or the existing exact 24-character millisecond-UTC shape.
- `latLonDerivation`: exact-integer-rescaling or rounded-half-even-to-1e-7-deg.

Height and accuracy ranges are chosen support limits, not physical validity rules.
Null height means no ellipsoidal height asserted; no 3D position or zero follows.
A sea-level or other-datum value cannot be relabeled as ellipsoid height. Unknown
is null, never a fabricated zero. Numerical resolution is not source accuracy.
The accuracy figure is uninterpreted source metadata, not a normalized confidence
radius or policy pass. All populated fields refer to one source sample/reference
point; component selection/conversion is the producer's responsibility.

## H1: exact-only millimetres (option b)

Keep the small row rather than add height/accuracy derivation enums. Any in-scope,
coherent populated height/accuracy value must rescale exactly to integer mm and be
inside the supported range. 12.345 m and 12.3450 m are exactly 12345 mm;
12.3456 m is not. Do not silently round, clamp or turn such a known unsupported
measurement into null. Do not emit that candidate pose; retain the raw source and
record the not-representable condition in the local acquisition/mapping record.

This differs from actual missing data, a different-datum height, or accuracy from
another sample: those do not supply the asserted member, so null is appropriate
with the original information and reason retained. None is physical absence.

## T1: retain exact millisecond form; do not lose time precision silently

Do not expand the shared timestamp matcher or claim a new date/time validator.
A source instant exactly expressible in UTC milliseconds can be represented
without loss (whole seconds add .000; .123000 has the same value as .123).
A source instant with nonzero sub-millisecond precision, an unknown UTC offset,
or an unapplied non-UTC timescale is not asserted here: use observedAt null and
retain the raw time and the reason in the local mapping record. Never truncate or
round it, nor substitute receipt ts, acquisition time or registration time.

Null means no source instant asserted in this member, not no timestamp at source.
The shared lexical matcher still accepts calendar-impossible date strings with
the prescribed shape. Passing it is not calendar validity or authenticated time.

## Producer-side arithmetic versus implemented validation

The contract's angular rule remains exact decimal arithmetic before commitment:
reject source latitude outside [-90,90] or longitude outside [-180,180] before
rounding, scale by 10^7, round half-even symmetrically when needed, write zero
without a sign, and normalize +180 degrees to -180. The derivation flag applies
only to the horizontal pair. No decoding or verifier step rewrites committed bytes.

**This increment does not add a navigation-source converter.** H1, T1, coherence
and angular conversion are producer-conformance rules, not new executed Rust
conversion checks. Author-side decimal examples are labeled as such in the
delivery. Typed Rust tests validate the resulting representation, not the source
transformation. A signed claim about derivation can be false; the current scalar
comparator cannot appraise this compound position object.

## D1–D4 implementation

D1: the v2 generation path validates a finite schema dialect and permits only
additionalProperties=false on object schemas. Runtime closed-object behavior is
opt-in for v2. The old v1 schemas, code path and open-object behavior remain.
No property is dropped to satisfy validation. Unknown outer fact fields remain
subject to the historical fact budget; this is not a closed fact-wrapper change.

D2: `vocabulary_for_digest` selects a table from the proof-bound content header's
exact full digest. The same handle controls classification, values, evidence and
remote rules, units, required-name checks, and table-identifying report code.
Unknown digests never guess a table from `version`, field names or a default.
Legacy classify/inspect_fact/report_json retain v1 semantics.

Policy configuration still rejects duplicates, excessive input and names unknown
to every compiled table. Names recognized by either table (including site.pose)
are accepted at configuration time and evaluated per block. After proof and table
selection, a requested name absent from that table gives
`UNSUPPORTED_BY_VOCABULARY`, null fact-provenance classification, semantic absence
false, and unestablished disclosure policy. It is not `FACT_UNAVAILABLE` as a claim
of absence, nor `ATTRIBUTION_FORBIDDEN`, nor globally satisfied merely by spelling.

A v2 subset withholding pose instead gives NOT_DISCLOSED_UNPROVEN; a complete v2
block without pose gives ABSENT_FROM_COMMITTED_BLOCK. Unknown/unbound vocabularies
leave required-name evaluation unestablished. Null commitments retain their own
no-block result. A mixed replay batch selects independently for every entry; chain
link checks remain a distinct result.

D3: original migration/generation scripts and v1 artifacts are byte-identical.
New reusable generation has per-profile fixed source/expected-table hashes and
counts, and checks explicit relation rows. It reproduces v1 exactly without
applying the v2 dialect to it. Equal counts alone do not prove equal rules.

D4: v2 is a separate file, identifier and digest. It contains only the new version
identifier and appended r2 row over v1; its origin/distribution hold is unchanged.
It does not bump the PSER profile or the released crate version.

## Outcomes that must remain separate

Membership, attribution/basis permission, valid metadata, raw evidence integrity,
value agreement, named-party authenticity and application acceptance are distinct.
A proved pose with extra fields can have valid membership and invalid_typed_value.
A platform estimate is forbidden, not an unknown vocabulary. Evidence-linked pose
bytes still compare NOT_COMPARABLE with the current unitless-scalar comparator;
comparison off remains NOT_RUN. Evidence requirements for appliance-measured remain.

No robot-key binding, hardware assurance, geometry containment, fresh clock,
independent operator, no-withheld-history guarantee or location truth is added.
Disclosure exposes the complete pose fact at its committed precision, not chosen
members of the object. One site.pose per block; no series is invented.
