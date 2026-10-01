# Local vocabulary v2 candidate: origin and distribution boundary

This file accompanies `content-vocabulary-v2-candidate.json`, identifier
`wilder.pser-content-vocab/2`. It does not change the PSER profile version.

The candidate is the exact accepted v1 vocabulary with only its version identifier
changed and the reviewed `site.pose` r2 row appended. The original JSON, migration
script, rule evidence and generated v1 table are retained byte-identically. The
row's `_status` and `_requires` review annotations are excluded from the vocabulary;
the input row is retained verbatim in the private delivery.

The accepted vocabulary's recorded distribution basis remains unresolved (see
`ORIGIN.md`). This candidate and its generated table inherit that limitation.
The new generated Rust table is not stamped with an invented Apache-2.0 permission.
A successful private test or a new digest does not establish public distribution
rights. The unchanged license guard is expected to flag both generated tables.

Generation and native classification are separate checks. The fixed expectations
are 47 facts, 200 per-fact combinations, 160 after global rules and 157 after
forbidden pairs: 157 permitted and 830 forbidden across 987 combinations. The
first 966 expected rows remain exactly the v1 relation; 21 pose rows are appended.

The exact source digest is recorded in
`tools/proposed07/vocabulary_profiles.json`. Runtime selection uses that committed
digest, never the display version string, a fact name or a caller's default table.
