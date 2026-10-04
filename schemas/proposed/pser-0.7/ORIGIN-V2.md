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

## 2026-10-01 addendum: artifact-specific Apache-2.0 promotion

On 2026-10-01 at 9:01 PM CDT (2026-10-02 02:01 UTC), Rob Wilder authorized
artifact-specific promotion of the five artifacts below into the Pask
interoperability implementation under Apache-2.0, **for the rights Rob Wilder and
Wilder Management Inc. control**. The authority is
`VOCABULARY_PROMOTION_DECISION_2026-10-01.md` in the private project record
(SHA-256 `fc5ac943b0336d1bb6fa39be90fdd6bca243dc136ac85bd23b15aa4db4d9b4f1`),
accepting the proposal with SHA-256
`0e66849396d779f9ec7aee7eb5f54ce97b63e3b5e90bcf47b2625c9afb3c461a`.

**Historical licensing hold superseded on 2026-10-01.** The earlier statements
that the distribution basis is unresolved, that this candidate inherits that
limitation, that the generated table lacks an authorized Apache-2.0 header, and
that the unchanged guard is expected to flag both tables are superseded for the
five artifacts and controlled rights identified here. They remain above as
history; a private test or a new digest still does not grant distribution rights.
The earlier byte-identical v1-table statement describes the pre-header historical
baseline; current licensed output has only the single added comment described
below. Vocabulary contents, counts and classification expectations are unchanged.

### Exact identities covered by the decision

| Artifact | SHA-256 at authorization |
|---|---|
| Original technical vocabulary, private `wilder-robotics/pask-tournament` commit `844bf9b0032972b17a1725f3598f92ce21567b8e`, `rounds/01/content-block/schema/vocab.json` | `e8c1a2c028114c82523514e4aab686692d2c9409ed343467ef6c6ba070adf0b0` |
| `schemas/proposed/pser-0.7/content-vocabulary.json` | `030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d` |
| `schemas/proposed/pser-0.7/content-vocabulary-v2-candidate.json` | `2fb4e3a099003638d318333dee66fe2b710fb39b6dec78f570f6ecf31592a248` |
| `crates/pask-wire/src/proposed_vocabulary_generated.rs` (pre-header) | `cb13b49683ad62e6345dda82e056403306998ba9dd295570f3edcf227e396cf9` |
| `crates/pask-wire/src/proposed_vocabulary_v2_generated.rs` (pre-header) | `d2d9aacc57ad1718127569f363bdb8447902f091ce5d2cc1ea7f7c6876a56af7` |

The original-source identity is retained provenance, not a claim that its bytes
were fetched again for this addendum. The Rust hashes identify the authorized
pre-header bytes, not the current licensed outputs.

### Scope and exclusions

Preserve all legitimate third-party notices and flag contrary provenance evidence
if found. The earlier absence of LICENSE, COPYING or NOTICE in the inspected
source inventory is not proof of exclusive ownership. The unrelated
`crates/pask-wire/THIRD-PARTY-NOTICES.txt` (fluent-uri) is unchanged.

This decision grants no rights to ISO material and does not promote the
surrounding private repository, evaluations or evidence. It permits preparing
these definitions for eventual IETF contribution under the applicable IETF Trust
terms; it does not replace those terms with an Apache-only restriction.

This is the actual dated licensing authorization, not DCO certification or a
public-action approval. Public push, PR, merge, registry release and IETF filing
remain separate decisions by Rob.

### Licensed generation and preserved history

Both JSON files remain byte-identical at the hashes above. Their adjacent grant
is recorded in [LICENSE-NOTE.md](LICENSE-NOTE.md). No rule, fixture, expected
relation, profile source hash or license-guard rule changes.

`tools/proposed07/generate.py` remains frozen for historical pre-header v1
reproduction. The current licensed path is
`python3 tools/proposed07/generate_vocabularies.py --write`; use `--check` to verify
committed output. It uses `vocabulary_codegen.py` for both profiles and adds
exactly one `// SPDX-License-Identifier: Apache-2.0` line after the existing
"Generated by" line. Every other generated byte, including both `VOCAB_SHA256`
constants, is preserved. The v1 `generate.py` attribution remains historical
provenance, not an instruction to regenerate the current licensed file with that
frozen script. `test_vocabularies.py` separately pins the two historical
pre-header byte streams and the two current licensed outputs.
