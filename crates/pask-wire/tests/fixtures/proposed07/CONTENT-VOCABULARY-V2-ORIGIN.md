# Packaged copy of the v2 vocabulary candidate: origin and license

`content-vocabulary-v2-candidate.json` in this directory is a byte-for-byte
copy of the repository artifact
`schemas/proposed/pser-0.7/content-vocabulary-v2-candidate.json`
(identifier `wilder.pser-content-vocab/2`), SHA-256

    2fb4e3a099003638d318333dee66fe2b710fb39b6dec78f570f6ecf31592a248

It exists so that the `pask-wire` package archive carries the input of
`tests/proposed_vocabulary_v2.rs` (`exact_v2_json_hash_matches_the_compiled_table`)
instead of reaching outside the package for a repository-only path. The
original under `schemas/proposed/pser-0.7/` remains the authoritative source
for `tools/proposed07/generate_vocabularies.py` and `vocabulary_profiles.json`;
nothing is generated from this copy.

Two checks keep the copy from drifting: `tools/proposed07/test_vocabularies.py`
asserts byte equality with the original, and the Rust test asserts the digest
above against the compiled `Vocabulary::V2` table. Do not reformat, normalize or
edit this file; replace it only together with the original and its recorded
digest.

License: this exact byte stream is covered by the artifact-specific Apache-2.0
grant recorded at `schemas/proposed/pser-0.7/LICENSE-NOTE.md`, with provenance
and history in `schemas/proposed/pser-0.7/ORIGIN-V2.md` (and `ORIGIN.md` for the
v1 vocabulary it extends), all at the repository root of
<https://github.com/wilder-robotics/pask-workspace>. That grant names this
digest. The copy relies on that existing authorization only; it grants no new
directory-wide rights, imports no private record, and does not change the
Apache-2.0 license of the `pask-wire` package (see `LICENSE` in the package
root). Preserve legitimate third-party notices and flag contrary provenance
evidence if found.
