#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local recipient-composition vectors. No Rust or network execution.

The immutable content framing is computed by the unchanged Python CONTENT-01
oracle. Expected report projections are explicit scenario expectations, NOT
native results or an independent implementation of the whole recipient.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import content_vectors
import rfc8785


def digest(b: bytes) -> str:
    return 'sha256:' + hashlib.sha256(b).hexdigest()


def fixture() -> dict:
    cases = []

    def row(name, fact, raw, expected, *, actual=None, pointer=None,
            state='bytes', include_reference=True, unit_marker=None):
        f = dict(fact)
        objects = []
        if pointer is not None:
            f['evidence'] = {'pointer': pointer}
        elif include_reference:
            f['evidence'] = {'digest': digest(raw)}
            if state != 'not_presented':
                objects = [{'digest': digest(raw), 'state': state,
                            'bytes_hex': (raw if actual is None else actual).hex()}]
        if unit_marker is not None:
            f['unit'] = unit_marker
        material = content_vectors.material([{'fact': f, 'salt_hex': '51' * 32}])
        cases.append({'id': name, 'material': material, 'objects': objects,
                      'expected': expected})

    def expected(provenance, integrity, comparison, *, metadata=0, forbidden=0):
        return {'state': 'ALL_COMMITTED_SLOTS', 'statement': 'passed', 'membership': 'passed',
                'binding': 'passed', 'vocabulary': 'passed', 'provenance': provenance,
                'integrity': integrity, 'comparison': comparison,
                'invalid_metadata': metadata, 'forbidden': forbidden,
                'contradictions': int(comparison == 'CONTRADICTION')}

    def model(v='Alpha'):
        return {'name': 'unit.model', 'assertedBy': 'site-policy', 'basis': 'declared', 'value': v}

    row('same-bytes-same-value', model(), b'"Alpha"', expected('EVIDENCE_LINKED','MATCHED','MATCH'))
    row('same-bytes-contradictory-value', model(), b'"Beta"', expected('EVIDENCE_LINKED','MATCHED','CONTRADICTION'))
    row('different-bytes-equal-value', model(), b'"Alpha" ', expected(None,'MISMATCH','NOT_RUN'), actual=b'"Alpha"')
    row('not-presented', model(), b'"Alpha"', expected('ATTRIBUTION_ONLY','BYTES_UNAVAILABLE','NOT_RUN'), state='not_presented')
    row('not-requested', model(), b'"Alpha"', expected('ATTRIBUTION_ONLY','NOT_REQUESTED','NOT_RUN'), state='not_requested')
    row('unavailable', model(), b'"Alpha"', expected('ATTRIBUTION_ONLY','BYTES_UNAVAILABLE','NOT_RUN'), state='unavailable')
    row('no-reference', model(), b'', expected('ATTRIBUTION_ONLY','NO_REFERENCE','NOT_RUN'), include_reference=False)
    row('pointer-only', model(), b'', expected('ATTRIBUTION_ONLY','DIGEST_BINDING_UNAVAILABLE','NOT_RUN'), pointer='opaque:local-locator')
    row('empty-presented-object', model(), b'', expected('EVIDENCE_LINKED','MATCHED','NOT_COMPARABLE'))
    row('compound-is-not-a-scalar', model(), b'{"value":"Alpha"}', expected('EVIDENCE_LINKED','MATCHED','NOT_COMPARABLE'))
    row('scalar-type-mismatch', model(), b'1', expected('EVIDENCE_LINKED','MATCHED','NOT_COMPARABLE'))
    row('malformed-unit', model(), b'"Alpha"', expected(None,'MATCHED','NOT_RUN',metadata=1), unit_marker=42)
    row('malformed-value', model(True), b'true', expected(None,'MATCHED','NOT_RUN',metadata=1))
    row('forbidden-but-linked', {'name':'limits.rated-force','assertedBy':'robot-attributed','basis':'measured','value':50},
        b'50', expected('ATTRIBUTION_FORBIDDEN','MATCHED','NOT_COMPARABLE',forbidden=1))
    row('implicit-unit-not-unitless', {'name':'limits.rated-force','assertedBy':'manufacturer-declared','basis':'declared','value':50},
        b'50', expected('EVIDENCE_LINKED','MATCHED','NOT_COMPARABLE'))
    row('negative-zero-is-zero', {'name':'outcome.severity-grade','assertedBy':'operator-entered','basis':'declared','value':0},
        b'-0', expected('EVIDENCE_LINKED','MATCHED','MATCH'))
    row('negative-zero-wrong-raw-bytes', {'name':'outcome.severity-grade','assertedBy':'operator-entered','basis':'declared','value':0},
        b'-0', expected(None,'MISMATCH','NOT_RUN'), actual=b'0')
    return {'schema': 'pask-local-recipient-fixtures/1',
            'construction': content_vectors.CONSTRUCTION,
            'scope': content_vectors.SCOPE,
            'vocabulary_digest': content_vectors.VOCAB,
            'note': 'Expected projections for native composition tests. Public synthetic facts/salts; no real-world or service assurance.',
            'cases': cases}


def verify(fixture: dict) -> dict:
    paths = 0
    for case in fixture['cases']:
        material = case['material']
        h = bytes.fromhex(material['header_hash'])
        for fact in material['facts']:
            encoded = bytes.fromhex(fact['canonical_hex'])
            assert rfc8785.dumps(fact['fact']) == encoded
            leaf = content_vectors.h(1, h, content_vectors.u64(fact['index']),
                                     bytes.fromhex(fact['salt_hex']), content_vectors.u64(len(encoded)), encoded)
            assert leaf.hex() == fact['leaf_hex']
            tree = content_vectors.rebuild(material['count'], fact['index'], leaf,
                                           [bytes.fromhex(p) for p in fact['proof_hex']])
            assert 'sha256:' + content_vectors.h(4, h, tree).hex() == material['root_digest']
            paths += 1
        # Check raw hash outcomes independently. Metadata and report projection
        # expectations are contract assertions consumed by the native target.
        if case['objects'] and case['objects'][0]['state'] == 'bytes':
            obj = case['objects'][0]
            eq = digest(bytes.fromhex(obj['bytes_hex'])) == obj['digest']
            assert eq == (case['expected']['integrity'] == 'MATCHED'), case['id']
    return {'fixture_cases': len(fixture['cases']), 'independently_rebuilt_memberships': paths,
            'native_recipient_executed': False,
            'expectations_are_proposals_until_native_execution': True}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    target = args.output or Path(__file__).resolve().parents[2] / 'crates/pask-wire/tests/fixtures/proposed07/recipient-composition-v1.json'
    obj = fixture()
    data = (json.dumps(obj, indent=2, ensure_ascii=True) + '\n').encode()
    result = verify(obj)
    if args.check:
        if target.read_bytes() != data:
            raise ValueError('fixture differs; expected bytes not rewritten')
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    result.update(fixture_sha256=hashlib.sha256(data).hexdigest(), fixture_bytes=len(data))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
