# SPDX-License-Identifier: Apache-2.0
"""Pinned, reusable local table generation; no distribution permission is inferred.

The original migrate_vocab.py, generate.py, v1 data and generated Rust are frozen.
This module can reproduce v1 without imposing the new v2 schema dialect on it.
V2 source identity and explicit expected relation are inputs, not discovered totals.
"""
import hashlib
import itertools
import json
from pathlib import Path

PATTERNS = frozenset((
    r'^[A-Za-z0-9:_.-]+$',
    r'^sha256:[0-9a-f]{64}$',
    r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$',
))
TYPES = frozenset(('boolean', 'integer', 'string', 'map-of-integer', 'object'))
I64_MIN, I64_MAX = -(2**63), 2**63 - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse_json(raw):
    def reject_constant(value):
        raise ValueError('non-JSON numeric constant: ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def unique_strings(values, label, nonempty=True):
    require(type(values) is list, label + ': expected array')
    require((not nonempty or bool(values)) and len(values) <= 256,
            label + ': empty or excessive array')
    require(all(type(x) is str and x and len(x) <= 256 for x in values),
            label + ': expected bounded nonempty strings')
    require(len(values) == len(set(values)), label + ': duplicate values')
    return set(values)


def validate_schema(schema, path='value', depth=0):
    """Validate exactly the supported finite v2 dialect, not general JSON Schema."""
    require(depth <= 8, path + ': schema depth')
    require(type(schema) is dict, path + ': schema must be object')
    kind = schema.get('type')
    require(type(kind) is str and kind in TYPES, path + ': unsupported type')
    allowed = {'type', 'nullable'}
    allowed |= {
        'boolean': set(),
        'integer': {'minimum', 'maximum'},
        'string': {'enum', 'maxLength', 'pattern'},
        'map-of-integer': set(),
        'object': {'properties', 'required', 'additionalProperties'},
    }[kind]
    require(set(schema) <= allowed, path + ': unknown/inapplicable schema keyword')
    if 'nullable' in schema:
        require(type(schema['nullable']) is bool, path + ': nullable must be boolean')
    for key in ('minimum', 'maximum'):
        if key in schema:
            require(type(schema[key]) is int and I64_MIN <= schema[key] <= I64_MAX,
                    path + ': integer bound must be i64, not boolean or float')
    if 'minimum' in schema and 'maximum' in schema:
        require(schema['minimum'] <= schema['maximum'], path + ': reversed bounds')
    if 'maxLength' in schema:
        require(type(schema['maxLength']) is int and 0 <= schema['maxLength'] <= 65536,
                path + ': invalid maxLength')
    if 'pattern' in schema:
        require(type(schema['pattern']) is str and schema['pattern'] in PATTERNS,
                path + ': unsupported pattern')
    if 'enum' in schema:
        unique_strings(schema['enum'], path + '.enum')
    if kind == 'object':
        props = schema.get('properties')
        require(type(props) is dict and len(props) <= 256, path + ': invalid properties')
        require(all(type(k) is str and 0 < len(k) <= 128 for k in props),
                path + ': invalid property name')
        if 'required' in schema:
            required = unique_strings(schema['required'], path + '.required', nonempty=False)
            require(required <= set(props), path + ': required property not declared')
        if 'additionalProperties' in schema:
            require(schema['additionalProperties'] is False,
                    path + ': only additionalProperties=false is supported')
        for name, child in props.items():
            validate_schema(child, path + '.properties.' + name, depth + 1)


def validate_vocabulary(vocab, profile):
    require(type(vocab) is dict, 'vocabulary must be object')
    require(vocab.get('version') == profile['version'], 'version mismatch')
    parties = unique_strings(vocab.get('assertedBy'), 'assertedBy')
    bases = unique_strings(vocab.get('basis'), 'basis')
    require(len(parties) == 7 and bases == {'measured', 'estimated', 'declared'},
            'party/basis inventory changed')
    facts = vocab.get('facts')
    require(type(facts) is list and len(facts) == profile['expected']['facts'],
            'fact count differs from pinned expectations')
    names = unique_strings([f.get('name') for f in facts if type(f) is dict], 'fact names')
    require(len(names) == len(facts), 'malformed fact or duplicate name')
    global_rules = vocab.get('globalRules')
    require(type(global_rules) is dict, 'globalRules must be object')
    by_party = global_rules.get('basisByParty')
    require(type(by_party) is dict and set(by_party) == parties, 'basisByParty keys differ')
    for party, values in by_party.items():
        require(unique_strings(values, 'basisByParty.' + party) <= bases, 'unknown global basis')
    require(unique_strings(global_rules.get('evidenceRequiredByParty'),
                           'evidenceRequiredByParty', nonempty=False) <= parties,
            'unknown evidence-required party')
    for fact in facts:
        require(unique_strings(fact['assertedBy'], fact['name'] + '.assertedBy') <= parties,
                'allowlist value absent from enumeration')
        require(unique_strings(fact['basis'], fact['name'] + '.basis') <= bases,
                'unknown fact basis')
        require(fact.get('evidence') in ('required', 'optional'), 'unsupported evidence rule')
        require(fact.get('remoteOrigin') in ('required', 'forbidden'), 'unsupported remote rule')
        require(fact.get('unit') is None or type(fact['unit']) is str, 'invalid unit')
        pairs = fact.get('pairsForbidden', [])
        require(type(pairs) is list, 'pairsForbidden must be array')
        seen = set()
        for pair in pairs:
            require(type(pair) is list and len(pair) == 2 and
                    type(pair[0]) is str and type(pair[1]) is str and
                    pair[0] in parties and pair[1] in bases, 'invalid forbidden pair')
            require(tuple(pair) not in seen, 'duplicate forbidden pair')
            seen.add(tuple(pair))
        if profile['strict_dialect']:
            validate_schema(fact['value'], fact['name'] + '.value')


def classifications(vocab):
    rows = []
    for fact, party, basis in itertools.product(vocab['facts'], vocab['assertedBy'], vocab['basis']):
        permitted = (party in fact['assertedBy'] and basis in fact['basis'] and
                     basis in vocab['globalRules']['basisByParty'].get(party, []) and
                     [party, basis] not in fact.get('pairsForbidden', []))
        rows.append(dict(name=fact['name'], party=party, basis=basis, allowed=permitted))
    return rows


def validate_relation(vocab, profile, expected):
    actual = classifications(vocab)
    require(actual == expected, 'classification differs from independent explicit expected relation')
    allowed = sum(row['allowed'] for row in actual)
    counts = {
        'facts': len(vocab['facts']),
        'per_fact_pairs': sum(len(f['assertedBy']) * len(f['basis']) for f in vocab['facts']),
        'after_global': sum(b in vocab['globalRules']['basisByParty'][p]
                            for f in vocab['facts'] for p in f['assertedBy'] for b in f['basis']),
        'allowed': allowed,
        'combinations': len(actual),
        'forbidden': len(actual) - allowed,
    }
    require(counts == profile['expected'], 'fixed count expectations differ')
    return counts


def render(vocab, digest, legacy=False):
    # Preserves the historical v1 generator's bytes, including its whitespace.
    def string(value):
        return json.dumps(value, ensure_ascii=True)
    def array(values):
        return '&[' + ','.join(string(v) for v in values) + ']'
    origin = ('// Generated by tools/proposed07/generate.py. DO NOT EDIT.' if legacy else
              '// Generated by tools/proposed07/generate_vocabularies.py. DO NOT EDIT.')
    lines = [origin,
             '// Local technical derivative; see schemas/proposed/pser-0.7/ORIGIN.md.',
             f'pub const VOCAB_SHA256: &str = "{digest}";',
             f"pub const PARTIES: &[&str] = {array(vocab['assertedBy'])};",
             f"pub const BASES: &[&str] = {array(vocab['basis'])};",
             f"pub const EVIDENCE_REQUIRED: &[&str] = {array(vocab['globalRules']['evidenceRequiredByParty'])};",
             'pub const PARTY_BASES: &[(&str, &[&str])] = &[' +
             ','.join(f'({string(k)},{array(bs)})' for k, bs in
                      vocab['globalRules']['basisByParty'].items()) + '];',
             'pub static FACTS: &[FactRule] = &[']
    for fact in vocab['facts']:
        pairs = '&[' + ','.join(f'({string(p)},{string(b)})' for p, b in
                                fact.get('pairsForbidden', [])) + ']'
        unit = 'None' if fact['unit'] is None else f"Some({string(fact['unit'])})"
        schema = string(json.dumps(fact['value'], sort_keys=True, separators=(',', ':')))
        lines.append('FactRule{' + f"name:{string(fact['name'])}, parties:{array(fact['assertedBy'])},"
                     f"bases:{array(fact['basis'])}, forbidden:{pairs}, unit:{unit},"
                     f"evidence_required:{str(fact['evidence'] == 'required').lower()},"
                     f"remote_required:{str(fact['remoteOrigin'] == 'required').lower()},"
                     f'value_json:{schema}' + '},')
    lines.append('];')
    return ('\n'.join(lines) + '\n').encode()


def confined(root, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute(), 'relative path required')
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), 'path outside source root')
    return path


def load_profile(root, profiles, name):
    require(profiles.get('schema') == 'pask-local-vocabulary-generation/1', 'unknown config schema')
    profile = profiles['profiles'][name]
    raw = confined(root, profile['source']).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == profile['source_sha256'], 'source hash mismatch')
    expected_raw = confined(root, profile['expected_relation']).read_bytes()
    require(hashlib.sha256(expected_raw).hexdigest() == profile['expected_relation_sha256'],
            'expected-relation hash mismatch')
    vocab = parse_json(raw)
    validate_vocabulary(vocab, profile)
    counts = validate_relation(vocab, profile, parse_json(expected_raw))
    return profile, vocab, counts, render(vocab, profile['source_sha256'], legacy=(name == 'v1'))
