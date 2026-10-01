# SPDX-License-Identifier: Apache-2.0
"""Author-side document/rule checks; no Rust or RFCXML execution is implied."""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / 'schemas/proposed/pser-0.7/content-vocabulary.json'
V2 = ROOT / 'schemas/proposed/pser-0.7/content-vocabulary-v2-candidate.json'
H1 = '030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d'
H2 = '2fb4e3a099003638d318333dee66fe2b710fb39b6dec78f570f6ecf31592a248'


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


VOCABULARY_SOURCE_COLUMNS = 69  # Pinned renderer adds three columns.


def display_json(value):
    output = []
    for line in json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).splitlines():
        if len(line) > VOCABULARY_SOURCE_COLUMNS:
            key, sep, token = line.partition(': ')
            require(bool(sep) and len(key) < VOCABULARY_SOURCE_COLUMNS, 'long unsplittable key')
            output.append(key + ':')
            if len(token) > VOCABULARY_SOURCE_COLUMNS:
                require(token.endswith(','), 'long unsplittable token')
                value_token = token[:-1]
                require(len(value_token) <= VOCABULARY_SOURCE_COLUMNS, 'long unsplittable token')
                output.extend([value_token, ','])
            else:
                output.append(token)
        else:
            output.append(line)
    return '\n'.join(output)


def blocks(text):
    require(not re.search(r'^\s*```', text, re.M), 'backtick fence')
    result = []
    pattern = re.compile(r'^~~~([^\n]*)\n(.*?)^~~~\n([^\n]+)', re.M | re.S)
    for m in pattern.finditer(text):
        info = m.group(1).strip()
        body = m.group(2).removesuffix('\n')
        attr = m.group(3)
        if attr == '{: title="Physical-Site Engagement Receipt payload"}':
            ident = 'payload-example'
        else:
            require(bool(re.fullmatch(r'\{: #[a-z0-9-]+\}', attr)), 'unlabelled block')
            ident = attr[4:-1]
        preceding = text[:m.start()].rstrip().rsplit('\n\n', 1)[-1].replace('\n', ' ')
        result.append((ident, info, body, preceding))
    require(sum(1 for l in text.splitlines() if l.startswith('~~~')) == 2 * len(result), 'unclosed/extra fence')
    require(len(result) == 53 and len({r[0] for r in result}) == 53, 'block inventory')
    return result


def check(text):
    require(hashlib.sha256(V1.read_bytes()).hexdigest() == H1, 'v1 changed')
    require(hashlib.sha256(V2.read_bytes()).hexdigest() == H2, 'v2 changed')
    v1, v2 = json.loads(V1.read_bytes()), json.loads(V2.read_bytes())
    require(len(v2['facts']) == 47 and v1['facts'] == v2['facts'][:46], 'legacy row identity')
    rows = blocks(text)
    indexed = {r[0]: r for r in rows}
    global_value = json.loads(indexed['vocabulary-global-definition'][2])
    for key in ['numbers', 'operatorPseudonym', 'remoteOrigin']:
        prefix = 'Artifact annotation `' + key + '`: '
        matches = [p[len(prefix):].replace('\n', ' ') for p in text.split('\n\n') if p.startswith(prefix)]
        require(matches == [v2['globalRules'][key]], 'global annotation ' + key)
        global_value['globalRules'][key] = matches[0]
    expected_global = {k: v for k, v in v2.items() if k not in ('version', 'facts')}
    require(global_value == expected_global, 'global definition')
    order = []
    for ident, info, body, preceding in rows:
        if ident.startswith('vocabulary-rule-'):
            row = json.loads(body)
            require(preceding.startswith('Meaning: '), 'row meaning missing')
            row['meaning'] = preceding[len('Meaning: '):]
            order.append(row)
            display = dict(row)
            display.pop('meaning')
            require(body == display_json(display), 'row display / duplicate properties')
    require(order == v2['facts'], 'all 47 complete rows / order')
    # ASCII/integer-only source vector: this is not a general JCS implementation.
    rust = (ROOT / 'crates/pask-wire/src/testvectors.rs').read_text()
    raw = re.search(r'pub const MINIMAL_VALID_JCS: &str = r#"(.*?)"#;', rust, re.S).group(1)
    payload = json.loads(raw)
    payload['spec'] = 'wilder.pser/0.7'
    payload['engagement']['contentDigest'] = None
    del payload['chain']['hash']
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    payload['chain']['hash'] = 'sha256:' + hashlib.sha256(canonical).hexdigest()
    expected_figure = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    require(indexed['payload-example'][2] == expected_figure, 'figure / source-derived hash')
    require('a URI identifying the Issuer, encoded as a' in text, 'issuer URI requirement')
    require('date: false\n    seriesinfo:\n      EPSG: "4979"' in text, 'undated EPSG metadata')
    require('dataset release date or version' in text, 'EPSG qualification')
    for forbidden in ['PRIVATE AUTHOR-REVIEW COPY', '3043168d9302786a838986322a95c8bf03dfe8ba',
                      'this private working copy', 'owner promotion/licensing decision']:
        require(forbidden not in text, 'private filing marker')
    require('including when its value is null' in text, 'legacy rejection wording')
    require('A generator for /2 MUST' not in text, 'generator-only requirement')
    # Exact no-new-artwork-overflow check; rendered text/idnits remain separate.
    long_lines = [(ident, i+1, len(line)) for ident, _, body, _ in rows
                  for i, line in enumerate(body.splitlines()) if len(line) > 72]
    require(len(long_lines) == 8 and all(i[0] == 'payload-example' for i in long_lines), 'new long artwork')
    nonpayload_overflow = [(ident, i + 1, len(line)) for ident, _, body, _ in rows
                           if ident != 'payload-example'
                           for i, line in enumerate(body.splitlines())
                           if len(line) > VOCABULARY_SOURCE_COLUMNS]
    require(not nonpayload_overflow, 'new artwork exceeds reserved renderer margin')
    anchors = re.findall(r'\{#([^}]+)\}|\{: #([^}]+)\}', text)
    anchors = [a or b for a,b in anchors]
    require(len(anchors) == len(set(anchors)), 'duplicate anchors')
    references = set(re.findall(r'^  ([A-Za-z0-9][A-Za-z0-9.-]*):', text.split('--- abstract')[0], re.M))
    unresolved = sorted(set(re.findall(r'\{\{([^}]+)\}\}', text)) - set(anchors) - references)
    require(not unresolved, 'unresolved cross references ' + repr(unresolved))
    return {'blocks': len(rows), 'complete_rows': len(order), 'long_artwork_lines': len(long_lines),
            'new_example_jcs_sha256': hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'draft_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'nonpayload_source_columns': VOCABULARY_SOURCE_COLUMNS,
            'reserved_renderer_margin': 3}


def integer_oracle(token):
    value = int(token)
    if abs(value) > 9007199254740991:
        raise ValueError('integer_token_out_of_range')
    return value


def reject_constant(token):
    raise ValueError('nonfinite ' + token)


def numeric_checks():
    # Independent stdlib parse_int callback, not a translation of the Rust scanner.
    positive = ['0', '9007199254740991', '-9007199254740991', '0.5', '1e+30',
                '"100000000000000000000"', '"quoted\\\"100000000000000000000"']
    negative = ['9007199254740992', '-9007199254740992', '18446744073709551616',
                '100000000000000000000', '-100000000000000000000',
                '[0,100000000000000000000]', '{"x":100000000000000000000}',
                '9' * 4096]
    for raw in positive:
        json.loads(raw, parse_int=integer_oracle, parse_constant=reject_constant)
    for raw in negative:
        try:
            json.loads(raw, parse_int=integer_oracle, parse_constant=reject_constant)
        except ValueError:
            pass
        else:
            raise ValueError('unexpected integer-domain acceptance')
    return {'author_numeric_oracle_positive': len(positive), 'negative': len(negative)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    paths = list((ROOT/'docs').glob('draft-wilder-scitt-physical-site-engage-receipt-*.md'))
    require(len(paths)==1, 'single active draft')
    text=paths[0].read_text()
    result=check(text)
    result.update(numeric_checks())
    if args.self_test:
        mutations = [
            text.replace('~~~ json', '```json', 1),
            text.replace('"maxLength": 64', '"maxLength": 65', 1),
            text.replace('Meaning: Model designation', 'Meaning: Bad designation', 1),
            text.replace('All numeric values are integers', 'All numeric values are floats', 1),
            text.replace('"maxLength": 64,', '"maxLength": 64,\n    "maxLength": 64,', 1),
            text + '\n~~~ json\n{}\n~~~\n{: #unreviewed}\n',
            text.replace('a URI identifying the Issuer, encoded as a', 'any string, encoded as a',1),
            text.replace('date: false', 'date: 2026-01-01',1),
        ]
        for i,bad in enumerate(mutations):
            try:check(bad)
            except (ValueError,KeyError,json.JSONDecodeError):pass
            else:raise ValueError('self-test missed mutation '+str(i))
        result['mutation_checks']=len(mutations)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
