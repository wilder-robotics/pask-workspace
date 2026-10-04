# SPDX-License-Identifier: Apache-2.0
"""Synthetic dual-vocabulary replay specimens; expected reports are NOT native results.

Reuses the accepted Python content framing/signing primitives. Original generators
and fixtures are never modified. Public deterministic keys/salts protect nothing.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import rfc8785
import content_vectors as content
import replay_vectors as replay
from vocabulary_codegen import parse_json

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'crates/pask-wire/tests/fixtures/proposed07/mobile-v2'
V1 = content.VOCAB
V2 = 'sha256:' + hashlib.sha256((ROOT / 'schemas/proposed/pser-0.7/content-vocabulary-v2-candidate.json').read_bytes()).hexdigest()
UNKNOWN = 'sha256:' + 'f' * 64
RAW = b'{"source":"synthetic navigation object; not an authenticated receiver"}'


def pose():
    return dict(name='site.pose', assertedBy='platform-recorded', basis='measured',
                value=dict(crs='EPSG:4979', referencePoint='antenna:1', latE7=411234568,
                           lonE7=-877654321, heightMm=None, horizontalAccuracyMm=None,
                           observedAt=None, latLonDerivation='rounded-half-even-to-1e-7-deg'),
                evidence={'digest': replay.digest(RAW)})


def entry(vocabulary, facts, selected=None, raw=RAW, seq=0, prev=None, null=False):
    ordered = sorted(facts, key=lambda f: f['name'].encode('ascii'))
    head = content.header_hash(len(ordered), vocabulary)
    encoded = [rfc8785.dumps(fact) for fact in ordered]
    salts = [hashlib.sha256(f'PUBLIC mobile v2 salt {i}'.encode()).digest() for i in range(len(ordered))]
    leaves = [content.h(1, head, content.u64(i), salt, content.u64(len(body)), body)
              for i, (body, salt) in enumerate(zip(encoded, salts))]
    root = 'sha256:' + content.h(4, head, content.tree(leaves, head)).hex()
    statement, chain_hash = replay.sign(None if null else root, seq=seq, prev=prev)
    selected = {f['name'] for f in ordered} if selected is None else set(selected)
    disclosures = [dict(record_hex=body.hex(), salt_hex=salts[i].hex(), index=i,
                        siblings_hex=[x.hex() for x in content.path(leaves, i, head)])
                   for i, body in enumerate(encoded) if ordered[i]['name'] in selected]
    return dict(statement_hex=statement,
                presentation=None if null else dict(construction=content.CONSTRUCTION, scope=content.SCOPE,
                    vocabulary_digest=vocabulary, fact_count=len(ordered), disclosures=disclosures),
                objects=[] if raw is None else [dict(digest=replay.digest(RAW), state='BYTES', bytes_hex=raw.hex())],
                policy=replay.policy(required=['site.pose'])), chain_hash


def build():
    files = {}; cases = []
    def add(name, entries, availability, mode='single', extra=None):
        raw = (json.dumps(dict(schema=replay.SCHEMA, entries=entries), indent=2) + '\n').encode()
        files[name + '.json'] = raw
        checks = [dict(path=['records', i, 'requested_facts', 0, 'availability'], equals=result)
                  for i, result in enumerate(availability)]
        checks += [dict(path=['records', i, 'application_acceptance', 'status'], equals='unestablished')
                   for i in range(len(entries))]
        checks += extra or []
        cases.append(dict(id=name, file=name + '.json', sha256=hashlib.sha256(raw).hexdigest(), mode=mode, checks=checks))
    full,_=entry(V2,[pose()])
    add('v2-pose',[full],['DISCLOSED'],extra=[dict(path=['records',0,'facts',0,'evidence','comparison'],equals='NOT_COMPARABLE')])
    p=pose();p['value']['heading']=10
    bad,_=entry(V2,[p]);add('v2-extra-field',[bad],['DISCLOSED'],extra=[dict(path=['records',0,'facts',0,'constraint','metadata_findings'],equals=['invalid_typed_value'])])
    p=pose();p['basis']='estimated'
    forbidden,_=entry(V2,[p]);add('v2-forbidden',[forbidden],['DISCLOSED'],extra=[dict(path=['records',0,'facts',0,'provenance'],equals='ATTRIBUTION_FORBIDDEN')])
    sub,_=entry(V2,[pose(),replay.model()],selected=['unit.model']);add('v2-pose-withheld',[sub],['NOT_DISCLOSED_UNPROVEN'])
    absent,_=entry(V2,[replay.model()]);add('v2-pose-absent',[absent],['ABSENT_FROM_COMMITTED_BLOCK'])
    null,_=entry(V2,[],null=True);add('v2-null',[null],['NO_BLOCK_COMMITTED'])
    old,_=entry(V1,[replay.model()]);add('v1-required-pose',[old],['UNSUPPORTED_BY_VOCABULARY'])
    old_pose,_=entry(V1,[pose()]);add('v1-committed-pose',[old_pose],['UNSUPPORTED_BY_VOCABULARY'],extra=[dict(path=['records',0,'facts',0,'constraint','classification'],equals='UNKNOWN_FACT')])
    unknown,_=entry(UNKNOWN,[pose()]);add('unknown-vocabulary',[unknown],['NOT_EVALUATED'],extra=[dict(path=['records',0,'vocabulary','status'],equals='unsupported')])
    evidence,_=entry(V2,[pose()],raw=b'altered');add('v2-bad-evidence',[evidence],['DISCLOSED'],extra=[dict(path=['records',0,'summary','evidence_failures'],equals=1)])
    a,ha=entry(V1,[replay.model()]);b,hb=entry(V2,[pose()],seq=1,prev=ha);c,_=entry(UNKNOWN,[pose()],seq=2,prev=hb)
    add('mixed-chain',[a,b,c],['UNSUPPORTED_BY_VOCABULARY','DISCLOSED','NOT_EVALUATED'],mode='chain',extra=[dict(path=['chain','check','status'],equals='passed')])
    files['public-key.hex']=replay.PUBLIC.hex().encode()+b'\n'
    files['catalog.json']=(json.dumps(dict(schema='pask-local-mobile-v2-fixtures/1',
        note='Public synthetic key and salts. Checks are authored native expectations, not execution evidence.',
        cases=cases),indent=2)+'\n').encode()
    return files


def verify(files):
    count=paths=0
    for case in parse_json(files['catalog.json'])['cases']:
        raw=files[case['file']]
        assert hashlib.sha256(raw).hexdigest()==case['sha256']
        for item in parse_json(raw)['entries']:
            protected, unprotected, payload, signature=replay.decode(bytes.fromhex(item['statement_hex']))
            assert unprotected=={}
            replay.KEY.public_key().verify(signature,replay.cbor(['Signature1',protected,b'',payload]))
            parsed=json.loads(payload);assert rfc8785.dumps(parsed)==payload
            unsigned=copy.deepcopy(parsed);del unsigned['chain']['hash']
            assert parsed['chain']['hash']==replay.digest(rfc8785.dumps(unsigned))
            p=item['presentation']
            if p:
                h=content.header_hash(p['fact_count'],p['vocabulary_digest'])
                for d in p['disclosures']:
                    body=bytes.fromhex(d['record_hex']);assert rfc8785.dumps(json.loads(body))==body
                    leaf=content.h(1,h,content.u64(d['index']),bytes.fromhex(d['salt_hex']),content.u64(len(body)),body)
                    root=content.h(4,h,content.rebuild(p['fact_count'],d['index'],leaf,[bytes.fromhex(x) for x in d['siblings_hex']]))
                    assert parsed['engagement']['contentDigest']=='sha256:'+root.hex();paths+=1
            count+=1
    return dict(documents=11, statement_occurrences_checked=count, membership_paths_checked=paths,
                expected_reports='NOT_RUN: native recipient outcomes remain expectations')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true')
    args=parser.parse_args();files=build();result=verify(files)
    if args.check:
        assert {p.name for p in DEST.iterdir() if p.is_file()}==set(files)
        for name,raw in files.items():assert (DEST/name).read_bytes()==raw,name
    else:
        DEST.mkdir(parents=True,exist_ok=True)
        for name,raw in files.items():(DEST/name).write_bytes(raw)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
