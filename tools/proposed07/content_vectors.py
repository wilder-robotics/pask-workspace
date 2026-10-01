#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent local CONTENT-01 hash/proof oracle; never invokes Rust.

Uses independently packaged rfc8785 0.1.4 for canonical bytes, hashlib for hashes.
Fixed salts are public synthetic test data, not production random salt guidance.
--check never rewrites the expected fixture. PYTHONPATH may point at the bundled
wheel; no automatic install or network access is performed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import rfc8785

D = b'PASK-LOCAL-CONTENT-TREE/1\0'
CONSTRUCTION = 'pask-local-content-tree/1'
SCOPE = 'PRESENTED_AT_SEAL'
VOCAB = 'sha256:030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d'

def h(tag: int, *parts: bytes) -> bytes:
    return hashlib.sha256(D + bytes([tag]) + b''.join(parts)).digest()

def u64(n: int) -> bytes:
    return struct.pack('>Q', n)

def header_hash(count: int, vocabulary: str = VOCAB) -> bytes:
    return h(0, u64(count), u64(len(CONSTRUCTION)), CONSTRUCTION.encode(),
             u64(len(SCOPE)), SCOPE.encode(), bytes.fromhex(vocabulary[7:]))

def split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)

def tree(leaves: list[bytes], header: bytes) -> bytes:
    if not leaves:
        return h(2, header)
    if len(leaves) == 1:
        return leaves[0]
    k = split(len(leaves))
    return h(3, tree(leaves[:k], header), tree(leaves[k:], header))

def path(leaves: list[bytes], i: int, header: bytes) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = split(len(leaves))
    if i < k:
        return path(leaves[:k], i, header) + [tree(leaves[k:], header)]
    return path(leaves[k:], i-k, header) + [tree(leaves[:k], header)]

def rebuild(count: int, index: int, leaf: bytes, siblings: list[bytes]) -> bytes:
    # Independent bottom-up fold: precompute directions, then consume strict path.
    n, i, directions = count, index, []
    if n < 1 or not 0 <= i < n:
        raise ValueError('invalid index')
    while n > 1:
        k = split(n)
        directions.append(i >= k)
        if i >= k:
            i, n = i-k, n-k
        else:
            n = k
    if len(directions) != len(siblings):
        raise ValueError('proof length')
    value = leaf
    for right, sibling in zip(reversed(directions), siblings):
        value = h(3, sibling, value) if right else h(3, value, sibling)
    return value

def material(records: list[dict]) -> dict:
    ordered = sorted(records, key=lambda x: x['fact']['name'].encode('ascii'))
    head = header_hash(len(records))
    encoded = [rfc8785.dumps(row['fact']) for row in ordered]
    leaves = [h(1, head, u64(i), bytes.fromhex(row['salt_hex']), u64(len(body)), body)
              for i, (row, body) in enumerate(zip(ordered, encoded))]
    root = h(4, head, tree(leaves, head))
    return {'count':len(records), 'header_hash':head.hex(),
            'root_digest':'sha256:'+root.hex(),
            'facts':[dict(fact=row['fact'], salt_hex=row['salt_hex'], canonical_hex=body.hex(),
                          index=i, leaf_hex=leaves[i].hex(),
                          proof_hex=[x.hex() for x in path(leaves, i, head)])
                     for i,(row,body) in enumerate(zip(ordered,encoded))]}

def fixture() -> dict:
    groups=[]
    for n in (0,1,2,3,4,5,9,17,64):
        rows=[{'fact':{'name':f'sample.fact-{i:03}', 'assertedBy':'operator-entered',
                       'basis':'declared', 'value':i},
               'salt_hex':hashlib.sha256(f'public CONTENT-01 salt {i}'.encode()).hexdigest()}
              for i in range(n)]
        groups.append(dict(id=f'tree-{n}', **material(list(reversed(rows)))))
    complex_rows=[
        {'fact':{'name':'unit.model','assertedBy':'site-policy','basis':'declared',
                 'value':'robot-\U0001f916', 'extra':{'\ue000':1,'\U00010000':2},
                 'evidence':{'digest':'sha256:'+'a'*64}}, 'salt_hex':'31'*32},
        {'fact':{'name':'limits.rated-force','assertedBy':'robot-attributed','basis':'measured',
                 'value':1.5,'unit':'N','extra':[True,None,'\n\t\u0001']}, 'salt_hex':'32'*32},
        {'fact':{'name':'scene.event-instant','assertedBy':'appliance-measured','basis':'measured',
                 'value':'2026-09-23T12:34:56.789Z','extra':{'nested':{'value':False}}}, 'salt_hex':'33'*32},
    ]
    groups.append(dict(id='mixed-with-forbidden-metadata',**material(complex_rows)))
    return {'construction':CONSTRUCTION,'scope':SCOPE,'vocabulary_digest':VOCAB,
            'note':'Local prototype; synthetic facts and salts. Not a PSER conformance corpus.',
            'groups':groups}

def checks(value: dict) -> dict:
    count=0
    for group in value['groups']:
        head=bytes.fromhex(group['header_hash'])
        for fact in group['facts']:
            leaf=bytes.fromhex(fact['leaf_hex'])
            proof=[bytes.fromhex(x) for x in fact['proof_hex']]
            root=h(4, head, rebuild(group['count'],fact['index'],leaf,proof))
            assert 'sha256:'+root.hex()==group['root_digest']
            changed=bytearray(leaf); changed[0]^=1
            altered=h(4,head,rebuild(group['count'],fact['index'],bytes(changed),proof))
            assert altered!=root
            for wrong in [proof+[bytes(32)]] + ([proof[:-1]] if proof else []):
                try: rebuild(group['count'],fact['index'],leaf,wrong)
                except ValueError:pass
                else:raise AssertionError('accepted wrong proof length')
            count+=1
    # Exhaust all indices/shapes up to the implemented maximum independently.
    exhaustive=0
    for n in range(1,257):
        head=header_hash(n)
        leaves=[hashlib.sha256(f'shape {n}/{i}'.encode()).digest() for i in range(n)]
        expected=tree(leaves,head)
        for i,leaf in enumerate(leaves):
            proof=path(leaves,i,head)
            assert len(proof)<=8
            assert rebuild(n,i,leaf,proof)==expected
            exhaustive+=1
    return {'fixed_groups':len(value['groups']),'fixed_membership_paths':count,
            'exhaustive_tree_paths_1_to_256':exhaustive,'native_rust_executed':False,
            'rfc8785_version':getattr(rfc8785,'__version__','unknown')}

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    target=args.output or Path(__file__).resolve().parents[2]/'crates/pask-wire/tests/fixtures/proposed07/content-tree-v1.json'
    obj=fixture(); data=(json.dumps(obj,indent=2,ensure_ascii=True)+'\n').encode()
    results=checks(obj)
    if args.check:
        if target.read_bytes()!=data:raise ValueError('fixed vectors do not match; not rewritten')
    else:
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    results.update(fixture_sha256=hashlib.sha256(data).hexdigest(),fixture_bytes=len(data))
    print(json.dumps(results,indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
