#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic LOCAL replay fixtures: original bytes, public synthetic keys.

Canonicalization/hash/signature checks are Python executions, not native Rust
recipient outcomes. Expected report fields are authored expectations. No network,
registry, remote evidence or production keys are used. --check never rewrites.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import re
import struct
from pathlib import Path
import content_vectors as content
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT/'crates/pask-wire/tests/fixtures/proposed07/replay'
SEED = bytes([123])*32  # PUBLIC, deterministic, synthetic; protects nothing.
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
SCHEMA = 'pask-local-recipient-replay/1'

def digest(data): return 'sha256:'+hashlib.sha256(data).hexdigest()
def major(m,n):
    if n<24:return bytes([m*32+n])
    if n<256:return bytes([m*32+24,n])
    if n<65536:return bytes([m*32+25])+struct.pack('>H',n)
    if n<2**32:return bytes([m*32+26])+struct.pack('>I',n)
    return bytes([m*32+27])+struct.pack('>Q',n)
def cbor(v):
    if v is None:return b'\xf6'
    if isinstance(v,int):return major(0,v) if v>=0 else major(1,-1-v)
    if isinstance(v,bytes):return major(2,len(v))+v
    if isinstance(v,str):b=v.encode();return major(3,len(b))+b
    if isinstance(v,list):return major(4,len(v))+b''.join(cbor(x) for x in v)
    if isinstance(v,dict):return major(5,len(v))+b''.join(cbor(k)+cbor(x) for k,x in v.items())
    raise TypeError(type(v))
def decode(data):
    def one(i):
        start=data[i];i+=1;m,ai=start>>5,start&31
        if m==7 and ai==22:return None,i
        if ai<24:n=ai
        elif ai in (24,25,26,27):
            width={24:1,25:2,26:4,27:8}[ai];n=int.from_bytes(data[i:i+width],'big');i+=width
        else:raise ValueError('unsupported fixture CBOR')
        if m==0:return n,i
        if m==1:return -1-n,i
        if m in (2,3):
            end=i+n
            if end>len(data):raise ValueError('truncated CBOR')
            value=data[i:end];return (value if m==2 else value.decode()),end
        if m==4:
            value=[]
            for _ in range(n):x,i=one(i);value.append(x)
            return value,i
        if m==5:
            value={}
            for _ in range(n):
                key,i=one(i);x,i=one(i)
                if key in value:raise ValueError('duplicate CBOR')
                value[key]=x
            return value,i
        if m==6 and n==18:return one(i)
        raise ValueError('unsupported CBOR major')
    result,end=one(0)
    if end!=len(data):raise ValueError('trailing CBOR')
    return result

def template():
    text=(ROOT/'crates/pask-wire/src/testvectors.rs').read_text()
    body=re.search(r'pub const MINIMAL_VALID_JCS: &str = r#"(.*?)"#;',text,re.S).group(1)
    return json.loads(body)

def sign(root,seq=0,prev=None,affiliation='NOT_DISCLOSED',legacy=False):
    value=template();value['spec']='wilder.pser/0.6' if legacy else 'wilder.pser/0.7'
    if not legacy:value['engagement']['contentDigest']=root
    value['chain']['seq']=seq;value['chain']['prevHash']=prev
    del value['chain']['hash'];value['issuerAffiliation']=affiliation
    value['chain']['hash']=digest(rfc8785.dumps(value))
    payload=rfc8785.dumps(value)
    subject=value['site']['id'] if not legacy else value['site']['id'].encode()
    protected=cbor({1:-8,3:'application/pser+json; profile='+value['spec'],15:{1:value['attestation']['witnessKey'],2:subject}})
    signature=KEY.sign(cbor(['Signature1',protected,b'',payload]))
    statement=b'\xd2'+cbor([protected,{},payload,signature])
    return statement.hex(),value['chain']['hash']

def policy(required=None,all_slots=False):return {'expected_context':None,'require_presented_content':True,'require_all_committed_slots':all_slots,'required_fact_names':required or [],'compare_unitless_scalars':True}
def model(value='Alpha',raw=b'"Alpha"'):
    return {'name':'unit.model','assertedBy':'site-policy','basis':'declared','value':value,'evidence':{'digest':digest(raw)}}
def material(facts):
    return content.material([{'fact':fact,'salt_hex':hashlib.sha256(f'PUBLIC replay salt {i}'.encode()).hexdigest()} for i,fact in enumerate(facts)])
def entry(mat, raw=b'"Alpha"',seq=0,prev=None,selected=None,affiliation='NOT_DISCLOSED',required=None,legacy=False):
    statement,head=sign(mat['root_digest'] if mat else None,seq,prev,affiliation,legacy)
    selected=range(mat['count']) if mat and selected is None else (selected or [])
    presentation=None if mat is None else {'construction':content.CONSTRUCTION,'scope':content.SCOPE,'vocabulary_digest':content.VOCAB,'fact_count':mat['count'],
        'disclosures':[{'record_hex':f['canonical_hex'],'salt_hex':f['salt_hex'],'index':f['index'],'siblings_hex':f['proof_hex']} for f in mat['facts'] if f['index'] in selected]}
    objects=[{'digest':digest(raw),'state':'BYTES','bytes_hex':raw.hex()}] if raw is not None else []
    return {'statement_hex':statement,'presentation':presentation,'objects':objects,'policy':policy(required)},head

def fixture_files():
    files={};cases=[]
    def add(name,entries,mode='single',expected=None):
        document={'schema':SCHEMA,'entries':entries}
        encoded=(json.dumps(document,indent=2,ensure_ascii=True)+'\n').encode()
        files[name+'.json']=encoded
        # Expected projections, not a second native recipient execution.
        cases.append({'id':name,'file':name+'.json','mode':mode,'expected':expected or {},'sha256':hashlib.sha256(encoded).hexdigest()})
    m=material([model()]); match,_=entry(m)
    add('single-match',[match],expected={'chain_status':'not-evaluated','statement_statuses':['passed'],'presentation_states':['ALL_COMMITTED_SLOTS'],'contradictions':[0],'forbidden':[0]})
    contradiction,_=entry(material([model(raw=b'"Beta"')]),raw=b'"Beta"')
    add('single-contradiction',[contradiction],expected={'chain_status':'not-evaluated','statement_statuses':['passed'],'contradictions':[1]})
    bad=copy.deepcopy(match);bad['objects'][0]['bytes_hex']=b'"Beta"'.hex()
    add('single-bad-evidence',[bad],expected={'chain_status':'not-evaluated','statement_statuses':['passed'],'evidence_failures':[1]})
    forbidden,_=entry(material([{'name':'limits.rated-force','assertedBy':'robot-attributed','basis':'measured','value':10,'unit':'N'}]),raw=None)
    add('single-forbidden',[forbidden],expected={'forbidden':[1],'disclosure_policy':['passed']})
    null,_=entry(None,raw=None)
    add('single-null',[null],expected={'presentation_states':['NULL_COMMITMENT'],'disclosure_policy':['failed']})
    withheld=copy.deepcopy(match);withheld['presentation']=None
    add('single-withheld',[withheld],expected={'presentation_states':['NOT_PRESENTED'],'disclosure_policy':['unestablished']})
    empty,_=entry(material([]),raw=None)
    add('single-empty',[empty],expected={'presentation_states':['EMPTY_COMMITTED_BLOCK'],'disclosure_policy':['passed']})
    subset,_=entry(material([model(),{'name':'unit.deployment-status','assertedBy':'site-policy','basis':'declared','value':'deployed'}]),selected=[0],required=['unit.model'])
    add('single-subset',[subset],expected={'presentation_states':['SELECTED_SLOTS'],'requested_availability':[['NOT_DISCLOSED_UNPROVEN']]})
    absent=copy.deepcopy(empty);absent['policy']['required_fact_names']=['unit.model']
    add('single-block-absence',[absent],expected={'requested_availability':[['ABSENT_FROM_COMMITTED_BLOCK']]})
    proof=copy.deepcopy(match);proof['presentation']['disclosures'][0]['salt_hex']='00'*32
    add('single-invalid-proof',[proof],expected={'presentation_states':['INVALID'],'membership':['failed']})
    legacy,_=entry(None,raw=None,legacy=True)
    add('single-legacy06',[legacy],expected={'statement_statuses':['passed'],'presentation_states':['LEGACY_PROFILE_UNSUPPORTED']})
    a,ha=entry(m);b,hb=entry(m,seq=1,prev=ha);c,_=entry(m,seq=2,prev=hb)
    add('chain-three',[a,b,c],'chain',{'chain_status':'passed','statement_statuses':['passed']*3,'affiliation_changes':0})
    add('chain-prefix',[a,b],'chain',{'chain_status':'passed','statement_statuses':['passed']*2})
    add('chain-genesis-only',[a],'chain',{'chain_status':'passed'})
    add('single-midchain',[b],expected={'chain_status':'not-evaluated','statement_statuses':['passed']})
    add('chain-midchain',[b,c],'chain',{'chain_status':'failed','statement_statuses':['passed']*2})
    gap,_=entry(m,seq=2,prev=ha)
    add('chain-sequence-gap',[a,gap],'chain',{'chain_status':'failed','statement_statuses':['passed']*2})
    wrong,_=entry(m,seq=1,prev='sha256:'+'f'*64)
    add('chain-wrong-predecessor',[a,wrong],'chain',{'chain_status':'failed','statement_statuses':['passed']*2})
    changed,_=entry(m,seq=1,prev=ha,affiliation='AFFILIATED')
    add('chain-affiliation-change',[a,changed],'chain',{'chain_status':'passed','affiliation_changes':1})
    contradictory,_=entry(material([model(raw=b'"Beta"')]),raw=b'"Beta"',seq=1,prev=ha)
    add('chain-contradictory-value',[a,contradictory],'chain',{'chain_status':'passed','contradictions':[0,1],'disclosure_policy':['passed','passed']})
    tampered=copy.deepcopy(b);wire=bytearray.fromhex(tampered['statement_hex']);wire[-1]^=1;tampered['statement_hex']=wire.hex()
    add('chain-invalid-signature',[a,tampered],'chain',{'chain_status':'unestablished','statement_statuses':['passed','failed']})
    files['public-key.hex']=PUBLIC.hex().encode()+b'\n'
    catalog={'schema':'pask-local-replay-fixtures/1','note':'PUBLIC deterministic synthetic inputs. Expected native report projections are assertions to test, not executed Rust results. No hardware or service attestation. Public key origin is this generator.','public_key_hex':PUBLIC.hex(),'cases':cases}
    files['catalog.json']=(json.dumps(catalog,indent=2)+'\n').encode()
    return files

def verify(files):
    catalog=json.loads(files['catalog.json']);statements=0;bad_signatures=0;paths=0
    for case in catalog['cases']:
        raw=files[case['file']];assert hashlib.sha256(raw).hexdigest()==case['sha256']
        sequence=[]; signatures_valid=True
        for item in json.loads(raw)['entries']:
            protected,unprotected,payload,signature=decode(bytes.fromhex(item['statement_hex']))
            assert unprotected=={};header=decode(protected);obj=json.loads(payload)
            assert rfc8785.dumps(obj)==payload
            without=copy.deepcopy(obj);del without['chain']['hash']
            assert digest(rfc8785.dumps(without))==obj['chain']['hash']
            assert header[15][1]==obj['attestation']['witnessKey']
            expected_sub=obj['site']['id'] if obj['spec']=='wilder.pser/0.7' else obj['site']['id'].encode()
            assert header[15][2]==expected_sub
            try:KEY.public_key().verify(signature,cbor(['Signature1',protected,b'',payload]))
            except InvalidSignature:
                assert case['id']=='chain-invalid-signature';bad_signatures+=1;signatures_valid=False
            statements+=1;sequence.append(obj)
            p=item['presentation']
            if p:
                h=content.header_hash(p['fact_count'])
                for d in p['disclosures']:
                    body=bytes.fromhex(d['record_hex']);assert rfc8785.dumps(json.loads(body))==body
                    leaf=content.h(1,h,content.u64(d['index']),bytes.fromhex(d['salt_hex']),content.u64(len(body)),body)
                    root=content.h(4,h,content.rebuild(p['fact_count'],d['index'],leaf,[bytes.fromhex(x) for x in d['siblings_hex']]))
                    if case['id']=='single-invalid-proof':assert 'sha256:'+root.hex()!=obj['engagement']['contentDigest']
                    else:assert 'sha256:'+root.hex()==obj['engagement']['contentDigest']
                    paths+=1
        if case['mode']=='chain':
            valid_links=bool(sequence) and sequence[0]['chain']['seq']==0 and sequence[0]['chain']['prevHash'] is None
            valid_links=valid_links and all(b['chain']['seq']==a['chain']['seq']+1 and b['chain']['prevHash']==a['chain']['hash'] for a,b in zip(sequence,sequence[1:]))
            model='unestablished' if not signatures_valid else ('passed' if valid_links else 'failed')
            if 'chain_status' in case['expected']:assert case['expected']['chain_status']==model
    assert bad_signatures==1
    return {'cases':len(catalog['cases']),'statements_checked':statements,'intentionally_bad_signatures':bad_signatures,'membership_calculations':paths,'native_results':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--output',type=Path)
    a=p.parse_args();dest=a.output or DEST;files=fixture_files();result=verify(files)
    if a.check:
        for name,data in files.items():assert (dest/name).read_bytes()==data,name
        assert {x.name for x in dest.iterdir() if x.is_file()}==set(files)
    else:
        dest.mkdir(parents=True,exist_ok=True)
        for name,data in files.items():(dest/name).write_bytes(data)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
