# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
"""Independent Python CBOR/hash/Ed25519 oracle. Fixed PUBLIC SOFTWARE TEST seeds.
No Rust helper imported. CallerAuthenticatedExternal test branches below model a
caller assertion only; these files do not authenticate any real key origin.
"""
from pathlib import Path
import hashlib,json,cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
p=Path(__file__).resolve().parent
enc=lambda x:cbor2.dumps(x,canonical=True)
sha=lambda b:hashlib.sha256(b).digest()
i=Ed25519PrivateKey.from_private_bytes(bytes([17])*32)
t=Ed25519PrivateKey.from_private_bytes(bytes([29])*32)
ct='application/json; profile=pask71-software-site/1'
# Deliberately noncanonical protected map ordering and integer width for alg label.
protected=b'\xbf\x03'+enc(ct)+b'\x18\x01\x27\x0f'+enc({1:'https://issuer.example.test',2:'site-A'})+b'\xff'
payload=b'{"site":{"id":"site-A"}}'
sig=i.sign(enc(['Signature1',protected,b'',payload]))
candidate=enc([protected,{},payload,sig])
sibling=sha(b'\x00independent other leaf')
root=sha(b'\x01'+sha(b'\x00'+candidate)+sibling)
rp=enc({1:-8,4:b'nonunique',15:{1:'https://ts.example.test',2:'site-A'},395:1})
rs=t.sign(enc(['Signature1',rp,b'',root]))
proof=enc([2,0,[sibling]])
receipts={n:enc(cbor2.CBORTag(18,[rp,{396:{-1:[proof]}},m,rs])) for n,m in [('attached',root),('detached',None)]}
outputs={'statement.cbor':enc(cbor2.CBORTag(18,[protected,{},payload,sig])), 'candidate.cbor':candidate,'root.bin':root,'issuer-key.bin':i.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),'service-key.bin':t.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
for n,r in receipts.items():
 outputs[f'{n}-receipt.cbor']=r
 outputs[f'{n}-transparent.cbor']=enc(cbor2.CBORTag(18,[protected,{394:[r]},payload,sig]))
for n,b in outputs.items():(p/n).write_bytes(b)
(p/'manifest.json').write_text(json.dumps({'origin':'PUBLIC SOFTWARE TEST seeds 0x11*32 and 0x1d*32; simulated provisioning, not real authenticated origins','independence':'Python cbor2/hashlib/cryptography; no Rust producer/verifier helpers','files':{n:hashlib.sha256(b).hexdigest() for n,b in outputs.items()}},indent=2)+'\n')
print('generated',len(outputs),'independent binary fixtures')
