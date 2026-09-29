#!/bin/bash
# Pask half of the SEV-SNP experiment. In-VM procedure for the 2026-09-28 SEV-SNP witness experiment.
# Copy-out rule: before anything leaves the VM, grep the copied tree for "PRIVATE KEY".
# That check must match PEM headers ("-----BEGIN PRIVATE KEY-----", "BEGIN OPENSSH PRIVATE
# KEY", "BEGIN EC PRIVATE KEY"), not just base64 key bodies. On 2026-09-29 the first run
# printed a PEM header line into the transcript from a sanity step; the header check caught
# it and the line was removed before publication. The sanity step no longer prints anything.
set -Eeuo pipefail
source "$HOME/.cargo/env"
export PATH="$HOME/snpguest/target/release:$PATH"
W="$HOME/pask-snp-witness-20260928"; mkdir -p "$W/certs" "$W/keys"; cd "$W"
exec > >(tee -a transcript.log) 2>&1
echo "=== STEP 0 environment"; date -u; uname -a; rustc --version; cargo --version; snpguest --version; ls -l /dev/sev-guest
cp -r "$HOME/snpup/tool" "$W/tool"; cp "$HOME/snpup/payload.template.json" "$W/"
echo "=== STEP 1 build helper from published crates"
(cd tool && cargo build --release --locked 2>&1 | tail -3 && cargo tree --depth 1 | grep -E "pask-attest|pask-wire|ed25519-dalek")
cargo install --locked pask-wire-cli@0.1.0 --root "$W/li" 2>&1 | tail -1
export PATH="$W/li/bin:$PATH"; SW="$W/tool/target/release/snp-witness"
sha256sum "$SW" "$W/li/bin/pask-wire-cli" | tee tool-hashes.txt
echo "=== STEP 2 generate witness key inside the VM"
"$SW" keygen "$W/keys"; chmod 600 keys/witness.priv.pem
echo "(private key written; not printed. OpenSSL 3.0 on this image cannot parse PKCS8 v2 Ed25519 keys; pask-wire-cli does, see step 6)"
echo "=== STEP 3 REPORT_DATA (EXP-SNP-RD-1) and SNP report"
"$SW" report-data keys/witness.pub.pem report-data.bin
sudo "$HOME/snpguest/target/release/snpguest" report report.bin report-data.bin --vmpl 0
sudo chown "$(id -u)" report.bin; ls -l report.bin
snpguest display report report.bin | tee report.display.txt >/dev/null
python3 - <<'PY'
r=open('report.bin','rb').read()
print('helper-decode version', int.from_bytes(r[0:4],'little'))
print('helper-decode report_data', r[0x50:0x90].hex())
print('helper-decode measurement', r[0x90:0xC0].hex())
print('helper-decode report_id', r[0x140:0x160].hex())
PY
echo "--- snpguest display (Report Data / Measurement / Report ID excerpts)"
grep -iA4 "Report Data" report.display.txt | head -6; grep -iA3 "^Measurement" report.display.txt | head -5; grep -iA2 "^Report ID:" report.display.txt | head -4
RDHEX=$(xxd -p report-data.bin | tr -d '\n'); INREP=$(python3 -c "print(open('report.bin','rb').read()[0x50:0x90].hex(),end='')")
[ "$RDHEX" = "$INREP" ] && echo REPORT_DATA_MATCH=yes || { echo REPORT_DATA_MATCH=no; exit 3; }
echo "=== STEP 4 AMD certificate chain"
snpguest fetch ca pem "$W/certs" --report report.bin --endorser vcek
snpguest fetch vcek pem "$W/certs" report.bin
ls -l certs/
snpguest verify certs "$W/certs"
snpguest verify attestation "$W/certs" report.bin
snpguest verify attestation "$W/certs" report.bin --report-data "0x$RDHEX"
echo "=== STEP 5 evidence manifest (EXP-SNP-EV-1) and sealed tar (EXP-SNP-SE-1)"
python3 - <<'PY'
import json,hashlib,glob
def d(p): return "sha256:"+hashlib.sha256(open(p,'rb').read()).hexdigest()
files={p.split('/')[-1]:d(p) for p in ['report.bin','report-data.bin','keys/witness.pub.pem']+sorted(glob.glob('certs/*.pem'))}
m={"format":"wilder.exp.snp-evidence/0","teeClass":"amd.sev-snp",
   "reportDataConvention":"EXP-SNP-RD-1 sha512(spki-der(witness public key))",
   "witnessKey":"key:tee:snp-gcp-20260928-witness-01","files":files}
open('snp-evidence.json','w').write(json.dumps(m,sort_keys=True,separators=(',',':')))
PY
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf snp-sealed.tar report.bin report-data.bin snp-evidence.json certs keys/witness.pub.pem
sha256sum snp-evidence.json snp-sealed.tar
echo "=== STEP 6 wilder.attest/0.1 quote, pask-attest verify, signed statement"
NB=$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ); NA=$(date -u -d '+3 hour' +%Y-%m-%dT%H:%M:%SZ); echo "$NB $NA" > validity.txt
"$SW" quote "$W/keys" key:tee:snp-gcp-20260928-witness-01 report.bin snp-evidence.json snp-sealed.tar "$NB" "$NA"
"$SW" verify keys/witness-quote.bin keys/witness.pub.pem key:tee:snp-gcp-20260928-witness-01
python3 - <<'PY'
import json,datetime
c=json.load(open('keys/witness-quote.claims.json')); p=json.load(open('payload.template.json'))
p['attestation'].update({k:c[k] for k in ('teeClass','measuredBoot','platformEvidence','sealedEvidence','validity','witnessKey')})
p['engagement']['evidenceDigest']=c['platformEvidence']['digest']
p['ts']=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
json.dump(p,open('payload.json','w'),indent=1)
PY
pask-wire-cli produce --input payload.json --private-key keys/witness.priv.pem --output witness-statement.cbor
pask-wire-cli verify --input witness-statement.cbor --public-key keys/witness.pub.pem --output witness-statement.verified.json
ls -l witness-statement.cbor; sha256sum witness-statement.cbor witness-statement.verified.json
echo "=== STEP 7 negative fixtures (wrong key, unknown identifier, non-registry class, expired clock, synthetic report)"
"$SW" keygen "$W/keys-other" >/dev/null
mkdir -p keys-dep && cp keys/witness.priv.pem keys-dep/
SNP_WITNESS_TEE_CLASS_OVERRIDE=amd.sev-snp-v1 "$SW" quote "$W/keys-dep" key:tee:snp-gcp-20260928-witness-01 report.bin snp-evidence.json snp-sealed.tar "$NB" "$NA"
shred -u keys-dep/witness.priv.pem
python3 -c "b=bytearray(open('report.bin','rb').read()); b[0x90]^=1; open('report.synthetic.bin','wb').write(b)"
echo "--- in-VM verifier shape"
"$SW" verify keys/witness-quote.bin keys/witness.pub.pem key:tee:snp-gcp-20260928-witness-01 || true
"$SW" verify keys/witness-quote.bin keys-other/witness.pub.pem key:tee:snp-gcp-20260928-witness-01 || true
"$SW" verify keys/witness-quote.bin keys/witness.pub.pem key:tee:nobody || true
"$SW" verify keys-dep/witness-quote.bin keys/witness.pub.pem key:tee:snp-gcp-20260928-witness-01 || true
"$SW" verify keys/witness-quote.bin keys/witness.pub.pem key:tee:snp-gcp-20260928-witness-01 2027-01-01T00:00:00Z || true
echo "--- synthetic report under snpguest (expect failure)"
snpguest verify attestation "$W/certs" report.synthetic.bin || echo "SYNTHETIC_REJECTED rc=$?"
RD2=$(python3 -c "import hashlib,subprocess;print(hashlib.sha512(subprocess.check_output(['openssl','pkey','-pubin','-in','keys-other/witness.pub.pem','-outform','DER'])).hexdigest())")
snpguest verify attestation "$W/certs" report.bin --report-data "0x$RD2" || echo "KEY_MISMATCH_REJECTED rc=$?"
pask-wire-cli verify --input witness-statement.cbor --public-key keys-other/witness.pub.pem || echo "RECEIPT_WRONG_KEY_REJECTED rc=$?"
echo "=== hashes"
find . -type f ! -name '*.priv.pem' ! -path './tool/target/*' ! -path './li/*' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
wc -l SHA256SUMS; date -u; echo RUN_COMPLETE
