"""Run real Rust classifications and compare to explicit Python expected relation.

Separate decision implementations; shared pinned vocabulary, not independent
authentication, evidence verification or a second cryptographic implementation.
"""
from pathlib import Path
import argparse
import json
import subprocess

p=argparse.ArgumentParser()
p.add_argument("binary",type=Path);p.add_argument("evidence",type=Path)
a=p.parse_args()
expected=json.loads((a.evidence/"expected-relation.json").read_text())
r=subprocess.run([str(a.binary)],input=json.dumps(expected).encode(),capture_output=True)
(a.evidence/"rust-classifier.stdout").write_bytes(r.stdout)
(a.evidence/"rust-classifier.stderr").write_bytes(r.stderr)
assert r.returncode==0
actual=json.loads(r.stdout)
assert len(actual)==len(expected)==966
diff=[dict(row=row,observed=result) for row,result in zip(expected,actual)
      if (result=="PERMITTED") != row["allowed"]]
assert not diff
assert actual.count("PERMITTED")==153 and actual.count("ATTRIBUTION_FORBIDDEN")==813
result=dict(classifications=966,allowed=actual.count("PERMITTED"),
    forbidden=actual.count("ATTRIBUTION_FORBIDDEN"),mismatches=diff,
    accepted_153_813_gate_met=True,
    historical_incorrect_reported_allowed=191,
    scope="party/basis layer only; typed values/evidence/commitments are separate")
(a.evidence/"rust-comparison.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result,indent=2))
