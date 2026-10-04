"""Local reconstruction of checkpoint-01 transform; original script not supplied.

Preserves raw source; duplicates/collisions fail before conversion.
"""
import argparse
import collections
import copy
import hashlib
import itertools
import json
from pathlib import Path

OLD, NEW = "robot-signed", "robot-attributed"
EXPECTED = "e8c1a2c028114c82523514e4aab686692d2c9409ed343467ef6c6ba070adf0b0"

def unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key: " + k)
        d[k] = v
    return d

def validate(v):
    parties, bases = v["assertedBy"], v["basis"]
    assert len(parties) == len(set(parties)) == 7
    assert set(bases) == {"measured", "estimated", "declared"}
    assert len(v["facts"]) == len({f["name"] for f in v["facts"]}) == 46
    g = v["globalRules"]
    assert set(g["basisByParty"]) <= set(parties)
    assert set(g["evidenceRequiredByParty"]) <= set(parties)
    for bs in g["basisByParty"].values():
        assert set(bs) <= set(bases)
    for f in v["facts"]:
        assert set(f["assertedBy"]) <= set(parties)
        assert len(f["assertedBy"]) == len(set(f["assertedBy"]))
        assert set(f["basis"]) <= set(bases)
        for p, b in f.get("pairsForbidden", []):
            assert p in parties and b in bases

def relation(v):
    # Explicit expected relation. Rust uses independently written decision logic.
    return {(f["name"], p, b) for f in v["facts"]
            for p in f["assertedBy"] for b in f["basis"]
            if b in v["globalRules"]["basisByParty"].get(p, [])
            and [p, b] not in f.get("pairsForbidden", [])}

def migrate(v):
    validate(v)
    assert OLD in v["assertedBy"] and NEW not in v["assertedBy"], "party collision"
    assert NEW not in v["globalRules"]["basisByParty"], "key collision"
    out, inventory = copy.deepcopy(v), []
    def rename_list(values, path, category, fact=None):
        for i, item in enumerate(values):
            if item == OLD:
                values[i] = NEW
                inventory.append(dict(path=f"{path}[{i}]", category=category,
                                      fact=fact, before=OLD, after=NEW))
    rename_list(out["assertedBy"], "$.assertedBy", "enumeration")
    for i, f in enumerate(out["facts"]):
        rename_list(f["assertedBy"], f"$.facts[{i}].assertedBy", "fact-allowlist", f["name"])
        for j, pair in enumerate(f.get("pairsForbidden", [])):
            if pair[0] == OLD:
                pair[0] = NEW
                inventory.append(dict(path=f"$.facts[{i}].pairsForbidden[{j}][0]",
                                      category="pairsForbidden", fact=f["name"], before=OLD, after=NEW))
    g = out["globalRules"]
    rename_list(g["evidenceRequiredByParty"], "$.globalRules.evidenceRequiredByParty",
                "evidenceRequiredByParty")
    g["basisByParty"] = {NEW if k == OLD else k: x for k, x in g["basisByParty"].items()}
    inventory.append(dict(path="$.globalRules.basisByParty['robot-signed']",
                          category="basisByParty-KEY", fact=None, before=OLD, after=NEW))
    validate(out)
    mapped = {(n, NEW if p == OLD else p, b) for n, p, b in relation(v)}
    assert relation(out) == mapped
    # Semantic reverse comparison guards every unrelated value and constraint.
    reverse = json.loads(json.dumps(out).replace(NEW, OLD))
    assert reverse == v
    return out, inventory

def main():
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("evidence_dir", type=Path)
    a = p.parse_args()
    raw = a.source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    v = json.loads(raw, object_pairs_hook=unique)
    out, inv = migrate(v)
    data = (json.dumps(out, sort_keys=True, indent=2) + "\n").encode()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_bytes(data)
    a.evidence_dir.mkdir(parents=True, exist_ok=True)
    def save(name, x):
        (a.evidence_dir / name).write_text(json.dumps(x, indent=2, sort_keys=True) + "\n")
    counts = dict(collections.Counter(i["category"] for i in inv))
    assert counts == {"enumeration": 1, "fact-allowlist": 33, "pairsForbidden": 1,
                      "evidenceRequiredByParty": 1, "basisByParty-KEY": 1}
    allowed = relation(out)
    raw_count = sum(len(f["assertedBy"])*len(f["basis"]) for f in out["facts"])
    global_count = sum(b in out["globalRules"]["basisByParty"].get(p, [])
                       for f in out["facts"] for p in f["assertedBy"] for b in f["basis"])
    assert (raw_count, global_count, len(allowed)) == (191, 154, 153)
    triples = [dict(name=f["name"], party=party, basis=basis,
                    allowed=(f["name"], party, basis) in allowed)
               for f, party, basis in itertools.product(out["facts"], out["assertedBy"], out["basis"])]
    assert len(triples) == 966
    save("rename-inventory.json", inv)
    save("expected-relation.json", triples)
    save("rule-comparison.json", dict(source_sha256=EXPECTED,
         output_sha256=hashlib.sha256(data).hexdigest(), categories=counts,
         before_allowed=len(relation(v)), after_allowed=len(allowed), differences=[],
         accepted_expected_allowed=153, accepted_expected_forbidden=813,
         accepted_relation_matches=len(allowed)==153,
         historical_incorrect_reported_allowed=191,
         unfiltered_fact_cross_product=raw_count, after_global_rules=global_count,
         after_forbidden_pair=len(allowed),
         semantic_reverse_equal=True,
         affected_facts=[i["fact"] for i in inv if i["category"] == "fact-allowlist"],
         singletons={f["name"]: f["assertedBy"] for f in out["facts"] if len(f["assertedBy"]) == 1}))
    assert a.source.read_bytes() == raw
    print(json.dumps(dict(locations=len(inv), categories=counts, combinations=len(triples),
                         allowed=len(allowed), forbidden=len(triples)-len(allowed),
                         output_sha256=hashlib.sha256(data).hexdigest()), indent=2))

if __name__ == "__main__":
    main()
