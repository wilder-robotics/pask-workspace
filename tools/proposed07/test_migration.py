import copy
import json
import unittest
from pathlib import Path
from migrate_vocab import migrate, unique, validate, relation, OLD, NEW

R = Path(__file__).resolve().parents[2]
class MigrationTests(unittest.TestCase):
    def test_accepted_stage_counts(self):
        v = self.v
        raw = sum(len(f["assertedBy"])*len(f["basis"]) for f in v["facts"])
        glob = sum(b in v["globalRules"]["basisByParty"].get(p, [])
                   for f in v["facts"] for p in f["assertedBy"] for b in f["basis"])
        self.assertEqual((raw,glob,len(relation(v))),(191,154,153))
    def setUp(self):
        # Reconstruct old spelling in memory, never modify frozen source bytes.
        self.v=json.loads((R/"schemas/proposed/pser-0.7/content-vocabulary.json").read_text().replace(NEW,OLD))
    def test_locations(self):
        out,inv=migrate(self.v)
        self.assertEqual(len(inv),37)
        self.assertEqual(len([r for r in inv if r["category"]=="fact-allowlist"]),33)
        self.assertEqual(len(relation(out)),len(relation(self.v)))
    def test_duplicate_keys(self):
        with self.assertRaises(ValueError):
            json.loads('{"x":1,"x":2}',object_pairs_hook=unique)
    def test_collision(self):
        self.v["globalRules"]["basisByParty"][NEW]=["declared"]
        with self.assertRaises(AssertionError): migrate(self.v)
    def test_unknown_at_each_location(self):
        cases=[]
        for key in ("assertedBy",):
            x=copy.deepcopy(self.v);x["facts"][0][key].append("unknown");cases.append(x)
        x=copy.deepcopy(self.v);x["globalRules"]["basisByParty"]["unknown"]=[];cases.append(x)
        x=copy.deepcopy(self.v);x["globalRules"]["evidenceRequiredByParty"].append("unknown");cases.append(x)
        x=copy.deepcopy(self.v);x["facts"][9]["pairsForbidden"][0][0]="unknown";cases.append(x)
        for x in cases:
            with self.assertRaises(AssertionError): validate(x)
    def test_effective_rules_and_evidence_preserved(self):
        o,_=migrate(self.v)
        self.assertEqual(o["globalRules"]["basisByParty"][NEW],
                         self.v["globalRules"]["basisByParty"][OLD])
        self.assertIn(NEW,o["globalRules"]["evidenceRequiredByParty"])
        self.assertEqual(o["facts"][9]["pairsForbidden"],[[NEW,"measured"]])
        self.assertEqual(json.loads(json.dumps(o).replace(NEW,OLD)),self.v)
if __name__=="__main__": unittest.main()
