"""Offline contract controls; no model downloads or inference in unit tests."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import qualify_mail_qwen_real_cpu as q
import verify_mail_qwen_cases as v


def fixture_result():
    rows = []
    for identifier,(source,value,scope) in v.GOLD.items():
        for policy in v.POLICIES:
            rows.append([identifier,policy,scope,"OK",source,value,"a"*64,"b"*64,1])
    return {**v.PINS,"model_inference":True,"automatic_promotion":False,
            "corpus_sha256":q.corpus_digest(),"model_calls":20,"rows":rows}


class RealModelContract(unittest.TestCase):
    def test_frozen_scope_and_pins(self):
        self.assertEqual(q.MODEL_SHA256,v.PINS["model_sha256"])
        self.assertEqual(q.LLAMA_COMMIT,v.PINS["engine_commit"])
        self.assertEqual(q.LLAMA_ASSET_SHA256,v.PINS["engine_asset_sha256"])
        dev = set()
        held = set()
        for task in q.TASKS:
            ids = q.scope_ids(task)
            self.assertEqual(",".join(ids),v.GOLD[task[0]][2])
            (dev if task[1]=="dev" else held).update(ids)
            text = q.prompt("plain",task)
            self.assertNotIn("beta-only",text)
            self.assertNotIn("GOLD",text)
            for excluded in set(r[0] for r in q.RECORDS)-set(ids):
                self.assertNotIn("ID="+excluded+" |",text)
        self.assertFalse(dev&held)
        self.assertEqual(len(q.TASKS)*len(q.POLICIES),q.RUNS)
        self.assertFalse({r[5] for r in q.RECORDS if r[1]=="dev"} &
                         {r[5] for r in q.RECORDS if r[1]=="heldout"})

    def test_strict_parser(self):
        for raw in (b'{"source_id":"a1","value":"120"}',
                    b' \n{"value":"120","source_id":"a1"}\n'):
            self.assertEqual(q.parse_model_json(raw,("a1",)),("OK","a1","120"))
        for raw in (
            b'prefix {"source_id":"a1","value":"120"}',
            b'{"source_id":"a1","value":"120"}{}',
            b'{"source_id":"a1","source_id":"a2","value":"120"}',
            b'{"nested":{"source_id":"a1","value":"120"}}',
            b'{"source_id":"a1","value":"120","extra":1}',
            b'{"source_id":"a1","value":120}',
            b'{"source_id":"a1","value":"UNKNOWN"}',
            b'{"source_id":"NONE","value":"120"}',
            b'{"source_id":"beta1","value":"120"}',
            b'{"source_id":"a1","value":"120"}\xff',
            b'x'*8193,
        ):
            self.assertNotEqual(q.parse_model_json(raw,("a1",))[0],"OK",raw[:100])
        self.assertEqual(q.parse_model_json(b'{"source_id":"NONE","value":"UNKNOWN"}',
                         ("a1",)),("OK","NONE","UNKNOWN"))

    def test_independent_dev_selection_and_holdout_nonpromotion(self):
        doc=fixture_result()
        got=v.grade(doc)
        self.assertEqual(got["selected_on_dev"],"plain")
        self.assertEqual(got["scores"]["plain"]["heldout"]["exact"],7)
        self.assertEqual(got["promotion"],"HOLD")
        for row in doc["rows"]:
            if row[0].startswith("D") and row[1]=="plain":
                row[3:6]=["JSON_INVALID","INVALID","INVALID"]
            if row[0].startswith("H") and row[1]=="evidence-first":
                row[3:6]=["JSON_INVALID","INVALID","INVALID"]
        got=v.grade(doc)
        self.assertEqual(got["selected_on_dev"],"evidence-first")
        self.assertEqual(got["scores"]["evidence-first"]["heldout"]["exact"],0)
        self.assertFalse(got["exploratory_quality_gate"])
        self.assertEqual(got["promotion"],"HOLD")

    def test_tampered_receipt_rejected(self):
        for index,value in ((0,"H99"),(1,"unreviewed"),(2,"beta1"),
                            (3,"PASS"),(4,"beta1"),(6,"bad"),(8,True)):
            doc=fixture_result()
            doc["rows"][0][index]=value
            with self.assertRaises(ValueError):
                v.grade(doc)
        doc=fixture_result()
        doc["rows"][0]=list(doc["rows"][1])
        with self.assertRaises(ValueError):
            v.grade(doc)
        doc=fixture_result()
        doc["automatic_promotion"]=True
        with self.assertRaises(ValueError):
            v.grade(doc)

if __name__=="__main__":
    unittest.main()
