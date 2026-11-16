"""Offline, no-network source/rights/task-leakage controls for actual model lane."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import qualify_mail_qwen_real_cpu as q


class RealCpuModelAdmissionTests(unittest.TestCase):
    def test_hard_pinned_model_and_backend(self):
        self.assertEqual(q.LLAMA_COMMIT,"b4c0e00a4fcc0287d0bb32fd7cb0d8b286af73ed")
        self.assertEqual(q.LLAMA_RELEASE,"b12428")
        self.assertEqual(q.LLAMA_ASSET_SHA256,"a9b243a3bc4ca172010e96c64062fc02afd1dc4f8b699716f813ae6845ada4c6")
        self.assertEqual(q.MODEL_COMMIT,"9217f5db79a29953eb74d5343926648285ec7e67")
        self.assertEqual(q.MODEL_SHA256,"9ee36184e616dfc76df4f5dd66f908dbde6979524ae36e6cefb67f532f798cb8")
        self.assertEqual(q.MODEL_REPO,"Qwen/Qwen2.5-0.5B-Instruct-GGUF")
        self.assertTrue(q.MODEL_URL.startswith("https://huggingface.co/Qwen/"))
        self.assertTrue(q.MODEL_URL.endswith("/qwen2.5-0.5b-instruct-q2_k.gguf"))
        self.assertEqual(q.LLAMA_REPO,"https://github.com/ggml-org/llama.cpp.git")
        self.assertEqual(q.MAX_MODEL_BYTES,460_000_000)

    def test_dev_holdout_and_accounts_are_separated(self):
        self.assertEqual(q.RUNS,2*(len(q.DEV)+len(q.HOLDOUT)))
        self.assertEqual(len(q.DEV),3)
        self.assertEqual(len(q.HOLDOUT),7)
        self.assertFalse({x[0] for x in q.DEV}&{x[0] for x in q.HOLDOUT})
        self.assertEqual({x[1] for x in q.HOLDOUT},{"en","de","th"})
        self.assertEqual(len(q.RECORDS),8)
        self.assertEqual(sum(r["tenant"]=="beta" for r in q.RECORDS),1)
        for policy in q.POLICIES:
            prompt=q.prompt(policy,"Find source")
            self.assertIn("EVIDENCE for tenant alpha:",prompt)
            self.assertNotIn("Confidential starling marker",prompt)
            self.assertNotIn("beta-only",prompt)

    def test_no_answer_leaks_into_model_prompt(self):
        for _,_,question,answer,expected_value in q.HOLDOUT:
            prompt=q.prompt("plain",question)
            self.assertIn(question,prompt)
            self.assertNotIn("ExpectedValue",prompt)
            self.assertNotIn("ground_truth",prompt)
        self.assertEqual(q.POLICIES,("plain","evidence-first"))
        self.assertEqual(q.IDS[-1],"NONE")

    def test_independent_metric_is_not_self_graded_promotion(self):
        measured=[
            {"exact":False,"valid_json":False,"incorrect_source":True,
             "abstained":False,"duration_ms":32},
            {"exact":True,"valid_json":True,"incorrect_source":False,
             "abstained":False,"duration_ms":20}]
        metric=q.metrics(measured)
        self.assertEqual(metric["exact"],1)
        self.assertEqual(metric["unsupported_source"],1)
        self.assertEqual(metric["count"],2)
        self.assertEqual(metric["total_inference_ms"],52)


if __name__=="__main__":
    unittest.main()
