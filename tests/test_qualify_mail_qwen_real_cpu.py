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

    def test_engine_magic_is_binary_not_double_escaped_string(self):
        self.assertEqual(bytes.fromhex("7f454c46"), bytes([127,69,76,70]))
        self.assertNotEqual(bytes.fromhex("7f454c46"), b"\\\\x7fELF")

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

    def test_real_model_json_output_parsing_has_independent_fixtures(self):
        cases = {
            '{"source_id":"a1","value":"120"}': ("a1","120"),
            '{"value":"approved","source_id":"a4"}': ("a4","approved"),
            'model header\\n{"source_id":"NONE","value":"UNKNOWN"}\\n': ("NONE","UNKNOWN"),
            'prefix {not-json} {"source_id":"a3","value":"denied"}': ("a3","denied"),
        }
        for output,expected in cases.items():
            with self.subTest(output=output):
                parsed=q.parse_model_json(output)
                self.assertEqual((parsed.get("source_id"),parsed.get("value")),expected)
        for bad in ('no braces', '{"source_id":"a1"}',
                    '{"source_id":"a1","value":"120","extra":"ignore"}',
                    '{"nested":{"source_id":"a1","value":"120"}}'):
            with self.subTest(bad=bad):
                self.assertEqual(q.parse_model_json(bad),{})

    def test_second_oracle_rejects_forged_model_citation_and_exact_count(self):
        import verify_gha_typed_receipt as verifier
        tasks=verifier.MODEL_HOLDOUT_GOLD
        cases=[
            {"id":identifier,"language":language,
             "source_id":source,"value":value,
             "valid_json":True,"exact":True,
             "incorrect_source":False,"abstained":source=="NONE",
             "duration_ms":1,"output_sha256":"a"*64}
            for identifier,(language,source,value) in tasks.items()
        ]
        metric=verifier.grade_public_model_cases(cases)
        self.assertEqual(metric["exact"],7)
        self.assertEqual(metric["valid"],7)
        cases[0]["source_id"]="a2"
        with self.assertRaisesRegex(verifier.VerdictError,"MODEL_CASE_ORACLE_MISMATCH"):
            verifier.grade_public_model_cases(cases)
        cases[0]["source_id"]="b1"
        cases[0]["exact"]=False
        with self.assertRaisesRegex(verifier.VerdictError,"MODEL_CASE_ORACLE_MISMATCH"):
            verifier.grade_public_model_cases(cases)

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
