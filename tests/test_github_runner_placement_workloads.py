import importlib.util,pathlib,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("placement",ROOT/"scripts"/"github_runner_placement_workloads.py")
MOD=importlib.util.module_from_spec(SPEC);assert SPEC.loader;SPEC.loader.exec_module(MOD)

class Tests(unittest.TestCase):
    def test_slim_wrong_label_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"):
            r=MOD.slim_contract("ubuntu-26.04")
        self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")

    def test_arm_wrong_arch_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"),              mock.patch.object(MOD.platform,"machine",return_value="x86_64"):
            r=MOD.arm_native_artifact("ubuntu-26.04")
        self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")

    def test_receipt_has_no_score(self):
        r=MOD.base("ubuntu-slim","x")
        self.assertNotIn("score",r)
        self.assertIn("not a runner ranking",r["warnings"][0])

if __name__=="__main__":unittest.main()
