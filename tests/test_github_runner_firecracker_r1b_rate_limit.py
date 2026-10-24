import importlib.util, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r1b",ROOT/"scripts"/"github_runner_firecracker_r1b_rate_limit.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class R1bTests(unittest.TestCase):
    def test_rate(self):
        self.assertEqual(MOD.LIMIT_BPS,16*1024*1024)
    def test_schema(self):
        self.assertEqual(MOD.SCHEMA,"firecracker-r1b-block-rate-limit/v1")
if __name__=="__main__": unittest.main()
