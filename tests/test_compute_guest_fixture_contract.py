import copy, json, pathlib, unittest
from scripts.compute_guest_fixture_contract import FixtureError, validate

ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE=json.loads((ROOT/"config"/"compute-guest-fixtures.json").read_text(encoding="utf-8"))

class Tests(unittest.TestCase):
    def test_current_contract(self):
        self.assertEqual(validate(copy.deepcopy(BASE))["status"],"PASS")

    def test_firecracker_digest_is_exact(self):
        p=copy.deepcopy(BASE)
        p["fixtures"]["firecracker_x86_64"]["sha256"]="latest"
        with self.assertRaises(FixtureError):
            validate(p)

    def test_windows_key_is_prohibited(self):
        p=copy.deepcopy(BASE)
        p["fixtures"]["windows11_enterprise_eval_x64"]["product_key_required"]=True
        with self.assertRaises(FixtureError):
            validate(p)

    def test_windows_media_cannot_be_pretend_pinned(self):
        p=copy.deepcopy(BASE)
        p["fixtures"]["windows11_enterprise_eval_x64"]["expected_sha256"]="0"*64
        with self.assertRaises(FixtureError):
            validate(p)

    def test_runtime_claims_remain_open(self):
        result=validate(copy.deepcopy(BASE))
        self.assertEqual(result["runtime_claims"],"OPEN")

if __name__=="__main__":
    unittest.main()
