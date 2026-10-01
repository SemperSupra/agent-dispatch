import copy,json,pathlib,unittest
from scripts.validate_compute_guest_fixtures import FixtureError, validate
ROOT=pathlib.Path(".")
def cfg(): return json.loads((ROOT/"config/compute-guest-fixtures.json").read_text())
class FixtureTests(unittest.TestCase):
    def test_current_contract(self): self.assertEqual(validate(cfg(),ROOT)["status"],"PASS")
    def test_v1_digest_fail_closed(self):
        c=cfg(); c["linux_v1"]["source"]["sha256"]="bad"
        with self.assertRaises(FixtureError): validate(c,ROOT)
    def test_v2_inner_guest_cannot_be_pretend_pinned(self):
        c=cfg(); c["firecracker_v2"]["inner_microvm"]["kernel"]["state"]="PINNED"
        with self.assertRaises(FixtureError): validate(c,ROOT)
    def test_windows_cannot_claim_winbot_early(self):
        c=cfg(); c["windows_w1"]["winbot_backend_status"]="ELIGIBLE"
        with self.assertRaises(FixtureError): validate(c,ROOT)
if __name__=="__main__": unittest.main()
