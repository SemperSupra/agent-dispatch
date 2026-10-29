import importlib.util, pathlib, unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("fit",ROOT/"scripts"/"github_runner_firecracker_fit.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class FitTests(unittest.TestCase):
    def test_no_kvm_is_valid_blocked_observation(self):
        with (
            mock.patch.object(MOD.platform,"system",return_value="Linux"),
            mock.patch.object(MOD.platform,"machine",return_value="aarch64"),
            mock.patch.object(MOD,"_kvm_observation",return_value={"user":{"present":False,"callable":False},"sudo":{"callable":False}}),
        ):
            r=MOD.run_probe("arm","preflight")
        self.assertEqual(r["result"]["classification"],"BLOCKED_NO_KVM")
        self.assertFalse(r["result"]["firecracker_guest_exercised"])
if __name__=="__main__": unittest.main()
