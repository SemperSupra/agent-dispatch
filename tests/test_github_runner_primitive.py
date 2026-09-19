import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_primitive", ROOT / "scripts" / "github_runner_primitive.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)

class PrimitiveTests(unittest.TestCase):
    def test_missing_kvm_is_negative_data(self):
        with mock.patch.object(MOD.platform, "system", return_value="Linux"),              mock.patch.object(MOD.pathlib.Path, "exists", return_value=False):
            cap = MOD.probe_kvm_api()
        self.assertEqual(cap["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(cap["exercised"])

    def test_docker_failure_is_oracle_failure_not_harness_failure(self):
        with mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/docker"),              mock.patch.object(MOD, "_run", return_value=(1, "", "daemon unavailable")):
            cap = MOD.probe_docker_daemon()
        self.assertEqual(cap["classification"], "ORACLE_FAILURE")
        self.assertTrue(cap["exercised"])
        self.assertFalse(cap["oracleSatisfied"])

    def test_docker_success_requires_server_response(self):
        with mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/docker"),              mock.patch.object(MOD, "_run", return_value=(0, '{"Platform":{"Name":"Docker Engine"}}', "")):
            cap = MOD.probe_docker_daemon()
        self.assertEqual(cap["classification"], "SUPPORTED")
        self.assertTrue(cap["oracleSatisfied"])

    def test_rosetta_wrong_platform_skips(self):
        with mock.patch.object(MOD.platform, "system", return_value="Linux"):
            cap = MOD.probe_rosetta()
        self.assertEqual(cap["classification"], "SKIPPED_GUARDRAIL")

if __name__ == "__main__":
    unittest.main()
