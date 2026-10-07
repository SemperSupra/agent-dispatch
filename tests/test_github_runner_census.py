import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_census", ROOT / "scripts" / "github_runner_census.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)

class PassiveRunnerCensusTests(unittest.TestCase):
    def test_receipt_has_common_contract(self):
        receipt = MOD.build_receipt("test-runner")
        self.assertEqual(receipt["schema"], "github-runner-capability/v1")
        self.assertEqual(receipt["provenance"]["requested_label"], "test-runner")
        self.assertIn("cpu", receipt["resources"])
        self.assertIn("memory", receipt["resources"])
        self.assertIn("storage", receipt["resources"])
        self.assertIsInstance(receipt["capabilities"], list)

    def test_presence_is_not_promoted_to_supported(self):
        cap = MOD._presence_capability("test", True, "evidence")
        self.assertEqual(cap["classification"], "INCONCLUSIVE")
        self.assertTrue(cap["observed"])
        self.assertFalse(cap["exercised"])
        self.assertFalse(cap["oracleSatisfied"])
        self.assertIsNone(cap["callable"])

    def test_absence_is_negative_observation_not_harness_failure(self):
        cap = MOD._presence_capability("test", False)
        self.assertEqual(cap["classification"], "NEGATIVE_OBSERVATION")
        self.assertNotEqual(cap["classification"], "HARNESS_FAILURE")

    def test_windows_hyperv_presence_remains_passive(self):
        evidence = '{"HypervisorPresent":true,"GetVMHostPresent":true,"GetVMSwitchPresent":true,"VMMSPresent":true,"VMMSStatus":"Running"}'
        with mock.patch.object(MOD.shutil, "which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=evidence):
            caps = MOD._windows_hyperv_capabilities()
        self.assertEqual(len(caps), 1)
        cap = caps[0]
        self.assertEqual(cap["name"], "windows:hyperv-control-plane")
        self.assertTrue(cap["observed"])
        self.assertEqual(cap["classification"], "INCONCLUSIVE")
        self.assertFalse(cap["exercised"])
        self.assertFalse(cap["oracleSatisfied"])

    def test_windows_hyperv_absence_is_negative_observation(self):
        evidence = '{"HypervisorPresent":false,"GetVMHostPresent":false,"GetVMSwitchPresent":false,"VMMSPresent":false,"VMMSStatus":null}'
        with mock.patch.object(MOD.shutil, "which", return_value="powershell.exe"), \
             mock.patch.object(MOD, "_run_text", return_value=evidence):
            cap = MOD._windows_hyperv_capabilities()[0]
        self.assertFalse(cap["observed"])
        self.assertEqual(cap["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(cap["oracleSatisfied"])

    def test_environment_is_allowlisted_not_dumped(self):
        receipt = MOD.build_receipt("test-runner")
        self.assertEqual(
            set(receipt["environment"]),
            {
                "github_actions",
                "runner_environment",
                "runner_temp_present",
                "runner_tool_cache_present",
                "cgroup_version",
            },
        )

if __name__ == "__main__":
    unittest.main()
