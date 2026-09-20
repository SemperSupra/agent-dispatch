import importlib.util
import pathlib
import unittest

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
