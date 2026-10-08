from __future__ import annotations

import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runner_runtime_template_contract",
    ROOT / "scripts" / "runner_runtime_template_contract.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)

CATALOG = ROOT / "config" / "runner-runtime-templates.json"


class RunnerRuntimeTemplateContractTests(unittest.TestCase):
    def setUp(self):
        self.doc = MOD.load(CATALOG)

    def test_runner_agent_reference_is_exact_and_cross_platform(self):
        agent = self.doc["runner_agent_reference"]
        self.assertEqual(agent["version"], "2.337.0")
        self.assertEqual(agent["observed_hosted_agent_version"], "2.337.0")
        self.assertEqual(
            set(agent["assets"]),
            {"linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows-x64", "windows-arm64"},
        )
        self.assertEqual(
            agent["assets"]["linux-x64"]["sha256"],
            "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613",
        )
        self.assertEqual(
            agent["linux_x64_oci"]["digest"],
            "sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4",
        )

    def test_runner_agent_drift_fails_closed(self):
        bad = copy.deepcopy(self.doc)
        bad["runner_agent_reference"]["version"] = "latest"
        with self.assertRaises(MOD.ContractError):
            MOD.validate(bad)

    def test_all_censused_gha_reference_classes_are_frozen(self):
        self.assertEqual(set(self.doc["gha_reference_classes"]), MOD.REQUIRED_GHA_CLASSES)

    def test_gha_reference_is_contract_not_hardware_clone(self):
        policy = self.doc["policy"]
        self.assertTrue(policy["gha_reference_is_compatibility_contract_not_hardware_clone"])
        self.assertTrue(policy["performance_observation_is_not_functional_support"])
        self.assertTrue(policy["representative_workload_oracle_required_for_placement"])

    def test_sovereign_gpu_profile_derives_from_compatible_base_and_requires_oracles(self):
        row = self.doc["sovereign_template_candidates"]["truenas-linux-x64-nvidia-gpu"]
        self.assertEqual(row["classification"], "SOVEREIGN_ENHANCED")
        self.assertEqual(row["compatible_base"], "truenas-ubuntu-24.04-x64")
        self.assertNotIn("reference", row)
        self.assertIn("gpu:device-visible-in-runner", row["required_local_oracles"])
        self.assertIn("gpu:bounded-compute-or-inference", row["required_local_oracles"])
        self.assertNotEqual(row["status"], "ADMITTED")

    def test_bigmac_native_enhancement_does_not_imply_gha_parity(self):
        compat = self.doc["sovereign_template_candidates"]["bigmac-macos-26-arm64"]
        enhanced = self.doc["sovereign_template_candidates"]["bigmac-macos-arm64-enhanced"]
        self.assertEqual(compat["status"], "DISCOVERY")
        self.assertEqual(enhanced["compatible_base"], "bigmac-macos-26-arm64")
        self.assertIn("host:macos-26-arm64-exact-version", compat["required_local_oracles"])
        self.assertIn("workload:representative-local-inference", enhanced["required_local_oracles"])

    def test_cross_architecture_parity_is_explicit_not_inherited(self):
        x64 = self.doc["sovereign_template_candidates"]["truenas-ubuntu-24.04-x64"]
        arm = self.doc["sovereign_template_candidates"]["bigmac-ubuntu-24.04-arm64"]
        self.assertEqual(x64["reference"], "ubuntu-24.04")
        self.assertEqual(arm["reference"], "ubuntu-24.04-arm")
        self.assertNotEqual(
            self.doc["gha_reference_classes"][x64["reference"]]["architecture"],
            self.doc["gha_reference_classes"][arm["reference"]]["architecture"],
        )

    def test_enhanced_on_enhanced_inheritance_fails_closed(self):
        bad = copy.deepcopy(self.doc)
        bad["sovereign_template_candidates"]["truenas-linux-x64-high-throughput"][
            "compatible_base"
        ] = "truenas-linux-x64-nvidia-gpu"
        with self.assertRaises(MOD.ContractError):
            MOD.validate(bad)

    def test_unknown_reference_fails_closed(self):
        bad = copy.deepcopy(self.doc)
        bad["sovereign_template_candidates"]["truenas-ubuntu-24.04-x64"][
            "reference"
        ] = "ubuntu-latest"
        with self.assertRaises(MOD.ContractError):
            MOD.validate(bad)

    def test_acceptance_rungs_are_ordered_t0_through_t8(self):
        self.assertEqual(list(self.doc["acceptance_rungs"]), [f"T{i}" for i in range(9)])


if __name__ == "__main__":
    unittest.main()
