from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

SPEC_CONTRACT = importlib.util.spec_from_file_location(
    "runner_runtime_template_contract",
    ROOT / "scripts" / "runner_runtime_template_contract.py",
)
CONTRACT = importlib.util.module_from_spec(SPEC_CONTRACT)
assert SPEC_CONTRACT and SPEC_CONTRACT.loader
SPEC_CONTRACT.loader.exec_module(CONTRACT)

SPEC_PROBE = importlib.util.spec_from_file_location(
    "runner_runtime_template_probe",
    ROOT / "scripts" / "runner_runtime_template_probe.py",
)
PROBE = importlib.util.module_from_spec(SPEC_PROBE)
assert SPEC_PROBE and SPEC_PROBE.loader
SPEC_PROBE.loader.exec_module(PROBE)

CATALOG = ROOT / "config" / "runner-runtime-templates.json"


def receipt(system: str, arch: str):
    return {
        "schema": "github-runner-capability/v1",
        "runner": {
            "system": system,
            "architecture": arch,
            "machine": arch,
        },
    }


class RunnerRuntimeTemplatePassiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.catalog = CONTRACT.load(CATALOG)

    def test_linux_x64_match_is_inconclusive_not_admitted(self):
        result = PROBE.evaluate_passive(
            self.catalog,
            "truenas-ubuntu-24.04-x64",
            receipt("Linux", "x86_64"),
        )
        self.assertTrue(result["passive_platform_arch_match"])
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertFalse(result["oracleSatisfied"])
        self.assertFalse(result["t3_primitive_oracles_claimed"])
        self.assertFalse(result["t4_representative_workloads_claimed"])
        self.assertFalse(result["placement_admitted"])

    def test_cross_architecture_mismatch_is_negative(self):
        result = PROBE.evaluate_passive(
            self.catalog,
            "bigmac-ubuntu-24.04-arm64",
            receipt("Linux", "x86_64"),
        )
        self.assertFalse(result["passive_platform_arch_match"])
        self.assertEqual(result["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(result["placement_admitted"])

    def test_enhanced_profile_resolves_through_compatible_base_reference(self):
        result = PROBE.evaluate_passive(
            self.catalog,
            "truenas-linux-x64-nvidia-gpu",
            receipt("Linux", "amd64"),
        )
        self.assertEqual(result["candidate_classification"], "SOVEREIGN_ENHANCED")
        self.assertEqual(result["compatible_base"], "truenas-ubuntu-24.04-x64")
        self.assertEqual(result["reference"], "ubuntu-24.04")
        self.assertIn("gpu:device-visible-in-runner", result["required_local_oracles"])
        self.assertFalse(result["placement_admitted"])

    def test_macos_arm_normalization(self):
        result = PROBE.evaluate_passive(
            self.catalog,
            "bigmac-macos-26-arm64",
            receipt("Darwin", "arm64"),
        )
        self.assertTrue(result["passive_platform_arch_match"])
        self.assertEqual(result["observed"]["platform"], "macos")
        self.assertEqual(result["observed"]["architecture"], "arm64")

    def test_unknown_candidate_fails_closed(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.evaluate_passive(self.catalog, "ubuntu-latest-local", receipt("Linux", "x86_64"))


if __name__ == "__main__":
    unittest.main()
