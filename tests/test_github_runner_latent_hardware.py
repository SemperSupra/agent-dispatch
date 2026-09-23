import sys
import unittest
from unittest import mock

sys.path.insert(0, "scripts")
import github_runner_latent_hardware as m


class LatentHardwareTests(unittest.TestCase):
    def test_cap_preserves_evidence_ladder(self):
        cap = m._cap(
            "x", observed=True, installed=True, callable_=False,
            exercised=True, oracle=False, classification="ORACLE_FAILURE",
            reason="bounded failure", evidence={"n": 1},
        )
        self.assertTrue(cap["observed"])
        self.assertFalse(cap["oracleSatisfied"])
        self.assertEqual(cap["classification"], "ORACLE_FAILURE")

    @mock.patch.object(m.platform, "system", return_value="Linux")
    def test_metal_is_guardrailed_off_non_macos(self, _system):
        cap = m.probe_macos_metal()
        self.assertEqual(cap["classification"], "SKIPPED_GUARDRAIL")

    @mock.patch.object(m.platform, "system", return_value="Darwin")
    @mock.patch.object(m, "_compile_run_macos")
    def test_metal_requires_real_oracle(self, compile_run, _system):
        compile_run.return_value = ("OK", {"metal_device": True, "oracle": True, "name": "Test GPU"})
        cap = m.probe_macos_metal()
        self.assertEqual(cap["classification"], "SUPPORTED")
        self.assertTrue(cap["oracleSatisfied"])

    @mock.patch.object(m.platform, "system", return_value="Darwin")
    @mock.patch.object(m, "_compile_run_macos")
    def test_coreml_presence_is_not_execution_claim(self, compile_run, _system):
        compile_run.return_value = (
            "OK",
            {"classes": ["MLCPUComputeDevice", "MLGPUComputeDevice", "MLNeuralEngineComputeDevice"]},
        )
        caps = {c["name"]: c for c in m.probe_macos_coreml_devices()}
        self.assertEqual(caps["macos:coreml-compute-device-enumeration"]["classification"], "SUPPORTED")
        for name in (
            "macos:coreml-cpu-surface",
            "macos:coreml-gpu-surface",
            "macos:coreml-neural-engine-surface",
        ):
            self.assertEqual(caps[name]["classification"], "INCONCLUSIVE")
            self.assertFalse(caps[name]["oracleSatisfied"])

    @mock.patch.object(m.platform, "system", return_value="Linux")
    @mock.patch.object(m, "_existing", return_value=[])
    @mock.patch.object(m, "_pci_accelerators", return_value=[])
    @mock.patch.object(m.shutil, "which", return_value=None)
    def test_linux_absence_is_negative_observation(self, _which, _pci, _existing, _system):
        caps = {c["name"]: c for c in m.probe_linux_surfaces()}
        self.assertEqual(caps["linux:rdma-device-surface"]["classification"], "NEGATIVE_OBSERVATION")
        self.assertEqual(caps["linux:fpga-device-surface"]["classification"], "NEGATIVE_OBSERVATION")
        self.assertEqual(caps["linux:gpu-dri-render-surface"]["classification"], "NEGATIVE_OBSERVATION")


if __name__ == "__main__":
    unittest.main()
