import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "container_substrate_qualification",
    ROOT / "scripts" / "container_substrate_qualification.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class ContainerSubstrateTests(unittest.TestCase):
    def test_host_census_has_core_identity(self):
        census = MOD.host_census()
        self.assertIn("system", census)
        self.assertIn("machine", census)
        self.assertIn("logical_cpus", census)

    def test_windows_missing_runtime_is_negative_observation(self):
        with mock.patch.object(MOD, "command", return_value=None), \
             mock.patch.object(MOD, "host_census", return_value={}):
            result = MOD.lane_windows()
        self.assertEqual(result["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(result["oracleSatisfied"])

    def test_apple_missing_runtime_is_negative_observation(self):
        with mock.patch.object(MOD, "command", return_value=None), \
             mock.patch.object(MOD, "host_census", return_value={}):
            result = MOD.lane_apple()
        self.assertEqual(result["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(result["oracleSatisfied"])

    def test_lxc_missing_tools_is_negative_observation(self):
        with mock.patch.object(MOD, "command", return_value=None), \
             mock.patch.object(MOD, "host_census", return_value={}):
            result = MOD.lane_lxc()
        self.assertEqual(result["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(result["oracleSatisfied"])

    def test_incus_missing_runtime_is_negative_observation(self):
        with mock.patch.object(MOD, "command", return_value=None), \
             mock.patch.object(MOD, "host_census", return_value={}):
            result = MOD.lane_incus()
        self.assertEqual(result["classification"], "NEGATIVE_OBSERVATION")
        self.assertFalse(result["oracleSatisfied"])

    def test_run_failure_is_evidence_not_exception(self):
        with mock.patch.object(MOD.subprocess, "run", side_effect=OSError("boom")):
            result = MOD.run(["nope"])
        self.assertIsNone(result["exit_code"])
        self.assertIn("OSError", result["stderr"])

    def test_linux_inner_census_names_required_sections(self):
        for section in (
            "UNAME", "CPU", "MEMINFO", "CGROUP", "MOUNTS",
            "NETWORK", "ROUTES", "DNS", "DNS_ORACLE", "TCP_443_ORACLE", "HTTPS_EGRESS",
            "DEVICES", "FILESYSTEM", "IDENTITY",
        ):
            self.assertIn(f"==={section}===", MOD.LINUX_INNER)

    def test_bridge_nat_unavailable_off_linux_is_data(self):
        with mock.patch.object(MOD.platform, "system", return_value="Darwin"):
            result = MOD.ensure_bridge_nat("test0")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["created"], [])

    def test_parse_sections_returns_structured_evidence(self):
        parsed = MOD.parse_sections("===CPU===\n4\n===HTTPS_EGRESS===\nPASS\n")
        self.assertEqual(parsed["CPU"], "4")
        self.assertEqual(parsed["HTTPS_EGRESS"], "PASS")

    def test_parse_json_stdout_requires_valid_successful_json(self):
        self.assertEqual(
            MOD.parse_json_stdout({"exit_code": 0, "stdout": '{"ok":true}'}),
            {"ok": True},
        )
        self.assertIsNone(MOD.parse_json_stdout({"exit_code": 1, "stdout": '{"ok":true}'}))
        self.assertIsNone(MOD.parse_json_stdout({"exit_code": 0, "stdout": "truncated"}))


    def test_lxc_capability_projection_keeps_observed_separate_from_supported(self):
        receipt = {
            "lane": "lxc",
            "oracleSatisfied": True,
            "classification": "SUPPORTED",
            "reason": "ok",
            "isolation": "shared-linux-kernel-system-container",
            "host": {"machine": "x86_64"},
            "container_census": {
                "DEVICES": "MISSING /dev/kvm\ncrw-rw-rw- 1 root root 10,200 /dev/net/tun\nMISSING /dev/fuse",
                "DNS_ORACLE": "github.com resolved",
                "TCP_443_ORACLE": "PASS",
                "HTTPS_EGRESS": "HTTP/2 200",
            },
        }
        facts = MOD.derive_capability_facts(receipt)
        self.assertEqual(facts["runtime:lxc"]["state"], "SUPPORTED")
        self.assertEqual(facts["kernel:shared"]["state"], "SUPPORTED")
        self.assertEqual(facts["device:kvm"]["state"], "NEGATIVE_OBSERVATION")
        self.assertEqual(facts["device:tun"]["state"], "OBSERVED")
        self.assertEqual(facts["network:https-egress"]["state"], "SUPPORTED")

    def test_apple_negative_guest_does_not_erase_callable_control_plane(self):
        receipt = {
            "lane": "apple",
            "oracleSatisfied": False,
            "classification": "NEGATIVE_OBSERVATION",
            "reason": "nested virtualization unavailable",
            "isolation": "lightweight-linux-vm-per-container",
            "host": {
                "machine": "arm64",
                "sysctl": {"hv_support": {"stdout": "0", "exit_code": 0}},
            },
            "steps": [
                {"version": {"exit_code": 0}},
                {"status": {"exit_code": 0}},
            ],
        }
        facts = MOD.derive_capability_facts(receipt)
        self.assertEqual(facts["runtime:apple-container"]["state"], "NEGATIVE_OBSERVATION")
        self.assertEqual(facts["apple-container:control-plane"]["state"], "SUPPORTED")
        self.assertEqual(facts["host:apple-hv-support"]["state"], "NEGATIVE_OBSERVATION")
        self.assertEqual(facts["gpu:apple"]["state"], "DOCUMENTED_NEGATIVE")

    def test_windows_gpu_visibility_is_not_directx_support(self):
        receipt = {
            "lane": "windows",
            "oracleSatisfied": True,
            "classification": "SUPPORTED",
            "reason": "ok",
            "isolation": "process",
            "host": {"machine": "AMD64"},
            "container_census": {
                "env": {"PROCESSOR_ARCHITECTURE": "AMD64"},
                "display": [{"Name": "Microsoft Hyper-V Video"}],
                "dnsLookup": ["example"],
                "httpsEgress": True,
                "net": [{"Name": "vEthernet"}],
            },
            "steps": [],
        }
        facts = MOD.derive_capability_facts(receipt)
        self.assertEqual(facts["runtime:windows-container"]["state"], "SUPPORTED")
        self.assertEqual(facts["gpu:windows-display"]["state"], "OBSERVED")
        self.assertEqual(facts["gpu:directx"]["state"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
