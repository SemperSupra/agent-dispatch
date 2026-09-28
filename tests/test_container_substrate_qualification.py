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
            "NETWORK", "ROUTES", "DNS", "DNS_ORACLE", "HTTPS_EGRESS",
            "DEVICES", "FILESYSTEM", "IDENTITY",
        ):
            self.assertIn(f"==={section}===", MOD.LINUX_INNER)

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


if __name__ == "__main__":
    unittest.main()
