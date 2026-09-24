import importlib.util
import pathlib
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "winget_config_preflight",
    ROOT / "scripts" / "github_runner_winget_config.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


class WinGetConfigPreflightTests(unittest.TestCase):
    def test_synthetic_configuration_is_public_v3_package_resource(self):
        text = MOD.SYNTHETIC_CONFIGURATION
        self.assertIn("identifier: dscv3", text)
        self.assertIn("type: Microsoft.WinGet/Package", text)
        self.assertIn("id: Git.Git", text)
        self.assertNotIn("WinBot", text)
        self.assertNotIn("SemperSupra", text)

    @patch.object(MOD.platform, "system", return_value="Linux")
    def test_non_windows_is_guarded(self, _system):
        receipt = MOD.qualify_winget_config_preflight("ubuntu-test")
        self.assertEqual(receipt["result"]["classification"], "SKIPPED_GUARDRAIL")
        self.assertFalse(receipt["result"]["passed"])

    @patch.object(MOD.shutil, "which", return_value=None)
    @patch.object(MOD.platform, "system", return_value="Windows")
    def test_missing_winget_is_guarded(self, _system, _which):
        receipt = MOD.qualify_winget_config_preflight("windows-test")
        self.assertEqual(receipt["result"]["classification"], "SKIPPED_GUARDRAIL")

    @patch.object(MOD.shutil, "which", return_value=r"C:\winget.exe")
    @patch.object(MOD.platform, "system", return_value="Windows")
    def test_pass_executes_only_version_help_validate_and_test(self, _system, _which):
        calls = []

        def fake_run(argv, timeout=180):
            calls.append(list(argv))
            if argv[1:] == ["--version"]:
                return 0, "v1.12.0", "", 0.1
            if argv[1:] == ["configure", "--help"]:
                return 0, "configure help", "", 0.1
            if argv[1:3] == ["configure", "validate"]:
                return 0, "validated", "", 0.2
            if argv[1:3] == ["configure", "test"]:
                return 0, "desired state", "", 0.3
            raise AssertionError(argv)

        with patch.object(MOD, "_run", side_effect=fake_run):
            receipt = MOD.qualify_winget_config_preflight("windows-2025")

        self.assertTrue(receipt["result"]["passed"])
        self.assertEqual(receipt["result"]["classification"], "SUPPORTED")
        self.assertEqual(receipt["configuration"]["package_id"], "Git.Git")
        self.assertFalse(receipt["configuration"]["desired_state_apply_performed"])
        self.assertEqual(len(calls), 4)
        self.assertFalse(any(call[1:] and call[1:] == ["configure"] for call in calls))
        self.assertFalse(any(len(call) > 1 and call[1] == "install" for call in calls))
        self.assertFalse(any(
            len(call) >= 2 and call[1] == "configure" and
            (len(call) == 2 or call[2] not in {"--help", "validate", "test"})
            for call in calls
        ))

    @patch.object(MOD.shutil, "which", return_value=r"C:\winget.exe")
    @patch.object(MOD.platform, "system", return_value="Windows")
    def test_validate_failure_stops_before_test(self, _system, _which):
        calls = []

        def fake_run(argv, timeout=180):
            calls.append(list(argv))
            if argv[1:] == ["--version"]:
                return 0, "v1.12.0", "", 0.1
            if argv[1:] == ["configure", "--help"]:
                return 0, "configure help", "", 0.1
            if argv[1:3] == ["configure", "validate"]:
                return 1, "", "bad config", 0.2
            raise AssertionError("test should not run after failed validate")

        with patch.object(MOD, "_run", side_effect=fake_run):
            receipt = MOD.qualify_winget_config_preflight("windows-2025")

        self.assertFalse(receipt["result"]["passed"])
        self.assertEqual(receipt["result"]["classification"], "ORACLE_FAILURE")
        self.assertEqual(len(calls), 3)

    @patch.object(MOD.shutil, "which", return_value=r"C:\winget.exe")
    @patch.object(MOD.platform, "system", return_value="Windows")
    def test_nonconverged_test_is_evidence_not_apply(self, _system, _which):
        def fake_run(argv, timeout=180):
            if argv[1:] == ["--version"]:
                return 0, "v1.12.0", "", 0.1
            if argv[1:] == ["configure", "--help"]:
                return 0, "configure help", "", 0.1
            if argv[1:3] == ["configure", "validate"]:
                return 0, "validated", "", 0.2
            if argv[1:3] == ["configure", "test"]:
                return 1, "not in desired state", "", 0.3
            raise AssertionError(argv)

        with patch.object(MOD, "_run", side_effect=fake_run):
            receipt = MOD.qualify_winget_config_preflight("windows-2025")

        self.assertFalse(receipt["result"]["passed"])
        self.assertEqual(receipt["result"]["classification"], "ORACLE_FAILURE")
        self.assertFalse(receipt["configuration"]["desired_state_apply_performed"])
        self.assertEqual(receipt["result"]["evidence"]["test_exit"], 1)


if __name__ == "__main__":
    unittest.main()
