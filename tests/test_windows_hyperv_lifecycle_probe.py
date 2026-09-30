import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "windows-2025-hyperv-lifecycle.yml"
SCRIPT = ROOT / "scripts" / "windows_hyperv_lifecycle_probe.ps1"


class WindowsHyperVLifecycleProbeContractTests(unittest.TestCase):
    def test_workflow_is_one_public_windows_2025_probe(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("runs-on: windows-2025"), 1)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("github-runner-capability/v1", SCRIPT.read_text(encoding="utf-8"))

    def test_actions_are_commit_pinned(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"uses:\s*([^\s]+)", text)
        self.assertTrue(uses)
        for value in uses:
            self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$", value)

    def test_probe_contains_full_vm_lifecycle_and_independent_cleanup(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "New-VM",
            "Start-VM",
            "Get-VM",
            "Stop-VM",
            "Remove-VM",
            "Get-VMNetworkAdapter",
            "Get-VMHardDiskDrive",
            "cleanup",
            "oracleSatisfied",
        ):
            self.assertIn(token, text)

    def test_probe_forbids_repairs_private_inputs_and_network_attachment(self):
        combined = (
            WORKFLOW.read_text(encoding="utf-8")
            + "\n"
            + SCRIPT.read_text(encoding="utf-8")
        ).lower()
        for forbidden in (
            "enable-windowsoptionalfeature",
            "enable-windowsfeature",
            "restart-computer",
            "restart-service vmms",
            "-switchname",
            "new-vhd",
            "add-vmharddiskdrive",
            "winbot_vm_password",
            "winbot_api_token",
            "c:\\winbot\\.api_token",
        ):
            self.assertNotIn(forbidden, combined)

    def test_failure_domains_are_preserved(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for classification in (
            "SUPPORTED",
            "ENVIRONMENT_FAILURE",
            "HARNESS_FAILURE",
            "ORACLE_FAILURE",
        ):
            self.assertIn(classification, text)


if __name__ == "__main__":
    unittest.main()
