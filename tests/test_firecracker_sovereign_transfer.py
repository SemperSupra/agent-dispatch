import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod

ADAPTER = load("firecracker_execution_adapter", pathlib.Path("scripts/firecracker_execution_adapter.py"))
TRANSFER = load("firecracker_sovereign_transfer", pathlib.Path("scripts/firecracker_sovereign_transfer.py"))


class FirecrackerSovereignTransferTests(unittest.TestCase):
    def test_direct_kvm_is_preferred(self):
        with (
            mock.patch.object(ADAPTER.f0, "_kvm_user_probe", return_value={
                "present": True, "callable": True, "api_version": 12, "error": None
            }),
            mock.patch.object(ADAPTER.f0, "_kvm_sudo_probe") as sudo_probe,
        ):
            result = ADAPTER.select_kvm_access()
        self.assertEqual(result["classification"], "SUPPORTED")
        self.assertEqual(result["mode"], "direct")
        self.assertEqual(result["command_prefix"], [])
        sudo_probe.assert_not_called()

    def test_sudo_is_fallback_only(self):
        with (
            mock.patch.object(ADAPTER.f0, "_kvm_user_probe", return_value={
                "present": True, "callable": False, "api_version": None, "error": "denied"
            }),
            mock.patch.object(ADAPTER.f0, "_kvm_sudo_probe", return_value={
                "available": True, "callable": True, "api_version": 12, "error": None
            }),
            mock.patch.object(ADAPTER.shutil, "which", return_value="/usr/bin/sudo"),
        ):
            result = ADAPTER.select_kvm_access()
        self.assertEqual(result["mode"], "sudo")
        self.assertEqual(result["command_prefix"], ["/usr/bin/sudo", "-n"])

    def test_no_kvm_is_setup_required(self):
        with (
            mock.patch.object(ADAPTER.f0, "_kvm_user_probe", return_value={
                "present": False, "callable": False, "api_version": None, "error": "absent"
            }),
            mock.patch.object(ADAPTER.shutil, "which", return_value=None),
        ):
            result = ADAPTER.select_kvm_access()
        self.assertEqual(result["classification"], "SETUP_REQUIRED")
        self.assertEqual(result["mode"], "unavailable")

    def test_preflight_declares_no_github_dependency(self):
        fake = {
            "result": {
                "host_admission_prerequisites_pass": True,
                "classification": "ADMISSION_PREREQUISITES_PASS",
                "operationally_qualified": False,
            }
        }
        with mock.patch.object(
            TRANSFER.detailed_preflight, "build_receipt", return_value=fake
        ):
            result = TRANSFER.preflight()
        self.assertEqual(result["result"]["classification"], "SUPPORTED")
        self.assertFalse(result["github_actions_environment_required"])
        self.assertFalse(result["result"]["operationally_qualified"])
        self.assertIs(result["detailed_preflight"], fake)


if __name__ == "__main__":
    unittest.main()
