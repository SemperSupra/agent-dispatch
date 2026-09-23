import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_f0", ROOT / "scripts" / "github_runner_firecracker_f0.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerF0Tests(unittest.TestCase):
    def test_manifest_pins_expected_release_digest(self):
        manifest = json.loads(
            (ROOT / "experiments" / "firecracker" / "firecracker-v1.17.0-x86_64.json").read_text()
        )
        self.assertEqual(manifest["version"], "v1.17.0")
        self.assertEqual(manifest["architecture"], "x86_64")
        self.assertEqual(
            manifest["archive_sha256"],
            "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
        )

    def test_sha256_helper_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "sample"
            p.write_bytes(b"firecracker-f0")
            self.assertEqual(
                MOD._sha256(p),
                hashlib.sha256(b"firecracker-f0").hexdigest(),
            )

    def test_wrong_platform_is_setup_required(self):
        classification, reason = MOD._classify(
            linux_x64=False,
            digest_ok=True,
            version_ok=True,
            kvm_present=True,
            kvm_sudo_ok=True,
        )
        self.assertEqual(classification, "SETUP_REQUIRED")
        self.assertIn("Linux x86_64", reason)

    def test_digest_mismatch_is_oracle_failure(self):
        classification, _ = MOD._classify(
            linux_x64=True,
            digest_ok=False,
            version_ok=True,
            kvm_present=True,
            kvm_sudo_ok=True,
        )
        self.assertEqual(classification, "ORACLE_FAILURE")

    def test_kvm_sudo_boundary_failure_is_environment_failure(self):
        classification, _ = MOD._classify(
            linux_x64=True,
            digest_ok=True,
            version_ok=True,
            kvm_present=True,
            kvm_sudo_ok=False,
        )
        self.assertEqual(classification, "ENVIRONMENT_FAILURE")

    def test_supported_requires_all_f0_oracles(self):
        classification, _ = MOD._classify(
            linux_x64=True,
            digest_ok=True,
            version_ok=True,
            kvm_present=True,
            kvm_sudo_ok=True,
        )
        self.assertEqual(classification, "SUPPORTED")

    def test_receipt_keeps_portable_and_venue_facts_separate(self):
        fake_manifest = {
            "name": "firecracker",
            "version": "v1.17.0",
            "architecture": "x86_64",
            "release_url": "https://example.invalid/release",
            "archive_url": "https://example.invalid/archive.tgz",
            "archive_sha256": "0" * 64,
            "expected_version_fragment": "Firecracker v1.17.0",
        }
        with tempfile.TemporaryDirectory() as td:
            manifest_path = pathlib.Path(td) / "manifest.json"
            manifest_path.write_text(json.dumps(fake_manifest))
            with (
                mock.patch.object(MOD.platform, "system", return_value="Darwin"),
                mock.patch.object(MOD.platform, "machine", return_value="arm64"),
                mock.patch.object(
                    MOD,
                    "_kvm_user_probe",
                    return_value={"present": False, "callable": False, "api_version": None, "error": "absent"},
                ),
            ):
                receipt = MOD.run_probe("test-runner", manifest_path)
        self.assertIn("portable", receipt)
        self.assertIn("venue_adapter", receipt)
        self.assertFalse(receipt["result"]["guest_boot_claimed"])
        self.assertFalse(receipt["sovereign_transfer"]["portable_contract_depends_on_github_actions"])


if __name__ == "__main__":
    unittest.main()
