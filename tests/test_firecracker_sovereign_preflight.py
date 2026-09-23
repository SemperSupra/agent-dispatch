import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "firecracker_sovereign_preflight",
    ROOT / "scripts" / "firecracker_sovereign_preflight.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerSovereignPreflightTests(unittest.TestCase):
    def test_portable_reproduction_scripts_exist(self):
        for rel in MOD.PORTABLE_REPRODUCTION:
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_exact_pinned_artifacts_remain_selected(self):
        vmm = json.loads(MOD.VMM_MANIFEST.read_text())
        kernel = json.loads(MOD.KERNEL_MANIFEST.read_text())
        self.assertEqual(vmm["version"], "v1.17.0")
        self.assertEqual(
            vmm["archive_sha256"],
            "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
        )
        self.assertEqual(kernel["kernel_version"], "6.18.48")
        self.assertEqual(
            kernel["kernel_sha256"],
            "9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2",
        )

    def test_preflight_never_claims_operational_qualification(self):
        fake_host = {
            "architecture": "x86_64",
            "cpu_vendor_id": "Test",
            "cpu_model_name": "Test CPU",
            "cpu_flags": [],
            "cpu_flags_sha256": "x",
            "logical_cpus": 4,
            "host_kernel_release": "test",
            "image_os": None,
            "image_version": None,
            "kvm_api_version": 12,
        }
        with (
            mock.patch.object(MOD, "fingerprint", return_value=fake_host),
            mock.patch.object(
                MOD.f0,
                "_kvm_user_probe",
                return_value={"present": True, "callable": True, "api_version": 12, "error": None},
            ),
            mock.patch.object(MOD, "_tool_state", return_value={"available": True, "path": "/bin/test"}),
            mock.patch.object(
                MOD,
                "_docker_state",
                return_value={"available": True, "path": "/bin/docker", "daemon_callable": True},
            ),
        ):
            receipt = MOD.build_receipt()
        self.assertTrue(receipt["result"]["host_admission_prerequisites_pass"])
        self.assertFalse(receipt["result"]["operationally_qualified"])
        self.assertEqual(receipt["kvm"]["selected_access_path"], "direct-user")

    def test_compare_to_emits_snapshot_gate(self):
        fake_host = {
            "architecture": "x86_64",
            "cpu_vendor_id": "Test",
            "cpu_model_name": "Test CPU",
            "cpu_flags": [],
            "cpu_flags_sha256": "same",
            "logical_cpus": 4,
            "host_kernel_release": "test",
            "image_os": None,
            "image_version": None,
            "kvm_api_version": 12,
        }
        with tempfile.TemporaryDirectory() as td:
            other = pathlib.Path(td) / "other.json"
            other.write_text(json.dumps({"host_fingerprint": fake_host}))
            with (
                mock.patch.object(MOD, "fingerprint", return_value=fake_host),
                mock.patch.object(
                    MOD.f0,
                    "_kvm_user_probe",
                    return_value={"present": True, "callable": True, "api_version": 12, "error": None},
                ),
                mock.patch.object(MOD, "_tool_state", return_value={"available": True, "path": "/bin/test"}),
                mock.patch.object(
                    MOD,
                    "_docker_state",
                    return_value={"available": False, "path": None, "daemon_callable": False},
                ),
            ):
                receipt = MOD.build_receipt(other)
        self.assertTrue(
            receipt["cross_host_snapshot_gate"]["compatible_for_initial_restore_attempt"]
        )


if __name__ == "__main__":
    unittest.main()
