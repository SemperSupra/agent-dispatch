import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "firecracker_host_fingerprint",
    ROOT / "scripts" / "firecracker_host_fingerprint.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerHostFingerprintTests(unittest.TestCase):
    def test_exact_match_passes(self):
        a = {
            "architecture": "x86_64",
            "cpu_vendor_id": "AuthenticAMD",
            "cpu_model_name": "AMD EPYC",
            "cpu_flags_sha256": "abc",
            "host_kernel_release": "6.11.0",
            "kvm_api_version": 12,
        }
        result = MOD.compare_for_initial_snapshot_restore(a, dict(a))
        self.assertTrue(result["compatible_for_initial_restore_attempt"])
        self.assertTrue(all(result["checks"].values()))

    def test_cpu_model_mismatch_is_compatibility_mismatch(self):
        a = {
            "architecture": "x86_64",
            "cpu_vendor_id": "AuthenticAMD",
            "cpu_model_name": "A",
            "cpu_flags_sha256": "abc",
            "host_kernel_release": "6.11.0",
            "kvm_api_version": 12,
        }
        b = dict(a)
        b["cpu_model_name"] = "B"
        result = MOD.compare_for_initial_snapshot_restore(a, b)
        self.assertFalse(result["compatible_for_initial_restore_attempt"])
        self.assertFalse(result["checks"]["cpu_model_name"])


if __name__ == "__main__":
    unittest.main()
