import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_capacity", ROOT / "scripts" / "github_runner_capacity.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)

class CapacityTests(unittest.TestCase):
    def test_probe_constants_are_bounded(self):
        self.assertLessEqual(MOD.HASH_BYTES, 256 * 1024 * 1024)
        self.assertLessEqual(MOD.DISK_BYTES, 128 * 1024 * 1024)
        self.assertLessEqual(MOD.MEMORY_BYTES, 64 * 1024 * 1024)
        self.assertLessEqual(MOD.COMPRESS_BYTES, 32 * 1024 * 1024)
        self.assertLessEqual(MOD.SPAWN_COUNT, 20)

    def test_guardrail_skips_without_failure(self):
        base = MOD.passive.build_receipt("test")
        base["resources"]["memory"]["available_bytes"] = 100
        base["resources"]["storage"] = [{
            "mount": "/",
            "filesystem": "test",
            "total_bytes": 1000,
            "free_bytes": 100,
        }]
        with mock.patch.object(MOD.passive, "build_receipt", return_value=base):
            receipt = MOD.build_capacity_receipt("test")
        cap = next(c for c in receipt["capabilities"] if c["name"] == "probe:capacity")
        self.assertEqual(cap["classification"], "SKIPPED_GUARDRAIL")
        self.assertFalse(cap["exercised"])

    def test_disk_probe_cleans_up(self):
        with tempfile.TemporaryDirectory() as td:
            results = MOD._disk_probe(pathlib.Path(td))
            self.assertEqual(len(results), 2)
            self.assertFalse((pathlib.Path(td) / "capacity-probe.bin").exists())

if __name__ == "__main__":
    unittest.main()
