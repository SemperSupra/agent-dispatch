import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_p1_concurrency",
    ROOT / "scripts" / "github_runner_firecracker_p1_concurrency.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerP1ConcurrencyTests(unittest.TestCase):
    def test_points_are_bounded(self):
        self.assertEqual(MOD.POINTS, (1, 2, 4))

    def test_cpu_busy_percent(self):
        self.assertEqual(MOD._cpu_busy_percent((100, 40), (200, 70)), 70.0)
        self.assertIsNone(MOD._cpu_busy_percent((100, 40), (100, 40)))

    def test_meminfo_shape(self):
        result = MOD._meminfo()
        self.assertIn("total_bytes", result)
        self.assertIn("available_bytes", result)

    def test_cpu_identity_shape(self):
        result = MOD._cpu_identity()
        self.assertIn("logical_cpus", result)
        self.assertIn("model", result)
        self.assertIn("flags_sha256", result)


if __name__ == "__main__":
    unittest.main()
