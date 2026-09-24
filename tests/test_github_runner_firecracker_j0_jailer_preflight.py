import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_j0_jailer_preflight",
    ROOT / "scripts" / "github_runner_firecracker_j0_jailer_preflight.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerJ0Tests(unittest.TestCase):
    def test_cgroup_inventory_shape(self):
        result = MOD._cgroup_inventory()
        self.assertIn("filesystem_type", result)
        self.assertIn("version", result)
        self.assertIn("controllers", result)

    def test_mount_inventory_shape(self):
        result = MOD._mount_inventory()
        self.assertIn("mount_count", result)
        self.assertIn("mount_namespace", result)
        self.assertIn("pid_namespace", result)

    def test_find_one_requires_exactly_one(self):
        with self.assertRaises(RuntimeError):
            MOD._find_one(pathlib.Path("/definitely/not/present"), ("jailer",))


if __name__ == "__main__":
    unittest.main()
