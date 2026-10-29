import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_p2_coexistence",
    ROOT / "scripts" / "github_runner_firecracker_p2_coexistence.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerP2CoexistenceTests(unittest.TestCase):
    def test_fixed_vm_count_is_bounded(self):
        self.assertEqual(MOD.N_VM, 2)

    def test_helper_source_exists(self):
        self.assertTrue(MOD.HELPER_SOURCE.exists())

    def test_helper_parser(self):
        m = MOD.HELPER_RE.search("P2_CPU_HELPER iterations=123 elapsed_ns=1200000000")
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), 123)
        self.assertEqual(int(m.group(2)), 1200000000)


if __name__ == "__main__":
    unittest.main()
