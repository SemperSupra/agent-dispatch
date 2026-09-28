import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_j1_jailed_f3",
    ROOT / "scripts" / "github_runner_firecracker_j1_jailed_f3.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerJ1Tests(unittest.TestCase):
    def test_find_binary_requires_exact_match(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            p=root/"jailer-v1.17.0-x86_64"; p.write_text("x")
            self.assertEqual(MOD._find_binary(root,p.name),p)

    def test_find_binary_rejects_missing(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                MOD._find_binary(pathlib.Path(td),"missing")


if __name__ == "__main__":
    unittest.main()
