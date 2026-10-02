import importlib.util
import os
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_runtime_dirs.py"
spec = importlib.util.spec_from_file_location("fritz_e2_d4", SCRIPT)
d4 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(d4)


class RuntimeDirectoryContractTests(unittest.TestCase):
    def test_path_metadata_missing(self):
        with tempfile.TemporaryDirectory() as td:
            x = d4.path_metadata(pathlib.Path(td), "/tmp")
            self.assertFalse(x["exists"])
            self.assertEqual(x["type"], "missing")

    def test_path_metadata_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "var" / "tmp").mkdir(parents=True)
            os.symlink("var/tmp", root / "tmp")
            d = d4.path_metadata(root, "/var/tmp")
            s = d4.path_metadata(root, "/tmp")
            self.assertEqual(d["type"], "directory")
            self.assertEqual(s["type"], "symlink")
            self.assertEqual(s["symlinkTarget"], "var/tmp")

    def test_classify_line(self):
        self.assertIn("mkdir", d4.classify_line("mkdir -p /tmp"))
        self.assertIn("mount", d4.classify_line("mount -t tmpfs tmpfs /tmp"))
        self.assertEqual(d4.classify_line("echo /tmp"), ["reference"])

    def test_path_boundary(self):
        self.assertTrue(d4._path_mentioned("mkdir /tmp", "/tmp"))
        self.assertFalse(d4._path_mentioned("mkdir /tmpfoo", "/tmp"))

    def test_fixture_requirement_for_missing_tmp(self):
        metadata = {
            key: {"path": path, "exists": True, "type": "directory", "mode": "0755", "symlinkTarget": None}
            for key, path in d4.FIXED_PATHS.items()
        }
        metadata["tmp"] = {"path": "/tmp", "exists": False, "type": "missing", "mode": None, "symlinkTarget": None}
        req = d4.inferred_fixture_requirements(metadata, [])
        self.assertTrue(any(x["path"] == "/tmp" and x["requirement"] == "materialize-runtime-path" for x in req))


if __name__ == "__main__":
    unittest.main()
