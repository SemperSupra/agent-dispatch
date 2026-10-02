import importlib.util
import os
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_var_tmp_runtime.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r4", SCRIPT)
r4 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r4)


class VarTmpFixtureTests(unittest.TestCase):
    def test_materialize_only_var_tmp(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "var").mkdir()
            os.symlink("./var/tmp", root / "tmp")
            result = r4.materialize_var_tmp(root)
            self.assertEqual(result["path"], "/var/tmp")
            self.assertFalse(result["before"]["exists"])
            self.assertEqual(result["after"]["type"], "directory")
            self.assertTrue((root / "var" / "tmp").is_dir())
            self.assertFalse((root / "var" / "run").exists())
            self.assertFalse((root / "dev" / "shm").exists())

    def test_refuses_existing_var_tmp(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "var" / "tmp").mkdir(parents=True)
            os.symlink("./var/tmp", root / "tmp")
            with self.assertRaises(RuntimeError):
                r4.materialize_var_tmp(root)

    def test_refuses_wrong_tmp_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "var").mkdir()
            (root / "tmp").mkdir()
            with self.assertRaises(RuntimeError):
                r4.materialize_var_tmp(root)


if __name__ == "__main__":
    unittest.main()
