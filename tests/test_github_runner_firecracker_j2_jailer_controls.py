import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("j2",ROOT/"scripts"/"github_runner_firecracker_j2_jailer_controls.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class J2Tests(unittest.TestCase):
    def test_schema(self):
        self.assertEqual(MOD.SCHEMA,"firecracker-j2-jailer-controls/v1")
    def test_authority(self):
        self.assertIn("#287",MOD.AUTHORITY)

if __name__=="__main__": unittest.main()
