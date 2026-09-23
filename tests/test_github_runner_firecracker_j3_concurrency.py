import importlib.util
import pathlib
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("j3",ROOT/"scripts"/"github_runner_firecracker_j3_concurrency.py")
MOD=importlib.util.module_from_spec(SPEC);assert SPEC.loader;SPEC.loader.exec_module(MOD)
class J3Tests(unittest.TestCase):
    def test_points(self):self.assertEqual(MOD.POINTS,(1,2,4))
    def test_authority(self):self.assertIn("#287",MOD.AUTHORITY)
if __name__=="__main__":unittest.main()
