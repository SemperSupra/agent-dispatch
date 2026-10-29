import importlib.util
import pathlib
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r0c",ROOT/"scripts"/"github_runner_firecracker_r0c_memory_headroom.py")
MOD=importlib.util.module_from_spec(SPEC);assert SPEC.loader;SPEC.loader.exec_module(MOD)
class R0cTests(unittest.TestCase):
    def test_points(self):self.assertEqual(MOD.POINTS_MIB,(4096,6144))
    def test_headroom(self):self.assertEqual(MOD.GUEST_HEADROOM_MIB,1024)
if __name__=="__main__":unittest.main()
