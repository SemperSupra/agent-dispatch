import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r0b",ROOT/"scripts"/"github_runner_firecracker_r0b_active_resources.py")
MOD=importlib.util.module_from_spec(SPEC);assert SPEC.loader;SPEC.loader.exec_module(MOD)

class R0bTests(unittest.TestCase):
    def test_memory_checksum_small(self):
        pages,checksum=MOD._mem_expected_checksum(1)
        self.assertEqual(pages,256)
        self.assertGreater(checksum,0)
    def test_cpu_points(self):
        self.assertEqual(MOD.CPU_POINTS,(1,2,4,8,16,32))
    def test_memory_ceiling(self):
        self.assertEqual(MOD.MEM_POINTS_MIB[-1],4096)
    def test_small_cpu_checksum(self):
        self.assertEqual(len(MOD._cpu_expected_checksum(2,10)),16)

if __name__=="__main__":unittest.main()
