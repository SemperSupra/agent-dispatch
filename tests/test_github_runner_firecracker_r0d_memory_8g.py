import importlib.util, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r0d",ROOT/"scripts"/"github_runner_firecracker_r0d_memory_8g.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class R0dTests(unittest.TestCase):
    def test_point(self): self.assertEqual(MOD.WORKING_SET_MIB,8192)
    def test_guest_headroom(self): self.assertEqual(MOD.GUEST_MEM_MIB-MOD.WORKING_SET_MIB,1024)
if __name__=="__main__":unittest.main()
