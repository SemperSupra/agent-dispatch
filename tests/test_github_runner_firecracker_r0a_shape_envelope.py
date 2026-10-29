import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r0a",ROOT/"scripts"/"github_runner_firecracker_r0a_shape_envelope.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class R0aTests(unittest.TestCase):
    def test_vcpu_points_are_bounded(self):
        self.assertEqual(MOD.VCPU_POINTS,(1,2,4,8,16,32))
    def test_memory_points_are_bounded(self):
        self.assertEqual(MOD.MEM_POINTS_MIB,(128,256,512,1024,2048,4096,8192))
    def test_host_guardrail_is_two_gib(self):
        self.assertEqual(MOD.MIN_HOST_AVAILABLE_AFTER_RESERVATION_BYTES,2*1024**3)

if __name__=="__main__": unittest.main()
