import importlib.util,pathlib,tempfile,unittest,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("aar_runtime",ROOT/"scripts"/"aar_runtime_qualify.py")
M=importlib.util.module_from_spec(SPEC); assert SPEC.loader; sys.modules[SPEC.name]=M; SPEC.loader.exec_module(M)
class T(unittest.TestCase):
 def test_contract(self):
  c=M.contract(); self.assertEqual(set(c["audiences"]),{"human","automation","agent"}); self.assertEqual(c["lifecycle"],"observe -> plan -> apply -> verify")
 def test_matrix(self):
  self.assertEqual(set(M.CLT),{("Windows","x86_64"),("Linux","x86_64"),("Darwin","x86_64"),("Darwin","arm64")})
 def test_image_mapping(self):
  self.assertTrue(M.image_package("Darwin","arm64").endswith("arm64-v8a")); self.assertTrue(M.image_package("Linux","x86_64").endswith("x86_64"))
 def test_accel_check_zero_means_usable(self):
  self.assertEqual(M.accel_status(0),"usable"); self.assertEqual(M.accel_status(11),"unavailable")
 def test_revert_empty(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"managed"; a=M.revert(p); b=M.revert(p); self.assertFalse(a["changed"]); self.assertFalse(b["changed"]); self.assertTrue(a["passed"] and b["passed"])
if __name__=="__main__": unittest.main()
