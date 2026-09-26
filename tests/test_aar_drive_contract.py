import importlib.util,pathlib,tempfile,unittest,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location("drive_contract",ROOT/"scripts"/"aar_drive_contract.py"); M=importlib.util.module_from_spec(S); sys.modules[S.name]=M; S.loader.exec_module(M)
class T(unittest.TestCase):
 def test_roles(self): self.assertEqual(M.ROLES["current-candidate"],"current"); self.assertEqual(M.ROLES["superseded"],"lineage")
 def test_parser(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"e"; p.write_text("export A='x'\nB=y\n",encoding="utf-8"); self.assertEqual(M.parse_env_file(p),{"A":"x","B":"y"})
 def test_public_default_is_boundary(self):
  with tempfile.TemporaryDirectory() as d:
   o=M.discover(pathlib.Path(d)/"missing"); self.assertFalse(o["live_oauth_ready"]); self.assertFalse(o["routing_ready"])
 def test_contract_audiences(self): self.assertEqual(set(M.contract()["audiences"]),{"human","automation","agent"})
if __name__=="__main__": unittest.main()
